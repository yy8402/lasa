import asyncio
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from lasa_service.enclosure import Enclosure
from lasa_service.errors import LasaError
from lasa_service.launcher import Launcher
from lasa_service.launcher_client import (
    DEFAULT_INSTANCE,
    LauncherClient,
    close_stream,
    launcher_scope,
    send_frame,
)
from lasa_service.runtime import CodexRuntime
from lasa_service.store import Store, identity
from lasa_service.workspace import Workspace


def test_symlinks_and_special_files_are_not_workspace_files(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    outside = tmp_path / "secret"
    outside.write_text("not visible")
    (root / "link").symlink_to(outside)
    os.mkfifo(root / "fifo")
    workspace = Workspace(root, 1024)
    for name in ("link", "fifo"):
        with pytest.raises((LasaError, OSError)):
            workspace.read(name)
        with pytest.raises((LasaError, OSError)):
            workspace.write(name, "bad")
    assert workspace.list()["entries"] == []
    assert outside.read_text() == "not visible"


async def test_unavailable_docker_cannot_confirm_absence(monkeypatch):
    enclosure = Enclosure("ignored", "scope")

    async def unavailable(*args, check=True):
        assert args[0] == "ps" and check
        raise LasaError("internal_error", 503)

    monkeypatch.setattr(enclosure, "run", unavailable)
    with pytest.raises(LasaError):
        await enclosure.remove(identity("attempt"))


async def test_launcher_lease_precedes_sweep_and_canary_has_own_scope(monkeypatch):
    service_id = "https://lasa.example.net"
    checked = []

    def launcher(instance):
        scope = launcher_scope(service_id, instance)
        enclosure = Enclosure(None, scope)

        async def verify(_version):
            checked.append(scope)

        async def inventory():
            return {}

        monkeypatch.setattr(enclosure, "verify_image", verify)
        monkeypatch.setattr(enclosure, "inventory", inventory)
        return Launcher(enclosure)

    with tempfile.TemporaryDirectory(prefix="lasa-lease-", dir="/tmp") as directory:
        root = Path(directory)
        active = launcher("live")
        candidate = launcher("canary")
        async with active.serve(root / "live.sock", root):
            with pytest.raises(ValueError, match="already owned"):
                async with launcher("live").serve(root / "duplicate.sock", root):
                    pytest.fail("A duplicate owner obtained a lease")
            async with candidate.serve(root / "canary.sock", root):
                assert checked == [active.enclosure.scope, candidate.enclosure.scope]
                with pytest.raises(LasaError):
                    await LauncherClient(root / "canary.sock", service_id, "live").check()
                await LauncherClient(root / "canary.sock", service_id, "canary").check()


@pytest.mark.integration
async def test_recover_lost_launch_reply_and_fence_duplicate(tmp_path, worker_launcher):
    launcher, path, service_id = worker_launcher
    task_id = identity("task")
    attempt_id = identity("attempt")
    store = Store(tmp_path / "state")
    try:
        session = identity("session")
        store.db.execute("INSERT INTO sessions VALUES(?,?,?)", (session, "owner", "{}"))
        store.db.execute(
            "INSERT INTO tasks VALUES(?,?,?,?,?,?,?,?)",
            (task_id, session, "executing", "{}", "{}", "{}", "{}", "{}"),
        )
        store.start_runtime(task_id, attempt_id)
        _, writer = await asyncio.open_unix_connection(path)
        try:
            await send_frame(
                writer,
                {
                    "operation": "launch",
                    "scope": launcher.enclosure.scope,
                    "attempt_id": attempt_id,
                    "model": "test-model",
                    "expires_at": time.time() + 10,
                },
            )
            async with asyncio.timeout(5):
                while True:
                    if attempt_id in await launcher.enclosure.inventory():
                        break
                    await asyncio.sleep(0.02)
            # The supervisor never reads the launch reply and has no container ID or PID.
            settings = {
                "launcher_socket": str(path),
                "launcher_instance": DEFAULT_INSTANCE,
                "startup_timeout_ms": 10000,
            }
            runtime = CodexRuntime(
                SimpleNamespace(
                    service_id=service_id,
                    document={
                        "runtime": settings,
                        "limits": {"reconciliation_timeout_seconds": 10},
                    },
                )
            )
            await runtime.recover(SimpleNamespace(store=store))
            assert not store.runtime_attempts()
            assert not await launcher.enclosure.inventory()
            with pytest.raises(LasaError):
                await LauncherClient(path, service_id).launch(attempt_id, "test-model", 10)
        finally:
            await close_stream(writer)
    finally:
        store.close()


@pytest.mark.integration
async def test_container_has_no_host_mounts_processes_or_network(tmp_path, worker_launcher):
    launcher, path, service_id = worker_launcher
    boundary = launcher.enclosure
    secret = tmp_path / "private-secret"
    secret.write_text("must stay private")
    canary = identity("canary")
    target = await asyncio.create_subprocess_exec(
        sys.executable,
        "-I",
        "-S",
        "-c",
        "import time; time.sleep(60)",
        env={"LASA_HOST_SECRET": canary},
    )
    attempt_id = identity("attempt")
    client = LauncherClient(path, service_id)
    writer = None
    try:
        _, writer = await client.launch(attempt_id, "test-model", 10)
        container_id = (await boundary.inventory(attempt_id))[attempt_id]
        script = """
import pathlib, socket, sys

def inaccessible(path):
    try:
        pathlib.Path(path).read_bytes()
        return False
    except OSError:
        return True

def network_blocked():
    try:
        socket.create_connection(("1.1.1.1", 443), timeout=0.25).close()
        return False
    except OSError:
        return True

assert inaccessible(sys.argv[1])
assert list(pathlib.Path("/workspace").iterdir()) == []
assert network_blocked()
for path in pathlib.Path("/proc").glob("[0-9]*/environ"):
    try:
        assert sys.argv[2].encode() not in path.read_bytes()
    except OSError:
        pass
pathlib.Path("/workspace/scratch.txt").write_text("private worker scratch")
"""
        async with asyncio.timeout(5):
            while True:
                _, status, _ = await boundary.run(
                    "inspect", "--format", "{{.State.Running}}", container_id
                )
                if status.strip() == b"true":
                    break
                await asyncio.sleep(0.02)
        status, _, stderr = await boundary.run(
            "exec",
            container_id,
            "python3",
            "-I",
            "-S",
            "-c",
            script,
            str(secret),
            canary,
            check=False,
        )
        assert status == 0, stderr.decode()
        _, stdout, _ = await boundary.run("inspect", container_id)
        settings = json.loads(stdout)[0]
        assert settings["HostConfig"]["NetworkMode"] == "none"
        assert all(mount["Type"] == "tmpfs" for mount in settings["Mounts"])
        assert not (tmp_path / "scratch.txt").exists()
        with pytest.raises(LasaError):
            await LauncherClient(path, "wrong-scope").stop(attempt_id)
        await client.stop(attempt_id)
        assert not await boundary.inventory(attempt_id)
    finally:
        if writer:
            await close_stream(writer)
        await client.stop(attempt_id)
        target.kill()
        await target.wait()
