import asyncio
import json
import os
import sys
from types import SimpleNamespace

import pytest

from lasa_service.enclosure import Enclosure
from lasa_service.errors import LasaError
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


@pytest.mark.integration
async def test_container_blocks_host_files_processes_and_network(tmp_path, runtime_image):
    boundary = Enclosure()
    workspace, home, protected = [tmp_path / name for name in ("workspace", "home", "protected")]
    for path in (workspace, home, protected, protected / "empty"):
        path.mkdir()
    (home / "config.toml").write_text("")
    (protected / "empty-file").write_text("")
    secret = tmp_path / "private-secret"
    secret.write_text("must stay private")
    (workspace / "escape").symlink_to(secret)
    canary = "host-environment-" + identity("canary")
    target = await asyncio.create_subprocess_exec(
        sys.executable,
        "-I",
        "-S",
        "-c",
        "import time; time.sleep(60)",
        env={"LASA_HOST_SECRET": canary},
        start_new_session=True,
    )
    task_id = identity("tsk")
    container_id = None
    try:
        container_id = await boundary.create(
            image=runtime_image,
            executable="/usr/local/bin/codex",
            task_id=task_id,
            service_id="lasa-test",
            workspace=workspace,
            home=home,
            protected=protected,
            token="task-only-handle",
            role="hold",
        )
        await boundary.run("start", container_id)
        script = """import json,os,pathlib,socket,sys
checks={}
for name,path in [('private_file',sys.argv[1]),('symlink','/workspace/escape')]:
 try: open(path).read(); checks[name]=False
 except OSError: checks[name]=True
for name,path in [('configuration','/home/lasa/config.toml'),('instructions','/workspace/AGENTS.md'),('project_configuration','/workspace/.codex/config.toml')]:
 try: open(path,'w').write('bad'); checks[name]=False
 except OSError: checks[name]=True
try: socket.create_connection(('1.1.1.1',443),timeout=.25).close(); checks['network']=False
except OSError: checks['network']=True
checks['host_environment']=True
for path in pathlib.Path('/proc').glob('[0-9]*/environ'):
 try:
  if sys.argv[2].encode() in path.read_bytes(): checks['host_environment']=False
 except OSError: pass
open('/workspace/allowed.txt','w').write('workspace access')
checks['workspace']=True
print(json.dumps(checks))
"""
        _, stdout, stderr = await boundary.run(
            "exec", container_id, "python3", "-I", "-S", "-c", script, secret, canary
        )
        assert all(json.loads(stdout).values()), (stdout.decode(), stderr.decode())
        assert (workspace / "allowed.txt").read_text() == "workspace access"
        _, network, _ = await boundary.run(
            "inspect", "--format", "{{.HostConfig.NetworkMode}}", container_id
        )
        assert network.strip() == b"none"
        # Recovery removes a recorded running container before admitting new work.
        store = Store(tmp_path / "state")
        try:
            store.db.execute(
                "INSERT INTO runtimes VALUES(?,?,?,?)", (task_id, 0, 0.0, container_id)
            )
            await CodexRuntime().recover(
                SimpleNamespace(store=store, config=SimpleNamespace(service_id="lasa-test"))
            )
            assert await boundary.inspect(container_id) is None
            assert store.db.execute("SELECT count(*) FROM runtimes").fetchone()[0] == 0
        finally:
            store.close()
    finally:
        if container_id:
            await boundary.remove(container_id, task_id, "lasa-test")
        target.kill()
        await target.wait()
