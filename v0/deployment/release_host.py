"""Host-side filesystem operations for a managed release."""

import fcntl
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

CONFIGS = ("config.json", "steady-config.json")
LIVE_STATES = (
    "evaluating",
    "awaiting_input",
    "accepted",
    "executing",
    "waiting_child",
    "cancelling",
)


def ensure_idle(layer):
    uri = (layer / "private/tasks.sqlite3").as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True) as db:
        markers = ",".join("?" for _ in LIVE_STATES)
        if db.execute(
            f"SELECT 1 FROM tasks WHERE state IN ({markers}) LIMIT 1", LIVE_STATES
        ).fetchone():
            raise RuntimeError("Backend has active tasks")


def replace_config(destination, data):
    pending = destination.with_suffix(".release-pending")
    with pending.open("wb") as target:
        target.write(data)
        target.flush()
        os.fsync(target.fileno())
    pending.replace(destination)


@contextmanager
def stopped_backend(layer):
    with (layer / "private/service.lock").open("rb") as lock:
        deadline = time.monotonic() + 10
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("Backend still owns the store") from None
                time.sleep(0.2)
        yield


def stage_release(root, layer, slot, wheel_name, wheel_digest, revision):
    wheel = slot / wheel_name
    if hashlib.sha256(wheel.read_bytes()).hexdigest() != wheel_digest:
        raise RuntimeError("Staged wheel checksum mismatch")
    for name in CONFIGS:
        data = (layer / name).read_bytes()
        (slot / name).write_bytes(data)
        config = json.loads(data)
        config["service"]["deployment_revision"] = revision
        (slot / ("candidate-" + name)).write_text(json.dumps(config, indent=2) + "\n")
    candidate = slot / "candidate-venv"
    shutil.copytree((root / "venv").resolve(strict=True), candidate, symlinks=True)
    python = candidate / "bin/python"
    subprocess.run(
        [
            str(Path.home() / ".local/bin/uv"),
            "pip",
            "install",
            "--python",
            str(python),
            "--no-deps",
            "--reinstall",
            str(wheel),
        ],
        check=True,
        timeout=35,
        capture_output=True,
    )
    subprocess.run(
        [str(python), "-I", "-m", "lasa_service.cli", "--help"],
        check=True,
        timeout=10,
        capture_output=True,
    )


def activate(root, layer, slot):
    ensure_idle(layer)
    for name in CONFIGS:
        if (layer / name).read_bytes() != (slot / name).read_bytes():
            raise RuntimeError("Configuration changed since staging")
    venv = root / "venv"
    previous = slot / "previous-venv"
    if os.path.lexists(previous):
        raise RuntimeError("Previous environment already recorded")
    venv.rename(previous)
    venv.symlink_to(slot / "candidate-venv", target_is_directory=True)
    for name in CONFIGS:
        replace_config(layer / name, (slot / ("candidate-" + name)).read_bytes())


def restore(root, layer, slot):
    venv = root / "venv"
    previous = slot / "previous-venv"
    if not os.path.lexists(previous):
        return
    if os.path.lexists(venv):
        if not venv.is_symlink() or venv.readlink() != slot / "candidate-venv":
            raise RuntimeError("Unexpected managed environment; preserved for operator review")
        venv.unlink()
    for name in CONFIGS:
        replace_config(layer / name, (slot / name).read_bytes())
    previous.rename(venv)


def main():
    os.umask(0o077)
    command, target, layer_name, release, *args = sys.argv[1:]
    root = Path(target)
    layer = root / layer_name
    slot = root / "backups" / release
    if command == "idle":
        ensure_idle(layer)
    elif command == "init":
        slot.mkdir(mode=0o700)
    elif command == "stage":
        stage_release(root, layer, slot, *args)
    elif command == "activate":
        with stopped_backend(layer):
            activate(root, layer, slot)
    elif command == "restore":
        with stopped_backend(layer):
            restore(root, layer, slot)
    else:
        raise ValueError("Unknown release operation")


if __name__ == "__main__":
    main()
