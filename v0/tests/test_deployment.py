import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from deployment import release_host
from deployment.deploy_release import Host, deploy


def test_mac_stop_waits_for_launchd_to_remove_the_service(monkeypatch, tmp_path):
    calls = []
    statuses = iter([0, 0, 0, 1])

    def launchctl(self, args, **kwargs):
        calls.append(args[1])
        return SimpleNamespace(returncode=next(statuses))

    monkeypatch.setattr(Host, "run", launchctl)
    Host("layer1", tmp_path, "https://localhost:8443").stop()
    assert calls == ["bootout", "print", "print", "print"]


def test_rollout_failure_restores_both_backends_in_dependency_order():
    steps = []

    class Host:
        def __init__(self, layer):
            self.layer = layer
            self.revision = layer + "-old"

        def host_operation(self, phase, release):
            steps.append((self.layer, phase))
            if phase == "activate":
                self.revision = release
            elif phase == "restore":
                self.revision = self.layer + "-old"

        def stage(self, release, wheel, checksum):
            steps.append((self.layer, "stage"))

        def start(self):
            steps.append((self.layer, "start"))

        def stop(self):
            steps.append((self.layer, "stop"))

        def check_ready(self, client, expected=None):
            if self.layer == "parent" and expected == "candidate":
                raise RuntimeError("injected readiness failure")
            if expected is not None:
                assert self.revision == expected
            return self.revision

    parent, child = Host("parent"), Host("child")
    with pytest.raises(RuntimeError, match="injected readiness failure"):
        deploy((parent, child), "candidate", Path("wheel"), "checksum", None)
    assert steps[-6:] == [
        ("parent", "stop"),
        ("child", "stop"),
        ("child", "restore"),
        ("child", "start"),
        ("parent", "restore"),
        ("parent", "start"),
    ]
    assert (parent.revision, child.revision) == ("parent-old", "child-old")


def test_restore_after_partial_activation_preserves_original_config_and_environment(
    tmp_path, monkeypatch
):
    root = tmp_path
    layer = root / "layer"
    private = layer / "private"
    private.mkdir(parents=True)
    with sqlite3.connect(private / "tasks.sqlite3") as db:
        db.execute("CREATE TABLE tasks (state TEXT)")
    slot = root / "backups" / "release"
    (slot / "candidate-venv").mkdir(parents=True)
    environment = root / "venv"
    environment.mkdir()
    (environment / "original").touch()
    for name in release_host.CONFIGS:
        original = json.dumps({"config": name, "revision": "original"})
        (layer / name).write_text(original)
        (slot / name).write_text(original)
        (slot / ("candidate-" + name)).write_text('{"revision":"candidate"}')
    replace = release_host.replace_config

    def fail_on_steady(path, data):
        if path.name == "steady-config.json":
            raise OSError("injected filesystem failure")
        replace(path, data)

    with monkeypatch.context() as patch:
        patch.setattr(release_host, "replace_config", fail_on_steady)
        with pytest.raises(OSError, match="injected filesystem failure"):
            release_host.activate(root, layer, slot)
    assert environment.is_symlink() and (slot / "previous-venv" / "original").exists()
    release_host.restore(root, layer, slot)
    assert not environment.is_symlink() and (environment / "original").exists()
    assert all(
        (layer / name).read_bytes() == (slot / name).read_bytes() for name in release_host.CONFIGS
    )
