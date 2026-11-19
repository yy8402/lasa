"""Deploy the staged 1.1 connector release to the two managed LASA backends."""

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from prepare_connectors import REMOTE, ROOT, STAGE, TARGET

from lasa_service import __version__

SSH = "yang@192.168.0.188"
TERMINAL = {"completed", "failed", "cancelled", "rejected", "indeterminate"}


def run(arguments):
    return subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=45)


def remote(command):
    return run(["ssh", "-o", "BatchMode=yes", SSH, command])


def main():
    os.umask(0o077)
    wheel = ROOT / f"verification/dist/lasa_service_v0-{__version__}-py3-none-any.whl"
    sha = hashlib.sha256(wheel.read_bytes()).hexdigest()
    report_file = ROOT / ("verification/connectors-20261119/release-" + sha[:12] + ".json")
    assert not report_file.exists(), "This exact wheel already has a deployment observation"
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    revision = "connectors-20261119-" + sha[:12] + "-steady"
    with sqlite3.connect(
        "file:" + str(TARGET / "layer1/private/tasks.sqlite3") + "?mode=ro", uri=True
    ) as db:
        assert all(state in TERMINAL for (state,) in db.execute("select state from tasks"))
    remote(
        "python3 - <<'PY'\nimport sqlite3\nwith sqlite3.connect('file:"
        + REMOTE
        + "/layer2/private/tasks.sqlite3?mode=ro',uri=True) as db:\n assert all(s in "
        + repr(TERMINAL)
        + " for s, in db.execute('select state from tasks'))\nPY"
    )
    backup = TARGET / "backups" / ("connectors-" + stamp)
    backup.mkdir(parents=True)
    for layer in ["layer1", "layer2"]:
        destination = backup / layer
        destination.mkdir()
        for name in [
            "config.json",
            "steady-config.json",
            "connectors.json",
            "contracts.json",
            "authorization.json",
        ]:
            if (TARGET / layer / name).is_file():
                shutil.copy2(TARGET / layer / name, destination / name)
        config_file = STAGE / layer / "config.json"
        config = json.loads(config_file.read_text())
        config["service"]["deployment_revision"] = revision
        config_file.write_text(json.dumps(config, indent=2) + "\n")
    incoming = TARGET / "connector-release/remote"
    incoming.mkdir(exist_ok=True)
    for path in (STAGE / "layer2").glob("*.json"):
        (incoming / path.name).write_text(path.read_text().replace(str(TARGET), REMOTE))
    remote(
        "mkdir -p "
        + REMOTE
        + "/connector-release "
        + REMOTE
        + "/documents/lasa "
        + REMOTE
        + "/release "
        + REMOTE
        + "/backups/connectors-"
        + stamp
    )
    run(["scp", "-q", str(wheel), SSH + ":" + REMOTE + "/release/"])
    run(
        [
            "scp",
            "-q",
            *map(str, incoming.glob("*.json")),
            SSH + ":" + REMOTE + "/connector-release/",
        ]
    )
    remote(
        "python3 - <<'PY'\nfrom pathlib import Path\nfor p in Path('"
        + REMOTE
        + "/documents/lasa').glob('*.md'):p.chmod(0o644)\nPY"
    )
    run(
        [
            "scp",
            "-q",
            *map(str, (TARGET / "documents/lasa").glob("*.md")),
            SSH + ":" + REMOTE + "/documents/lasa/",
        ]
    )
    remote(
        "cp "
        + REMOTE
        + "/layer2/{config,steady-config,contracts,authorization,connectors}.json "
        + REMOTE
        + "/backups/connectors-"
        + stamp
        + "/ && systemctl --user stop lasa-layer2.service"
    )
    domain = "gui/" + str(os.getuid())
    run(["launchctl", "bootout", domain + "/com.lasa.layer1"])
    print("Both backends quiesced; persistent stores and workspaces retained.", flush=True)
    run(
        [
            str(Path.home() / ".local/bin/uv"),
            "pip",
            "install",
            "--python",
            str(TARGET / "venv/bin/python"),
            "--no-deps",
            "--reinstall",
            str(wheel),
        ]
    )
    remote(
        "~/.local/bin/uv pip install --python "
        + REMOTE
        + "/venv/bin/python --no-deps --reinstall "
        + REMOTE
        + "/release/"
        + wheel.name
    )
    for layer in ["layer1", "layer2"]:
        for name in ["config.json", "contracts.json", "authorization.json", "connectors.json"]:
            shutil.copy2(STAGE / layer / name, TARGET / layer / name)
        shutil.copy2(TARGET / layer / "config.json", TARGET / layer / "steady-config.json")
    remote(
        "python3 - <<'PY'\nfrom pathlib import Path\nimport shutil\np=Path('"
        + REMOTE
        + "')\nfor name in ['config.json','contracts.json','authorization.json','connectors.json']:\n shutil.copy2(p/'connector-release'/name,p/'layer2'/name)\n (p/'layer2'/name).chmod(0o600)\nshutil.copy2(p/'layer2/config.json',p/'layer2/steady-config.json')\nfor f in (p/'documents/lasa').glob('*.md'):f.chmod(0o444)\nPY"
    )
    run(
        [
            "scp",
            "-q",
            str(ROOT / "deployment/run_service.py"),
            SSH + ":" + REMOTE + "/release/run_service.py",
        ]
    )
    remote("systemctl --user start lasa-layer2.service")
    run(
        [
            "launchctl",
            "bootstrap",
            domain,
            str(Path.home() / "Library/LaunchAgents/com.lasa.layer1.plist"),
        ]
    )
    report = {
        "version": __version__,
        "wheel_sha256": sha,
        "deployment_revision": revision,
        "backup": str(backup),
        "state": "deployed; HTTPS readiness and real integrations must be checked",
    }
    report_file.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report), flush=True)


if __name__ == "__main__":
    main()
