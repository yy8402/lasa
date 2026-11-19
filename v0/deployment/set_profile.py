"""Apply a bounded verification profile to the managed two-layer deployment.

Only target configuration and the two LASA backend services are changed. The
steady profile restores the intended peer preference and generic fallback.
"""

import argparse
import copy
import hashlib
import json
import os
import sqlite3
import ssl
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx

from lasa_service import __version__

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / ".deploy/target"
REMOTE = "/home/yang/Dev/CodeX/LASA/v0/.deploy/target"
SSH = "yang@192.168.0.188"
TERMINAL = {"completed", "failed", "cancelled", "rejected", "indeterminate"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "profile",
        choices=[
            "local_first",
            "delegate_first",
            "fallback_disabled",
            "fallback_enabled",
            "steady",
        ],
    )
    args = parser.parse_args()
    os.umask(0o077)
    with sqlite3.connect(
        "file:" + str(TARGET / "layer1/private/tasks.sqlite3") + "?mode=ro", uri=True
    ) as db:
        assert all(state in TERMINAL for (state,) in db.execute("SELECT state FROM tasks")), (
            "Layer 1 has active work"
        )
    subprocess.run(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            SSH,
            "python3 - <<'PY'\nfrom pathlib import Path\nimport sqlite3\np=Path.home()/'Dev/CodeX/LASA/v0/.deploy/target/layer2/private/tasks.sqlite3'\nwith sqlite3.connect('file:'+str(p)+'?mode=ro',uri=True) as db:\n assert all(s in {'completed','failed','cancelled','rejected','indeterminate'} for s, in db.execute('select state from tasks')), 'Layer 2 has active work'\nPY",
        ],
        check=True,
        timeout=15,
    )
    configs = [
        json.loads((TARGET / layer / "steady-config.json").read_text())
        for layer in ["layer1", "layer2"]
    ]
    first, second = configs
    first["routing"] = {
        "preferred_executor": "local" if args.profile == "local_first" else "peer",
        "unclaimed_peer_fallback": "attempt"
        if args.profile in {"steady", "fallback_enabled"}
        else "reject",
    }
    if args.profile.startswith("fallback"):
        first["bindings"] = [
            x for x in first["bindings"] if x["contract"]["id"].endswith("/task.attempt")
        ]
        second["published_contracts"] = [
            x for x in second["published_contracts"] if x["id"].endswith("/task.attempt")
        ]
    package = sha(
        (ROOT / f"verification/dist/lasa_service_v0-{__version__}-py3-none-any.whl").read_bytes()
    )
    changes = []
    for layer, config in zip(["layer1", "layer2"], configs, strict=True):
        config["service"]["deployment_revision"] = (
            "connectors-20261119-" + package[:12] + "-" + args.profile
        )
        data = json.dumps(config, indent=2) + "\n"
        destination = TARGET / layer / "config.json"
        before = sha(destination.read_bytes())
        destination.with_suffix(".pending").write_text(data)
        destination.with_suffix(".pending").replace(destination)
        if layer == "layer2":
            remote_data = data.replace(str(TARGET / "layer2"), REMOTE + "/layer2")
            destination = TARGET / "remote-layer2/config.json"
            destination.write_text(remote_data)
            subprocess.run(
                ["scp", "-q", str(destination), SSH + ":" + REMOTE + "/layer2/config.pending"],
                check=True,
                timeout=15,
            )
            subprocess.run(
                [
                    "ssh",
                    "-o",
                    "BatchMode=yes",
                    SSH,
                    "chmod 600 "
                    + REMOTE
                    + "/layer2/config.pending && mv "
                    + REMOTE
                    + "/layer2/config.pending "
                    + REMOTE
                    + "/layer2/config.json && systemctl --user restart lasa-layer2.service",
                ],
                check=True,
                timeout=50,
            )
            data = remote_data
        changes.append(
            {
                "layer": layer,
                "before_staging_sha256": before,
                "deployed_config_sha256": sha(data.encode()),
                "deployment_revision": config["service"]["deployment_revision"],
                "routing": config["routing"],
                "published_contracts": copy.deepcopy(config["published_contracts"]),
                "local_binding_contracts": [x["contract"] for x in config["bindings"]],
            }
        )
    subprocess.run(
        ["launchctl", "kickstart", "-k", "gui/" + str(os.getuid()) + "/com.lasa.layer1"],
        check=True,
        timeout=50,
    )
    ca = str(Path.home() / ".config/lasa/two-layer/tls/ca.pem")
    with httpx.Client(
        verify=ssl.create_default_context(cafile=ca), trust_env=False, timeout=3
    ) as client:
        for layer, origin in [
            ("layer2", "https://192.168.0.188"),
            ("layer1", "https://localhost:8443"),
        ]:
            until = time.monotonic() + 30
            while True:
                try:
                    response = client.get(
                        origin + "/health/ready",
                        headers={
                            "Authorization": "Bearer "
                            + (TARGET / layer / "operator-token.txt").read_text().strip()
                        },
                    )
                    if response.status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                if time.monotonic() >= until:
                    raise TimeoutError(layer + " did not become ready")
                time.sleep(0.2)
    log = TARGET / "profile-changes.jsonl"
    with log.open("a") as output:
        output.write(
            json.dumps(
                {
                    "timestamp": datetime.now(UTC).isoformat(),
                    "profile": args.profile,
                    "wheel_sha256": package,
                    "changes": changes,
                }
            )
            + "\n"
        )
    print(json.dumps({"profile": args.profile, "services": "both ready over verified HTTPS"}))


if __name__ == "__main__":
    main()
