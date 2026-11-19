"""Stage, roll out, and roll back a wheel on the managed Mac and air188 services."""

import argparse
import fcntl
import hashlib
import json
import os
import shlex
import shutil
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

import httpx

TARGET = Path(__file__).resolve().parents[1] / ".deploy/target"
HOST_OPERATIONS = Path(__file__).with_name("release_host.py")
REMOTE = "yang@192.168.0.188"
SSH = ("ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", REMOTE)


class RollbackDrill(Exception):
    pass


class RollbackFailed(RuntimeError):
    pass


@dataclass(frozen=True)
class Host:
    layer: str
    root: Path
    origin: str
    remote: bool = False

    def run(self, args, *, source=None, check=True, timeout=55):
        command = [*SSH, shlex.join(args)] if self.remote else args
        return subprocess.run(
            command, input=source, text=True, capture_output=True, check=check, timeout=timeout
        )

    def host_operation(self, phase, release, *args):
        python = "python3" if self.remote else sys.executable
        self.run(
            [python, "-I", "-", phase, str(self.root), self.layer, release, *args],
            source=HOST_OPERATIONS.read_text(),
        )

    def stage(self, release, wheel, checksum):
        self.host_operation("init", release)
        slot = self.root / "backups" / release
        if self.remote:
            subprocess.run(
                ["scp", "-q", "-o", "BatchMode=yes", str(wheel), REMOTE + ":" + str(slot) + "/"],
                check=True,
                timeout=30,
                capture_output=True,
            )
        else:
            shutil.copyfile(wheel, slot / wheel.name)
        self.host_operation("stage", release, wheel.name, checksum, release)

    def stop(self):
        if self.remote:
            self.run(["systemctl", "--user", "stop", "lasa-layer2.service"])
        else:
            service = f"gui/{os.getuid()}/com.lasa.layer1"
            self.run(["launchctl", "bootout", service], check=False)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if self.run(["launchctl", "print", service], check=False, timeout=3).returncode:
                    return
                time.sleep(0.2)
            raise RuntimeError("Layer 1 has not finished unloading")

    def start(self):
        args = (
            ["systemctl", "--user", "start", "lasa-layer2.service"]
            if self.remote
            else [
                "launchctl",
                "bootstrap",
                f"gui/{os.getuid()}",
                str(Path.home() / "Library/LaunchAgents/com.lasa.layer1.plist"),
            ]
        )
        self.run(args)

    def check_ready(self, client, expected=None):
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            try:
                token = (TARGET / self.layer / "operator-token.txt").read_text().strip()
                headers = {"Authorization": "Bearer " + token}
                ready = client.get(self.origin + "/health/ready", headers=headers)
                ready.raise_for_status()
                descriptor = client.get(self.origin + "/lasa/v1/descriptor", headers=headers)
                descriptor.raise_for_status()
                value = descriptor.json()
                if value["service_id"] == self.origin + "/lasa" and (
                    expected is None or value["deployment_revision"] == expected
                ):
                    return value["deployment_revision"]
            except (httpx.HTTPError, OSError, ValueError, KeyError):
                pass
            time.sleep(0.3)
        raise RuntimeError(f"{self.layer} did not serve the expected revision over HTTPS")


def rollback(hosts, release, previous, client):
    stopped = []
    errors = []
    for host in hosts:
        try:
            host.stop()
            stopped.append(host)
        except Exception as exc:
            errors.append(f"{host.layer} stop ({type(exc).__name__})")
    for host in reversed(stopped):
        try:
            host.host_operation("restore", release)
            host.start()
            host.check_ready(client, previous[host.layer])
            print(f"Restored {host.layer} to {previous[host.layer]}", flush=True)
        except Exception as exc:
            errors.append(f"{host.layer} restore ({type(exc).__name__})")
    if errors:
        raise RollbackFailed("; ".join(errors))


def deploy(hosts, release, wheel, checksum, client, *, drill=False):
    previous = {host.layer: host.check_ready(client) for host in hosts}
    for host in hosts:
        host.host_operation("idle", release)
        host.stage(release, wheel, checksum)
    for host in hosts:
        host.host_operation("idle", release)

    touched = []
    try:
        for host in hosts:
            touched.append(host)
            host.stop()
        for host in reversed(hosts):
            host.host_operation("activate", release)
            host.start()
            host.check_ready(client, release)
            print(f"{host.layer} is serving {release}", flush=True)
            if drill:
                raise RollbackDrill("Interrupted rollout after air188 passed readiness")
    except BaseException as failure:
        print(
            f"Release {release} interrupted after {host.layer}; restoring previous release",
            flush=True,
        )
        rollback(touched, release, previous, client)
        if not isinstance(failure, RollbackDrill):
            raise
        return "rollback-verified"
    return "deployed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--rollback-drill", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    wheel = args.wheel.resolve(strict=True)
    if wheel.suffix != ".whl":
        parser.error("--wheel must point to a wheel")
    checksum = hashlib.sha256(wheel.read_bytes()).hexdigest()
    release = f"lasa-{checksum[:12]}-{uuid4().hex[:8]}"
    hosts = (
        Host("layer1", TARGET, "https://localhost:8443"),
        Host(
            "layer2",
            Path("/home/yang/Dev/CodeX/LASA/v0/.deploy/target"),
            "https://192.168.0.188",
            True,
        ),
    )
    ca = Path.home() / ".config/lasa/two-layer/tls/ca.pem"
    with (
        (TARGET / "release.lock").open("a") as lock,
        httpx.Client(
            verify=ssl.create_default_context(cafile=ca), trust_env=False, timeout=4
        ) as client,
    ):
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(f"Staging {release}", flush=True)
        state = deploy(hosts, release, wheel, checksum, client, drill=args.rollback_drill)
        report = {"release": release, "wheel_sha256": checksum, "state": state}
        output = TARGET / "backups" / release / "outcome.json"
        output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report), flush=True)


if __name__ == "__main__":
    main()
