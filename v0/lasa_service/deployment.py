"""Manage the optional local DLP stack on a supervisor Docker network."""

import argparse
import hashlib
import json
import os
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from .config import ConfigurationError
from .contracts import parse_json, protocol_contracts
from .errors import LasaError
from .inspection import InspectionBindings

MANAGED_HOST = "lasa-inspection"
MANAGED_ORIGIN = f"https://{MANAGED_HOST}:8443"
MANAGED_URL = MANAGED_ORIGIN + "/inspect"
GATEWAY_ID = "local-dlp"
POLICY_REVISION = "english-dlp-v1"
INSPECTOR_IMAGE = "lasa-inspector:1.0.0"
PRESIDIO_IMAGE = (
    "ghcr.io/data-privacy-stack/presidio-analyzer:2.2.366"
    "@sha256:036d2f9b3c274fb36497383acef8f2d5aea528a014801c2c3040fb067990c79c"
)
INSPECTOR_FILES = Path("/run/inspection")
STARTUP_SECONDS = 60


def docker(*args, document=None, timeout=30):
    try:
        result = subprocess.run(
            ["docker", *args],
            input=json.dumps(document) if document is not None else None,
            timeout=timeout,
            capture_output=True,
            text=True,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise ConfigurationError("Docker did not finish before the deployment deadline") from None
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or "Docker command failed"
        raise ConfigurationError(detail)
    return result.stdout.strip()


@dataclass(frozen=True)
class DockerDeployment:
    network: str
    supervisors: tuple[Path, ...]
    local_dlp: dict

    @classmethod
    def load(cls, path):
        document = protocol_contracts().validate("DockerDeployment", parse_json(path.read_bytes()))
        return cls(
            document["supervisor_network"],
            tuple(path.parent / name for name in document.get("supervisors", [])),
            document.get("local_dlp", {}),
        )

    @property
    def enabled(self):
        return self.local_dlp.get("enabled", False)

    @property
    def policy_revision(self):
        return self.local_dlp.get("policy_revision", POLICY_REVISION)

    @property
    def project(self):
        network_id = hashlib.sha256(self.network.encode()).hexdigest()[:16]
        return f"lasa-dlp-{network_id}"

    def validate_profiles(self):
        contracts = protocol_contracts()
        for path in self.supervisors:
            manifest = contracts.validate("Config", parse_json(path.read_bytes()))
            for profile in InspectionBindings.from_manifest(manifest).active_profiles():
                if (urlsplit(profile["url"]).hostname or "").rstrip(".") != MANAGED_HOST:
                    continue
                label = f"{path}: inspection profile {profile['id']}"
                if not self.enabled:
                    raise ConfigurationError(f"{label} requires local_dlp.enabled=true")
                if (
                    profile["url"] != MANAGED_URL
                    or profile["gateway_id"] != GATEWAY_ID
                    or profile["policy_revision"] != self.policy_revision
                ):
                    raise ConfigurationError(
                        f"{label} must pin {MANAGED_URL}, gateway {GATEWAY_ID}, "
                        f"and policy revision {self.policy_revision}"
                    )

    def compose_document(self, platform=None):
        inspector = {
            "image": self.local_dlp.get("inspector_image", INSPECTOR_IMAGE),
            "networks": {"supervisors": {"aliases": [MANAGED_HOST]}, "backend": {}},
        }
        if self.enabled:
            directory = Path(self.local_dlp["secrets_directory"])
            if not directory.is_absolute():
                raise ConfigurationError("local_dlp.secrets_directory must be absolute")
            inspector.update(
                user=f"{os.getuid()}:{os.getgid()}",
                read_only=True,
                restart="unless-stopped",
                volumes=[
                    {
                        "type": "bind",
                        "source": str(directory).replace("$", "$$"),
                        "target": str(INSPECTOR_FILES),
                        "read_only": True,
                        "bind": {"create_host_path": False},
                    }
                ],
                command=[
                    "--gateway-id",
                    GATEWAY_ID,
                    "--policy-revision",
                    self.policy_revision,
                    "--presidio-url",
                    "http://presidio:3000",
                    "--token-file",
                    str(INSPECTOR_FILES / "token.txt"),
                    "--tls-cert",
                    str(INSPECTOR_FILES / "certificate.pem"),
                    "--tls-key",
                    str(INSPECTOR_FILES / "key.pem"),
                ],
            )
            if platform:
                inspector["platform"] = platform
        return {
            "services": {
                "inspector": inspector,
                "presidio": {
                    "image": self.local_dlp.get("presidio_image", PRESIDIO_IMAGE),
                    "networks": ["backend"],
                    "restart": "unless-stopped",
                },
            },
            "networks": {
                "supervisors": {"external": True, "name": self.network},
                "backend": {"internal": True},
            },
        }

    def compose(self, *args, platform=None, timeout=30):
        return docker(
            "compose",
            "--project-name",
            self.project,
            "-f",
            "-",
            *args,
            document=self.compose_document(platform),
            timeout=timeout,
        )

    def check_ready(self, *, wait=0):
        self.compose(
            "exec",
            "-T",
            "inspector",
            "python",
            "-m",
            "lasa_service.deployment",
            "--policy-revision",
            self.policy_revision,
            "--wait",
            str(wait),
            timeout=wait + 10,
        )

    def check(self):
        self.validate_profiles()
        if self.enabled:
            self.check_ready()

    def apply(self):
        self.validate_profiles()
        if not self.enabled:
            self.compose("down", timeout=60)
            return
        image = self.local_dlp.get("inspector_image", INSPECTOR_IMAGE)
        directory = Path(self.local_dlp["secrets_directory"])
        if not directory.is_absolute():
            raise ConfigurationError("local_dlp.secrets_directory must be absolute")
        for name in ("token.txt", "ca.pem", "certificate.pem", "key.pem"):
            path = directory / name
            if not path.is_file() or not os.access(path, os.R_OK):
                raise ConfigurationError(f"Cannot read local DLP file {path}")
        platform = docker("image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", image)
        self.compose("up", "--detach", platform=platform.strip("/"), timeout=180)
        self.check_ready(wait=STARTUP_SECONDS)


def probe(policy_revision, *, wait=0, directory=INSPECTOR_FILES, transport=None):
    context = ssl.create_default_context(cafile=directory / "ca.pem")
    token = (directory / "token.txt").read_text(encoding="ascii").strip()
    expected = {"gateway_id": GATEWAY_ID, "policy_revision": policy_revision}
    deadline = time.monotonic() + wait
    with httpx.Client(
        verify=context,
        transport=transport,
        trust_env=False,
        follow_redirects=False,
        timeout=2,
        headers={"Authorization": "Bearer " + token},
    ) as client:
        while True:
            try:
                with client.stream("GET", MANAGED_ORIGIN + "/health/ready") as reply:
                    if reply.status_code == 200:
                        data = bytearray()
                        for chunk in reply.iter_bytes():
                            data.extend(chunk)
                            if len(data) > 4096:
                                raise ConfigurationError("Invalid local DLP readiness response")
                        if parse_json(data) != expected:
                            raise ConfigurationError(
                                "Local DLP readiness returned an unexpected gateway ID or policy revision"
                            )
                        return
                    if reply.status_code != 503:
                        raise ConfigurationError(
                            f"Local DLP readiness returned HTTP {reply.status_code}"
                        )
            except httpx.TransportError:
                pass
            if time.monotonic() >= deadline:
                raise ConfigurationError("Local DLP did not become ready over authenticated HTTPS")
            time.sleep(0.25)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Probe the running managed inspector")
    parser.add_argument("--policy-revision", required=True)
    parser.add_argument("--wait", type=int, default=0)
    args = parser.parse_args()
    try:
        probe(args.policy_revision, wait=args.wait)
    except (ConfigurationError, LasaError, OSError, ValueError) as exc:
        detail = (
            str(exc)
            if isinstance(exc, ConfigurationError)
            else "Invalid readiness configuration or response"
        )
        print(detail, file=sys.stderr)
        raise SystemExit(2) from None
