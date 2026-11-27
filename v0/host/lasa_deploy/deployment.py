"""Docker deployment primitives and the optional local inspection stack."""

import fcntl
import hashlib
import json
import os
import ssl
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509

from .contracts import ConfigurationError, digest, parse_json, require, validate

MANAGED_DLP_HOST = "lasa-inspection"
MANAGED_DLP_ORIGIN = f"https://{MANAGED_DLP_HOST}:8443"
MANAGED_DLP_URL = MANAGED_DLP_ORIGIN + "/inspect"
MANAGED_DLP_GATEWAY_ID = "local-dlp"
MANAGED_DLP_POLICY_REVISION = "english-dlp-v1"
INSPECTOR_IMAGE = "dlplite:0.1.0"
PRESIDIO_IMAGE = (
    "ghcr.io/data-privacy-stack/presidio-analyzer:2.2.366"
    "@sha256:036d2f9b3c274fb36497383acef8f2d5aea528a014801c2c3040fb067990c79c"
)
INSPECTOR_FILES = Path("/run/inspection")
SECRET_FILES = ("token.txt", "ca.pem", "certificate.pem", "key.pem")
STARTUP_SECONDS = 60


def write_atomic(path, value):
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".lasa-")
    try:
        with os.fdopen(fd, "w") as file:
            file.write(value)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        Path(temporary).unlink(missing_ok=True)


def read_json(path):
    return parse_json(Path(path).read_bytes())


def secret(path):
    with Path(path).open() as file:
        value = file.read(65537).strip()
    require(
        0 < len(value) <= 65536 and not any(c.isspace() for c in value),
        f"Invalid bearer token file {path}",
    )
    return value


def bind(source, target=None, *, writable=False):
    return {
        "type": "bind",
        "source": str(source),
        "target": str(target or source),
        "read_only": not writable,
        "bind": {"create_host_path": False},
    }


def docker(*args, document=None, input_text=None, input_file=None, timeout=30):
    try:
        result = subprocess.run(
            ["docker", *args],
            input=json.dumps(document).replace("$", "$$") if document is not None else input_text,
            stdin=input_file,
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
    supervisor_profiles: tuple
    local_dlp: dict
    state: Path

    @classmethod
    def load(cls, path):
        from .runtime import ReleaseImages, config_mounts

        document = validate("DockerDeployment", read_json(path))
        profiles = []
        if supervisors := document.get("supervisors"):
            release = validate("ReleaseManifest", read_json(path.parent / document["release"]))
            runner = ReleaseImages(release)
            for name in supervisors:
                config = (path.parent / name).resolve()
                result = runner.supervisor(
                    "inspection", mounts=config_mounts({"config": str(config)}), config=str(config)
                )
                profiles.append((config, result["inspection_profiles"]))
        return cls(
            document["supervisor_network"],
            tuple(profiles),
            document.get("local_dlp", {}),
            path.parent / ".lasa-inspection",
        )

    @property
    def enabled(self):
        return self.local_dlp.get("enabled", False)

    @property
    def policy_revision(self):
        return self.local_dlp.get("policy_revision", MANAGED_DLP_POLICY_REVISION)

    @property
    def namespace(self):
        return "lasa-dlp-" + hashlib.sha256(self.network.encode()).hexdigest()[:16]

    def validate_profiles(self):
        for path, profiles in self.supervisor_profiles:
            for profile in profiles:
                if (urlsplit(profile["url"]).hostname or "").rstrip(".") != MANAGED_DLP_HOST:
                    continue
                label = f"{path}: inspection profile {profile['id']}"
                if not self.enabled:
                    raise ConfigurationError(f"{label} requires local_dlp.enabled=true")
                if (
                    profile["url"] != MANAGED_DLP_URL
                    or profile["gateway_id"] != MANAGED_DLP_GATEWAY_ID
                    or profile["policy_revision"] != self.policy_revision
                ):
                    raise ConfigurationError(
                        f"{label} must pin {MANAGED_DLP_URL}, gateway {MANAGED_DLP_GATEWAY_ID}, "
                        f"and policy revision {self.policy_revision}"
                    )

    def credentials(self):
        directory = Path(self.local_dlp["secrets_directory"])
        if not directory.is_absolute():
            raise ConfigurationError("local_dlp.secrets_directory must be absolute")
        for name in SECRET_FILES:
            path = directory / name
            if not path.is_file() or not os.access(path, os.R_OK):
                raise ConfigurationError(f"Cannot read local DLP file {path}")
        if not (directory / "token.txt").read_text().strip():
            raise ConfigurationError("Local DLP bearer token is empty")
        try:
            path = directory / "certificate.pem"
            certificate = x509.load_pem_x509_certificate(path.read_bytes())
            names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            if MANAGED_DLP_HOST not in names.value.get_values_for_type(x509.DNSName):
                raise ValueError("unexpected certificate hostname")
            if (
                not certificate.not_valid_before_utc
                <= datetime.now(UTC)
                <= certificate.not_valid_after_utc
            ):
                raise ValueError("certificate outside its validity period")
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(
                path, directory / "key.pem", password=""
            )
            ssl.create_default_context(cafile=directory / "ca.pem")
        except (OSError, ValueError, x509.ExtensionNotFound):
            raise ConfigurationError(
                f"Invalid local DLP TLS bundle in {directory}; expected a valid {MANAGED_DLP_HOST} certificate, key, and CA"
            ) from None
        return directory

    def compose_document(self, directory=None, inspector_image=None, presidio_image=None):
        inspector = {
            "image": inspector_image or INSPECTOR_IMAGE,
            "networks": {"backend": {"aliases": [MANAGED_DLP_HOST]}},
            "labels": {
                "com.lasa.inspection": self.namespace,
                "com.lasa.inspection-owner": digest(str(self.state.resolve()))[7:],
            },
        }
        if directory is not None:
            inspector.update(
                user=f"{os.getuid()}:{os.getgid()}",
                read_only=True,
                restart="unless-stopped",
                volumes=[
                    {
                        "type": "bind",
                        "source": str(directory),
                        "target": str(INSPECTOR_FILES),
                        "read_only": True,
                        "bind": {"create_host_path": False},
                    }
                ],
                command=[
                    "--gateway-id",
                    MANAGED_DLP_GATEWAY_ID,
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
        return {
            "services": {
                "inspector": inspector,
                "presidio": {
                    "image": presidio_image or PRESIDIO_IMAGE,
                    "networks": ["backend"],
                    "restart": "unless-stopped",
                },
            },
            "networks": {"backend": {"internal": True}},
        }

    def compose(self, project, *args, document=None, timeout=30):
        return docker(
            "compose",
            "--project-name",
            project,
            "-f",
            "-",
            *args,
            document=document or self.compose_document(),
            timeout=timeout,
        )

    def check_ready(self, inspector, *, wait=0):
        docker(
            "exec",
            inspector,
            "dlplite-probe",
            "--url",
            MANAGED_DLP_ORIGIN + "/health/ready",
            "--gateway-id",
            MANAGED_DLP_GATEWAY_ID,
            "--policy-revision",
            self.policy_revision,
            "--ca-file",
            str(INSPECTOR_FILES / "ca.pem"),
            "--token-file",
            str(INSPECTOR_FILES / "token.txt"),
            "--wait",
            str(wait),
            timeout=wait + 10,
        )

    def active(self, *, owned_only=False):
        entries = docker(
            "ps",
            "--all",
            "--filter",
            f"network={self.network}",
            "--filter",
            f"label=com.lasa.inspection={self.namespace}",
            "--format",
            '{{.ID}} {{.Label "com.docker.compose.project"}} {{.Label "com.lasa.inspection-owner"}}',
        ).splitlines()
        if len(entries) > 1:
            raise ConfigurationError(
                "Multiple managed DLPLite gateways are attached to this network"
            )
        if not entries:
            return None, None
        container, project, owner = entries[0].split()
        if owner != digest(str(self.state.resolve()))[7:]:
            if owned_only:
                return None, None
            raise ConfigurationError("The managed DLPLite gateway has a different deployment owner")
        return container, project

    def check(self):
        self.validate_profiles()
        if self.enabled:
            inspector, _ = self.active()
            if not inspector:
                raise ConfigurationError("No managed DLPLite gateway is attached")
            self.check_ready(inspector)

    def image_pins(self):
        return {
            field: docker(
                "image",
                "inspect",
                "--format",
                "{{.Id}} {{.Os}}/{{.Architecture}}",
                self.local_dlp.get(field, default),
            ).split()
            for field, default in (
                ("inspector_image", INSPECTOR_IMAGE),
                ("presidio_image", PRESIDIO_IMAGE),
            )
        }

    def apply(self, *, validate=True, owned_only=False):
        if validate:
            self.validate_profiles()
        if not self.enabled and not self.active(owned_only=owned_only)[0]:
            return
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        with (self.state / (self.namespace + ".lock")).open("a") as lease:
            try:
                fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ConfigurationError(
                    "A DLPLite deployment operation is already running"
                ) from None
            self.apply_locked()

    def apply_locked(self):
        if not self.enabled:
            _, previous = self.active()
            if previous:
                self.compose(previous, "down", timeout=60)
            return
        source = self.credentials()
        files = {name: (source / name).read_bytes() for name in SECRET_FILES}
        images = list(self.image_pins().values())
        generation = digest(
            [
                self.policy_revision,
                images,
                [hashlib.sha256(value).hexdigest() for value in files.values()],
            ]
        )[7:23]
        project = f"{self.namespace}-{generation}"
        old, previous = self.active()
        if previous == project:
            self.check_ready(old, wait=STARTUP_SECONDS)
            return
        directory = self.state / project
        if not directory.exists():
            with tempfile.TemporaryDirectory(dir=self.state) as temporary:
                stage = Path(temporary) / "bundle"
                stage.mkdir(mode=0o700)
                for name, value in files.items():
                    fd = os.open(stage / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "wb") as handle:
                        handle.write(value)
                stage.rename(directory)
        document = self.compose_document(directory, *(image for image, _ in images))
        for service, (_, platform) in zip(("inspector", "presidio"), images, strict=True):
            document["services"][service]["platform"] = platform
        detached = False
        try:
            self.compose(
                project, "up", "--detach", "--pull", "never", document=document, timeout=180
            )
            inspector = self.compose(project, "ps", "-q", "inspector", document=document)
            if not inspector:
                raise ConfigurationError("The staged DLPLite gateway did not start")
            self.check_ready(inspector, wait=STARTUP_SECONDS)
            if old:
                docker("network", "disconnect", self.network, old)
                detached = True
            docker("network", "connect", "--alias", MANAGED_DLP_HOST, self.network, inspector)
        except BaseException:
            try:
                self.compose(project, "down", timeout=60)
            finally:
                if detached:
                    docker("network", "connect", "--alias", MANAGED_DLP_HOST, self.network, old)
            raise
        if previous:
            self.compose(previous, "down", timeout=60)

    def run(self, action):
        if action == "plan":
            self.validate_profiles()
            if self.enabled:
                self.credentials()
            return {"network": self.network, "local_dlp": self.enabled}
        if action == "apply":
            self.apply()
        elif action != "status":
            raise ConfigurationError("Use a host deployment to pause, resume, or roll back")
        self.check()
        inspector, project = self.active()
        return {"network": self.network, "inspector": inspector, "project": project}
