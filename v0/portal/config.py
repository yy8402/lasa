"""Runtime settings for one portal origin and one LASA receiver."""

import json
import ssl
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


class PortalError(Exception):
    def __init__(self, status, code, message, *, field=None, retry_after=None):
        super().__init__(code)
        self.status = status
        self.code = code
        self.message = message
        self.field = field
        self.retry_after = retry_after


def https_url(value, *, origin=False):
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or (origin and parsed.path)
        or any(part in parsed.path for part in ("//", "..", "%", "\\"))
        or value.endswith("/")
    ):
        raise ValueError("Expected a canonical HTTPS URL")
    return parsed


@dataclass(frozen=True)
class Settings:
    public_origin: str
    lasa_url: str
    lasa_service_id: str
    issuer: str
    client_id: str
    client_secret_file: str
    state_dir: str
    encryption_key_file: str
    journal_key_file: str
    ticket_key_file: str
    base_path: str = ""
    ca_file: str | None = None
    audience_parameter: str = "resource"
    assignment_claim: str | None = None
    assignment_value: str | None = None
    scope: str = "openid"
    allowed_processing_domains: tuple[str, ...] = ()
    timeout_seconds: int = 10
    login_seconds: int = 300
    ticket_seconds: int = 1800
    idle_seconds: int = 1800
    session_seconds: int = 28800
    journal_seconds: int = 604800
    body_bytes: int = 131072
    artifact_bytes: int = 4 * 1024 * 1024
    per_user_journal: int = 256
    max_journal: int = 10000
    max_sessions: int = 1000
    max_concurrency: int = 32

    def __post_init__(self):
        https_url(self.public_origin, origin=True)
        if self.base_path not in {"", "/app"}:
            raise ValueError("The portal base path must be /app or empty")
        for value in (self.lasa_url, self.lasa_service_id, self.issuer):
            https_url(value)
        if self.client_id == self.lasa_service_id or not self.client_id:
            raise ValueError("Register a portal client ID distinct from the LASA service ID")
        if (
            self.audience_parameter not in {"resource", "audience"}
            or "openid" not in self.scope.split()
        ):
            raise ValueError("Invalid OAuth resource or scope configuration")
        if bool(self.assignment_claim) != bool(self.assignment_value):
            raise ValueError("Configure both assignment claim and value")
        ranges = {
            "timeout_seconds": (1, 60),
            "login_seconds": (1, 600),
            "ticket_seconds": (1, 3600),
            "idle_seconds": (1, 28800),
            "session_seconds": (1, 86400),
            "journal_seconds": (1, 31 * 86400),
            "body_bytes": (1024, 1024 * 1024),
            "artifact_bytes": (1024, 32 * 1024 * 1024),
            "per_user_journal": (1, 10000),
            "max_journal": (1, 100000),
            "max_sessions": (1, 10000),
            "max_concurrency": (1, 256),
        }
        for name, (minimum, maximum) in ranges.items():
            value = getattr(self, name)
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError(f"Invalid {name}")
        if self.ticket_seconds > self.journal_seconds or self.idle_seconds > self.session_seconds:
            raise ValueError("Token lifetime exceeds state retention")
        if not isinstance(self.allowed_processing_domains, (list, tuple)) or not all(
            isinstance(domain, str) and domain for domain in self.allowed_processing_domains
        ):
            raise ValueError("Invalid processing domain allowlist")
        paths = [
            self.state_dir,
            self.client_secret_file,
            self.encryption_key_file,
            self.journal_key_file,
            self.ticket_key_file,
        ]
        if self.ca_file:
            paths.append(self.ca_file)
        if any(not Path(path).is_absolute() for path in paths):
            raise ValueError("Use absolute state and secrets paths")

    @property
    def callback(self):
        return self.public_origin + self.base_path + "/auth/callback"

    def tls_context(self):
        context = ssl.create_default_context()
        if self.ca_file:
            context.load_verify_locations(self.ca_file)
        return context

    @classmethod
    def read(cls, path):
        return cls(**json.loads(Path(path).read_bytes()))

    def keys(self):
        keys = tuple(
            read_key(path)
            for path in (self.encryption_key_file, self.journal_key_file, self.ticket_key_file)
        )
        if len(set(keys)) != 3:
            raise ValueError("Use three distinct portal keys")
        return keys


def read_key(path):
    key = bytes.fromhex(Path(path).read_text().strip())
    if len(key) != 32:
        raise ValueError("Portal keys must contain 32 hex-encoded bytes")
    return key
