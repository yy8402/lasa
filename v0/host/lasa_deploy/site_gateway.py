"""Publish a LASA site through one managed HTTPS listener."""

import hashlib
import json
import os
import re
import ssl
import tempfile
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from .contracts import ConfigurationError, digest, https_origin, require
from .deployment import bind, docker, read_json, write_atomic
from .keycloak import KEYCLOAK_PATH, KEYCLOAK_PORT, REALM

GATEWAY_IMAGE = (
    "caddy:2.11.9-alpine@sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0"
)
SUPERVISOR_PATH = "/lasa/v1"
PORTAL_PATH = "/app"
PORTAL_PORT = 8080
CONFIG = "/etc/lasa-gateway/routes/Caddyfile"
STAGED_CONFIG = "/etc/lasa-gateway/routes/Caddyfile.next"
ADMIN_SOCKET = "unix//tmp/lasa-gateway.sock"
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
IMAGE_PIN = re.compile(r"(?:[a-zA-Z0-9][a-zA-Z0-9._:/-]*@)?sha256:[a-f0-9]{64}")
TLS_FILES = ("certificate.pem", "key.pem", "public-ca.pem", "upstream-ca.pem")


def site_origin(base_url):
    require(base_url.endswith(SUPERVISOR_PATH), f"Use {SUPERVISOR_PATH} for the LASA API URL")
    parsed = https_origin(base_url.removesuffix(SUPERVISOR_PATH))
    host = parsed.hostname
    require(
        len(host) <= 253 and all(DNS_LABEL.fullmatch(label) for label in host.split(".")),
        "Use a DNS hostname for the managed HTTPS gateway",
    )
    authority = f"{host}:{parsed.port}" if parsed.port is not None else host
    require(parsed.netloc == authority and parsed.port not in {0, 443}, "Use a canonical site URL")
    return "https://" + authority


class Gateway:
    def __init__(self, project, entry, timeout):
        self.entry = entry
        self.spec = entry["spec"]
        self.settings = self.spec["gateway"]
        self.project = project + "-edge"
        self.identity_host = project + "-identity-keycloak"
        self.root = Path(self.spec["control_directory"]) / "gateway"
        self.record = self.root / "rollout.json"
        self.routes = self.root / "routes"
        self.origin = urlsplit(site_origin(entry["base_url"]))
        self.port = self.origin.port or 443
        self.timeout = timeout

    def journal(self):
        return (
            read_json(self.record)
            if self.record.exists()
            else {
                "active": None,
                "previous": None,
                "pending": None,
            }
        )

    def save(self, journal):
        write_atomic(self.record, json.dumps(journal, indent=2) + "\n")

    def report(self, journal):
        return {"site_url": self.origin.geturl(), **journal}

    def tls_directory(self, revision):
        return self.root / "tls" / revision["tls"][7:]

    @staticmethod
    def tls_revision(material):
        return digest({name: hashlib.sha256(value).hexdigest() for name, value in material.items()})

    def read_tls(self, revision):
        directory = self.tls_directory(revision)
        material = {
            name: (directory / name).read_bytes()
            for name in TLS_FILES
            if (directory / name).is_file()
        }
        require(self.tls_revision(material) == revision["tls"], "Gateway TLS snapshot changed")
        return material

    def candidate(self, active, *, image=None, certificate=None, key=None, ca=None):
        listen = self.settings.get("listen_host", "0.0.0.0")
        require(ip_address(listen).version == 4, "The gateway listen_host must be an IPv4 address")
        require(bool(certificate) == bool(key), "Provide both the site certificate and private key")
        if active:
            material = self.read_tls(active)
            image = image or active["image"]
        else:
            certificate = self.settings["certificate_file"]
            key = self.settings["key_file"]
            ca = self.settings.get("ca_file")
            material = {"upstream-ca.pem": Path(ca).read_bytes()} if ca else {}
            image = self.entry["release"]["images"].get("gateway")
        if certificate:
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(certificate, key, password="")
            material.update(
                {
                    "certificate.pem": Path(certificate).read_bytes(),
                    "key.pem": Path(key).read_bytes(),
                }
            )
        if ca:
            ssl.create_default_context(cafile=ca)
            material["public-ca.pem"] = Path(ca).read_bytes()
        require(
            image and IMAGE_PIN.fullmatch(image), "Provide a locally loaded gateway image digest"
        )
        platform = self.entry["release"]["platform"]
        actual = docker(
            "image",
            "inspect",
            "--platform",
            platform,
            "--format",
            "{{.Os}}/{{.Architecture}}",
            image,
        )
        require(actual == platform, f"Gateway image platform is {actual}, expected {platform}")
        image_id = docker("image", "inspect", "--format", "{{.Id}}", image)
        return {"image": image_id, "tls": self.tls_revision(material)}, material

    def snapshot(self, revision, material):
        target = self.tls_directory(revision)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not target.exists():
            with tempfile.TemporaryDirectory(dir=target.parent) as temp:
                stage = Path(temp) / "tls"
                stage.mkdir(mode=0o700)
                for name, value in material.items():
                    fd = os.open(stage / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                    with os.fdopen(fd, "wb") as file:
                        file.write(value)
                        file.flush()
                        os.fsync(file.fileno())
                self.sync_directory(stage)
                stage.rename(target)
                self.sync_directory(target.parent)
        self.read_tls(revision)

    @staticmethod
    def sync_directory(path):
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def maintain(self, action, wait, qualify, **candidate_options):
        journal = self.journal()
        current = journal["active"]
        require(current, "Apply the LASA deployment to initialize its gateway")
        if action == "plan":
            target, _ = self.candidate(current, **candidate_options)
            return {**self.report(journal), "candidate": target, "change": target != current}
        if journal["pending"]:
            self.recover(journal, wait, qualify)
            if action == "rollback":
                return self.report(journal)
        if action == "rollback":
            target = journal["previous"]
            require(target, "There is no previous gateway revision to restore")
            self.read_tls(target)
        else:
            target, material = self.candidate(current, **candidate_options)
            self.snapshot(target, material)
        if target != current:
            self.switch(journal, target, wait, qualify)
        else:
            self.install(current, wait)
            qualify(current)
        return self.report(journal)

    def recover(self, journal, wait, qualify):
        current = journal["active"]
        self.install(current, wait)
        qualify(current)
        journal["pending"] = None
        self.save(journal)

    def switch(self, journal, target, wait, qualify):
        journal["pending"] = target
        self.save(journal)
        try:
            self.install(target, wait)
            qualify(target)
        except BaseException as exc:
            try:
                self.recover(journal, wait, qualify)
            except (ConfigurationError, OSError, ValueError, httpx.HTTPError) as restore_error:
                raise ConfigurationError(
                    f"Gateway change failed ({exc}); gateway recovery is pending ({restore_error})"
                ) from None
            raise ConfigurationError(
                f"Gateway change failed; previous gateway restored: {exc}"
            ) from None
        journal.update(active=target, previous=journal["active"], pending=None)
        self.save(journal)

    def caddyfile(self, revision):
        host = self.origin.hostname
        ca = (
            "tls_trust_pool file /etc/lasa-gateway/tls/upstream-ca.pem"
            if (self.tls_directory(revision) / "upstream-ca.pem").is_file()
            else ""
        )
        api = f"lasa-{self.spec['name']}-supervisor:{self.entry['ports']['supervisor']}"
        portal = f"lasa-{self.spec['name']}-portal:{PORTAL_PORT}"
        lines = [
            "{",
            f"  admin {ADMIN_SOCKET}",
            "  auto_https off",
            "  servers {",
            "    protocols h1 h2",
            "  }",
            "  log {",
            "    format filter {",
            "      wrap json",
            "      fields {",
            "        request>uri delete",
            "        request>headers delete",
            "      }",
            "    }",
            "  }",
            "}",
            f"{self.origin.geturl()} {{",
            "  tls /etc/lasa-gateway/tls/certificate.pem /etc/lasa-gateway/tls/key.pem",
            f"  @api path {SUPERVISOR_PATH} {SUPERVISOR_PATH}/*",
            "  handle @api {",
            f"    reverse_proxy https://{api} {{",
            "      header_up Host {http.request.host}",
            "      header_up -Cookie",
            "      transport http {",
            f"        tls_server_name {host}",
            f"        {ca}",
            "      }",
            "    }",
            "  }",
        ]
        if "portal" in self.spec:
            lines.extend(
                [
                    f"  redir {PORTAL_PATH} {PORTAL_PATH}/ 308",
                    f"  handle_path {PORTAL_PATH}/* {{",
                    f"    reverse_proxy http://{portal}",
                    "  }",
                ]
            )
        if "keycloak" in self.spec:
            lines.extend(
                [
                    f"  @login path {KEYCLOAK_PATH}/realms/{REALM}/* {KEYCLOAK_PATH}/resources/*",
                    "  handle @login {",
                    f"    reverse_proxy https://{self.identity_host}:{KEYCLOAK_PORT} {{",
                    "      header_up Host {http.request.host}",
                    '      header_up Cookie "(^|; *)__Host-lasa_(portal|login)=[^;]*" ""',
                    '      header_up Cookie "^; *" ""',
                    "      transport http {",
                    f"        tls_server_name {host}",
                    f"        {ca}",
                    "      }",
                    "    }",
                    "  }",
                ]
            )
        lines += ["  handle {", "    respond 404", "  }", "}", ""]
        return "\n".join(lines)

    def compose(self, *args, revision=None):
        revision = revision or self.journal()["active"]
        require(revision, "Apply the gateway before operating its container")
        mounts = [
            bind(self.routes, "/etc/lasa-gateway/routes"),
            bind(self.tls_directory(revision), "/etc/lasa-gateway/tls"),
        ]
        service = {
            "image": revision["image"],
            "platform": self.entry["release"]["platform"],
            "user": f"{os.getuid()}:{os.getgid()}",
            "cap_add": ["NET_BIND_SERVICE"],
            "restart": "unless-stopped",
            "command": ["caddy", "run", "--config", CONFIG, "--adapter", "caddyfile"],
            "environment": {"XDG_CONFIG_HOME": "/tmp", "XDG_DATA_HOME": "/tmp"},
            "networks": {"site": {"aliases": [self.origin.hostname]}},
            "ports": [
                {
                    "target": self.port,
                    "published": str(self.port),
                    "host_ip": self.settings.get("listen_host", "0.0.0.0"),
                }
            ],
            "volumes": mounts,
        }
        return docker(
            "compose",
            "-p",
            self.project,
            "-f",
            "-",
            *args,
            document={
                "services": {"gateway": service},
                "networks": {"site": {"external": True, "name": self.spec["network"]}},
            },
            timeout=self.timeout,
        )

    def down(self):
        docker(
            "compose",
            "-p",
            self.project,
            "-f",
            "-",
            "down",
            document={"services": {"gateway": {"image": GATEWAY_IMAGE}}},
            timeout=self.timeout,
        )

    def request(self, route, *, revision=None, **headers):
        revision = revision or self.journal()["active"]
        require(revision, "Apply the gateway before probing HTTPS")
        listen = self.settings.get("listen_host", "0.0.0.0")
        host = "127.0.0.1" if listen == "0.0.0.0" else listen
        ca = self.tls_directory(revision) / "public-ca.pem"
        with httpx.Client(
            verify=ssl.create_default_context(cafile=ca if ca.is_file() else None),
            trust_env=False,
            timeout=5,
        ) as http:
            return http.get(
                f"https://{host}:{self.port}{route}",
                headers={"Host": self.origin.netloc, **headers},
                extensions={"sni_hostname": self.origin.hostname},
            )

    def install(self, revision, wait):
        self.read_tls(revision)
        self.routes.mkdir(mode=0o700, parents=True, exist_ok=True)
        staged = self.routes / "Caddyfile.next"
        write_atomic(staged, self.caddyfile(revision))
        self.compose(
            "run",
            "--rm",
            "--no-deps",
            "--entrypoint",
            "caddy",
            "gateway",
            "validate",
            "--config",
            STAGED_CONFIG,
            "--adapter",
            "caddyfile",
            revision=revision,
        )
        staged.replace(self.routes / "Caddyfile")
        self.compose("up", "-d", "--pull", "never", revision=revision)
        wait(
            lambda: self.request("/", revision=revision).status_code == 404,
            "Gateway did not respond over HTTPS",
        )
        self.compose(
            "exec",
            "-T",
            "gateway",
            "caddy",
            "reload",
            "--address",
            ADMIN_SOCKET,
            "--config",
            CONFIG,
            "--adapter",
            "caddyfile",
            revision=revision,
        )
