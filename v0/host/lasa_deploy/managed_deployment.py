"""Install and roll back one LASA host deployment with a durable admission gate."""

import fcntl
import hashlib
import json
import os
import shutil
import ssl
import tempfile
import time
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from .contracts import ConfigurationError, digest, require, validate
from .deployment import DockerDeployment, bind, docker, read_json, secret, write_atomic
from .image_cache import (
    ensure_release_images,
    entry_images,
    missing_images,
    planned_import,
    rollout_images,
)
from .keycloak import KEYCLOAK_IMAGES, ManagedKeycloak
from .runtime import ReleaseImages, config_mounts, state_mounts
from .site_gateway import PORTAL_PATH, PORTAL_PORT, Gateway, site_origin

SOCKET_PATH = "/run/lasa/launcher.sock"
LEASE_MOUNT = "/run/lasa-launcher-locks"
LEASE_VOLUME = "lasa-launcher-locks"
GATE_PATH = "/run/lasa-deploy/admission"


def config_tree(config):
    root = Path(config).parent
    require(root != Path("/"), "Use a dedicated configuration directory")
    files = {}
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(), f"Configuration snapshot cannot contain a symlink: {path}")
        if not path.is_dir():
            require(path.is_file(), f"Configuration snapshot requires a regular file: {path}")
            with path.open("rb") as file:
                files[str(path.relative_to(root))] = hashlib.file_digest(file, "sha256").hexdigest()
    return files


class HostDeployment:
    def __init__(self, spec):
        self.spec = spec
        self.root = Path(spec["control_directory"])
        self.project = f"lasa-{spec['name']}-{digest(str(self.root))[7:19]}"
        self.timeout = spec.get("timeout_seconds", 90)
        self.gate_dir = self.root / "gate"
        self.gate = self.gate_dir / "admission"
        self.record = self.root / "rollout.json"
        self.socket = spec.get("docker_socket", "/var/run/docker.sock")
        self.identities = {}

    @classmethod
    def load(cls, path, document=None):
        return cls(validate("HostDeployment", read_json(path) if document is None else document))

    def daemon(self):
        configured_host = os.environ.get("DOCKER_HOST")
        if not configured_host or os.environ.get("DOCKER_CONTEXT"):
            configured_host = docker("context", "inspect", "--format", "{{.Endpoints.docker.Host}}")
        require(configured_host.startswith("unix://"), "Use a host-local Docker context")
        return docker("info", "--format", "{{.ID}}")

    @staticmethod
    def network_exists(network):
        return bool(docker("network", "ls", "-q", "--filter", f"name=^{network}$"))

    def journal(self):
        return (
            read_json(self.record)
            if self.record.exists()
            else {"active": None, "previous": None, "pending": None}
        )

    def save(self, journal):
        write_atomic(self.record, json.dumps(journal, indent=2) + "\n")

    @contextmanager
    def lock(self):
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        require(
            not self.root.is_symlink()
            and self.root.stat().st_uid == os.getuid()
            and not self.root.stat().st_mode & 0o077,
            f"Use an owner-only control directory: {self.root}",
        )
        with (self.root / "rollout.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ConfigurationError("A deployment operation is already running") from None
            self.gate_dir.mkdir(exist_ok=True, mode=0o700)
            yield

    def mode(self):
        return self.gate.read_text().strip() if self.gate.exists() else "closed"

    def set_mode(self, mode):
        write_atomic(self.gate, mode + "\n")

    def snapshot_path(self, entry, role):
        return self.root / "revisions" / entry["key"][7:] / role

    def inspection(self, entry):
        spec = entry["spec"]
        local = spec.get("local_dlp", {})
        if local.get("enabled"):
            local = {**local, "secrets_directory": str(self.snapshot_path(entry, "inspection"))}
        return DockerDeployment(spec["network"], (), local, self.root / "dlp")

    def identity(self, spec):
        if "keycloak" not in spec:
            return None
        key = digest(spec["keycloak"])
        if key not in self.identities:
            self.identities[key] = ManagedKeycloak(
                spec["keycloak"], self.project, spec["network"], self.timeout
            )
        return self.identities[key]

    def gateway(self, entry):
        if "gateway" in entry["spec"]:
            return Gateway(self.project, entry, self.timeout)
        return None

    def release_inputs(self, active):
        spec = self.spec
        release = validate("ReleaseManifest", read_json(spec["release"]))
        daemon = self.daemon()
        if active:
            require(active["daemon"] == daemon, "Deployment belongs to a different Docker daemon")
        network = spec["network"]
        if self.network_exists(network):
            require(
                docker("network", "inspect", "--format", "{{.Driver}} {{.Internal}}", network)
                == "bridge false",
                f"Managed deployment network {network} must be a bridge that supports published ports",
            )
        roles = ["supervisor", "launcher", "worker"]
        if "portal" in spec:
            roles.append("portal")
        if "keycloak" in spec:
            require(
                KEYCLOAK_IMAGES.keys() <= release["images"].keys(),
                "Select a release that includes Keycloak and PostgreSQL",
            )
            roles.extend(KEYCLOAK_IMAGES)
        if not active and "gateway" in spec:
            require(
                "gateway" in release["images"], "Select a release that includes the LASA gateway"
            )
            roles.append("gateway")
        return release, daemon, {role: release["images"][role] for role in roles}

    def candidate(self, active, release, daemon, images):
        spec = deepcopy(self.spec)
        runner = ReleaseImages(release)
        main = spec["supervisor"]
        mounts = config_mounts(main)
        layout = runner.supervisor("layout", mounts=mounts, config=main["config"])
        require(
            all(
                layout[field] == release[field] for field in ("store_schema", "wire_schema_digest")
            ),
            "The pinned supervisor image does not match the release wire and store schema",
        )
        base_url = layout["base_url"]
        origin = site_origin(base_url) if "gateway" in spec else None
        require(
            layout["listen_host"] == "0.0.0.0" and layout["tls"],
            "Managed supervisors require a 0.0.0.0 listener with TLS",
        )
        require(
            layout["launcher_instance"] == spec["name"]
            and layout["launcher_socket"] == SOCKET_PATH,
            f"Set runtime.launcher_instance to {spec['name']} and launcher_socket to {SOCKET_PATH}",
        )
        service_id = layout["service_id"]
        authentication = layout["authentication"]
        identity = self.identity(spec)
        if identity:
            identity.check_inputs(service_id)
            require(
                not origin or identity.origin.geturl() == origin, "Use the site origin for Keycloak"
            )
            require(
                authentication["mode"] == "jwt"
                and authentication["issuer"] == identity.issuer
                and authentication.get("jwks_file") == str(identity.jwks)
                and identity.policy == Path(layout["policy_file"])
                and str(identity.policy.parent) in main.get("mounts", []),
                "Use the receiver identity configuration created by deploy init",
            )
        else:
            for field in ("caller_token_file", "operator_token_file"):
                secret(main[field])
        ssl.create_default_context(cafile=main.get("ca_file"))
        checked = runner.supervisor(
            "preflight",
            mounts=mounts + state_mounts(layout["state_root"]),
            config=main["config"],
            issuer_bootstrap=bool(identity and not identity.record.exists()),
        )
        state_status = checked.pop("state")
        require(checked == layout, "Supervisor configuration changed during preflight")
        require(
            state_status != "owned" or active,
            f"State root {layout['state_root']} already has an owner",
        )
        role_paths = {"supervisor": Path(main["config"]).parent}
        states = {"supervisor": layout["state_root"]}
        port = {"supervisor": layout["listen_port"]}
        portal_url = None
        if portal := spec.get("portal"):
            require(
                portal["port"] != main["port"], "Portal and supervisor need distinct host ports"
            )
            settings = runner.portal(portal)
            require(
                settings["lasa_url"] == base_url
                and settings["lasa_service_id"] == service_id
                and authentication["mode"] == "jwt"
                and settings["issuer"] == authentication["issuer"],
                "Portal must use this deployment's JWT receiver, issuer, and public LASA URL",
            )
            if not identity:
                secret(portal["receiver_token_file"])
            if origin:
                require(
                    settings["public_origin"] == origin and settings["base_path"] == PORTAL_PATH,
                    "Use the site origin and /app base path for the caller portal",
                )
            portal_url = settings["public_origin"] + (
                settings["base_path"] + "/" if settings["base_path"] else ""
            )
            role_paths["portal"] = Path(portal["config"]).parent
            states["portal"] = settings["state_dir"]
            port["portal"] = PORTAL_PORT
        inspection = DockerDeployment(
            spec["network"],
            ((Path(main["config"]), layout["inspection_profiles"]),),
            spec.get("local_dlp", {}),
            self.root / "dlp",
        )
        inspection.validate_profiles()
        if inspection.enabled:
            role_paths["inspection"] = inspection.credentials()
            inspection.active()
            for field, (image_id, _platform) in inspection.image_pins().items():
                spec["local_dlp"][field] = image_id
        protected = [self.root.resolve(), *(Path(value).resolve() for value in states.values())]
        for index, left in enumerate(protected):
            for right in (*protected[index + 1 :], *(p.resolve() for p in role_paths.values())):
                require(
                    not (left.is_relative_to(right) or right.is_relative_to(left)),
                    "Control, runtime state, and configuration trees must be separate",
                )
        for role in ("supervisor", "portal"):
            for mount in spec.get(role, {}).get("mounts", []):
                require(Path(mount).exists(), f"Missing {role} bind mount {mount}")
                root = role_paths[role].resolve()
                mount_path = Path(mount).resolve()
                require(
                    not (mount_path.is_relative_to(root) or root.is_relative_to(mount_path)),
                    f"Mount overlaps the {role} configuration snapshot: {mount}",
                )
                require(
                    not any(
                        p.is_relative_to(mount_path) or mount_path.is_relative_to(p)
                        for p in protected
                    ),
                    f"Mount overlaps a control or state path: {mount}",
                )
        if active:
            require(
                active["spec"]["name"] == spec["name"]
                and active["spec"]["network"] == spec["network"]
                and active["spec"]["supervisor"]["port"] == main["port"]
                and active["service_id"] == service_id
                and active["base_url"] == base_url
                and active["release"]["platform"] == release["platform"]
                and active["spec"].get("docker_socket", "/var/run/docker.sock") == self.socket
                and active["states"]["supervisor"] == states["supervisor"]
                and all(
                    states.get(role, value) == value for role, value in active["states"].items()
                )
                and active["release"]["store_schema"] == release["store_schema"]
                and active["release"]["wire_schema_digest"] == release["wire_schema_digest"],
                "This rollout would change the service identity, endpoint, platform contract, or state root",
            )
            require(
                active["spec"].get("keycloak") == spec.get("keycloak"),
                "The managed Keycloak identity is fixed for an installed deployment",
            )
            require(
                active["spec"].get("gateway") == spec.get("gateway"),
                "Use deploy gateway to change the gateway image or site TLS files",
            )
        if identity:
            require(
                spec["keycloak"]["port"] not in {main["port"], spec["portal"]["port"]},
                "Keycloak needs a distinct host port",
            )
        image_ids = {}
        for role, image in images.items():
            if role == "gateway":
                continue
            if role in KEYCLOAK_IMAGES:
                platform = docker(
                    "image",
                    "inspect",
                    "--platform",
                    release["platform"],
                    "--format",
                    "{{.Os}}/{{.Architecture}}",
                    image,
                )
                image_ids[role] = docker("image", "inspect", "--format", "{{.Id}}", image)
            else:
                image_ids[role], platform = docker(
                    "image", "inspect", "--format", "{{.Id}} {{.Os}}/{{.Architecture}}", image
                ).split()
            require(
                platform == release["platform"],
                f"{role} image platform is {platform}, expected {release['platform']}",
            )
        contents = {role: config_tree(root / "config.json") for role, root in role_paths.items()}
        entry = {
            "spec": spec,
            "release": release,
            "images": image_ids,
            "states": states,
            "ports": port,
            "service_id": service_id,
            "base_url": base_url,
            "trees": contents,
            "daemon": daemon,
            "portal_url": portal_url,
        }
        if origin:
            gateway = self.gateway(entry)
            if not gateway.journal()["active"]:
                gateway.candidate(None)
            backends = (
                part["port"]
                for role in ("supervisor", "portal", "keycloak")
                if (part := spec.get(role))
            )
            require(gateway.port not in backends, "Use a gateway port distinct from backend ports")
        if identity:
            entry["identity_images"] = {name: image_ids.pop(name) for name in KEYCLOAK_IMAGES}
            if active:
                require(
                    active["identity_images"] == entry["identity_images"],
                    "Keycloak and PostgreSQL images are pinned for the lifetime of this deployment",
                )
        entry["key"] = digest(entry)
        return entry, role_paths, state_status

    def snapshot(self, entry, paths):
        target = self.snapshot_path(entry, "supervisor").parent
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not target.exists():
            with tempfile.TemporaryDirectory(dir=target.parent, prefix="snapshot-") as temp:
                stage = Path(temp) / "revision"
                stage.mkdir(mode=0o700)
                for role, source in paths.items():
                    shutil.copytree(source, stage / role)
                    require(
                        config_tree(stage / role / "config.json") == entry["trees"][role],
                        f"{role} configuration changed during the rollout",
                    )
                stage.rename(target)
        self.verify_snapshot(entry)

    def verify_snapshot(self, entry):
        for role, expected in entry["trees"].items():
            require(
                config_tree(self.snapshot_path(entry, role) / "config.json") == expected,
                f"Deployment snapshot changed for {role}",
            )

    def document(self, entry, docker_gid):
        spec = entry["spec"]
        images = entry["images"]
        user = f"{os.getuid()}:{os.getgid()}"
        standard = {
            "user": user,
            "restart": "unless-stopped",
            "read_only": True,
            "platform": entry["release"]["platform"],
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
        }
        launcher = {
            **standard,
            "image": images["launcher"],
            "network_mode": "none",
            "group_add": [docker_gid],
            "volumes": [
                bind(
                    spec.get("docker_socket", "/var/run/docker.sock"),
                    "/var/run/docker.sock",
                    writable=True,
                ),
                {"source": "lease", "target": LEASE_MOUNT, "type": "volume"},
                {"source": "socket", "target": "/run/lasa", "type": "volume"},
            ],
            "command": [
                "--image",
                images["worker"],
                "--scope",
                entry["service_id"],
                "--instance",
                spec["name"],
                "--socket",
                SOCKET_PATH,
                "--lock-directory",
                LEASE_MOUNT,
            ],
        }
        services = {"launcher": launcher}
        for role in entry["states"]:
            settings = spec[role]
            mounts = [
                bind(self.snapshot_path(entry, role), Path(settings["config"]).parent),
                bind(entry["states"][role], writable=True),
                *(bind(path) for path in settings.get("mounts", [])),
            ]
            command = ["--config", settings["config"]]
            if role == "supervisor":
                mounts += [
                    {
                        "source": "socket",
                        "target": "/run/lasa",
                        "type": "volume",
                        "read_only": True,
                    },
                    bind(self.gate_dir, Path(GATE_PATH).parent),
                ]
                command += ["--admission-gate", GATE_PATH]
            services[role] = {
                **standard,
                "image": images[role],
                "networks": {"supervisors": {"aliases": [f"lasa-{spec['name']}-{role}"]}},
                "volumes": mounts,
                "ports": [
                    {
                        "target": entry["ports"][role],
                        "published": str(settings["port"]),
                        "host_ip": "127.0.0.1",
                    }
                ],
                "command": command,
            }
        return {
            "services": services,
            "networks": {"supervisors": {"external": True, "name": spec["network"]}},
            "volumes": {
                "socket": {"external": True, "name": self.project + "-socket"},
                "lease": {"external": True, "name": LEASE_VOLUME},
            },
        }

    def compose(self, entry, *args, input_text=None, timeout=60):
        if input_text is None:
            return docker(
                "compose",
                "-p",
                self.project,
                "-f",
                "-",
                *args,
                document=self.document(entry, entry.get("docker_gid", "0")),
                timeout=timeout,
            )
        # Compose reads its document from stdin. Use a concrete container ID for credential stdin.
        require(
            args[:2] == ("exec", "portal"), "Credential input is limited to portal qualification"
        )
        container = self.compose(entry, "ps", "-q", "portal")
        return docker("exec", "-i", container, *args[2:], input_text=input_text, timeout=timeout)

    def prepare(self, entry):
        for path in entry["states"].values():
            Path(path).mkdir(parents=True, exist_ok=True, mode=0o700)
        network = entry["spec"]["network"]
        if not self.network_exists(network):
            docker("network", "create", network)
        image = entry["images"]["launcher"]
        platform = entry["release"]["platform"]
        socket = entry["spec"].get("docker_socket", "/var/run/docker.sock")
        entry["docker_gid"] = docker(
            "run",
            "--rm",
            "--pull",
            "never",
            "--platform",
            platform,
            "--network",
            "none",
            "--entrypoint",
            "stat",
            "--mount",
            f"type=bind,src={socket},dst=/var/run/docker.sock",
            image,
            "-c",
            "%g",
            "/var/run/docker.sock",
        )
        volumes = (
            (LEASE_VOLUME, "chmod", "1777"),
            (self.project + "-socket", "chown", f"{os.getuid()}:{os.getgid()}"),
        )
        for volume, command, ownership in volumes:
            docker("volume", "create", volume)
            docker(
                "run",
                "--rm",
                "--pull",
                "never",
                "--platform",
                platform,
                "--network",
                "none",
                "--user",
                "0:0",
                "--entrypoint",
                command,
                "--mount",
                f"type=volume,src={volume},dst=/lasa-init",
                image,
                ownership,
                "/lasa-init",
            )

    def supervisor_get(self, entry, path, *, operator=False):
        setting = entry["spec"]["supervisor"]
        field = "operator_token_file" if operator else "caller_token_file"
        identity = self.identity(entry["spec"])
        token = identity.token(operator=operator) if identity else secret(setting[field])
        name = setting.get("tls_server_name") or urlsplit(entry["base_url"]).hostname
        with httpx.Client(
            verify=ssl.create_default_context(cafile=setting.get("ca_file")),
            trust_env=False,
            timeout=3,
        ) as client:
            response = client.get(
                f"https://127.0.0.1:{setting['port']}{path}",
                headers={"Authorization": "Bearer " + token},
                extensions={"sni_hostname": name},
            )
            response.raise_for_status()
            return response.json()

    def wait(self, check, detail):
        deadline = time.monotonic() + self.timeout
        error = ""
        while True:
            try:
                if check():
                    return
            except httpx.HTTPStatusError as exc:
                error = f" (HTTP {exc.response.status_code})"
            except (httpx.RequestError, ValueError):
                error = ""
            if time.monotonic() >= deadline:
                raise ConfigurationError(detail + error)
            time.sleep(0.3)

    def drain(self, entry):
        if self.mode() != "closed":
            self.set_mode("drain")
            self.wait(
                lambda: self.supervisor_get(entry, "/health/drain", operator=True)["tasks"] == 0,
                "Timed out waiting for active tasks; resolve pending inputs or retry",
            )
            self.set_mode("closed")

        def quiet():
            state = self.supervisor_get(entry, "/health/drain", operator=True)
            return state == {"mode": "closed", "writes": 0, "tasks": 0}

        self.wait(quiet, "Timed out waiting for in-flight writes")

    def ready(self, entry, *, gateway_revision=None):
        self.wait(
            lambda: self.supervisor_get(entry, "/health/ready") == {"status": "ready"},
            "Supervisor did not pass authenticated HTTPS readiness",
        )
        prefix = urlsplit(entry["base_url"]).path
        descriptor = self.supervisor_get(entry, prefix + "/descriptor")
        require(
            descriptor["service_id"] == entry["service_id"]
            and any(
                protocol["wire_schema_digest"] == entry["release"]["wire_schema_digest"]
                for protocol in descriptor["protocols"]
            ),
            "Running supervisor does not match the release identity and wire digest",
        )
        self.supervisor_get(entry, "/health/drain", operator=True)
        if self.inspection(entry).enabled:
            self.compose(
                entry,
                "exec",
                "-T",
                "supervisor",
                "lasa",
                "config",
                "check",
                "--offline",
                "--probe-inspection",
                "--config",
                entry["spec"]["supervisor"]["config"],
            )
        self.qualify_portal(entry)
        if gateway := self.gateway(entry):
            self.gateway_ready(entry, gateway, gateway_revision, descriptor)

    def qualify_portal(self, entry):
        portal = entry["spec"].get("portal")
        if not portal:
            return
        url = f"http://127.0.0.1:{portal['port']}/health/ready"
        self.wait(
            lambda: httpx.get(url, trust_env=False, timeout=3).status_code == 200,
            "Portal did not pass local readiness",
        )
        identity = self.identity(entry["spec"])
        token = identity.token() if identity else secret(portal["receiver_token_file"])
        self.compose(
            entry,
            "exec",
            "portal",
            "python",
            "-m",
            "portal",
            "--config",
            portal["config"],
            "--qualify",
            input_text=token,
        )

    def gateway_ready(self, entry, gateway, revision, descriptor):
        identity = self.identity(entry["spec"])
        caller = (
            identity.token()
            if identity
            else secret(entry["spec"]["supervisor"]["caller_token_file"])
        )
        route = urlsplit(entry["base_url"]).path + "/descriptor"
        response = gateway.request(route, revision=revision, Authorization="Bearer " + caller)
        public = response.json() if response.status_code == 200 else {}
        require(
            all(
                public.get(field) == descriptor[field]
                for field in ("service_id", "deployment_revision", "protocols")
            ),
            "Gateway did not return the authenticated LASA descriptor",
        )
        if "portal" in entry["spec"]:
            response = gateway.request(PORTAL_PATH + "/", revision=revision)
            require(
                response.status_code == 200 and 'href="/app/auth/login?' in response.text,
                "Gateway did not return the caller portal at /app/",
            )
        if identity:
            response = gateway.request(
                urlsplit(identity.issuer).path + "/.well-known/openid-configuration",
                revision=revision,
            )
            require(
                response.status_code == 200 and response.json()["issuer"] == identity.issuer,
                "Gateway did not return the managed Keycloak issuer",
            )

    def qualify(self, entry):
        gateway = self.gateway(entry)
        if not gateway:
            self.ready(entry)
            return
        journal = gateway.journal()
        revision = journal["active"]
        if not revision:
            revision, material = gateway.candidate(None)
            gateway.snapshot(revision, material)
        gateway.install(revision, self.wait)
        self.ready(entry, gateway_revision=revision)
        if not journal["active"]:
            journal["active"] = revision
            gateway.save(journal)

    def qualify_gateway(self, entry, gateway, revision):
        descriptor = self.supervisor_get(entry, urlsplit(entry["base_url"]).path + "/descriptor")
        self.gateway_ready(entry, gateway, revision, descriptor)
        self.qualify_portal(entry)

    def gateway_action(self, action, **candidate_options):
        if action == "status":
            gateway = self.gateway_context()
            return gateway.report(gateway.journal())
        with self.lock():
            gateway = self.gateway_context()
            entry = gateway.entry
            require(
                entry["daemon"] == self.daemon(), "Deployment belongs to a different Docker daemon"
            )
            return gateway.maintain(
                action,
                self.wait,
                lambda revision: self.qualify_gateway(entry, gateway, revision),
                **candidate_options,
            )

    def gateway_context(self):
        app = self.journal()
        entry = app["active"]
        require(
            entry and not app["pending"],
            "Finish applying the LASA release before managing its gateway",
        )
        require(
            entry["spec"]["name"] == self.spec["name"],
            "Settings name does not match the installed site",
        )
        gateway = self.gateway(entry)
        require(gateway, "This site uses an operator-managed gateway")
        return gateway

    def install(self, entry):
        self.verify_snapshot(entry)
        self.prepare(entry)
        if identity := self.identity(entry["spec"]):
            identity.install(entry)
        self.inspection(entry).apply(validate=False, owned_only=True)
        self.compose(entry, "up", "--detach", "--remove-orphans", "--pull", "never", "launcher")
        self.wait(
            lambda: self.launcher_ready(entry), "Launcher did not answer on its private socket"
        )
        self.compose(entry, "up", "--detach", "--remove-orphans", "--pull", "never")
        self.qualify(entry)

    def launcher_ready(self, entry):
        try:
            self.compose(
                entry,
                "exec",
                "-T",
                "launcher",
                "python",
                "-c",
                "import asyncio, sys; from lasa_service.launcher_client import LauncherClient; "
                "asyncio.run(LauncherClient(*sys.argv[1:]).check())",
                SOCKET_PATH,
                entry["service_id"],
                entry["spec"]["name"],
                timeout=8,
            )
        except ConfigurationError:
            return False
        return True

    def restore(self, journal):
        pending = journal["pending"]
        active = journal["active"]
        if pending["phase"] == "switching":
            self.set_mode("closed")
            self.compose(pending["target"], "down", "--remove-orphans")
            if active:
                self.install(active)
            else:
                target = pending["target"]
                if gateway := self.gateway(target):
                    gateway.down()
                if self.inspection(target).enabled:
                    DockerDeployment(target["spec"]["network"], (), {}, self.root / "dlp").apply()
        journal["pending"] = None
        self.save(journal)
        self.set_mode(pending["mode"] if active else "closed")

    def switch(self, journal, target, *, hold):
        active = journal["active"]
        with rollout_images(self.project, target, active):
            original_mode = self.mode()
            journal["pending"] = {"target": target, "mode": original_mode, "phase": "draining"}
            self.save(journal)
            try:
                if active:
                    self.drain(active)
                else:
                    self.set_mode("closed")
                journal["pending"]["phase"] = "switching"
                self.save(journal)
                if active:
                    self.compose(active, "down", "--remove-orphans")
                self.install(target)
            except BaseException as exc:
                try:
                    self.restore(journal)
                except (ConfigurationError, OSError, ValueError, httpx.HTTPError) as restore_error:
                    raise ConfigurationError(
                        f"Rollout failed ({exc}); recovery is pending ({restore_error})"
                    ) from None
                raise ConfigurationError(
                    f"Rollout failed; predecessor restored if present: {exc}"
                ) from None
            journal.update(active=target, previous=active, pending=None)
            self.save(journal)
            self.set_mode("closed" if hold else "open")

    def status(self):
        journal = self.journal()
        active = journal["active"]
        identity = self.identity(active["spec"] if active else self.spec)
        return {
            "deployment": self.spec["name"],
            "active": self.revision(active),
            "previous": self.revision(journal["previous"]),
            "pending": self.revision(journal["pending"]["target"]) if journal["pending"] else None,
            "admission": self.mode(),
            "portal_url": active.get("portal_url") if active else None,
            "site_url": site_origin(active["base_url"])
            if active and "gateway" in active["spec"]
            else None,
            "keycloak": {"issuer": identity.issuer, "ready": identity.available()}
            if identity
            else None,
            "containers": self.compose(active, "ps", "--all", "--format", "json").splitlines()
            if active
            else [],
        }

    @staticmethod
    def revision(entry):
        return entry["release"]["release_id"] if entry else None

    def plan(self):
        active = self.journal()["active"]
        release, daemon, images = self.release_inputs(active)
        missing = missing_images(images, release["platform"])
        imports = []
        if missing:
            imports.append(planned_import(self.spec["release"], release, missing, "candidate"))
            target, state, change = None, None, None
        else:
            target, _, state = self.candidate(active, release, daemon, images)
            change = not active or target["key"] != active["key"]
        if active and change is not False:
            candidate_pins = set(images.values())
            fallback = {
                role: image
                for role, image in entry_images(active).items()
                if image not in candidate_pins
            }
            recovery = missing_images(fallback, active["release"]["platform"])
            if recovery:
                imports.append(
                    planned_import(
                        active["spec"]["release"], active["release"], recovery, "recovery"
                    )
                )
        identity = self.identity(self.spec)
        readiness = "ready"
        if imports:
            readiness = (
                "deferred"
                if all(item["archive_status"] == "verified" for item in imports)
                else "blocked"
            )
        return {
            "deployment": self.spec["name"],
            "release": release["release_id"],
            "state": state,
            "images": target["images"]
            if target
            else {
                role: image
                for role, image in images.items()
                if role not in KEYCLOAK_IMAGES and role != "gateway"
            },
            "portal": "portal" in self.spec,
            "portal_url": target["portal_url"] if target else None,
            "site_url": site_origin(target["base_url"])
            if target and "gateway" in self.spec
            else None,
            "keycloak": identity.issuer if identity else None,
            "local_dlp": self.spec.get("local_dlp", {}).get("enabled", False),
            "change": change,
            "readiness": readiness,
            "preflight": "deferred" if missing else "complete",
            "image_imports": imports,
        }

    def run(self, action, *, hold=False):
        if action == "status":
            return self.status()
        if action == "plan":
            return self.plan()
        with self.lock():
            journal = self.journal()
            active = journal["active"]
            owner = active or (journal["pending"]["target"] if journal["pending"] else None)
            if owner:
                require(
                    owner["spec"]["name"] == self.spec["name"],
                    "Settings name does not match the installed site",
                )
                require(
                    owner["daemon"] == self.daemon(),
                    "Deployment belongs to a different Docker daemon",
                )
            if active and (gateway := self.gateway(active)):
                gateway_journal = gateway.journal()
                if gateway_journal["pending"]:
                    gateway.recover(
                        gateway_journal,
                        self.wait,
                        lambda revision: self.qualify_gateway(active, gateway, revision),
                    )
            if journal["pending"]:
                with rollout_images(
                    self.project, active if journal["pending"]["phase"] == "switching" else None
                ):
                    self.restore(journal)
                if action == "rollback":
                    return self.status()
            if action == "apply":
                release, daemon, images = self.release_inputs(active)
                ensure_release_images(self.spec["release"], release, images)
                target, paths, _ = self.candidate(active, release, daemon, images)
                if active and target["key"] == active["key"]:
                    self.qualify(active)
                    if hold and self.mode() != "closed":
                        self.drain(active)
                else:
                    self.snapshot(target, paths)
                    self.switch(journal, target, hold=hold)
            elif action == "rollback":
                require(journal["previous"], "There is no previous release to restore")
                self.verify_snapshot(journal["previous"])
                self.switch(journal, journal["previous"], hold=hold)
            else:
                require(active, f"Cannot {action} before a release is installed")
                if action == "pause":
                    self.drain(active)
                else:
                    self.ready(active)
                    self.set_mode("open")
            return self.status()

    def users(self, action, *, email=None, username=None, credentials=None):
        with self.lock():
            journal = self.journal()
            active = journal["active"]
            require(
                active and not journal["pending"],
                "Finish applying the deployment before managing users",
            )
            require(
                active["daemon"] == self.daemon(), "Deployment belongs to a different Docker daemon"
            )
            identity = self.identity(active["spec"])
            require(identity, "Manage users at the configured external identity provider")
            return identity.users(
                action,
                images=ReleaseImages(active["release"]),
                email=email,
                username=username,
                credentials=credentials,
            )
