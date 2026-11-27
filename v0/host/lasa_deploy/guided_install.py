"""Provision a deployment from the operator's install JSON."""

import secrets
import shutil
import ssl
from pathlib import Path
from urllib.parse import urlsplit

from .contracts import ConfigurationError, digest, require, validate, validator
from .deployment import read_json, secret
from .image_cache import ensure_release_images
from .install_oidc import https_endpoint, verify_subjects
from .keycloak import (
    KEYCLOAK_IMAGES,
    KEYCLOAK_PATH,
    PORTAL_CLIENT,
    REALM,
    initial_users,
    scaffold_identity,
    write_json,
)
from .managed_deployment import SOCKET_PATH, HostDeployment
from .runtime import ReleaseImages
from .site_gateway import PORTAL_PATH, SUPERVISOR_PATH, site_origin

DEFAULT_PORTS = {"supervisor": 8443, "portal": 8080, "keycloak": 9443}
PROFILE_SETTINGS = {"portal-keycloak": "keycloak", "portal-oidc": "oidc"}


def install_path(base, value):
    return (base / Path(value).expanduser()).resolve()


def config_errors(settings):
    errors = []
    for error in validator("InstallConfig").iter_errors(settings):
        prefix = ".".join(map(str, error.absolute_path))
        field = prefix or "install.json"
        if error.validator == "required":
            errors.extend(
                f"{prefix + '.' if prefix else ''}{key}: required"
                for key in error.validator_value
                if key not in error.instance
            )
        elif error.validator == "additionalProperties":
            errors.extend(
                f"{prefix + '.' if prefix else ''}{key}: unknown setting"
                for key in sorted(error.instance.keys() - error.schema["properties"].keys())
            )
        else:
            errors.append(f"{field}: invalid value ({error.validator})")
    return list(dict.fromkeys(errors))


def require_valid(errors):
    require(not errors, "Invalid install configuration\n  " + "\n  ".join(errors))


def read_install_config(path):
    config = read_json(path)
    require_valid(config_errors(config))
    profile = config.setdefault("profile", "core")
    errors = [
        f"{group}: requires profile {mode}"
        for mode, group in PROFILE_SETTINGS.items()
        if group in config and profile != mode
    ]
    config.setdefault("release", "release.json")
    for prefix, group in (
        ("", config),
        ("model.", config["model"]),
        ("tls.", config["tls"]),
        ("oidc.", config.get("oidc", {})),
    ):
        for key, value in group.items():
            if key == "release" or key.endswith("_file"):
                candidate = install_path(path.parent, value)
                if not candidate.is_file():
                    errors.append(f"{prefix}{key}: expected a file at {candidate}")
                else:
                    try:
                        with candidate.open("rb"):
                            pass
                    except OSError:
                        errors.append(f"{prefix}{key}: cannot read {candidate}")
                group[key] = str(candidate)
    require_valid(errors)
    if profile == "portal-keycloak":
        config["keycloak"] = {"users": initial_users(config.get("keycloak", {}).get("users", []))}
    return config


def copy_secret(source, target):
    shutil.copyfile(source, target)
    target.chmod(0o600)
    return str(target)


def installation_spec(config, root, name, origin):
    profile = config["profile"]
    tls = config["tls"]
    ports = {**DEFAULT_PORTS, **config.get("ports", {})}
    spec = {
        "name": name,
        "network": f"lasa-{name}",
        "control_directory": str(root / "control"),
        "release": config["release"],
        "supervisor": {"config": str(root / "supervisor/config.json"), "port": ports["supervisor"]},
        "gateway": {**tls, "listen_host": config.get("gateway_listen_host", "0.0.0.0")},
    }
    if profile != "core":
        spec["portal"] = {"config": str(root / "portal/config.json"), "port": ports["portal"]}
    if profile == "portal-keycloak":
        spec["keycloak"] = {
            **tls,
            "origin": origin,
            "port": ports["keycloak"],
            "directory": str(root / "identity"),
        }
        spec["timeout_seconds"] = 240
    if profile == "portal-oidc":
        oidc = config["oidc"]
        for role in ("caller", "operator"):
            key = f"{role}_token_file"
            spec["supervisor"][key] = oidc[key]
        spec["portal"]["receiver_token_file"] = oidc["caller_token_file"]
    if profile == "core":
        for role in ("caller", "operator"):
            spec["supervisor"][f"{role}_token_file"] = str(root / "clients" / f"{role}-token.txt")
    if tls.get("ca_file"):
        spec["supervisor"]["ca_file"] = str(root / "supervisor/ca.pem")
    used = [spec[role]["port"] for role in ("supervisor", "portal", "keycloak") if role in spec]
    used.append(urlsplit(origin).port or 443)
    require(len(set(used)) == len(used), "ports: gateway and backend ports must be distinct")
    return validate("HostDeployment", spec)


def initialize(path):
    path = path.expanduser().resolve()
    config = read_install_config(path)
    profile = config["profile"]
    origin = config["site_url"]
    try:
        site_origin(origin + SUPERVISOR_PATH)
    except ValueError as exc:
        raise ConfigurationError(f"site_url: {exc}") from None
    host = urlsplit(origin).hostname
    name = host.replace(".", "-")
    if len(name) > 63:
        name = name[:50] + "-" + digest(host)[7:19]
    name = config.get("name", name)
    root = (
        install_path(path.parent, config["output"])
        if "output" in config
        else (Path.home() / ".local/share/lasa" / name).resolve()
    )
    require(not root.exists(), f"output: choose an unused deployment directory at {root}")
    service_id = config.get("service_id", f"{origin}/services/{name}")
    for field, url in (("service_id", service_id), ("model.base_url", config["model"]["base_url"])):
        try:
            https_endpoint(url)
        except ValueError as exc:
            raise ConfigurationError(f"{field}: {exc}") from None
    try:
        secret(config["model"]["credential_file"])
    except (OSError, ValueError):
        raise ConfigurationError(
            "model.credential_file: provide a valid model credential"
        ) from None
    tls = config["tls"]
    try:
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(
            tls["certificate_file"], tls["key_file"], password=""
        )
    except (OSError, ValueError):
        raise ConfigurationError(
            "tls.certificate_file and tls.key_file must form a valid pair"
        ) from None
    for group in ("tls", "model", "oidc"):
        if ca := config.get(group, {}).get("ca_file"):
            try:
                ssl.create_default_context(cafile=ca)
            except (OSError, ValueError):
                raise ConfigurationError(
                    f"{group}.ca_file: cannot read a valid CA bundle"
                ) from None

    package = validate("ReleaseManifest", read_json(config["release"]))
    require("gateway" in package["images"], "Select a release that includes the LASA gateway")
    roles = ["supervisor", "launcher", "worker", "gateway"]
    if profile != "core":
        roles.append("portal")
    if profile == "portal-keycloak":
        require(
            KEYCLOAK_IMAGES.keys() <= package["images"].keys(),
            "Select a release that includes Keycloak and PostgreSQL",
        )
        roles.extend(KEYCLOAK_IMAGES)
    spec = installation_spec(config, root, name, origin)
    external = None
    if profile == "portal-oidc":
        oidc = config["oidc"]
        try:
            client_secret = secret(oidc["client_secret_file"])
        except (OSError, ValueError):
            raise ConfigurationError(
                "oidc.client_secret_file: provide a valid client secret"
            ) from None
        external = (*verify_subjects(oidc, tls.get("ca_file"), service_id), client_secret)

    HostDeployment(spec).daemon()
    ensure_release_images(config["release"], package, roles)
    root.mkdir(mode=0o700, parents=True)
    try:
        return write_configuration(config, spec, ReleaseImages(package), root, service_id, external)
    except BaseException:
        shutil.rmtree(root)
        raise


def write_configuration(config, spec, images, root, service_id, external):
    profile = config["profile"]
    origin = config["site_url"]
    model = config["model"]
    tls = config["tls"]
    base = origin + SUPERVISOR_PATH
    sup = root / "supervisor"
    sup.mkdir(mode=0o700)
    clients = root / "clients"
    clients.mkdir(mode=0o700)
    if ca := tls.get("ca_file"):
        copy_secret(ca, sup / "ca.pem")
    policy_file = None
    additional_callers = []
    user_credentials = []
    mounts = [(sup, True), (clients, True)]
    tokens = {}
    if profile == "core":
        authentication = {"mode": "static_token"}
        caller, operator = "caller", "operator"
        tokens = {role: spec["supervisor"][f"{role}_token_file"] for role in (caller, operator)}
    elif profile == "portal-keycloak":
        identity = root / "identity"
        issuer = origin + KEYCLOAK_PATH + f"/realms/{REALM}"
        receiver = identity / "receiver"
        authentication = {
            "mode": "jwt",
            "issuer": issuer,
            "allowed_algorithms": ["RS256"],
            "jwks_file": str(receiver / "keycloak-jwks.json"),
        }
        client_id = PORTAL_CLIENT
        portal_secret = secrets.token_urlsafe(36)
        callers, user_credentials = scaffold_identity(
            identity,
            service_id,
            origin + PORTAL_PATH + "/auth/callback",
            portal_secret,
            config["keycloak"]["users"],
            clients / "users",
        )
        caller = callers[0] if callers else None
        additional_callers = callers[1:]
        operator = None
        spec["supervisor"]["mounts"] = [str(receiver)]
        policy_file = str(receiver / "authorization.json")
        mounts.append((receiver, True))
    else:
        oidc = config["oidc"]
        algorithm, jwks, caller, operator, portal_secret = external
        issuer, client_id = oidc["issuer"], oidc["client_id"]
        keys = sup / "issuer-jwks.json"
        write_json(keys, jwks)
        authentication = {
            "mode": "jwt",
            "issuer": issuer,
            "allowed_algorithms": [algorithm],
            "jwks_file": str(keys),
        }
    scaffold = images.supervisor(
        "scaffold",
        mounts=mounts,
        output=str(sup),
        manifest={
            "service_id": service_id,
            "base_url": base,
            "authentication": authentication,
            "launcher_socket": SOCKET_PATH,
            "model": model["id"],
            "provider_url": model["base_url"],
            "credential_ref": "file:" + copy_secret(model["credential_file"], sup / "model-key"),
            "state_root": str(root / "state"),
        },
        runtime={"launcher_instance": spec["name"], "startup_timeout_ms": 25000},
        storage={
            "listen_host": "0.0.0.0",
            "tls": {
                "certificate_file": copy_secret(tls["certificate_file"], sup / "certificate.pem"),
                "key_file": copy_secret(tls["key_file"], sup / "key.pem"),
            },
        },
        provider_ca=copy_secret(model["ca_file"], sup / "provider-ca.pem")
        if "ca_file" in model
        else None,
        caller=caller,
        additional_callers=additional_callers,
        operator=operator,
        policy_file=policy_file,
        tokens=tokens,
    )
    if additional_callers:
        require(
            scaffold.get("caller_count") == len(user_credentials),
            "Select a release that supports provisioning multiple Keycloak users",
        )
    result = {"profile": profile, "site_url": origin}
    if profile == "core":
        result["caller_credentials_file"] = tokens["caller"]
        result["operator_credentials_file"] = tokens["operator"]
    else:
        portal = root / "portal"
        portal.mkdir(mode=0o700)
        key_paths = {}
        for purpose in ("encryption", "journal", "ticket"):
            filename = portal / (purpose + "-key")
            filename.write_text(secrets.token_hex(32) + "\n")
            key_paths[purpose + "_key_file"] = str(filename)
        (portal / "client-secret").write_text(portal_secret + "\n")
        oidc = config.get("oidc", {})
        settings = {
            "public_origin": origin,
            "base_path": PORTAL_PATH,
            "lasa_url": base,
            "lasa_service_id": service_id,
            "issuer": issuer,
            "client_id": client_id,
            "client_secret_file": str(portal / "client-secret"),
            "state_dir": str(root / "portal-state"),
            "audience_parameter": oidc.get("audience_parameter", "resource"),
            **key_paths,
        }
        sources = dict.fromkeys(path for path in (tls.get("ca_file"), oidc.get("ca_file")) if path)
        if sources:
            bundle = portal / "ca.pem"
            bundle.write_bytes(b"\n".join(Path(path).read_bytes() for path in sources))
            settings["ca_file"] = str(bundle)
        write_json(portal / "config.json", settings)
        images.portal(spec["portal"])
        result["portal_url"] = origin + PORTAL_PATH + "/"
        if profile == "portal-keycloak":
            result["user_credentials"] = user_credentials
    destination = root / "deployment.json"
    write_json(destination, validate("HostDeployment", spec))
    return {**result, "settings": str(destination)}
