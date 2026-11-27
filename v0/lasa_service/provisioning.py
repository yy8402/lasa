"""Scaffold and check an operator-managed LASA deployment."""

import asyncio
import fcntl
import json
import os
import secrets
import ssl
import tempfile
import time
from pathlib import Path

import httpx
import jwt
from jsonschema import ValidationError

from . import __version__
from .auth import (
    STATIC_TOKEN_REGISTRY_MAX_BYTES,
    Authentication,
    read_static_tokens,
    static_token_digest,
)
from .capabilities import CapabilityRegistry, reference
from .config import (
    Configuration,
    ConfigurationError,
    builtin_capabilities,
    packaged_defaults,
    require,
    validate_url,
)
from .content_security import new_client
from .contracts import digest, protocol_contracts
from .errors import LasaError
from .inspection import MANAGED_DLP_URL
from .runtime import CodexRuntime
from .store import StateStoreError, identity, inspect_state


def configuration_error(exc):
    if isinstance(exc, (ConfigurationError, StateStoreError)):
        return str(exc)
    if isinstance(exc.__cause__, ValidationError):
        error = exc.__cause__
        path = ".".join(map(str, error.absolute_path)) or "document"
        if error.validator == "required":
            missing = ", ".join(key for key in error.validator_value if key not in error.instance)
            return f"Missing required settings in {path}: {missing}"
        return f"Schema validation failed at {path} ({error.validator})"
    if isinstance(exc, LasaError):
        return f"Invalid configuration ({exc.code})"
    if isinstance(exc, OSError) and exc.filename:
        return f"Cannot access {exc.filename}"
    return "Invalid configuration data"


def initial_manifest(
    *,
    service_id,
    base_url,
    authentication,
    launcher_socket,
    model,
    provider_url,
    credential_ref,
    state_root=None,
):
    for url in (service_id, base_url, provider_url):
        validate_url(url)
    for key in ("issuer", "jwks_url"):
        if key in authentication:
            validate_url(authentication[key])
    Configuration.check_secret_reference(credential_ref)
    manifest = {
        "config_version": __version__,
        "service": {"id": service_id, "base_url": base_url},
        "authentication": authentication,
        "executors": [
            {
                "id": "codex",
                "model": model,
                "provider_base_url": provider_url,
                "credential_ref": credential_ref,
            }
        ],
        "runtime": {"launcher_socket": str(Path(launcher_socket).absolute())},
    }
    if state_root is not None:
        manifest["storage"] = {"state_root": str(Path(state_root).absolute())}
    return protocol_contracts().validate("Config", manifest)


def initial_policy(consumer_subjects, operator_subject, capability="design.review"):
    principals = []
    if consumer_subjects:
        definition, _ = builtin_capabilities()[capability]
        review = capability == "design.review"
        principals.extend(
            {
                "subject": consumer_subject,
                "kind": "user",
                "rules": [
                    {
                        "authorization_ref": "default",
                        "contracts": [reference(definition)],
                        "resources": [{"resource": "workspace:self", "actions": ["read"]}]
                        if review
                        else [],
                        "effects": ["workspace.read"] if review else [],
                        "budget": packaged_defaults()["limits"]["max_task_budget"],
                        "delegation_grants": [],
                        "content_diagnostics": False,
                    }
                ],
            }
            for consumer_subject in consumer_subjects
        )
    if operator_subject:
        if operator_subject in consumer_subjects:
            raise ValueError("Consumer and operator subjects must be distinct")
        principals.append({"subject": operator_subject, "kind": "operator", "rules": []})
    policy = {"revision": "initial", "principals": principals}
    return protocol_contracts().validate("AuthorizationPolicy", policy)


def write_scaffold(directory, manifest, policy):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    defaults = packaged_defaults()
    documents = {}
    if policy is not None:
        documents[defaults["authorization"]["policy_file"]] = policy
    authentication = manifest["authentication"]
    if authentication.get("mode") == "static_token":
        documents[defaults["static_tokens_file"]] = {"tokens": []}
    documents["config.json"] = manifest
    created = []
    try:
        for name, document in documents.items():
            path = directory / name
            try:
                with path.open("x", encoding="utf-8") as target:
                    created.append(path)
                    json.dump(document, target, indent=2)
                    target.write("\n")
            except FileExistsError:
                raise ConfigurationError(f"{name} already exists in the output directory") from None
    except BaseException:
        for path in created:
            path.unlink()
        raise


def issue_static_token(config, config_directory, subject, output, ttl_hours):
    require(config.auth_mode == "static_token", "Static tokens require static_token authentication")
    require(ttl_hours > 0, "Token lifetime must be positive")
    require(
        any(principal["subject"] == subject for principal in config.policy()["principals"]),
        "The token subject needs a principal in the receiver policy",
    )
    output = output.resolve()
    require(
        not output.is_relative_to(config_directory.resolve()),
        "Write the caller token outside the server configuration directory",
    )
    registry_path = Path(config.document["authentication"]["tokens_file"]).resolve()
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    entry = {
        "subject": subject,
        "digest": static_token_digest(config.service_id, token),
        "expires_at": now + ttl_hours * 3600,
    }
    with registry_path.with_name(registry_path.name + ".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        registry = read_static_tokens(registry_path)
        registry["tokens"] = [
            record for record in registry["tokens"] if record["expires_at"] > now
        ] + [entry]
        protocol_contracts().validate("StaticTokenRegistry", registry)
        data = (json.dumps(registry, indent=2) + "\n").encode()
        require(len(data) <= STATIC_TOKEN_REGISTRY_MAX_BYTES, "Static token registry is too large")
        with output.open("x", encoding="utf-8") as secret_file:
            try:
                secret_file.write(token + "\n")
                secret_file.flush()
                os.fsync(secret_file.fileno())
                replace_token_registry(registry_path, data)
            except BaseException:
                output.unlink()
                raise


def replace_token_registry(path, data):
    fd, temporary = tempfile.mkstemp(prefix=".tokens-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as target:
            target.write(data)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def check_storage(config):
    for path in (config.private_root, config.workspace_root):
        directory = path
        while not directory.exists() and not directory.is_symlink():
            directory = directory.parent
        require(
            directory.is_dir() and os.access(directory, os.W_OK | os.X_OK),
            f"State directory unavailable for {path}: {directory} must be a writable directory",
        )
    return inspect_state(config.private_root)


def check_deployment(config, *, offline, issuer_bootstrap=False, readonly_state=False):
    try:
        CapabilityRegistry.configured(config).close()
    except LasaError as exc:
        raise ConfigurationError(
            f"Contract registry, publication or bindings: {exc.code}"
        ) from None

    settings = config.document["storage"]
    state = (
        inspect_state(config.private_root, readonly=True)
        if readonly_state
        else check_storage(config)
    )
    if tls := settings.get("tls"):
        try:
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(
                tls["certificate_file"], tls["key_file"], password=""
            )
        except (OSError, ValueError):
            raise ConfigurationError("Cannot load the configured TLS certificate and key") from None

    ca_files = [
        item[key]
        for items, key in (
            (config.document["executors"], "provider_ca_file"),
            (config.peers, "ca_file"),
            (config.connectors.values(), "ca_file"),
            (config.inspection.profiles.values(), "ca_file"),
        )
        for item in items
        if key in item
    ]
    for filename in ca_files:
        try:
            ssl.create_default_context(cafile=filename)
        except (OSError, ValueError):
            raise ConfigurationError(f"Cannot load configured CA file {filename}") from None

    for connector in config.connectors.values():
        label = f"Connector {connector['id']}"
        if connector["kind"] == "mcp-stdio":
            command = Path(connector["command"])
            require(
                command.is_file() and os.access(command, os.X_OK), f"{label}: cannot run command"
            )
        for secret in connector.get("secret_env", {}).values():
            config.secret(secret, label=label)
        if "credential_ref" in connector:
            config.secret(connector["credential_ref"], label=label)

    if not issuer_bootstrap:
        asyncio.run(check_authentication_and_worker(config, offline=offline))
    return state


async def check_authentication_and_worker(config, *, offline):
    settings = config.document["authentication"]
    if config.auth_mode == "static_token" or "jwks_file" in settings or not offline:
        try:
            await Authentication(config).start()
        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
            LasaError,
            httpx.HTTPError,
            jwt.PyJWTError,
        ):
            if config.auth_mode == "static_token":
                raise ConfigurationError("Cannot load a valid static token registry") from None
            raise ConfigurationError(
                "Cannot load valid signing keys from the configured JWKS"
            ) from None
    if not offline:
        try:
            await CodexRuntime(config).verify_worker()
        except (OSError, LasaError, TimeoutError):
            raise ConfigurationError(
                "Cannot verify the configured worker launcher and Docker daemon"
            ) from None


def probe_inspection(config):
    async def check():
        for profile in config.inspection.active_profiles():
            if profile["url"] != MANAGED_DLP_URL:
                continue
            try:
                content = {"input": {"objective": "Confirm LASA deployment readiness."}}
                request = {
                    "version": "1",
                    "inspection_id": identity("inspection"),
                    "binding_revision": digest("deployment"),
                    "policy_revision": digest("deployment"),
                    "gateway_policy_revision": profile["policy_revision"],
                    "channel": "reasoning.request",
                    "purpose": "execution",
                    "media_type": "application/json",
                    "inspection_digest": digest(content),
                    "content": content,
                }
                token = config.secret(profile["credential_ref"], label="Inspection profile")
                async with new_client(profile, None) as client:
                    response = await client.post(
                        profile["url"],
                        json=request,
                        timeout=5,
                        headers={"Authorization": "Bearer " + token},
                    )
                response.raise_for_status()
                result = config.contracts.validate("ContentInspectionResponse", response.json())
                require(
                    result["verdict"] == "permit"
                    and result["gateway_id"] == profile["gateway_id"]
                    and all(
                        result[key] == request[key]
                        for key in ("inspection_id", "inspection_digest", "gateway_policy_revision")
                    ),
                    "Unexpected synthetic DLPLite inspection result",
                )
            except (httpx.HTTPError, LasaError, OSError, ValueError):
                raise ConfigurationError(
                    f"DLPLite qualification failed for profile {profile['id']}"
                ) from None

    asyncio.run(check())
