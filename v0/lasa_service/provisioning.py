"""Scaffold and check an operator-managed LASA deployment."""

import asyncio
import json
import os
import ssl
from pathlib import Path

import httpx
import jwt

from .auth import Authentication
from .capabilities import CapabilityRegistry, reference
from .config import (
    Configuration,
    ConfigurationError,
    builtin_capabilities,
    packaged_defaults,
    require,
    validate_url,
)
from .contracts import protocol_contracts
from .errors import LasaError
from .runtime import CodexRuntime


def initial_manifest(
    *, service_id, base_url, issuer, jwks, algorithms, image, model, provider_url, credential_ref
):
    for url in (service_id, base_url, issuer, provider_url):
        validate_url(url)
    if "jwks_url" in jwks:
        validate_url(jwks["jwks_url"])
    Configuration.check_secret_reference(credential_ref)
    manifest = {
        "config_version": "2.0",
        "service": {"id": service_id, "base_url": base_url},
        "authentication": {"issuer": issuer, "allowed_algorithms": algorithms, **jwks},
        "authorization": {"policy_file": "authorization.json"},
        "executors": [
            {
                "id": "codex",
                "model": model,
                "provider_base_url": provider_url,
                "credential_ref": credential_ref,
            }
        ],
        "runtime": {"image": image},
    }
    return protocol_contracts().validate("Config", manifest)


def initial_policy(operator_subject):
    principals = []
    if operator_subject:
        definition, _ = builtin_capabilities()["design.review"]
        principals.append(
            {
                "subject": operator_subject,
                "kind": "user",
                "rules": [
                    {
                        "authorization_ref": "default",
                        "contracts": [reference(definition)],
                        "resources": [{"resource": "workspace:self", "actions": ["read"]}],
                        "effects": ["workspace.read"],
                        "budget": packaged_defaults()["limits"]["max_task_budget"],
                        "delegation_grants": [],
                        "max_hops": 0,
                        "content_diagnostics": False,
                    }
                ],
            }
        )
    policy = {"revision": "initial", "principals": principals, "trusted_delegator_service_ids": []}
    return protocol_contracts().validate("AuthorizationPolicy", policy)


def write_scaffold(directory, manifest, policy):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    created = []
    try:
        for name, document in (("authorization.json", policy), ("config.json", manifest)):
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


def check_storage(settings, service):
    for value in (settings["data_root"], service["workspace_root"]):
        directory = Path(value)
        while not directory.exists() and not directory.is_symlink():
            directory = directory.parent
        require(
            directory.is_dir() and os.access(directory, os.W_OK | os.X_OK),
            "Private state and workspace paths must be writable directories",
        )


def check_deployment(config, *, offline):
    try:
        CapabilityRegistry.configured(config).close()
    except LasaError as exc:
        raise ConfigurationError(
            f"Contract registry, publication or bindings: {exc.code}"
        ) from None

    settings = config.document["storage"]
    check_storage(settings, config.document["service"])
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

    asyncio.run(check_jwks_and_worker(config, offline=offline))


async def check_jwks_and_worker(config, *, offline):
    if "jwks_file" in config.document["authentication"] or not offline:
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
            raise ConfigurationError(
                "Cannot load valid signing keys from the configured JWKS"
            ) from None
    if not offline:
        try:
            await CodexRuntime().verify_worker(config.document["runtime"])
        except (OSError, LasaError):
            raise ConfigurationError(
                "Cannot verify the configured Docker worker image and packaged Codex version"
            ) from None
