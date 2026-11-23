"""Strict private target configuration and explicit secret references."""

import copy
import os
import ssl
from dataclasses import dataclass, field
from functools import cache
from importlib.resources import files
from pathlib import Path
from urllib.parse import unquote, urlsplit

import jwt

from . import __version__
from .auth import peer_workload_identity
from .capabilities import reference
from .connector_schema import check_schema, validate
from .contracts import digest, parse_json, protocol_contracts
from .grants import grant_key


class ConfigurationError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ConfigurationError(message)


@cache
def packaged_defaults():
    return parse_json(files("lasa_service").joinpath("config_defaults.json").read_bytes())


@cache
def builtin_capabilities():
    root = files("lasa_contracts").joinpath("examples")
    return {
        name: (parse_json(root.joinpath(f"capability-{file}.json").read_bytes()), verifier)
        for name, file, verifier in [
            ("design.review", "review", "design-review-v1"),
            ("task.attempt", "attempt", "task-attempt-v1"),
            ("documents.read", "documents-read", "documents-read-v1"),
            ("documents.search", "documents-search", "documents-search-v1"),
            ("repository.inspect", "repository-inspect", "repository-inspect-v1"),
        ]
    }


BUILTIN_NAMESPACE = "https://contracts.example.net/capabilities/"
LOCAL_BUILTINS = {
    "design.review": (["read"], ["workspace.read"]),
    "task.attempt": (["read", "create", "update"], ["workspace.read", "workspace.write"]),
}


def local_bindings(published, executor_id):
    return [
        {
            "binding_id": "binding-" + name,
            "contract": ref,
            "executor_id": executor_id,
            "approved_resources": [{"resource": "workspace:self", "actions": list(actions)}],
            "allowed_effects": list(effects),
            "required_operations": [],
        }
        for name, (actions, effects) in LOCAL_BUILTINS.items()
        if (ref := reference(builtin_capabilities()[name][0])) in published
    ]


def effective_document(manifest, defaults):
    document = copy.deepcopy(manifest)
    for section in (
        "service",
        "runtime",
        "limits",
        "discovery_cache",
        "storage",
        "routing",
        "authorization",
    ):
        document[section] = copy.deepcopy(defaults[section]) | document.get(section, {})
    authn = document["authentication"]
    if authn.setdefault("mode", "jwt") == "static_token":
        authn.setdefault("tokens_file", defaults["static_tokens_file"])
    document.setdefault("default_executor", document["executors"][0]["id"])
    document.setdefault("peers", [])
    document.setdefault("contract_publishers", [])
    document["published_contracts"] = [
        reference(builtin_capabilities()[entry][0]) if isinstance(entry, str) else entry
        for entry in document.get("published_contracts", defaults["published_contracts"])
    ]
    require(
        len({digest(ref) for ref in document["published_contracts"]})
        == len(document["published_contracts"]),
        "Duplicate published contract",
    )
    if "bindings" not in document:
        document["bindings"] = local_bindings(
            document["published_contracts"], document["default_executor"]
        )
    for executor in document["executors"]:
        executor.setdefault("connectors", [])
    for peer in document["peers"]:
        peer.setdefault("request_timeout_seconds", defaults["peer_timeout_seconds"])
    return document


def validate_url(url):
    value = urlsplit(url)
    require(
        value.scheme == "https"
        and value.hostname
        and not (value.username or value.password or value.query or value.fragment),
        "Expected an HTTPS URL without credentials/query/fragment",
    )
    return value


def within_url(url, base):
    value, boundary = urlsplit(url), validate_url(base)
    if (
        value.scheme != "https"
        or value.username
        or value.password
        or value.fragment
        or any(ord(c) < 32 for c in url)
    ):
        return False
    path = unquote(value.path)
    return (
        "\\" not in path
        and value.netloc == boundary.netloc
        and ".." not in path.split("/")
        and (path == boundary.path or path.startswith(boundary.path.rstrip("/") + "/"))
    )


@dataclass
class Configuration:
    document: dict
    environ: dict = field(repr=False)
    prompts: dict[str, str] = field(repr=False)
    publishers: list = field(repr=False)
    secrets: dict = field(default_factory=dict, repr=False)
    connectors: dict = field(default_factory=dict, repr=False)

    @classmethod
    def load(cls, path, *, environ=None):
        path = Path(path).absolute()
        return cls.from_document(
            parse_json(path.read_bytes()), environ=environ, base_dir=path.parent
        )

    @classmethod
    def from_document(cls, document, *, environ=None, base_dir=None):
        contracts = protocol_contracts()
        contracts.validate("Config", document)
        document = effective_document(document, packaged_defaults())
        base_dir = Path.cwd() if base_dir is None else Path(base_dir).absolute()

        def artifact(value):
            return str(base_dir / value)

        service = document["service"]
        validate_url(service["id"])
        validate_url(service["base_url"])
        service["base_url"] = service["base_url"].rstrip("/")
        authn = document["authentication"]
        if authn["mode"] == "static_token":
            authn["tokens_file"] = artifact(authn["tokens_file"])
        else:
            validate_url(authn["issuer"])
            if "jwks_file" in authn:
                authn["jwks_file"] = artifact(authn["jwks_file"])
            else:
                validate_url(authn["jwks_url"])
        authz = document["authorization"]
        authz["policy_file"] = artifact(authz["policy_file"])
        tls = document["storage"].get("tls")
        require(
            document["storage"]["listen_host"] == "127.0.0.1" or tls,
            "TLS certificate and key are required for a non-loopback listener",
        )
        if tls:
            require(
                all(Path(path).is_absolute() for path in tls.values()), "TLS paths must be absolute"
            )
        ids = {service["id"]}
        for peer in document["peers"]:
            require(peer["expected_service_id"] not in ids, "Duplicate or self peer service ID")
            ids.add(peer["expected_service_id"])
            require(
                within_url(peer["descriptor_url"], peer["allowed_base_url"]),
                "Peer descriptor escaped configured boundary",
            )
        if "prompts_file" in document:
            prompt_path = Path(document["prompts_file"])
            require(prompt_path.is_absolute(), "Prompt file path must be absolute")
        else:
            prompt_path = files("lasa_service").joinpath("prompts.json")
        prompts = contracts.validate("Prompts", parse_json(prompt_path.read_bytes()))

        builtins = builtin_capabilities()
        publishers = [
            {
                "namespace": BUILTIN_NAMESPACE,
                "definitions": [value[0] for value in builtins.values()],
            }
        ]
        for publisher in document["contract_publishers"]:
            path = Path(artifact(publisher["trusted_registry_file"]))
            publisher["trusted_registry_file"] = str(path)
            definitions = parse_json(path.read_bytes())
            require(isinstance(definitions, list), "Contract registry must contain a JSON array")
            publishers.append({"namespace": publisher["namespace"], "definitions": definitions})
        document["verifiers"] = [
            {"contract": reference(definition), "verifier_id": verifier}
            for definition, verifier in builtins.values()
        ] + document.get("verifiers", [])

        config = cls(
            document, dict(os.environ if environ is None else environ), prompts, publishers
        )
        require(config.state_root.is_absolute(), "State root path must be absolute")
        require(
            not any(path.is_symlink() for path in (config.private_root, config.workspace_root)),
            "Private and workspace directories must be direct children of the state root",
        )
        if "deployment_revision" not in service:
            service["deployment_revision"] = f"{__version__}-{config.revision[7:23]}"
        executor_ids = [x["id"] for x in document["executors"]]
        require(len(executor_ids) == len(set(executor_ids)), "Duplicate executor IDs")
        require(document["default_executor"] in executor_ids, "Unknown default_executor")
        operation_owners = {}
        executor_operations = {}

        for executor in document["executors"]:
            validate_url(executor["provider_base_url"])
            if ca_file := executor.get("provider_ca_file"):
                require(Path(ca_file).is_absolute(), "Provider CA path must be absolute")
            config.secret(executor["credential_ref"], label=f"Executor {executor['id']}")
            operations = set()
            connector_ids = set()
            for resource in executor["connectors"]:
                require(resource["id"] not in connector_ids, "Duplicate connector ID")
                connector_ids.add(resource["id"])
                old = config.connectors.get(resource["id"])
                require(old is None or old == resource, "Conflicting connector configuration")
                config.connectors[resource["id"]] = resource
                for value in resource.get("secret_env", {}).values():
                    config.check_secret_reference(value)
                if "credential_ref" in resource:
                    config.check_secret_reference(resource["credential_ref"])
                if resource["kind"] == "mcp-stdio":
                    require(
                        Path(resource["command"]).is_absolute(),
                        "Connector command must be absolute",
                    )
                elif resource["kind"] == "mcp-http":
                    validate_url(resource["url"])
                else:
                    validate_url(resource["base_url"])
                    require(
                        not {key.lower() for key in resource["headers"]}
                        & {"authorization", "cookie", "proxy-authorization"},
                        "Credentials require private references",
                    )
                for operation in resource["operations"]:
                    op_id = operation["operation_id"]
                    require(op_id not in operations, "Duplicate operation ID")
                    require(
                        operation_owners.get(op_id, resource["id"]) == resource["id"],
                        "Operation IDs must be globally unique",
                    )
                    operation_owners[op_id] = resource["id"]
                    operations.add(op_id)
                    schemas = [
                        operation["input_schema"],
                        operation["argument_constraints"],
                        operation["output_schema"],
                    ]
                    for match in operation["task_input_bindings"]:
                        require(
                            match["argument_field"]
                            in operation["input_schema"].get("properties", {}),
                            "Task binding names an unknown operation argument",
                        )
                    if resource["kind"] == "json-get":
                        require(
                            within_url(operation["url"], resource["base_url"]),
                            "Application operation escaped approved base",
                        )
                        validate_url(operation["url"])
                        schemas.append(operation["response_schema"])
                        validate(operation["input_schema"], operation["probe_arguments"])
                        validate(operation["argument_constraints"], operation["probe_arguments"])
                    elif operation["upstream_output_schema"] is not None:
                        schemas.append(operation["upstream_output_schema"])
                    for schema in schemas:
                        check_schema(schema)
            executor_operations[executor["id"]] = operations
        bindings = {digest(binding["contract"]) for binding in document["bindings"]}
        require(len(bindings) == len(document["bindings"]), "Duplicate contract bindings")
        for binding in document["bindings"]:
            require(binding["executor_id"] in executor_ids, "Unknown executor binding")
            require(
                "external.write" not in binding["allowed_effects"],
                "External-write bindings are not implemented",
            )
            for op_id in binding["required_operations"]:
                require(
                    op_id in executor_operations[binding["executor_id"]],
                    "Binding requires an unregistered operation",
                )
                connector = config.connectors[operation_owners[op_id]]
                operation = next(
                    op for op in connector["operations"] if op["operation_id"] == op_id
                )
                require(
                    operation["effect"] in binding["allowed_effects"]
                    and any(
                        rule["resource"] == operation["resource"] and "read" in rule["actions"]
                        for rule in binding["approved_resources"]
                    ),
                    "Binding cannot authorize its required operation",
                )
        for peer in config.peers:
            token = config.secret(peer["credential_ref"], label="Peer credential")
            try:
                peer_workload_identity(token, peer, config.service_id)
            except (jwt.PyJWTError, ValueError):
                raise ConfigurationError(
                    "Peer credential does not match its configured authentication mode or service ID"
                ) from None
        config.policy()
        return config

    @property
    def contracts(self):
        return protocol_contracts()

    @property
    def revision(self):
        service = {
            key: value
            for key, value in self.document["service"].items()
            if key != "deployment_revision"
        }
        return digest(
            {
                "manifest": {**self.document, "service": service},
                "publishers": self.publishers,
                "prompts": self.prompts,
            }
        )

    @property
    def service_id(self):
        return self.document["service"]["id"]

    @property
    def state_root(self):
        return Path(self.document["storage"]["state_root"])

    @property
    def private_root(self):
        return self.state_root / "private"

    @property
    def workspace_root(self):
        return self.state_root / "workspaces"

    @property
    def descriptor_url(self):
        return self.document["service"]["base_url"] + "/descriptor"

    @property
    def auth_mode(self):
        return self.document["authentication"]["mode"]

    @property
    def peers(self):
        return self.document["peers"]

    def secret(self, reference, *, label="Credential"):
        self.check_secret_reference(reference)
        kind, _, name = reference.partition(":")
        if kind == "file" or reference not in self.secrets:
            try:
                value = self.environ.get(name) if kind == "env" else Path(name).read_text().strip()
            except (OSError, UnicodeError):
                raise ConfigurationError(f"{label}: cannot read secret file {name}") from None
            require(
                isinstance(value, str) and bool(value.strip()), f"{label}: missing secret {name}"
            )
            self.secrets[reference] = value
        return self.secrets[reference]

    @staticmethod
    def check_secret_reference(reference):
        kind, separator, name = reference.partition(":")
        require(separator and name and kind in {"env", "file"}, "Unsupported secret reference")
        require(kind != "file" or Path(name).is_absolute(), "Secret file path must be absolute")

    def policy(self):
        path = Path(self.document["authorization"]["policy_file"])
        policy = self.contracts.validate("AuthorizationPolicy", parse_json(path.read_bytes()))
        subjects = [x["subject"] for x in policy["principals"]]
        require(len(subjects) == len(set(subjects)), "Duplicate policy subjects")
        for principal in policy["principals"]:
            names = [r["authorization_ref"] for r in principal["rules"]]
            require(len(names) == len(set(names)), "Duplicate authority reference")
            for rule in principal["rules"]:
                keys = [grant_key(grant) for grant in rule["delegation_grants"]]
                require(len(keys) == len(set(keys)), "Duplicate delegation grant")
        return policy

    def executor(self, binding=None):
        executor_id = binding["executor_id"] if binding else self.document["default_executor"]
        return next(x for x in self.document["executors"] if x["id"] == executor_id)

    def provider_verify(self, executor):
        ca_file = executor.get("provider_ca_file")
        return ssl.create_default_context(cafile=ca_file) if ca_file else True
