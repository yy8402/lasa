"""Strict private target configuration and explicit secret references."""

import copy
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .contracts import Contracts, digest, parse_json


def require(condition, message):
    if not condition:
        raise ValueError(message)


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
    secrets: dict = field(default_factory=dict, repr=False)
    connectors: dict = field(default_factory=dict, repr=False)
    executor_operations: dict = field(default_factory=dict, repr=False)

    @classmethod
    def load(cls, path, *, environ=None):
        return cls.from_document(parse_json(Path(path).read_bytes()), environ=environ)

    @classmethod
    def from_document(cls, document, *, environ=None):
        document = copy.deepcopy(document)
        Contracts().validate("Config", document)
        validate_url(document["service"]["base_url"])
        require(
            within_url(document["service"]["descriptor_url"], document["service"]["base_url"]),
            "Descriptor escaped base URL",
        )
        require(
            Path(document["storage"]["data_root"]).is_absolute()
            and Path(document["service"]["workspace_root"]).is_absolute(),
            "Storage paths must be absolute",
        )
        data = Path(document["storage"]["data_root"]).resolve()
        workspace = Path(document["service"]["workspace_root"]).resolve()
        require(
            data != workspace and data not in workspace.parents and workspace not in data.parents,
            "Private and workspace roots overlap",
        )
        require(
            document["authentication"]["audience"] == document["service"]["id"],
            "Invalid receiver audience",
        )
        if "peer" in document:
            peer = document["peer"]
            require(peer["expected_service_id"] != document["service"]["id"], "Self peer")
            require(
                within_url(peer["descriptor_url"], peer["allowed_base_url"]),
                "Peer descriptor escaped configured boundary",
            )
        config = cls(document, dict(os.environ if environ is None else environ))
        executor_ids = [x["id"] for x in document["executors"]]
        require(len(executor_ids) == len(set(executor_ids)), "Duplicate executor IDs")
        operation_owners = {}
        from .connector_schema import check_schema

        for executor in document["executors"]:
            validate_url(executor["provider_base_url"])
            config.secret(executor["credential_ref"])
            config.read_private("RuntimeProfile", executor["runtime_profile_file"])
            policy = config.read_private("ConnectorPolicy", executor["connector_policy_file"])
            operations = set()
            connector_ids = set()
            for resource in policy["connectors"]:
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
                        from .connector_schema import validate

                        validate(operation["input_schema"], operation["probe_arguments"])
                        validate(operation["argument_constraints"], operation["probe_arguments"])
                    elif operation["upstream_output_schema"] is not None:
                        schemas.append(operation["upstream_output_schema"])
                    for schema in schemas:
                        check_schema(schema)
            config.executor_operations[executor["id"]] = operations
        for binding in document["bindings"]:
            require(binding["executor_id"] in executor_ids, "Unknown executor binding")
            require(
                "external.write" not in binding["allowed_effects"],
                "External-write bindings are not implemented",
            )
            for op_id in binding["required_operations"]:
                require(
                    op_id in config.executor_operations[binding["executor_id"]],
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
        if config.peer:
            config.secret(config.peer["credential_ref"])
        config.policy()
        return config

    @property
    def contracts(self):
        return Contracts()

    @property
    def revision(self):
        return digest(self.document)

    @property
    def service_id(self):
        return self.document["service"]["id"]

    @property
    def peer(self):
        return self.document.get("peer")

    def secret(self, reference):
        self.check_secret_reference(reference)
        kind, separator, name = reference.partition(":")
        require(separator and kind in {"env", "file"}, "Unsupported secret reference")
        if kind == "file" or reference not in self.secrets:
            value = self.environ.get(name) if kind == "env" else Path(name).read_text().strip()
            require(isinstance(value, str) and bool(value), "Missing secret")
            self.secrets[reference] = value
        return self.secrets[reference]

    @staticmethod
    def check_secret_reference(reference):
        kind, separator, name = reference.partition(":")
        require(separator and name and kind in {"env", "file"}, "Unsupported secret reference")
        require(kind != "file" or Path(name).is_absolute(), "Secret file path must be absolute")

    def read_private(self, name, path):
        return Contracts().validate(name, parse_json(Path(path).read_bytes()))

    def policy(self):
        policy = self.read_private(
            "AuthorizationPolicy", self.document["authorization"]["policy_file"]
        )
        subjects = [x["subject"] for x in policy["principals"]]
        require(len(subjects) == len(set(subjects)), "Duplicate policy subjects")
        for principal in policy["principals"]:
            names = [r["authorization_ref"] for r in principal["rules"]]
            require(len(names) == len(set(names)), "Duplicate authority reference")
        return policy

    def executor(self, binding=None):
        executor_id = binding["executor_id"] if binding else self.document["executors"][0]["id"]
        return next(x for x in self.document["executors"] if x["id"] == executor_id)
