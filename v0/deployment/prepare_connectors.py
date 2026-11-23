"""Stage the approved read-only connector deployment without restarting services."""

import copy
import hashlib
import json
import os
from pathlib import Path

from lasa_service.capabilities import reference
from lasa_service.config import Configuration, effective_document, packaged_defaults

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / ".deploy/target"
REMOTE = "/home/yang/Dev/CodeX/LASA/v0/.deploy/target"
STAGE = TARGET / "connector-release"


def read(path):
    return json.loads(path.read_text())


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


def limits(refresh=300, recovery=30):
    return {
        "max_queue": 8,
        "request_timeout_seconds": 25,
        "response_bytes": 1048576,
        "recovery_interval_seconds": recovery,
        "schema_refresh_seconds": refresh,
    }


def operation(name, resource, description, **fields):
    return {
        "operation_id": name,
        "resource": resource,
        "effect": "external.read",
        "description": description,
        "task_input_bindings": [],
        **fields,
    }


def connectors(document_names):
    directory = str(TARGET / "documents/lasa")
    fs = read(TARGET / "connectors/filesystem-schemas.json")["read_text_file"]
    wiki = read(TARGET / "connectors/deepwiki-schema.json")
    empty = {"type": "object", "properties": {}, "additionalProperties": False}
    metadata = {
        "type": "object",
        "properties": {
            "full_name": {"const": "modelcontextprotocol/python-sdk"},
            "description": {"type": ["string", "null"]},
            "default_branch": {"type": "string"},
            "html_url": {"const": "https://github.com/modelcontextprotocol/python-sdk"},
        },
        "required": ["full_name", "description", "default_branch", "html_url"],
    }
    entries = {
        "type": "array",
        "maxItems": 500,
        "items": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "type": {"type": "string"},
                "html_url": {"type": ["string", "null"]},
            },
            "required": ["name", "type", "html_url"],
        },
    }
    github = []
    for name, schema, suffix in [
        ("repository.metadata", metadata, ""),
        ("repository.documents", entries, "/contents/"),
    ]:
        output = copy.deepcopy(schema)
        (output["items"] if output["type"] == "array" else output)["additionalProperties"] = False
        github.append(
            operation(
                name,
                "repository:python-sdk",
                "Read approved public Python SDK repository "
                + ("metadata." if not suffix else "top-level document filenames."),
                input_schema=empty,
                argument_constraints=empty,
                output_schema=output,
                response_schema=schema,
                result_fields=["name", "type", "html_url"]
                if suffix
                else ["full_name", "description", "default_branch", "html_url"],
                probe_arguments={},
                url="https://api.github.com/repos/modelcontextprotocol/python-sdk" + suffix,
            )
        )
    return {
        "connectors": [
            {
                "id": "lasa-documents",
                "kind": "mcp-stdio",
                "command": str(TARGET / "connectors/node-v24.22.3-linux-x64/bin/node"),
                "args": [
                    str(
                        TARGET
                        / "connectors/filesystem/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"
                    ),
                    directory,
                ],
                "secret_env": {},
                "limits": limits(60, 3),
                "operations": [
                    operation(
                        "documents.read",
                        "documents:lasa",
                        "Read the full selected LASA document from the approved documentation collection.",
                        **fs,
                        result_format="text",
                        output_schema={
                            "type": "object",
                            "properties": {"text": {"type": "string"}},
                            "required": ["text"],
                            "additionalProperties": False,
                        },
                        upstream_tool="read_text_file",
                        argument_constraints={
                            "type": "object",
                            "properties": {
                                "path": {
                                    "enum": [directory + "/" + name for name in document_names]
                                }
                            },
                            "required": ["path"],
                            "additionalProperties": False,
                        },
                    )
                ],
            },
            {
                "id": "github-public",
                "kind": "json-get",
                "base_url": "https://api.github.com/repos/modelcontextprotocol/python-sdk",
                "headers": {
                    "User-Agent": "LASA-readonly-verification",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                "limits": limits(600, 60),
                "operations": github,
            },
            {
                "id": "deepwiki-public",
                "kind": "mcp-http",
                "url": "https://mcp.deepwiki.com/mcp",
                "limits": limits(),
                "operations": [
                    operation(
                        "repository.documentation",
                        "documentation:python-sdk",
                        "Read the documentation structure of the approved Python SDK repository.",
                        **wiki,
                        upstream_tool="read_wiki_structure",
                        result_format="structured",
                        output_schema=wiki["upstream_output_schema"],
                        argument_constraints={
                            "properties": {"repoName": {"const": "modelcontextprotocol/python-sdk"}}
                        },
                    )
                ],
            },
        ]
    }


def main():
    os.umask(0o077)
    corpus = TARGET / "documents/lasa"
    corpus.mkdir(parents=True, exist_ok=True)
    documents = [
        ROOT / "README.md",
        ROOT / "design/architecture.md",
        ROOT / "design/capabilities.md",
    ]
    hashes = {}
    for source in documents:
        data = source.read_bytes()
        assert len(data) <= 8192
        data.decode("utf-8")
        destination = corpus / source.name
        if not destination.exists() or destination.read_bytes() != data:
            pending = destination.with_name("." + destination.name + ".pending")
            pending.write_bytes(data)
            pending.chmod(0o444)
            pending.replace(destination)
        hashes[source.name] = {
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "source": str(source.relative_to(ROOT)),
        }
    policy = connectors(list(hashes))
    policy["connectors"][0]["operations"][0]["task_input_bindings"] = [
        {"input_field": "document_id", "argument_field": "path", "comparison": "basename"}
    ]
    policy["connectors"][2]["operations"][0]["task_input_bindings"] = [
        {"input_field": "repository", "argument_field": "repoName", "comparison": "exact"}
    ]
    profiles = [
        ("documents-read", "documents-read-v1", ["documents.read"], ["documents:lasa"]),
        (
            "documents-search",
            "documents-search-v1",
            ["repository.documents"],
            ["repository:python-sdk"],
        ),
        (
            "repository-inspect",
            "repository-inspect-v1",
            ["repository.metadata", "repository.documentation"],
            ["repository:python-sdk", "documentation:python-sdk"],
        ),
    ]
    definitions = [
        read(ROOT / ("design/examples/capability-" + name + ".json")) for name, *_ in profiles
    ]
    refs = [reference(value) for value in definitions]
    for layer in ["layer1", "layer2"]:
        directory = TARGET / layer
        stage = STAGE / layer
        config = read(directory / "config.json")
        executor_id = config.get("default_executor", config["executors"][0]["id"])
        if layer == "layer2":
            executor = next(x for x in config["executors"] if x["id"] == executor_id)
            executor["connectors"] = policy["connectors"]
        effective = effective_document(config, packaged_defaults())
        config["bindings"] = effective["bindings"]
        config["published_contracts"] = [*effective["published_contracts"], *refs]
        if layer == "layer2":
            for ref, (_, _, operations, resources) in zip(refs, profiles, strict=True):
                config["bindings"].append(
                    {
                        "binding_id": "binding-" + ref["id"].rsplit("/", 1)[1],
                        "contract": ref,
                        "executor_id": executor_id,
                        "approved_resources": [
                            {"resource": item, "actions": ["read"]} for item in resources
                        ],
                        "allowed_effects": ["external.read"],
                        "required_operations": operations,
                    }
                )
        authorization = read(directory / config["authorization"]["policy_file"])
        authorization["revision"] = "readonly-connectors-20261119"
        for principal in authorization["principals"]:
            for rule in principal["rules"]:
                rule["contracts"] = config["published_contracts"]
                rule["effects"] = ["workspace.read", "workspace.write", "external.read"]
                rule["resources"] = [
                    rule["resources"][0],
                    *[
                        {"resource": item, "actions": ["read"]}
                        for item in [
                            "documents:lasa",
                            "repository:python-sdk",
                            "documentation:python-sdk",
                        ]
                    ],
                ]
                rule["delegation_grants"] = [
                    {
                        "sender_service_id": config["service"]["id"],
                        "receiver_service_id": peer["expected_service_id"],
                        "contract": contract,
                        "effects": rule["effects"],
                        "resources": rule["resources"],
                        "disclosure_resources": [
                            resource["resource"] for resource in rule["resources"]
                        ],
                    }
                    for peer in config["peers"]
                    for contract in config["published_contracts"]
                ]
        config["authorization"]["policy_file"] = "authorization.json"
        write(stage / "authorization.json", authorization)
        write(stage / "config.json", config)
        checked = copy.deepcopy(config)
        checked["authorization"]["policy_file"] = str(stage / "authorization.json")
        Configuration.from_document(
            checked, base_dir=directory, environ={"LASA_MODEL_API_KEY": "offline-validation"}
        )
    write(ROOT / "verification/connectors-20261119/documents.json", hashes)
    print(
        json.dumps(
            {
                "staged": str(STAGE),
                "documents": list(hashes),
                "connectors": 3,
                "operations": 4,
                "contracts": 5,
            }
        )
    )


if __name__ == "__main__":
    main()
