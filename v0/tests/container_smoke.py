"""Verify an installed LASA image using isolated services and local HTTPS fixtures."""

import argparse
import copy
import hashlib
import json
import os
import secrets
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import Response

from lasa_service.auth import static_token_digest
from lasa_service.config import builtin_capabilities, local_bindings, reference
from lasa_service.contracts import digest
from lasa_service.deployment import GATEWAY_ID as DLP_GATEWAY_ID
from lasa_service.deployment import POLICY_REVISION as DLP_REVISION
from lasa_service.deployment import PRESIDIO_IMAGE, DockerDeployment

from .http_helpers import certificate
from .protocol_helpers import sse_final, sse_tool

ROOT = Path(__file__).resolve().parents[1]
PEERS = {"review": "design.review", "attempt": "task.attempt"}
MODEL_KEY = "local-responses-fixture"
GATEWAY_KEY = "local-inspection-fixture"
SOURCE_KEY = "local-connector-fixture"
GATEWAY_ID = "smoke-local-inspection"
DLP_PROFILE = "local-text-dlp"
DLP_ARTIFACT_PROFILE = "local-artifact-dlp"
DLP_MODES = ("enforce", "observe")
DLP_STREAMS = {
    "caller-intake": ("caller", "caller.request", "task"),
    "caller-question": ("caller", "caller.response", "clarification"),
    "result-release": ("caller", "candidate.release", "result"),
    "artifact-release": ("caller", "candidate.release", "artifact"),
    "model-request": ("model", "reasoning.request", "execution"),
    "model-response": ("model", "reasoning.response", "execution"),
    "delegate-request": ("delegates", "delegation.request", "task"),
    "delegate-result": ("delegates", "delegation.response", "result"),
    "connector-request": ("connectors", "tool.invoke", "arguments"),
    "connector-result": ("connectors", "tool.result", "result"),
}
DLP_GROUPS = tuple(dict.fromkeys(group for group, _, _ in DLP_STREAMS.values()))
DLP_TARGETS = {f"{group}-{mode}": (group, mode) for mode in DLP_MODES for group in DLP_GROUPS}
DLP_CASES = {
    "clean": "Synthetic review text for the local DLP smoke test.",
    "pii_detected": "lasa-dlp-synthetic@example.com",
    "credential_detected": "ghp_3Q1vZHfJ2CW8K6M0RwtPN5yAE7LbUmGXkT9s",  # Synthetic.
}
PROFILE_REVISIONS = {
    "standard": "standard-v1",
    "artifacts": "artifact-v2",
    "document": "document-v3",
}
MARKERS = {
    "caller": "SMOKE_CALLER_BLOCK",
    "model_request": "SMOKE_MODEL_REQUEST_BLOCK",
    "model_response": "SMOKE_MODEL_RESPONSE_BLOCK",
    "release": "SMOKE_FINAL_RELEASE_BLOCK",
    "invalid_verdict": "SMOKE_INVALID_GATEWAY_VERDICT",
    "delegation_request": "SMOKE_DELEGATE_REQUEST_BLOCK",
    "delegation_response": "SMOKE_DELEGATE_RESPONSE_BLOCK",
    "connector_argument": "blocked-argument.md",
    "connector_result": "SMOKE_CONNECTOR_RESULT_BLOCK",
    "artifact": "SMOKE_ARTIFACT_RELEASE_BLOCK",
    "wrong_revision": "SMOKE_WRONG_PROFILE_REVISION",
    "observe": "SMOKE_MODEL_OBSERVE_DENY",
    "delegate_off": "SMOKE_DELEGATE_RESPONSE_OFF",
    "connector_off": "SMOKE_CONNECTOR_RESPONSE_OFF",
}
CHANNEL_DENIALS = {
    "caller.request": ("caller",),
    "reasoning.request": ("model_request",),
    "reasoning.response": ("model_response", "observe"),
    "candidate.release": ("release", "artifact"),
    "delegation.request": ("delegation_request",),
    "delegation.response": ("delegation_response", "delegate_off"),
    "tool.invoke": ("connector_argument",),
    "tool.result": ("connector_result", "connector_off"),
}
GATEWAY_FIELDS = {
    "caller.request": {"input", "attachments", "dependencies", "answer"},
    "caller.response": {"question", "content"},
    "reasoning.request": {"input"},
    "reasoning.response": {"output", "deltas"},
    "candidate.release": {"output", "text"},
    "delegation.request": {"input", "dependencies", "attachments"},
    "delegation.response": {"output", "text", "content"},
    "tool.invoke": {"arguments"},
    "tool.result": {"output"},
}
PORT = 8443
LAUNCHER_SOCKET = "/run/lasa/launcher.sock"


def origin(name):
    return f"https://lasa-{name}:{PORT}"


def base(name):
    return origin(name) + "/lasa/v1"


def read(path):
    return json.loads(path.read_text())


def save(path, document):
    path.write_text(json.dumps(document, indent=2) + "\n")


def docker(*args, timeout=30, check=True):
    result = subprocess.run(
        ["docker", *map(str, args)], capture_output=True, text=True, timeout=timeout, check=False
    )
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    if args[0] == "logs" and result.returncode:
        return ""
    return (result.stdout + result.stderr if args[0] == "logs" else result.stdout).strip()


def mount(source, target=None, *, read_only=True):
    return f"type=bind,source={source},target={target or source}" + (
        ",readonly" if read_only else ""
    )


def configure(root, name, namespace, *, trusted_parent=None):
    directory = root / name
    identity = f"https://identity.lasa.test/services/{namespace}"
    command = [
        sys.executable,
        str(ROOT / "tools/create_development_config.py"),
        "--output",
        str(directory),
        "--base-url",
        base(name),
        "--service-id",
        f"{identity}/{name}",
        "--launcher-socket",
        LAUNCHER_SOCKET,
        "--listen-port",
        str(PORT),
    ]
    if trusted_parent:
        command += ["--trusted-parent-id", f"{identity}/{trusted_parent}"]
    subprocess.run(command, check=True, timeout=10)
    cert, key = certificate(directory, dns_name=f"lasa-{name}")
    config = read(directory / "config.json")
    if name == "review":
        registry = {"tokens": []}
        for subject, filename in (
            ("operator", "operator-token.txt"),
            ("peer-parent", "peer-token.txt"),
        ):
            token = secrets.token_urlsafe(32)
            (directory / filename).write_text(token + "\n")
            registry["tokens"].append(
                {
                    "subject": subject,
                    "digest": static_token_digest(config["service"]["id"], token),
                    "expires_at": int(time.time()) + 3600,
                }
            )
        save(directory / "static-tokens.json", registry)
        config["authentication"] = {"mode": "static_token"}
    config["storage"].update(
        state_root=str(root / "state" / name),
        listen_host="0.0.0.0",
        tls={"certificate_file": str(cert), "key_file": str(key)},
    )
    config["runtime"]["startup_timeout_ms"] = 25000
    for executor in config["executors"]:
        executor.update(
            provider_base_url=origin("model") + "/v1", provider_ca_file=str(root / "ca.pem")
        )
    return config


def configure_content(root, name, configs):
    config = configs[name]
    enforce = {"mode": "enforce", "profile": "standard"}
    observe = {"mode": "observe", "profile": "standard"}
    release = {**enforce, "artifact_profile": "artifacts"}
    bindings = {
        "caller": {"request": enforce, "response": release},
        "model": {"request": enforce, "response": observe if name == "attempt" else enforce},
    }
    if name == "parent":
        review = configs["review"]["service"]["id"]
        bindings["delegates"] = {
            "request": enforce,
            "response": release,
            "overrides": [{"service_id": review, "response": {"mode": "off"}}],
        }
    if name == "review":
        bindings["connectors"] = {
            "request": enforce,
            "response": observe,
            "overrides": [
                {
                    "connector_id": "fixture-source",
                    "operation_id": "documents.read",
                    "response": {"mode": "enforce", "profile": "document"},
                },
                {"connector_id": "fixture-source", "response": {"mode": "off"}},
            ],
        }
    config["content_security"] = {
        "inspection_profiles": [
            {
                "id": profile,
                "gateway_id": GATEWAY_ID,
                "url": origin("inspection") + "/inspect/" + profile,
                "policy_revision": revision,
                "credential_ref": "env:LASA_GATEWAY_KEY",
                "ca_file": str(root / "ca.pem"),
                "region": "isolated",
                "retention": "fixture-only",
            }
            for profile, revision in PROFILE_REVISIONS.items()
        ],
        "bindings": bindings,
    }
    if name == "review":
        configure_connectors(root, name, config)


def configure_connectors(root, name, config):
    definitions = {
        contract: reference(builtin_capabilities()[contract][0])
        for contract in ("documents.read", "documents.search")
    }
    config["published_contracts"] = ["design.review", "task.attempt", *definitions]
    config["bindings"] = [
        {
            "binding_id": "fixture-review",
            "contract": reference(builtin_capabilities()["design.review"][0]),
            "executor_id": config["executors"][0]["id"],
            "approved_resources": [{"resource": "workspace:self", "actions": ["read"]}],
            "allowed_effects": ["workspace.read"],
            "required_operations": [],
        },
        *[
            {
                "binding_id": "fixture-" + contract,
                "contract": definitions[contract],
                "executor_id": config["executors"][0]["id"],
                "approved_resources": [{"resource": resource, "actions": ["read"]}],
                "allowed_effects": ["external.read"],
                "required_operations": [contract],
            }
            for contract, resource in (
                ("documents.read", "documents:lasa"),
                ("documents.search", "repository:python-sdk"),
            )
        ],
    ]
    input_schema = {
        "type": "object",
        "properties": {"report_id": {"type": "string"}},
        "required": ["report_id"],
        "additionalProperties": False,
    }
    output_schema = {
        "type": "object",
        "properties": {"text": {"type": "string"}},
        "required": ["text"],
        "additionalProperties": False,
    }
    index_fields = {key: {"type": "string"} for key in ("name", "type", "html_url")}
    index_schema = {
        "type": "array",
        "items": {
            "type": "object",
            "properties": index_fields,
            "required": list(index_fields),
            "additionalProperties": False,
        },
    }
    source_url = origin("source") + "/documents"
    config["executors"][0]["connectors"] = [
        {
            "id": "fixture-source",
            "kind": "json-get",
            "base_url": source_url,
            "headers": {},
            "credential_ref": "env:LASA_SOURCE_KEY",
            "ca_file": str(root / "ca.pem"),
            "limits": {
                "max_queue": 4,
                "request_timeout_seconds": 4,
                "response_bytes": 65536,
                "recovery_interval_seconds": 1,
                "schema_refresh_seconds": 60,
            },
            "operations": [
                {
                    "operation_id": "documents.read",
                    "description": "Read a fixture document.",
                    "task_input_bindings": [
                        {
                            "input_field": "document_id",
                            "argument_field": "report_id",
                            "comparison": "exact",
                        }
                    ],
                    "effect": "external.read",
                    "resource": "documents:lasa",
                    "url": source_url,
                    "input_schema": input_schema,
                    "argument_constraints": {},
                    "output_schema": output_schema,
                    "response_schema": output_schema,
                    "result_fields": ["text"],
                    "probe_arguments": {"report_id": "probe.md"},
                },
                {
                    "operation_id": "documents.search",
                    "description": "Read the fixture document index.",
                    "task_input_bindings": [
                        {"input_field": "query", "argument_field": "query", "comparison": "exact"},
                    ],
                    "effect": "external.read",
                    "resource": "repository:python-sdk",
                    "url": source_url + "/index",
                    "input_schema": {
                        "type": "object",
                        "properties": {"query": {"type": "string"}},
                        "required": ["query"],
                        "additionalProperties": False,
                    },
                    "argument_constraints": {},
                    "output_schema": index_schema,
                    "response_schema": index_schema,
                    "result_fields": list(index_fields),
                    "probe_arguments": {"query": "probe"},
                },
            ],
        }
    ]
    policy_file = root / name / "authorization.json"
    policy = read(policy_file)
    for principal in policy["principals"]:
        for rule in principal["rules"]:
            rule["contracts"].extend(definitions.values())
            rule["effects"].append("external.read")
            rule["resources"].extend(
                {"resource": resource, "actions": ["read"]}
                for resource in ("documents:lasa", "repository:python-sdk")
            )
    save(policy_file, policy)


def configure_dlp(root, name, config, group, mode):
    token_file = root / name / "inspection-token.txt"
    token_file.write_bytes((root / "inspection" / "token.txt").read_bytes())
    token_file.chmod(0o600)
    rule = {"mode": mode, "profile": DLP_PROFILE}
    response = {**rule, "artifact_profile": DLP_ARTIFACT_PROFILE} if group == "caller" else rule
    config["content_security"] = {
        "inspection_profiles": [
            {
                "id": profile,
                "gateway_id": DLP_GATEWAY_ID,
                "url": origin("inspection") + "/inspect",
                "policy_revision": DLP_REVISION,
                "credential_ref": "file:" + str(token_file),
                "ca_file": str(root / "ca.pem"),
                "region": "isolated",
                "retention": "metadata-only",
            }
            for profile in (DLP_PROFILE, DLP_ARTIFACT_PROFILE)
        ],
        "bindings": {group: {"request": rule, "response": response}},
    }
    if group in {"caller", "connectors"}:
        configure_connectors(root, name, config)


def configure_recovery_contract(root, name, config):
    definition = copy.deepcopy(builtin_capabilities()["task.attempt"][0])
    original = reference(definition)
    definition["version"] = "1.0.1"
    definition["input_schema"]["properties"]["context"]["x-lasa-optional-context"] = True
    recovered = reference(definition)
    directory = root / name
    registry = directory / "recovery-contracts.json"
    save(registry, [definition])
    config["contract_publishers"] = [
        {
            "namespace": definition["id"].rsplit("/", 1)[0] + "/",
            "trusted_registry_file": str(registry),
        }
    ]
    config["verifiers"] = [{"contract": recovered, "verifier_id": "task-attempt-v1"}]
    contracts = [reference(builtin_capabilities()["design.review"][0]), original]
    config["published_contracts"] = [contracts[0], recovered]
    config["bindings"] = local_bindings(contracts, config["executors"][0]["id"])
    for binding in config["bindings"]:
        if binding["contract"] == original:
            binding["contract"] = recovered
    path = directory / "authorization.json"
    policy = read(path)
    for principal in policy["principals"]:
        for rule in principal["rules"]:
            rule["contracts"] = [recovered if ref == original else ref for ref in rule["contracts"]]
    save(path, policy)


def authorize(root, configs, parent_name="parent", peers=PEERS):
    parent = configs[parent_name]
    policy_path = root / parent_name / "authorization.json"
    policy = read(policy_path)
    rule = policy["principals"][0]["rules"][0]
    parent["routing"]["unclaimed_peer_fallback"] = "reject"
    for name, contract_name in peers.items():
        receiver = configs[name]["service"]["id"]
        token_path = root / parent_name / f"{name}-token.txt"
        token_path.write_bytes((root / name / "peer-token.txt").read_bytes())
        token_path.chmod(0o600)
        parent["peers"].append(
            {
                "descriptor_url": base(name) + "/descriptor",
                "expected_service_id": receiver,
                "allowed_base_url": base(name),
                "credential_ref": "file:" + str(token_path),
                "authorization_ref": "default",
                "request_timeout_seconds": 5,
                "ca_file": str(root / "ca.pem"),
            }
        )
        if name == "review":
            parent["peers"][-1]["authentication"] = {
                "mode": "static_token",
                "subject": "peer-parent",
            }
        rule["delegation_grants"].append(
            {
                "sender_service_id": parent["service"]["id"],
                "receiver_service_id": receiver,
                "contract": next(
                    ref for ref in rule["contracts"] if ref["id"].endswith("/" + contract_name)
                ),
                "effects": rule["effects"],
                "resources": rule["resources"],
                "disclosure_resources": ["workspace:self"],
            }
        )
    save(policy_path, policy)


def payload(body):
    for item in reversed(body["input"]):
        if item.get("role") != "user":
            continue
        for part in item["content"]:
            try:
                value = json.loads(part.get("text", ""))
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict) and ("request" in value or "outcome_contract" in value):
                return value
    raise ValueError("Fixture could not find the LASA model payload")


def dlp_fixture_text(label, scenario):
    prefix = f"dlp-{scenario}-"
    if label.startswith(prefix):
        return DLP_CASES.get(label.removeprefix(prefix).removesuffix(".md"))
    return None


def propose_plan(context):
    request = context["request"]
    requirements = [requirement["requirement_id"] for requirement in context["requirements"]]
    objective = request["input"]["objective"]
    if objective.startswith(("dlp-delegate-", "dlp-recovery-delegate-")):
        return {
            "steps": [
                {
                    "step_id": "step-delegate",
                    "requirement_ids": requirements,
                    "depends_on": [],
                    "contract_digest": request["contract"]["digest"],
                    "input_json": json.dumps(request["input"]),
                    "local_assessment": "sufficient",
                    "assessment_summary": "Exercise one authenticated delegate.",
                }
            ]
        }
    review = next(
        d
        for d, contract in context["contracts"].items()
        if contract["id"].endswith("/design.review")
    )
    review_inputs = {
        "design": MARKERS["delegate_off"],
        "criteria": [{"id": "selection", "description": "Check bounded peer selection."}],
    }
    if MARKERS["delegation_request"] in objective:
        review_inputs["design"] = MARKERS["delegation_request"]
    steps = [
        ("step-review", review, review_inputs, []),
        ("step-attempt", request["contract"]["digest"], request["input"], ["step-review"]),
    ]
    return {
        "steps": [
            {
                "step_id": step,
                "requirement_ids": requirements,
                "depends_on": dependencies,
                "contract_digest": contract,
                "input_json": json.dumps(inputs),
                "local_assessment": "sufficient",
                "assessment_summary": "Deterministic container fixture.",
            }
            for step, contract, inputs, dependencies in steps
        ]
    }


def execute_fixture(context):
    contract = context["outcome_contract"]
    inputs = context["input"]
    if contract["id"].endswith(("/documents.read", "/documents.search")):
        output = {"ready_for_verification": True}
    elif contract["id"].endswith("/design.review"):
        fixture_text = dlp_fixture_text(inputs["design"], "result-release") or next(
            (
                MARKERS[key]
                for key in ("model_response", "observe", "delegate_off")
                if MARKERS[key] in inputs["design"]
            ),
            "The receivers are distinct.",
        )
        output = {
            "findings": [],
            "coverage": [
                {
                    "criterion_id": item["id"],
                    "disposition": "reviewed",
                    "evidence": fixture_text,
                }
                for item in inputs["criteria"]
            ],
        }
    else:
        objective = inputs["objective"]
        flagged = next(
            (
                MARKERS[key]
                for key in ("release", "delegation_response")
                if MARKERS[key] in objective
            ),
            None,
        )
        if marker := dlp_fixture_text(objective, "delegate-result"):
            summary = marker
        elif objective.startswith(
            ("dlp-model-response-", "dlp-delegate-request-", "dlp-recovery-")
        ):
            summary = "The requested execution completed."
        elif flagged:
            summary = flagged
        elif results := context.get("verified_step_results"):
            assert (
                results["step-attempt"]["output"]["summary"]
                == "The worker consumed the verified review."
            )
            summary = "The parent integrated both verified peer results."
        else:
            assert (
                context["delegated_dependencies"]["step-review"]["coverage"][0]["criterion_id"]
                == "selection"
            )
            summary = "The worker consumed the verified review."
        output = {
            "disposition": "fulfilled",
            "summary": summary,
            "requirement_evidence": [
                {"id": item["id"], "evidence": summary} for item in inputs["requirements"]
            ],
        }
    return {
        "output": output,
        "artifact_ids": [],
        "evidence": [
            {
                "criterion_id": item["id"],
                "disposition": "passed",
                "summary": "Fixture evidence.",
                "artifact_ids": [],
            }
            for item in contract["postconditions"]
        ],
    }


def capture(directory, document):
    with (directory / "traffic.jsonl").open("a") as file:
        file.write(json.dumps(document, separators=(",", ":")) + "\n")


def serve_fixture(directory):
    app = FastAPI()
    transient_sent = False
    recovery_faults = set()

    @app.post("/recovery-inspect")
    async def recovery_inspect(request: Request):
        body = await request.json()
        context = json.dumps(body["content"])
        fault = "forwarded"
        if body["channel"] == "reasoning.request" and body["purpose"] == "execution":
            if "dlp-recovery-scanner-persistent" in context:
                fault = "persistent_503"
            elif "dlp-recovery-scanner-transient" in context and "transient" not in recovery_faults:
                recovery_faults.add("transient")
                fault = "transient_503"
            elif "dlp-recovery-scanner-invalid" in context:
                fault = "invalid_digest"
        with (directory / "recovery-shim.jsonl").open("a") as output:
            output.write(
                json.dumps({"inspection_id": body["inspection_id"], "fault": fault}) + "\n"
            )
        if fault.endswith("_503"):
            return Response(status_code=503)
        ca = ssl.create_default_context(cafile=directory.parent / "ca.pem")
        async with httpx.AsyncClient(verify=ca, trust_env=False, timeout=3) as client:
            response = await client.post(
                origin("inspection") + "/inspect",
                content=await request.body(),
                headers={
                    "Authorization": request.headers["Authorization"],
                    "Content-Type": "application/json",
                },
            )
        if fault == "invalid_digest" and response.status_code == 200:
            return {**response.json(), "inspection_digest": "sha256:" + "0" * 64}
        return Response(
            response.content, status_code=response.status_code, media_type="application/json"
        )

    @app.post("/inspect/{profile}")
    async def inspect_content(request: Request, profile: str):
        nonlocal transient_sent
        assert request.headers["Authorization"] == "Bearer " + GATEWAY_KEY
        body = await request.json()
        revision = PROFILE_REVISIONS[profile]
        capture(directory, {"fixture_profile": profile, **body})
        assert body["gateway_policy_revision"] == revision
        assert body["inspection_digest"] == digest(body["content"])
        assert set(body["content"]) <= GATEWAY_FIELDS[body["channel"]]
        markers = json.dumps(body["content"])
        if (
            not transient_sent
            and body["channel"] == "reasoning.request"
            and "SMOKE_TRANSIENT_INSPECTION" in markers
        ):
            transient_sent = True
            return Response(status_code=503)
        blocked = any(MARKERS[key] in markers for key in CHANNEL_DENIALS.get(body["channel"], ()))
        return {
            "version": "1",
            "gateway_id": GATEWAY_ID,
            "gateway_policy_revision": (
                PROFILE_REVISIONS["artifacts"]
                if body["channel"] == "reasoning.request" and MARKERS["wrong_revision"] in markers
                else revision
            ),
            "inspection_id": body["inspection_id"],
            "verdict": "hard_deny" if blocked else "permit",
            "reason_codes": ["fixture-denial"] if blocked else [],
            "inspection_digest": (
                "sha256:" + "0" * 64
                if body["channel"] == "reasoning.request" and MARKERS["invalid_verdict"] in markers
                else body["inspection_digest"]
            ),
        }

    @app.get("/documents")
    async def source(request: Request, report_id: str, note: str | None = None):
        assert request.headers["Authorization"] == "Bearer " + SOURCE_KEY
        capture(directory, {"report_id": report_id, **({"note": note} if note is not None else {})})
        return {
            "text": dlp_fixture_text(report_id, "connector-result")
            or dlp_fixture_text(report_id, "artifact-release")
            or {
                "blocked-result.md": MARKERS["connector_result"],
                "blocked-artifact.md": MARKERS["artifact"],
            }.get(report_id, "An allowed HTTPS source record."),
        }

    @app.get("/documents/index")
    async def source_index(request: Request, query: str):
        assert request.headers["Authorization"] == "Bearer " + SOURCE_KEY
        capture(directory, {"query": query})
        name = (query if query in DLP_CASES.values() else MARKERS["connector_off"]) + ".md"
        return [
            {
                "name": name,
                "type": "file",
                "html_url": "https://github.com/modelcontextprotocol/python-sdk/blob/main/" + name,
            }
        ]

    @app.post("/{prefix:path}/responses")
    async def respond(request: Request, prefix: str):
        assert request.headers["Authorization"] == "Bearer " + MODEL_KEY
        receiver, _, version = prefix.rpartition("/")
        assert version == "v1"
        body = await request.json()
        capture(directory, {"fixture_receiver": receiver, **body} if receiver else body)
        if body.get("stream"):
            context = payload(body)
            inputs = context["input"]
            contract = context["outcome_contract"]["id"]
            first_turn = not any(
                item.get("type") == "function_call_output" for item in body["input"]
            )
            if first_turn and contract.endswith("/documents.read"):
                arguments = {"report_id": inputs["document_id"]}
                if note := dlp_fixture_text(inputs["document_id"], "recovery-connector"):
                    arguments["note"] = note
                data = sse_tool("documents_read", arguments, 1)
            elif first_turn and contract.endswith("/documents.search"):
                data = sse_tool("documents_search", {"query": inputs["query"]}, 1)
            elif first_turn and (
                question := dlp_fixture_text(inputs.get("design", ""), "caller-question")
            ):
                data = sse_tool("lasa_request_input", {"message": question}, 1)
            elif first_turn and (
                text := dlp_fixture_text(inputs.get("objective", ""), "model-response")
            ):
                data = sse_tool("workspace_write", {"relative_path": "effect.txt", "text": text}, 1)
            elif (
                first_turn
                and any(
                    MARKERS[key] in inputs.get("objective", "")
                    for key in ("release", "delegation_response")
                )
                or (first_turn and dlp_fixture_text(inputs.get("objective", ""), "delegate-result"))
            ):
                data = sse_tool(
                    "workspace_write", {"relative_path": "effect.txt", "text": "confirmed"}, 1
                )
            else:
                data = sse_final(json.dumps(execute_fixture(context)), 2 if not first_turn else 1)
            return Response(data, media_type="text/event-stream")
        message_format = body["text"]["format"]
        if message_format["name"] == "lasa_verification":
            developer, context, candidate = body["input"]
            assert [developer["role"], context["role"], candidate["role"]] == [
                "developer",
                "user",
                "user",
            ]
            assert (
                "The last user message is the complete candidate_output"
                in developer["content"][0]["text"]
            )
            context = json.loads(context["content"][0]["text"])
            candidate = json.loads(candidate["content"][0]["text"])
            assert "candidate_output" not in context and "output_schema" not in context["contract"]
            if context["contract"]["ref"]["id"].endswith("/design.review"):
                assert set(candidate) == {"coverage", "findings"}
            elif context["contract"]["ref"]["id"].endswith("/task.attempt"):
                assert candidate["disposition"] == "fulfilled"
                material = context["trusted_execution_evidence"]
                if candidate["summary"] != MARKERS["release"] and not context["input"][
                    "objective"
                ].startswith("dlp-"):
                    assert material["dependencies"]
                if material["step_id"] is None and len(material.get("dependencies", ())) == 2:
                    review_input, attempt_input = material["step_inputs"]
                    assert review_input["step_id"] == "step-review"
                    assert review_input["content"]["criteria"][0]["id"] == "selection"
                    assert attempt_input["step_id"] == "step-attempt"
                    assert attempt_input["content"] == context["input"]
        schema = message_format["schema"]
        answer = (
            propose_plan(payload(body))
            if "steps" in schema["properties"]
            else {"passed": True, "reason": "Deterministic verification fixture."}
        )
        return {
            "output": [
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": json.dumps(answer)}],
                }
            ],
            "usage": {"input_tokens": 10, "output_tokens": 10, "total_tokens": 20},
        }

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=PORT,
        ssl_certfile=str(directory / "certificate.pem"),
        ssl_keyfile=str(directory / "key.pem"),
        access_log=False,
    )


def read_traffic(root, name):
    path = root / name / "traffic.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def state_rows(root, name, statement, arguments=()):
    path = root / "state" / name / "private" / "tasks.sqlite3"
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as db:
        return db.execute(statement, arguments).fetchall()


def checked_task(
    client, root, name, profile, inputs, scenario, *, intake_denied=False, answer_question=None
):
    token = (root / name / "operator-token.txt").read_text().strip()
    headers = {"Authorization": "Bearer " + token}
    catalog = client.get(base(name) + "/capabilities", headers=headers).raise_for_status().json()
    offer = next(x for x in catalog["offers"] if x["contract"]["id"].endswith("/" + profile))
    session_key = "session-" + scenario
    task_key = "task-" + scenario
    session = (
        client.post(
            base(name) + "/sessions",
            json={"operation_id": session_key},
            headers={**headers, "Idempotency-Key": session_key},
        )
        .raise_for_status()
        .json()
    )
    payload = {
        "operation_id": task_key,
        "selection": {field: offer[field] for field in ("contract", "offer_id", "catalog_view")}
        | {"offer_revision": offer["revision"]},
        "input": inputs,
        "requested_limits": {
            "budget": offer["max_budget"],
            "max_hops": min(1, offer["max_hops"]),
            "deadline": (datetime.now(UTC) + timedelta(seconds=160)).isoformat(),
        },
        "authorization_ref": offer["authorization_ref"],
        "diagnostics": "metadata",
    }
    response = client.post(
        base(name) + f"/sessions/{session['session_id']}/tasks",
        json=payload,
        headers={**headers, "Idempotency-Key": task_key},
    )
    if intake_denied:
        assert response.status_code == 403 and response.json()["code"] == "disclosure_denied", (
            response.text
        )
        return None, response.json(), headers
    location = response.raise_for_status().headers["Location"]
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        current = client.get(location, headers=headers).raise_for_status()
        task = current.json()
        if task["status"] in {"completed", "rejected", "failed", "indeterminate", "cancelled"}:
            return location, task, headers
        if task["status"] == "awaiting_input" and answer_question:
            question = task["question"]
            answer = answer_question(question["prompt"])
            answer_key = "answer-" + scenario
            client.post(
                location + "/inputs",
                headers={
                    **headers,
                    "Idempotency-Key": answer_key,
                    "If-Match": current.headers["ETag"],
                },
                json={
                    "operation_id": answer_key,
                    "question_id": question["question_id"],
                    "question_revision": question["revision"],
                    "answer": answer,
                },
            ).raise_for_status()
            answer_question = None
        time.sleep(0.1)
    raise TimeoutError(f"Fixture task {scenario} did not settle")


def attempt_input(objective):
    return {
        "objective": objective,
        "requirements": [
            {
                "id": "fixture-effect",
                "description": "Exercise the controlled boundary.",
                "acceptance": ["Record the operation outcome."],
            }
        ],
    }


def inspection_decisions(root, receiver, task_id, channel):
    return [
        json.loads(row)
        for (row,) in state_rows(
            root,
            receiver,
            "SELECT document FROM audit WHERE kind='content_decision' AND task_id IS ? "
            "AND json_extract(document,'$.channel')=?",
            (task_id, channel),
        )
    ]


def verify_content(client, root):
    outcomes = {}
    marker = "SMOKE_TRANSIENT_INSPECTION"
    model_start = len(read_traffic(root, "model"))
    _, recovered, _ = checked_task(
        client,
        root,
        "review",
        "design.review",
        {
            "design": marker,
            "criteria": [{"id": "fixture", "description": "Check transient recovery."}],
        },
        "transient-inspection",
    )
    assert recovered["status"] == "completed", recovered
    decisions = inspection_decisions(root, "review", recovered["task_id"], "reasoning.request")
    (failed,) = [row for row in decisions if row["reason_code"] == "gateway_transient_failure"]
    (retried,) = [
        row
        for row in decisions
        if row.get("inspection_id") != failed["inspection_id"]
        and row.get("inspection_digest") == failed["inspection_digest"]
        and row["reason_code"] == "gateway_permit"
    ]
    assert failed["transfer_id"] == retried["transfer_id"]
    dispatched = [
        row
        for row in read_traffic(root, "model")[model_start:]
        if row.get("stream") and marker in json.dumps(row)
    ]
    assert len(dispatched) == 1, dispatched
    outcomes["transient_inspection"] = {"retries": 1, "model_dispatches": 1}
    for scenario in (
        "caller",
        "model_request",
        "model_response",
        "release",
        "invalid_verdict",
        "wrong_revision",
    ):
        if scenario == "release":
            inputs = attempt_input(MARKERS[scenario])
            name, profile = "attempt", "task.attempt"
        else:
            inputs = {
                "design": MARKERS[scenario],
                "criteria": [{"id": "fixture", "description": "Check the controlled boundary."}],
            }
            name, profile = "review", "design.review"
        location, task, headers = checked_task(
            client, root, name, profile, inputs, scenario, intake_denied=scenario == "caller"
        )
        problem = task if scenario == "caller" else task["problem"]
        expected = (
            "content_gateway_unavailable"
            if scenario in {"invalid_verdict", "wrong_revision"}
            else "disclosure_denied"
        )
        assert problem["code"] == expected and "result" not in task, (scenario, task)
        outcomes[scenario] = problem["code"]
        if scenario == "release":
            assert problem["effect_disposition"] == "known", task
            control = (
                client.get(location + "?view=control", headers=headers).raise_for_status().json()
            )
            assert control["effect_disposition"] == "known" and control["usage"]["tool_calls"] == 1

    for scenario in ("delegation_request", "delegation_response"):
        receiver = "review" if scenario == "delegation_request" else "attempt"
        child_tasks = state_rows(root, receiver, "SELECT count(*) FROM tasks")[0][0]
        inputs = attempt_input(MARKERS[scenario])
        location, task, headers = checked_task(
            client, root, "parent", "task.attempt", inputs, scenario
        )
        assert task["problem"]["code"] == "disclosure_denied" and "result" not in task, task
        admitted = state_rows(root, receiver, "SELECT count(*) FROM tasks")[0][0] - child_tasks
        if scenario == "delegation_request":
            assert admitted == 0 and task["problem"]["effect_disposition"] == "none"
        else:
            assert admitted == 1 and task["problem"]["effect_disposition"] == "known", task
            control = (
                client.get(location + "?view=control", headers=headers).raise_for_status().json()
            )
            assert control["usage"]["tool_calls"] == 1
        outcomes[scenario] = {"blocked": True, "child_tasks_admitted": admitted}

    _, observed_task, _ = checked_task(
        client,
        root,
        "attempt",
        "design.review",
        {
            "design": MARKERS["observe"],
            "criteria": [
                {"id": "fixture", "description": "Exercise an observation-only verdict."},
            ],
        },
        "observe",
    )
    assert observed_task["status"] == "completed", observed_task
    assert observed_task["result"]["output"]["coverage"][0]["evidence"] == MARKERS["observe"]
    observed = inspection_decisions(root, "attempt", observed_task["task_id"], "reasoning.response")
    assert any(
        record["mode"] == "observe"
        and record["reason_code"] == "gateway_hard_deny"
        and record["profile_id"] == "standard"
        for record in observed
    )
    outcomes["observe"] = {"status": "completed", "gateway_verdict": "hard_deny"}

    query = MARKERS["connector_off"]
    before = sum(event.get("query") == query for event in read_traffic(root, "source"))
    _, index_task, _ = checked_task(
        client,
        root,
        "review",
        "documents.search",
        {"collection": "python-sdk-root", "query": query, "limit": 1},
        "connector_off",
    )
    assert index_task["status"] == "completed", index_task
    assert index_task["result"]["output"]["matches"][0]["document_id"] == query + ".md"
    assert sum(event.get("query") == query for event in read_traffic(root, "source")) - before == 1
    index_records = inspection_decisions(root, "review", index_task["task_id"], "tool.result")
    assert len(index_records) == 1 and index_records[0]["mode"] == "off"
    assert index_records[0]["mode_origin"] == "connector:fixture-source"
    assert "profile_id" not in index_records[0]
    request_records = inspection_decisions(root, "review", index_task["task_id"], "tool.invoke")
    assert any(record["profile_id"] == "standard" for record in request_records)
    outcomes["connector_off"] = {"response": "off", "request": "standard", "source_calls": 1}

    for scenario, name in (
        ("connector_allowed", "allowed.md"),
        ("connector_argument", MARKERS["connector_argument"]),
        ("connector_result", "blocked-result.md"),
        ("artifact", "blocked-artifact.md"),
    ):
        source_calls = sum(event.get("report_id") == name for event in read_traffic(root, "source"))
        location, task, headers = checked_task(
            client,
            root,
            "review",
            "documents.read",
            {"collection": "lasa-docs", "document_id": name},
            scenario,
        )
        observed = (
            sum(event.get("report_id") == name for event in read_traffic(root, "source"))
            - source_calls
        )
        assert observed == int(scenario != "connector_argument"), (scenario, observed)
        artifacts = state_rows(
            root,
            "review",
            "SELECT id,released FROM artifacts WHERE task_id=?",
            (task["task_id"],),
        )
        if scenario == "connector_allowed":
            assert task["status"] == "completed", task
            (manifest,) = task["result"]["artifacts"]
            assert manifest["provenance"]["operation_id"].startswith("tool-")
            artifact = client.get(
                location + "/artifacts/" + manifest["artifact_id"], headers=headers
            )
            assert (
                artifact.status_code == 200
                and artifact.json()["text"] == "An allowed HTTPS source record."
            )
        elif scenario == "artifact":
            assert task["problem"]["code"] == "disclosure_denied" and "result" not in task, task
            ((artifact_id, visibility),) = artifacts
            assert visibility == -1
            artifact = client.get(location + "/artifacts/" + artifact_id, headers=headers)
            assert artifact.status_code == 404 and MARKERS["artifact"] not in artifact.text
        else:
            assert (
                task["status"] in {"failed", "rejected"} and not artifacts and "result" not in task
            ), task
        if scenario != "connector_argument":
            decisions = inspection_decisions(root, "review", task["task_id"], "tool.result")
            assert any(
                record["mode"] == "enforce"
                and record["mode_origin"] == "operation:documents.read"
                and record["profile_id"] == "document"
                and record["gateway_policy_revision"] == PROFILE_REVISIONS["document"]
                for record in decisions
            )
        outcomes[scenario] = {"status": task["status"], "source_calls": observed}

    model = json.dumps(read_traffic(root, "model"))
    for key in ("caller", "model_request", "invalid_verdict", "wrong_revision", "connector_result"):
        assert MARKERS[key] not in model, f"Blocked {key} bytes reached the model"
    gateway = read_traffic(root, "inspection")
    for channel, denied in CHANNEL_DENIALS.items():
        inspected = json.dumps(
            [entry["content"] for entry in gateway if entry["channel"] == channel]
        )
        for kind in denied:
            if kind in {"delegate_off", "connector_off"}:
                assert MARKERS[kind] not in inspected, (channel, kind)
            else:
                assert MARKERS[kind] in inspected, (channel, kind)
    for profile, channel, marker in (
        ("artifacts", "candidate.release", MARKERS["artifact"]),
        ("document", "tool.result", MARKERS["connector_result"]),
        ("standard", "reasoning.request", MARKERS["wrong_revision"]),
    ):
        assert any(
            entry["fixture_profile"] == profile
            and entry["channel"] == channel
            and entry["gateway_policy_revision"] == PROFILE_REVISIONS[profile]
            and marker in json.dumps(entry["content"])
            for entry in gateway
        ), (profile, channel)
    projection = json.dumps([entry["content"] for entry in gateway])
    for protected in (
        MODEL_KEY,
        GATEWAY_KEY,
        SOURCE_KEY,
        "The last user message is the complete candidate_output",
    ):
        assert protected not in projection
    audit = [
        document
        for name in (*PEERS, "parent")
        for (document,) in state_rows(
            root,
            name,
            "SELECT document FROM audit WHERE kind IN ('content_decision','content_transfer')",
        )
    ]
    assert audit and all(
        private not in "".join(audit)
        for private in (*MARKERS.values(), MODEL_KEY, GATEWAY_KEY, SOURCE_KEY)
    )
    print(
        json.dumps(
            {
                "content_security": outcomes,
                "model_requests": len(read_traffic(root, "model")),
                "inspection_requests": len(gateway),
                "local_gateway_id": GATEWAY_ID,
                "requests_by_profile": {
                    profile: sum(item["fixture_profile"] == profile for item in gateway)
                    for profile in PROFILE_REVISIONS
                },
                "metadata_only_content_records": len(audit),
            },
            indent=2,
        )
    )


def wait_ready(client, url, headers, *, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if client.get(url + "/health/ready", headers=headers).status_code == 200:
                return
        except httpx.TransportError:
            pass
        time.sleep(0.2)
    raise RuntimeError(f"{url} did not become ready")


def dlp_task(scenario, label, marker):
    if scenario == "connector-request":
        return "documents.search", {"collection": "python-sdk-root", "query": marker, "limit": 1}
    if scenario in {"connector-result", "artifact-release"}:
        return "documents.read", {"collection": "lasa-docs", "document_id": label + ".md"}
    if scenario in {"model-response", "delegate-request", "delegate-result"}:
        objective = f"{label} {marker}" if scenario == "delegate-request" else label
        return "task.attempt", attempt_input(objective)
    return "design.review", {
        "design": marker if scenario in {"caller-intake", "model-request"} else label,
        "criteria": [{"id": "dlp", "description": "Review the text."}],
    }


def verify_dlp_case(client, root, mode, scenario, reason, marker):
    group, channel, purpose = DLP_STREAMS[scenario]
    receiver = f"{group}-{mode}"
    child = receiver + "-child"
    label = f"dlp-{scenario}-{reason}"
    operation = f"{label}-{mode}"
    blocked = mode == "enforce" and reason != "clean"
    intake_denied = blocked and scenario == "caller-intake"
    model_start = len(read_traffic(root, "model"))
    source_start = len(read_traffic(root, "source"))
    if scenario.startswith("delegate-"):
        existing_children = {row[0] for row in state_rows(root, child, "SELECT id FROM tasks")}
    questions = []

    def answer_question(prompt):
        assert not blocked and prompt == marker, (operation, prompt)
        questions.append(prompt)
        return "The review scope is confirmed."

    capability, inputs = dlp_task(scenario, label, marker)
    location, task, headers = checked_task(
        client,
        root,
        receiver,
        capability,
        inputs,
        operation,
        intake_denied=intake_denied,
        answer_question=answer_question if scenario == "caller-question" else None,
    )
    task_id = task.get("task_id")
    if blocked and scenario != "caller-question":
        problem = task if intake_denied else task["problem"]
        expected = "verification_failed" if group == "connectors" else "disclosure_denied"
        assert problem["code"] == expected and "result" not in task, (operation, task)
    else:
        assert task["status"] == "completed", (operation, task)
    if blocked:
        assert "question" not in task and marker not in json.dumps(task), operation

    model = [
        request
        for request in read_traffic(root, "model")[model_start:]
        if request["fixture_receiver"] == receiver
    ]
    source = read_traffic(root, "source")[source_start:]
    if scenario in {"caller-intake", "model-request"}:
        deliveries = sum(marker in json.dumps(request) for request in model)
        assert not model if blocked else deliveries > 0, (operation, deliveries)
        if scenario == "caller-intake":
            admitted = state_rows(
                root,
                receiver,
                "SELECT resource_id FROM operations WHERE operation_id=?",
                ("task-" + operation,),
            )
            assert admitted == ([] if blocked else [(task_id,)]), (operation, admitted)
    elif scenario == "caller-question":
        deliveries = len(questions)
        if blocked:
            assert state_rows(
                root,
                receiver,
                "SELECT json_extract(result,'$.error.code') FROM actions "
                "WHERE task_id=? AND json_extract(intent,'$.name')='lasa.request_input'",
                (task_id,),
            ) == [("disclosure_denied",)], operation
    elif scenario == "result-release":
        assert any(marker in json.dumps(request) for request in model), operation
        deliveries = int(
            task.get("result", {}).get("output", {}).get("coverage", [{}])[0].get("evidence")
            == marker
        )
    elif scenario == "model-response":
        writes = state_rows(
            root,
            receiver,
            "SELECT state,intent FROM actions WHERE task_id=? AND effect='workspace.write'",
            (task_id,),
        )
        assert (
            writes == []
            if blocked
            else (
                len(writes) == 1
                and writes[0][0] == "finished"
                and json.loads(writes[0][1])["arguments"]["text"] == marker
            )
        ), (operation, writes)
        control = client.get(location + "?view=control", headers=headers).raise_for_status().json()
        assert control["usage"]["model_calls"] >= 1
        assert control["usage"]["tool_calls"] == int(not blocked)
        deliveries = len(writes)
    elif scenario.startswith("delegate-"):
        ((record,),) = state_rows(
            root, receiver, "SELECT document FROM children WHERE task_id=?", (task_id,)
        )
        delegation = json.loads(record)
        children = [
            (document, request)
            for child_id, document, request in state_rows(
                root, child, "SELECT id,document,request FROM tasks"
            )
            if child_id not in existing_children
        ]
        assert len(children) == int(not blocked or scenario == "delegate-result"), (
            operation,
            delegation["state"],
        )
        if scenario == "delegate-request":
            assert delegation["dispatched"] == (not blocked), (operation, delegation["state"])
            deliveries = sum(marker in request for _, request in children)
        else:
            ((document, _),) = children
            assert json.loads(document)["result"]["output"]["summary"] == marker
            control = (
                client.get(location + "?view=control", headers=headers).raise_for_status().json()
            )
            assert control["effect_disposition"] == "known" and control["usage"]["tool_calls"] == 1
            deliveries = int(task.get("result", {}).get("output", {}).get("summary") == marker)
            assert any(marker in json.dumps(request) for request in model) == (not blocked), (
                operation
            )
    elif scenario == "connector-request":
        deliveries = sum(event.get("query") == marker for event in source)
        if not blocked:
            assert task["result"]["output"]["matches"][0]["document_id"] == marker + ".md"
    else:
        assert sum(event.get("report_id") == inputs["document_id"] for event in source) == 1
        artifacts = state_rows(
            root, receiver, "SELECT id,released FROM artifacts WHERE task_id=?", (task_id,)
        )
        if scenario == "connector-result":
            deliveries = sum(
                item.get("type") == "function_call_output" and marker in json.dumps(item)
                for request in model
                for item in request["input"]
            )
            if blocked:
                assert not artifacts and not any(marker in json.dumps(request) for request in model)
            else:
                assert task["result"]["output"]["content"] == marker and artifacts
        else:
            ((artifact_id, released),) = artifacts
            artifact = client.get(location + "/artifacts/" + artifact_id, headers=headers)
            assert released == (-1 if blocked else 1)
            assert artifact.status_code == (404 if blocked else 200)
            deliveries = int(marker in artifact.text)
            if not blocked:
                assert artifact.json()["text"] == marker
    assert deliveries == 0 if blocked else deliveries > 0, (operation, deliveries)

    verdict = "permit" if reason == "clean" else "hard_deny"
    profile = DLP_ARTIFACT_PROFILE if scenario == "artifact-release" else DLP_PROFILE
    records = inspection_decisions(
        root, receiver, None if scenario == "caller-intake" else task_id, channel
    )
    inspections = [
        record
        for record in records
        if record["purpose"] == purpose
        and (scenario != "caller-intake" or record["operation_id"] == "task-" + operation)
        and record["mode"] == mode
        and record["profile_id"] == profile
        and record["gateway_policy_revision"] == DLP_REVISION
        and record["gateway_id"] == DLP_GATEWAY_ID
        and "inspection_id" in record
        and record["reason_code"] == "gateway_" + verdict
    ]
    assert inspections, (operation, records)
    blocked_transfers = {
        transfer_id
        for (transfer_id,) in state_rows(
            root,
            receiver,
            "SELECT json_extract(document,'$.transfer_id') FROM audit WHERE kind='content_transfer' "
            "AND task_id IS ? AND json_extract(document,'$.outcome')='blocked'",
            (None if scenario == "caller-intake" else task_id,),
        )
    }
    assert all((record["transfer_id"] in blocked_transfers) == blocked for record in inspections), (
        operation
    )
    return {
        "mode": mode,
        "scenario": scenario,
        "case": reason,
        "verdict": verdict,
        "blocked": blocked,
        "status": task.get("status", "denied"),
        "deliveries": deliveries,
        "inspection_ids": [record["inspection_id"] for record in inspections],
    }


def verify_dlp(root):
    ca = ssl.create_default_context(cafile=root / "ca.pem")
    names = (*DLP_TARGETS, *(f"delegates-{mode}-child" for mode in DLP_MODES))
    with httpx.Client(verify=ca, trust_env=False, timeout=6) as client:
        for name in names:
            token = (root / name / "operator-token.txt").read_text().strip()
            wait_ready(client, origin(name), {"Authorization": "Bearer " + token})
        gateway = origin("inspection")
        token = (root / "inspection/token.txt").read_text().strip()
        wait_ready(client, gateway, {"Authorization": "Bearer " + token}, timeout=90)
        assert client.get(gateway + "/health/ready").status_code == 401
        assert client.post(gateway + "/inspect", json={}).status_code == 401
        cases = [
            verify_dlp_case(client, root, mode, scenario, reason, marker)
            for mode in DLP_MODES
            for scenario in DLP_STREAMS
            for reason, marker in DLP_CASES.items()
        ]
    audit = [
        document
        for name in names
        for (document,) in state_rows(
            root,
            name,
            "SELECT document FROM audit WHERE kind IN ('content_decision','content_transfer')",
        )
    ]
    assert audit and all(
        private not in "".join(audit)
        for private in (*DLP_CASES.values(), token, MODEL_KEY, SOURCE_KEY)
    )
    print(json.dumps({"cases": cases, "metadata_only_content_records": len(audit)}))


def recovery_records(root, receiver, task_id):
    return [
        json.loads(document)
        for (document,) in state_rows(
            root,
            receiver,
            "SELECT document FROM audit WHERE task_id=? AND kind='content_recovery'",
            (task_id,),
        )
    ]


def real_inspection(decision, verdict, reason=None):
    return {
        "inspection_id": decision["inspection_id"],
        "inspection_digest": decision["inspection_digest"],
        "verdict": verdict,
        "reason_codes": [reason] if reason else [],
    }


def shim_records(root):
    return {
        item["inspection_id"]: item
        for item in map(json.loads, (root / "model/recovery-shim.jsonl").read_text().splitlines())
    }


def verify_revision(client, root, group, reason):
    marker = DLP_CASES[reason]
    receiver = group + "-enforce"
    child = "delegates-enforce-child"
    scenario = f"dlp-recovery-{group}-{reason}"
    model_start = len(read_traffic(root, "model"))
    source_start = len(read_traffic(root, "source"))
    child_start = state_rows(root, child, "SELECT count(*) FROM tasks")[0][0]
    if group == "connectors":
        inputs = {"collection": "lasa-docs", "document_id": f"dlp-recovery-connector-{reason}.md"}
        profile, channel = "documents.read", "tool.invoke"
    else:
        inputs = {**attempt_input(scenario.replace("delegates", "delegate")), "context": marker}
        profile = "task.attempt"
        channel = "reasoning.request" if group == "model" else "delegation.request"
    _, task, _ = checked_task(client, root, receiver, profile, inputs, scenario)
    task_id = task["task_id"]
    assert task["status"] == "completed", (group, reason, task.get("problem"))
    if group == "model":
        model = [
            item
            for item in read_traffic(root, "model")[model_start:]
            if item.get("fixture_receiver") == receiver
        ]
        assert all(marker not in json.dumps(item) for item in model)
        dispatched = [item for item in model if item.get("stream")]
        assert len(dispatched) == 1 and payload(dispatched[0])["input"] == {
            key: value for key, value in inputs.items() if key != "context"
        }
        (verification,) = [
            item
            for item in model
            if item.get("text", {}).get("format", {}).get("name") == "lasa_verification"
        ]
        material = json.loads(verification["input"][-2]["content"][0]["text"])
        (step_input,) = material["trusted_execution_evidence"]["step_inputs"]
        revised_input = payload(dispatched[0])["input"]
        assert material["input"] == step_input["content"] == revised_input
        ((document,),) = state_rows(
            root,
            receiver,
            "SELECT document FROM audit WHERE task_id=? AND kind='model_input_revision'",
            (task_id,),
        )
        receipt = json.loads(document)
        assert step_input == {
            "content": revised_input,
            "step_id": receipt["step_id"],
            **material["input_revision"],
        }
        assert material["input_revision"] == {
            key: receipt[key]
            for key in (
                "admitted_input_digest",
                "input_digest",
                "operation_id",
                "transfer_id",
                "model_request_digest",
            )
        }
        assert receipt["admitted_input_digest"] == digest(inputs)
        assert receipt["input_digest"] == digest(revised_input)
        assert receipt["model_request_digest"] == digest(
            {key: item for key, item in dispatched[0].items() if key != "fixture_receiver"}
        )
    elif group == "delegates":
        ((document,),) = state_rows(
            root, receiver, "SELECT document FROM children WHERE task_id=?", (task_id,)
        )
        receipt = json.loads(document)
        assert receipt["dispatched"] and receipt["state"] == "completed"
        assert state_rows(root, child, "SELECT count(*) FROM tasks")[0][0] == child_start + 1
        ((request,),) = state_rows(
            root, child, "SELECT request FROM tasks WHERE id=?", (receipt["task_id"],)
        )
        dispatched = [json.loads(request)]
        assert dispatched[0]["input"] == {
            key: value for key, value in inputs.items() if key != "context"
        }
        assert marker not in request
    else:
        dispatched = [
            item
            for item in read_traffic(root, "source")[source_start:]
            if item.get("report_id") == inputs["document_id"]
        ]
        assert dispatched == [{"report_id": inputs["document_id"]}]
        assert task["result"]["output"]["document_id"] == inputs["document_id"]
    decisions = inspection_decisions(root, receiver, task_id, channel)
    attempts = recovery_records(root, receiver, task_id)
    revisions = [attempt for attempt in attempts if attempt["action"] == "candidate_revision"]
    assert (
        revisions
        and len(attempts) <= 4
        and len({r["transfer_id"] for r in revisions}) == len(revisions)
    )
    real = []
    for revision in revisions:
        same_transfer = [
            row
            for row in decisions
            if row["transfer_id"] == revision["transfer_id"] and "inspection_id" in row
        ]
        (denied,) = [
            row
            for row in same_transfer
            if row["candidate_revision"] == 0 and row["reason_code"] == "gateway_hard_deny"
        ]
        (revised,) = [
            row
            for row in same_transfer
            if row["candidate_revision"] == 1 and row["reason_code"] != "scanner_disclosure"
        ]
        assert denied["payload_digest"] == revision["payload_digest"]
        assert denied["inspection_digest"] != revised["inspection_digest"]
        assert denied["candidate_revision"] == 0
        assert revised["reason_code"] == "gateway_permit"
        real.extend(
            (real_inspection(denied, "hard_deny", reason), real_inspection(revised, "permit"))
        )
    return {
        "binding": group + ".request",
        "case": reason,
        "status": task["status"],
        "revisions": len(revisions),
        "execution_dispatches": len(dispatched),
    }, real


def verify_scanner_recovery(client, root, fault):
    receiver = "model-enforce"
    case = f"dlp-recovery-scanner-{fault}"
    model_start = len(read_traffic(root, "model"))
    _, task, _ = checked_task(client, root, receiver, "task.attempt", attempt_input(case), case)
    decisions = inspection_decisions(root, receiver, task["task_id"], "reasoning.request")
    execution = [
        row
        for row in decisions
        if row["purpose"] == "execution"
        and row.get("inspection_id")
        and row["reason_code"] != "scanner_disclosure"
    ]
    shim = {key: row["fault"] for key, row in shim_records(root).items()}
    dispatches = [
        row
        for row in read_traffic(root, "model")[model_start:]
        if row.get("fixture_receiver") == receiver and row.get("stream")
    ]
    attempts = recovery_records(root, receiver, task["task_id"])
    expected = 0 if fault == "invalid" else 1
    assert len(attempts) == expected and all(
        row["action"] == "inspection_retry" for row in attempts
    )
    assert len(execution) == 1 + expected
    assert len({row["inspection_digest"] for row in execution}) == 1
    assert len({row["transfer_id"] for row in execution}) == 1
    assert len({row["inspection_id"] for row in execution}) == len(execution)
    real = []
    if fault == "transient":
        assert task["status"] == "completed" and len(dispatches) == 1
        assert [shim[row["inspection_id"]] for row in execution] == ["transient_503", "forwarded"]
        assert execution[-1]["reason_code"] == "gateway_permit"
        real.append(real_inspection(execution[-1], "permit"))
    else:
        assert task["problem"]["code"] == "content_gateway_unavailable" and not dispatches
        if fault == "invalid":
            assert shim[execution[0]["inspection_id"]] == "invalid_digest"
            real.append(real_inspection(execution[0], "permit"))
        else:
            assert all(shim[row["inspection_id"]] == "persistent_503" for row in execution)
    return {
        "fault": fault,
        "status": task["status"],
        "retries": expected,
        "execution_dispatches": len(dispatches),
    }, real


def verify_recovery_canary(root):
    names = ("model-enforce", "delegates-enforce", "delegates-enforce-child", "connectors-enforce")
    recovering, inspections = [], []
    tls = ssl.create_default_context(cafile=root / "ca.pem")
    with httpx.Client(verify=tls, trust_env=False, timeout=6) as client:
        for name in names:
            token = (root / name / "operator-token.txt").read_text().strip()
            wait_ready(client, origin(name), {"Authorization": "Bearer " + token})
        for group in ("model", "delegates", "connectors"):
            for reason in ("pii_detected", "credential_detected"):
                report, checks = verify_revision(client, root, group, reason)
                recovering.append(report)
                inspections.extend(checks)
        for fault in ("transient", "persistent", "invalid"):
            report, checks = verify_scanner_recovery(client, root, fault)
            recovering.append(report)
            inspections.extend(checks)
        cases = [
            verify_dlp_case(client, root, "enforce", scenario, reason, DLP_CASES[reason])
            for scenario in (
                "model-request",
                "delegate-request",
                "connector-request",
                "model-response",
                "delegate-result",
                "connector-result",
            )
            for reason in ("clean", "pii_detected", "credential_detected")
        ]
    token = (root / "inspection/token.txt").read_text().strip()
    audit = [
        document
        for name in names
        for (document,) in state_rows(
            root,
            name,
            "SELECT document FROM audit WHERE kind IN ('content_decision','content_transfer','content_recovery','model_input_revision')",
        )
    ]
    assert audit and all(
        value not in "".join(audit) for value in (*DLP_CASES.values(), token, MODEL_KEY, SOURCE_KEY)
    )
    print(
        json.dumps(
            {
                "cases": cases,
                "recovery": recovering,
                "recovery_inspections": inspections,
                "metadata_only_content_records": len(audit),
            }
        )
    )


def verify_dlp_logs(output, logs, token):
    report = json.loads(output)
    assert all(
        private not in logs for private in (*DLP_CASES.values(), token, MODEL_KEY, SOURCE_KEY)
    )
    events = {
        event["inspection_id"]: event
        for line in logs.splitlines()
        if "inspection {" in line
        for event in [json.loads(line.split("inspection ", 1)[1])]
    }
    for case in report["cases"]:
        for key in case.pop("inspection_ids"):
            event = events[key]
            assert event["verdict"] == case["verdict"], event
            expected = [] if case["case"] == "clean" else [case["case"]]
            assert event["reason_codes"] == expected, event
    for expected in report.pop("recovery_inspections", ()):
        event = events[expected["inspection_id"]]
        assert all(event[key] == value for key, value in expected.items()), (event, expected)
    report["metadata_only_gateway_records"] = len(events)
    print(json.dumps(report, indent=2))


def verify(root):
    verify_tls = ssl.create_default_context(cafile=root / "ca.pem")
    token = (root / "parent/operator-token.txt").read_text().strip()
    with httpx.Client(
        verify=verify_tls, trust_env=False, timeout=6, headers={"Authorization": "Bearer " + token}
    ) as client:
        for name in (*PEERS, "parent"):
            receiver_token = (root / name / "operator-token.txt").read_text().strip()
            wait_ready(client, origin(name), {"Authorization": "Bearer " + receiver_token})
        review_operator = (root / "review/operator-token.txt").read_text().strip()
        review = (
            client.get(
                base("review") + "/descriptor",
                headers={"Authorization": "Bearer " + review_operator},
            )
            .raise_for_status()
            .json()
        )
        assert review["authentication"]["mode"] == "static_token"
        assert "bounded-delegation" in review["protocols"][0]["features"]
        descriptor = client.get(base("parent") + "/descriptor").raise_for_status().json()
        protocol = descriptor["protocols"][0]["version"]
        assert protocol == review["protocols"][0]["version"] == "lasa/1.0.0", descriptor
        assert descriptor["descriptor_version"] == review["descriptor_version"] == "1.0.0"
        sibling_token = (root / "review/peer-token.txt").read_text().strip()
        assert (
            client.get(
                base("attempt") + "/descriptor",
                headers={"Authorization": "Bearer " + sibling_token},
            ).status_code
            == 401
        )
        catalog = client.get(base("parent") + "/capabilities").raise_for_status().json()
        offer = next(
            item for item in catalog["offers"] if item["contract"]["id"].endswith("/task.attempt")
        )
        session = (
            client.post(
                base("parent") + "/sessions",
                json={"operation_id": "session-container-smoke"},
                headers={"Idempotency-Key": "session-container-smoke"},
            )
            .raise_for_status()
            .json()
        )
        task = client.post(
            base("parent") + f"/sessions/{session['session_id']}/tasks",
            headers={"Idempotency-Key": "task-container-smoke"},
            json={
                "operation_id": "task-container-smoke",
                "selection": {
                    field: offer[field] for field in ("contract", "offer_id", "catalog_view")
                }
                | {"offer_revision": offer["revision"]},
                "input": {
                    "objective": "Verify two bounded peer results.",
                    "requirements": [
                        {
                            "id": "requirement-main",
                            "description": "Integrate a downstream review and attempt.",
                            "acceptance": ["Use both peer outcomes."],
                        }
                    ],
                },
                "requested_limits": {
                    "budget": offer["max_budget"],
                    "max_hops": 1,
                    "deadline": (datetime.now(UTC) + timedelta(seconds=240)).isoformat(),
                },
                "authorization_ref": offer["authorization_ref"],
                "diagnostics": "metadata",
            },
        ).raise_for_status()
        location = task.headers["Location"]
        deadline = time.monotonic() + 115
        while time.monotonic() < deadline:
            outcome = client.get(location).raise_for_status().json()
            if outcome["status"] in {
                "completed",
                "rejected",
                "failed",
                "indeterminate",
                "cancelled",
            }:
                break
            time.sleep(0.25)
        assert outcome["status"] == "completed", outcome
        result = outcome["result"]
        assert result["usage"]["delegations"] == 2
        assert result["output"]["summary"] == "The parent integrated both verified peer results."
        report = client.get(location + "/delegations").raise_for_status().json()
        children = report["children"]
        for child, name in zip(children, PEERS, strict=True):
            receiver = read(root / name / "config.json")["service"]["id"]
            assert child["service_id"] == receiver and child["state"] == "completed", child
            events = child["trace"]["events"]
            routing = next(event["payload"] for event in events if event["kind"] == "routing")
            assert routing["contract"]["id"].endswith("/" + PEERS[name]), routing
            calls = [
                event["payload"]
                for event in events
                if event["kind"] == "call" and event["payload"]["call_type"] == "model"
            ]
            executions = {
                call["operation_id"]
                for call in calls
                if call["phase"] == "started" and call.get("purpose") == "execution"
            }
            finished = {call["operation_id"] for call in calls if call["phase"] == "finished"}
            assert len(executions) == 1 and executions <= finished, child
        seen = inspection_decisions(root, "parent", outcome["task_id"], "delegation.response")
        for child, name in zip(children, PEERS, strict=True):
            records = [
                record
                for record in seen
                if record["destination"] == "peer:" + child["service_id"]
                and record["purpose"] == "result"
            ]
            if name == "review":
                assert len(records) == 1 and records[0]["mode"] == "off"
                assert records[0]["mode_origin"] == "peer:" + child["service_id"]
                assert "profile_id" not in records[0]
            else:
                assert any(
                    record["mode"] == "enforce"
                    and record["profile_id"] == "standard"
                    and record["mode_origin"] == "delegates.default"
                    for record in records
                )
        print(
            json.dumps(
                {
                    "protocol": protocol,
                    "task_id": outcome["task_id"],
                    "status": outcome["status"],
                    "delegations": [
                        {"service_id": child["service_id"], "task_id": child["task_id"]}
                        for child in children
                    ],
                    "wrong_audience_status": 401,
                    "model_calls": result["usage"]["model_calls"],
                    "delegate_response_modes": {"review": "off", "attempt": "enforce"},
                },
                indent=2,
            )
        )

        verify_content(client, root)


def deploy_command(path, action, *, error=None):
    result = subprocess.run(
        [sys.executable, "-m", "lasa_service.cli", "deploy", action, "--settings", str(path)],
        capture_output=True,
        text=True,
        timeout=260,
        check=False,
    )
    if error:
        assert result.returncode == 2 and error in result.stderr, result.stderr
    elif result.returncode:
        raise RuntimeError(result.stderr)


def start_managed_dlp(path, document):
    disabled = {"supervisor_network": document["supervisor_network"]}
    save(path, disabled)
    deploy_command(path, "apply")
    assert not DockerDeployment.load(path).compose("ps", "-aq")

    save(path, {**disabled, "supervisors": document["supervisors"]})
    deploy_command(path, "apply", error="requires local_dlp.enabled=true")
    assert not DockerDeployment.load(path).compose("ps", "-aq")

    save(path, document)
    deploy_command(path, "apply")
    deployment = DockerDeployment.load(path)
    inspector = deployment.compose("ps", "-q", "inspector")
    analyzer = deployment.compose("ps", "-q", "presidio")
    assert inspector and analyzer
    deploy_command(path, "apply")
    assert inspector == deployment.compose("ps", "-q", "inspector")
    assert analyzer == deployment.compose("ps", "-q", "presidio")
    host_network = document["supervisor_network"]
    backend = deployment.project + "_backend"
    assert docker("network", "inspect", "--format", "{{.Internal}}", backend) == "true"
    for container, expected in ((inspector, {host_network, backend}), (analyzer, {backend})):
        status = json.loads(docker("inspect", container))[0]
        assert set(status["NetworkSettings"]["Networks"]) == expected
        assert not status["HostConfig"]["PortBindings"]

    wrong_revision = {**document["local_dlp"], "policy_revision": "different-revision"}
    save(path, {**document, "local_dlp": wrong_revision})
    deploy_command(path, "check", error="must pin")
    save(path, {**document, "local_dlp": wrong_revision, "supervisors": []})
    deploy_command(path, "check", error="unexpected gateway ID or policy revision")
    save(path, document)
    deploy_command(path, "check")
    return inspector, analyzer


def run(args, root):
    namespace = "lasa-smoke-" + uuid4().hex[:10]
    image = docker("image", "inspect", "--format", "{{.Id}}", args.service_image)
    launcher_image = docker("image", "inspect", "--format", "{{.Id}}", args.launcher_image)
    runtime = docker("image", "inspect", "--format", "{{.Id}}", args.runtime_image)
    socket_mount = mount(args.docker_socket, "/var/run/docker.sock", read_only=False)
    gid = docker(
        "run",
        "--rm",
        "--network",
        "none",
        "--mount",
        socket_mount,
        "--entrypoint",
        "stat",
        launcher_image,
        "-c",
        "%g",
        "/var/run/docker.sock",
    )
    dlp = args.inspector_image is not None
    recovery = args.recovery_canary
    if dlp:
        targets = (
            ("model-enforce", "delegates-enforce", "connectors-enforce")
            if recovery
            else DLP_TARGETS
        )
        configs = {name: configure(root, name, namespace) for name in targets}
        for mode in ("enforce",) if recovery else DLP_MODES:
            parent = f"delegates-{mode}"
            child = parent + "-child"
            configs[child] = configure(root, child, namespace, trusted_parent=parent)
            if recovery:
                for name in (parent, child, "model-enforce"):
                    configure_recovery_contract(root, name, configs[name])
            authorize(root, configs, parent, {child: "task.attempt"})
    else:
        configs = {
            name: configure(
                root, name, namespace, trusted_parent="parent" if name in PEERS else None
            )
            for name in (*PEERS, "parent")
        }
        authorize(root, configs)
    fixtures = ("model", "source") if dlp else ("model", "inspection", "source")
    certificates = (*fixtures, "inspection") if dlp else fixtures
    for name in certificates:
        directory = root / name
        directory.mkdir()
        certificate(directory, dns_name="lasa-" + name)
    ca = root / "ca.pem"
    ca.write_bytes(
        b"".join(
            (root / name / "certificate.pem").read_bytes() for name in (*configs, *certificates)
        )
    )
    if dlp:
        token_file = root / "inspection/token.txt"
        token_file.write_text(secrets.token_urlsafe(32) + "\n")
        token_file.chmod(0o600)
        (root / "inspection/ca.pem").write_bytes((root / "inspection/certificate.pem").read_bytes())
    for name, config in configs.items():
        if dlp:
            for executor in config["executors"]:
                executor["provider_base_url"] = origin("model") + f"/{name}/v1"
        if name in DLP_TARGETS:
            configure_dlp(root, name, config, *DLP_TARGETS[name])
        elif not dlp:
            configure_content(root, name, configs)
        if recovery and name == "connectors-enforce":
            operation = config["executors"][0]["connectors"][0]["operations"][0]
            assert operation["operation_id"] == "documents.read"
            operation["optional_context_arguments"] = ["note"]
            operation["input_schema"]["properties"]["note"] = {"type": "string"}
        if recovery and name == "model-enforce":
            profile = config["content_security"]["inspection_profiles"][0]
            profile["url"] = origin("model") + "/recovery-inspect"
        save(root / name / "config.json", config)
    containers = []
    volumes = []
    deployment_file = root / "deployment.json"
    gateway = analyzer = None
    docker("network", "create", "--internal", namespace)
    user = f"{os.getuid()}:{os.getgid()}"
    fixture = [
        "--mount",
        mount(ROOT / "tests", "/verify/tests"),
        "--workdir",
        "/verify",
        "--entrypoint",
        "python",
    ]
    try:
        if dlp:
            gateway, analyzer = start_managed_dlp(
                deployment_file,
                {
                    "supervisor_network": namespace,
                    "supervisors": [str(root / name / "config.json") for name in configs],
                    "local_dlp": {
                        "enabled": True,
                        "secrets_directory": str(root / "inspection"),
                        "inspector_image": args.inspector_image,
                        "presidio_image": args.presidio_image,
                    },
                },
            )
        for name in fixtures:
            containers.append(namespace + "-" + name)
            docker(
                "run",
                "-d",
                "--name",
                containers[-1],
                "--network",
                namespace,
                "--network-alias",
                "lasa-" + name,
                "--user",
                user,
                "--mount",
                mount(root / name, read_only=False),
                "--mount",
                mount(ca),
                *fixture,
                image,
                "-m",
                "tests.container_smoke",
                "fixture",
                root / name,
            )
        for name, config in configs.items():
            state = Path(config["storage"]["state_root"])
            state.mkdir(mode=0o700, parents=True)
            volume = namespace + "-socket-" + name
            volumes.append(volume)
            docker("volume", "create", volume)
            socket_volume = f"type=volume,source={volume},target=/run/lasa"
            docker(
                "run",
                "--rm",
                "--network",
                "none",
                "--user",
                "0:0",
                "--mount",
                socket_volume,
                "--entrypoint",
                "chown",
                image,
                user,
                "/run/lasa",
            )
            launcher = namespace + "-launcher-" + name
            containers.append(launcher)
            docker(
                "run",
                "-d",
                "--name",
                launcher,
                "--network",
                "none",
                "--user",
                user,
                "--group-add",
                gid,
                "--mount",
                socket_mount,
                "--mount",
                socket_volume,
                launcher_image,
                "--image",
                runtime,
                "--scope",
                config["service"]["id"],
                "--socket",
                LAUNCHER_SOCKET,
            )
            end = time.monotonic() + 20
            while True:
                if (
                    docker(
                        "exec",
                        launcher,
                        "sh",
                        "-c",
                        "test -S /run/lasa/launcher.sock && echo ready",
                        check=False,
                    )
                    == "ready"
                ):
                    break
                if time.monotonic() > end:
                    raise TimeoutError(f"Launcher for {name} did not become ready")
                time.sleep(0.1)
            supervisor = namespace + "-" + name
            containers.append(supervisor)
            docker(
                "run",
                "-d",
                "--name",
                supervisor,
                "--network",
                namespace,
                "--network-alias",
                "lasa-" + name,
                "--user",
                user,
                "--mount",
                socket_volume + ",readonly",
                "--mount",
                mount(root / name),
                "--mount",
                mount(state, read_only=False),
                "--mount",
                mount(ca),
                "--env",
                "LASA_MODEL_API_KEY=" + MODEL_KEY,
                "--env",
                "LASA_GATEWAY_KEY=" + GATEWAY_KEY,
                "--env",
                "LASA_SOURCE_KEY=" + SOURCE_KEY,
                image,
                "--config",
                root / name / "config.json",
            )
            mounts = json.loads(docker("inspect", "--format", "{{json .Mounts}}", supervisor))
            assert all(x["Destination"] != "/var/run/docker.sock" for x in mounts)
            checked = docker(
                "exec",
                supervisor,
                "lasa",
                "config",
                "check",
                "--offline",
                "--config",
                root / name / "config.json",
            )
            report = json.loads(checked.split("Effective content inspection\n")[1])
            if dlp:
                target = DLP_TARGETS.get(name)
                for group, directions in report["defaults"].items():
                    for effective in directions.values():
                        if target and group == target[0]:
                            assert (
                                effective["mode"] == target[1]
                                and effective["profile"] == DLP_PROFILE
                            )
                        else:
                            assert effective["mode"] == "off"
            elif name == "parent":
                peer = configs["review"]["service"]["id"]
                assert report["delegates"][peer]["response"]["mode"] == "off"
                assert report["delegates"][peer]["request"]["profile"] == "standard"
            elif name == "review":
                assert report["connectors"]["fixture-source"]["response"]["mode"] == "off"
                assert (
                    report["operations"]["fixture-source/documents.read"]["response"]["profile"]
                    == "document"
                )
            else:
                assert report["defaults"]["model"]["response"]["mode"] == "observe"
                assert (
                    report["defaults"]["connectors"]["request"]["origins"]["mode"] == "unconfigured"
                )
        client = namespace + "-verify"
        containers.append(client)
        output = docker(
            "run",
            "--rm",
            "--name",
            client,
            "--network",
            namespace,
            "--user",
            user,
            "--mount",
            mount(root),
            *fixture,
            image,
            "-m",
            "tests.container_smoke",
            "verify-recovery" if recovery else "verify-dlp" if dlp else "verify",
            root,
            timeout=480 if dlp else 240,
        )
        if dlp:
            token = (root / "inspection/token.txt").read_text().strip()
            verify_dlp_logs(output, docker("logs", gateway), token)
            analyzer_logs = docker("logs", analyzer)
            assert all(
                private not in analyzer_logs
                for private in (*DLP_CASES.values(), token, MODEL_KEY, SOURCE_KEY)
            )
        else:
            print(output)
        for name, config in configs.items():
            label = (
                "label=com.lasa.launcher="
                + hashlib.sha256(config["service"]["id"].encode()).hexdigest()
            )
            assert not docker("ps", "-aq", "--filter", label), "A task enclosure was left running"
            state = Path(config["storage"]["state_root"])
            with sqlite3.connect(state / "private" / "tasks.sqlite3") as store:
                assert store.execute("SELECT count(*) FROM runtimes").fetchone() == (0,)
            if not dlp or name not in {f"delegates-{mode}" for mode in DLP_MODES}:
                assert any((state / "workspaces").iterdir())
    except Exception:
        for container in (gateway, analyzer, *containers):
            if not container:
                continue
            logs = docker("logs", "--tail", "80", container, check=False)
            if logs:
                print(f"{container}\n{logs}", file=sys.stderr)
        raise
    finally:
        for container in reversed(containers):
            docker("stop", "-t", "5", container, check=False)
            docker("rm", "-f", container, check=False)
        for config in configs.values():
            label = (
                "label=com.lasa.launcher="
                + hashlib.sha256(config["service"]["id"].encode()).hexdigest()
            )
            remaining = docker("ps", "-aq", "--filter", label, check=False).splitlines()
            if remaining:
                docker("rm", "-f", *remaining)
        for volume in volumes:
            docker("volume", "rm", volume)
        if dlp:
            save(
                deployment_file, {"supervisor_network": namespace, "local_dlp": {"enabled": False}}
            )
            deploy_command(deployment_file, "apply")
            deployment = DockerDeployment.load(deployment_file)
            assert not deployment.compose("ps", "-aq")
            assert not docker(
                "network", "ls", "-q", "--filter", f"name=^{deployment.project}_backend$"
            )
        docker("network", "rm", namespace)


if __name__ == "__main__":
    if sys.argv[1:2] == ["fixture"]:
        serve_fixture(Path(sys.argv[2]))
    elif sys.argv[1:2] == ["verify"]:
        verify(Path(sys.argv[2]))
    elif sys.argv[1:2] == ["verify-dlp"]:
        verify_dlp(Path(sys.argv[2]))
    elif sys.argv[1:2] == ["verify-recovery"]:
        verify_recovery_canary(Path(sys.argv[2]))
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--service-image", default="lasa-supervisor:1.0.0")
        parser.add_argument("--launcher-image", default="lasa-launcher:1.0.0")
        parser.add_argument("--runtime-image", default="lasa-codex-worker:1.0.0")
        parser.add_argument(
            "--inspector-image", help="Verify the real local DLP gateway with this image."
        )
        parser.add_argument(
            "--recovery-canary",
            action="store_true",
            help="Exercise enforce recovery with the real local gateway.",
        )
        parser.add_argument("--presidio-image", default=PRESIDIO_IMAGE)
        parser.add_argument("--docker-socket", type=Path, default=Path("/var/run/docker.sock"))
        args = parser.parse_args()
        if args.recovery_canary and not args.inspector_image:
            parser.error("--recovery-canary requires --inspector-image")
        with tempfile.TemporaryDirectory(prefix="lasa-container-") as directory:
            run(args, Path(directory).resolve())
