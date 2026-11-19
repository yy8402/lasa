"""Exact source fields are assembled from operation artifacts, never model guesses."""

import hashlib
import json
import sys
from pathlib import Path

import httpx
import pytest

from lasa_service.capabilities import reference
from lasa_service.contracts import canonical, digest
from lasa_service.errors import LasaError
from lasa_service.outcomes import source_output

from .conftest import FakeRuntime, documents, example, settled, submit, task_request
from .test_connector_transports import LIMITS, operation


def register_read(raw, *, local=True):
    definition = example("capability-documents-read")
    ref = reference(definition)
    path = Path(raw["contract_publishers"][0]["trusted_registry_file"])
    path.write_text(json.dumps([*json.loads(path.read_text()), definition]))
    raw["verifiers"].append({"contract": ref, "verifier_id": "documents-read-v1"})
    raw["published_contracts"].append(ref)
    if local:
        op = operation("documents.read")
        op["resource"] = "documents:lasa"
        op["argument_constraints"] = {
            "properties": {"report_id": {"enum": ["guide.md", "other.md"]}}
        }
        op["task_input_bindings"] = [
            {"input_field": "document_id", "argument_field": "report_id", "comparison": "exact"}
        ]
        resource = {
            "id": "document-source",
            "kind": "mcp-stdio",
            "command": sys.executable,
            "args": ["-u", str((Path(__file__).parent / "fixtures/mcp_server.py").resolve())],
            "secret_env": {},
            "limits": LIMITS,
            "operations": [op],
        }
        Path(raw["executors"][0]["connector_policy_file"]).write_text(
            json.dumps({"connectors": [resource]})
        )
        raw["bindings"].append(
            {
                "binding_id": "binding-documents-read",
                "contract": ref,
                "executor_id": raw["executors"][0]["id"],
                "approved_resources": [{"resource": "documents:lasa", "actions": ["read"]}],
                "allowed_effects": ["external.read"],
                "required_operations": ["documents.read"],
            }
        )
    path = Path(raw["authorization"]["policy_file"])
    policy = json.loads(path.read_text())
    for principal in policy["principals"]:
        for rule in principal["rules"]:
            rule["contracts"].append(ref)
            rule["delegated_contracts"].append(ref)
            if "external.read" not in rule["effects"]:
                rule["effects"].append("external.read")
            rule["resources"].append({"resource": "documents:lasa", "actions": ["read"]})
    path.write_text(json.dumps(policy))
    return ref


async def read_workflow(context, *, wrong_argument=False, no_operation=False):
    if not no_operation:
        from lasa_service.connector_schema import validate

        catalog = await context.coordinator.broker.tools(context.task_id)
        schema = next(tool["inputSchema"] for tool in catalog if tool["name"] == "documents_read")
        validate(schema, {"report_id": context.prompt["input"]["document_id"]})
        with pytest.raises(LasaError):
            validate(schema, {"report_id": "other.md"})
        await context.coordinator.broker.call(
            context.task_id,
            "source-read",
            "documents.read",
            {"report_id": "other.md" if wrong_argument else context.prompt["input"]["document_id"]},
        )
    return {
        "output": {"ready_for_verification": True},
        "evidence": [
            {
                "criterion_id": item["id"],
                "disposition": "passed",
                "summary": "The approved source operation returned the requested document.",
                "artifact_ids": [],
            }
            for item in context.definition["postconditions"]
        ],
        "artifact_ids": [],
    }


@pytest.mark.parametrize(
    "mode", ["success", "wrong-document", "no-operation", "semantic-rejection"]
)
async def test_source_receipts_exact_assembly_scope_and_independent_rejection(
    services, tmp_path, mode
):
    raw = documents(tmp_path)
    register_read(raw)

    async def handler(context):
        return await read_workflow(
            context, wrong_argument=mode == "wrong-document", no_operation=mode == "no-operation"
        )

    client, app = await services(raw=raw, runtime=FakeRuntime(handler))
    c = app.state.coordinator

    async def assess(task_id, purpose, payload, schema):
        if purpose == "verification":
            checked = payload["trusted_execution_evidence"]["source_validation"]
            assert checked["source"] == "receiver_deterministic_checks"
            assert checked["output_digest"] == digest(payload["candidate_output"])
            assert "UTF-8 content hashes" in checked["checks"]
        return {"passed": mode != "semantic-rejection", "reason": "Controlled independent verdict."}

    c.planner.verifier = None
    c.models.ask = assess
    request = await task_request(
        client,
        app,
        profile="documents.read",
        inputs={"collection": "lasa-docs", "document_id": "guide.md"},
    )
    result = await settled(client, await submit(client, app, request))
    if mode == "success":
        assert result["status"] == "completed", result
        output = result["result"]["output"]
        assert output["content"] == "Report guide.md"
        assert (
            output["content_digest"]
            == "sha256:" + hashlib.sha256(output["content"].encode()).hexdigest()
        )
        manifest = result["result"]["artifacts"][0]
        assert manifest["provenance"]["input_digest"] == digest(request["input"])
        assert manifest["provenance"]["contract"] == request["selection"]["contract"]
        assert manifest["digest"] == manifest["provenance"]["result_digest"]
    else:
        assert result["status"] == "failed" and "result" not in result
        assert result["problem"]["code"] == (
            "authority_denied" if mode == "wrong-document" else "verification_failed"
        )


@pytest.mark.parametrize("tamper", ["none", "artifact-bytes", "output-digest", "output-content"])
async def test_parent_verifies_actual_child_source_artifact_bytes(services, tmp_path, tamper):
    child_raw = documents(tmp_path / "child", "layer2")
    register_read(child_raw)
    child_client, child_app = await services(raw=child_raw, runtime=FakeRuntime(read_workflow))
    inner = httpx.ASGITransport(app=child_app)

    class Transport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            response = await inner.handle_async_request(request)
            content = await response.aread()
            if tamper == "artifact-bytes" and "/artifacts/" in request.url.path:
                content = b"changed source bytes"
            elif tamper.startswith("output-") and "/tasks/" in request.url.path:
                body = json.loads(content)
                if body.get("status") == "completed" and "result" in body:
                    output = body["result"]["output"]
                    if tamper == "output-digest":
                        output["content_digest"] = "sha256:" + "0" * 64
                    else:
                        output["content"] = "model-authored replacement"
                    content = json.dumps(body).encode()
            return httpx.Response(
                response.status_code, content=content, headers=response.headers, request=request
            )

    raw = documents(tmp_path / "parent", peer=True)
    register_read(raw, local=False)
    client, app = await services(raw=raw, peer_transport=Transport())
    result = await settled(
        client,
        await submit(
            client,
            app,
            await task_request(
                client,
                app,
                profile="documents.read",
                inputs={"collection": "lasa-docs", "document_id": "guide.md"},
            ),
        ),
    )
    assert result["status"] == ("completed" if tamper == "none" else "failed"), result
    if tamper == "none":
        assert result["result"]["output"]["content"] == "Report guide.md"
        assert (
            result["result"]["artifacts"][0]["provenance"]["service_id"]
            == child_raw["service"]["id"]
        )
        assert app.state.coordinator.store.children(result["task_id"])


def material(contract, inputs, values):
    artifacts = []
    for sequence, (resource, value) in enumerate(values, 1):
        data = canonical(value)
        artifacts.append(
            {
                "manifest": {
                    "digest": digest(value),
                    "provenance": {
                        "kind": "operation-result",
                        "service_id": "https://source.example.net/lasa",
                        "sequence": sequence,
                        "contract": contract,
                        "input_digest": digest(inputs),
                        "resource": resource,
                        "result_digest": digest(value),
                    },
                },
                "bytes_verified": True,
                "content": {"text": data.decode()},
            }
        )
    return {"artifacts": artifacts}


@pytest.mark.parametrize(
    "alteration", ["digest", "bytes", "oversized", "truncated", "other-input", "workspace-export"]
)
def test_source_assembly_rejects_altered_missing_or_oversized_facts(alteration):
    ref = reference(example("capability-documents-read"))
    inputs = {"collection": "lasa-docs", "document_id": "guide.md"}
    proof = material(ref, inputs, [("documents:lasa", {"text": "source"})])
    artifact = proof["artifacts"][0]
    if alteration == "digest":
        artifact["manifest"]["digest"] = "sha256:" + "0" * 64
    elif alteration == "bytes":
        artifact["content"]["text"] = '{"text":"changed"}'
    elif alteration == "oversized":
        proof = material(ref, inputs, [("documents:lasa", {"text": "x" * 8193})])
    elif alteration == "truncated":
        artifact.pop("content")
        artifact["content_omitted"] = True
    elif alteration == "other-input":
        artifact["manifest"]["provenance"]["input_digest"] = digest({"different": "document"})
    else:
        artifact["manifest"].pop("provenance")
    with pytest.raises(LasaError, match="verification_failed"):
        source_output("documents-read-v1", ref, inputs, proof)


def test_application_search_and_http_mcp_index_use_exact_recorded_values():
    search_ref = reference(example("capability-documents-search"))
    inputs = {"collection": "python-sdk-root", "query": "read", "limit": 1}
    entries = [
        {
            "name": "README.md",
            "type": "file",
            "html_url": "https://github.com/modelcontextprotocol/python-sdk/blob/main/README.md",
        },
        {
            "name": "read-extra.md",
            "type": "file",
            "html_url": "https://github.com/modelcontextprotocol/python-sdk/blob/main/read-extra.md",
        },
        {
            "name": "reader.py",
            "type": "file",
            "html_url": "https://github.com/modelcontextprotocol/python-sdk/blob/main/reader.py",
        },
    ]
    result = source_output(
        "documents-search-v1",
        search_ref,
        inputs,
        material(search_ref, inputs, [("repository:python-sdk", entries)]),
    )
    assert result["truncated"] and result["matches"][0]["document_id"] == "README.md"
    ref = reference(example("capability-repository-inspect"))
    inputs = {"repository": "modelcontextprotocol/python-sdk"}
    metadata = {
        "full_name": inputs["repository"],
        "description": "Observed metadata",
        "default_branch": "main",
        "html_url": "https://github.com/" + inputs["repository"],
    }
    index = "# Exact index\n- Introduction\n- Clients\n"
    proof = material(
        ref,
        inputs,
        [("repository:python-sdk", metadata), ("documentation:python-sdk", {"result": index})],
    )
    result = source_output("repository-inspect-v1", ref, inputs, proof)
    assert (
        result["documentation_index"] == index and result["description"] == metadata["description"]
    )
