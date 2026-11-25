"""Durable execution facts support verification without overriding its verdict."""

import json
from pathlib import Path

import httpx
import pytest

from lasa_service.contracts import canonical, digest, parse_json
from lasa_service.errors import LasaError
from lasa_service.evidence import MAX_BYTES, append_evidence, verification_material
from lasa_service.planning import Planner, criterion_verdicts
from lasa_service.store import encode

from .conftest import (
    FakeRuntime,
    configuration,
    documents,
    operator_get,
    settled,
    submit,
    task_request,
)
from .protocol_helpers import verification_report


@pytest.mark.parametrize("passed", [True, False])
async def test_review_verification_separates_candidate_from_evidence(services, tmp_path, passed):
    raw = documents(tmp_path)
    custom = "Use the supplied review criterion to evaluate the candidate."
    prompts = dict(configuration(raw).prompts, outcome_verification=custom)
    prompt_path = tmp_path / "prompts.json"
    prompt_path.write_text(json.dumps(prompts))
    raw["prompts_file"] = str(prompt_path)
    inputs = {
        "design": "The operator checks each backup before marking it verified.",
        "criteria": [{"id": "check-first", "description": "Does the check occur first?"}],
    }
    output = {
        "coverage": [
            {
                "criterion_id": "check-first",
                "disposition": "reviewed",
                "evidence": inputs["design"],
            }
        ],
        "findings": [],
    }
    requests = []

    async def model(request):
        body = json.loads(request.content)
        assert body["text"]["format"]["name"] == "lasa_verification"
        developer, context, candidate = body["input"]
        assert [part["role"] for part in body["input"]] == ["developer", "user", "user"]
        instruction = developer["content"][0]["text"]
        assert custom in instruction
        assert "The last user message is the complete candidate_output JSON value" in instruction
        assert "already checked the candidate's output schema" in instruction
        facts = json.loads(context["content"][0]["text"])
        assert set(facts) == {
            "contract",
            "input",
            "claimed_evidence",
            "original_requirements",
            "trusted_execution_evidence",
            "criteria",
            "evidence_refs",
        }
        assert facts["input"] == inputs
        verdict_fields = body["text"]["format"]["schema"]["properties"]["criteria"]["items"][
            "properties"
        ]
        assert verdict_fields["criterion_id"]["enum"] == [item["id"] for item in facts["criteria"]]
        assert verdict_fields["evidence_refs"]["items"]["enum"] == facts["evidence_refs"]
        assert "output_schema" not in facts["contract"]
        assert facts["contract"]["ref"]["id"].endswith("/design.review")
        assert json.loads(candidate["content"][0]["text"]) == output
        verdict = verification_report(facts["criteria"], passed)
        requests.append(body)
        return httpx.Response(
            200,
            json={
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": json.dumps(verdict)}],
                    }
                ],
                "usage": {"total_tokens": 100},
            },
        )

    client, app = await services(raw=raw, model_transport=httpx.MockTransport(model))
    app.state.coordinator.planner.verifier = None
    body = await task_request(client, app, profile="design.review", inputs=inputs)
    result = await settled(client, await submit(client, app, body))
    assert len(requests) == 1
    if passed:
        assert result["status"] == "completed" and result["result"]["output"] == output
    else:
        assert result["status"] == "failed" and result["problem"]["code"] == "verification_failed"


@pytest.mark.parametrize("performed,accept", [(False, True), (True, True), (True, False)])
async def test_verifier_gets_receiver_receipts_and_verified_artifact_without_forced_pass(
    services, performed, accept
):
    observed = []

    async def handler(context):
        result = await FakeRuntime().run(context)
        if performed:
            context.coordinator.diagnostics.register_secret(
                context.task_id, "private-executor-token"
            )
            broker = context.coordinator.broker
            await broker.call(
                context.task_id,
                "write-proof",
                "workspace.write",
                {"relative_path": "proof.txt", "text": "verified readback"},
            )
            await broker.call(
                context.task_id, "read-proof", "workspace.read", {"relative_path": "proof.txt"}
            )
            artifact = context.coordinator.snapshot_artifact(
                context.task_id, "text/plain", "verified readback"
            )
            result["artifact_ids"] = [artifact["artifact_id"]]
        return result

    async def assess(task_id, purpose, payload, schema, **_):
        assert purpose == "verification"
        material = payload["trusted_execution_evidence"]
        observed.append(material)
        assert material["task_id"] == task_id and material["source"] == "receiver_durable_store"
        assert (
            "private-executor-token" in app.state.coordinator.diagnostics.active_secrets[task_id]
            if performed
            else True
        )
        if performed:
            write, read = material["operations"]
            assert write["succeeded"] and read["succeeded"]
            assert write["sequence"] < read["sequence"]
            assert write["input_digest"] == digest(write["content"]["request"])
            assert read["result_digest"] == digest(read["content"]["result"])
            assert read["content"]["result"]["value"]["text"] == "verified readback"
            assert material["artifacts"][0]["bytes_verified"]
            assert material["artifacts"][0]["content"]["text"] == "verified readback"
        else:
            assert material["operations"] == [] and material["artifacts"] == []
        return verification_report(payload["criteria"], performed and accept)

    client, app = await services(runtime=FakeRuntime(handler))
    c = app.state.coordinator
    c.planner.verifier = None
    c.models.ask = assess
    response = await submit(client, app, await task_request(client, app))
    result = await settled(client, response)
    assert result["status"] == ("completed" if performed and accept else "failed")
    assert observed
    assert result["task_id"] not in c.diagnostics.active_secrets
    if not (performed and accept):
        assert result["problem"]["code"] == "verification_failed" and "result" not in result
    page = (await operator_get(client, app, response.headers["Location"], "/events")).json()
    assert all("content" not in event for event in page["events"])


async def test_material_is_task_and_step_scoped_bounded_redacted_and_policy_checked(services):
    async def handler(context):
        broker = context.coordinator.broker
        await broker.call(
            context.task_id,
            "write-large",
            "workspace.write",
            {"relative_path": "large.txt", "text": "x" * 30000},
        )
        await broker.call(
            context.task_id,
            "write-secret",
            "workspace.write",
            {"relative_path": "secret.txt", "text": "test-model-key"},
        )
        return await FakeRuntime().run(context)

    client, app = await services(runtime=FakeRuntime(handler))
    c = app.state.coordinator
    result = await settled(client, await submit(client, app, await task_request(client, app)))
    assert result["status"] == "completed"
    task_id = result["task_id"]
    material = verification_material(c, task_id, step_id="step-main")
    assert len(material["operations"]) == 2 and material["truncated"]
    assert len(canonical(material)) <= MAX_BYTES
    assert "test-model-key" not in canonical(material).decode()
    assert material["operations"][0]["content_omitted"]
    assert material["operations"][1]["content"]["request"]["arguments"]["text"] == "[REDACTED]"
    material["dependencies"] = []
    append_evidence(
        c, task_id, material, "dependencies", {"step_id": "large-step"}, "x" * MAX_BYTES
    )
    append_evidence(
        c, task_id, material, "dependencies", {"step_id": "secret-step"}, "test-model-key"
    )
    assert len(canonical(material)) <= MAX_BYTES
    assert material["dependencies"][0]["content_omitted"]
    assert material["dependencies"][1]["content"] == "[REDACTED]"
    assert verification_material(c, task_id, step_id="another-step")["operations"] == []
    c.runtime = FakeRuntime()
    another = await settled(client, await submit(client, app, await task_request(client, app)))
    assert verification_material(c, another["task_id"])["operations"] == []
    path = Path(c.config.document["authorization"]["policy_file"])
    policy = json.loads(path.read_text())
    policy["principals"][0]["rules"][0]["effects"] = ["workspace.read"]
    path.write_text(json.dumps(policy))
    assert verification_material(c, task_id)["operations"] == []


async def test_changed_execution_facts_invalidate_cached_semantic_verdict(services):
    async def handler(context):
        await context.coordinator.broker.call(
            context.task_id,
            "write-proof",
            "workspace.write",
            {"relative_path": "proof.txt", "text": "first"},
        )
        return await FakeRuntime().run(context)

    client, app = await services(runtime=FakeRuntime(handler))
    result = await settled(client, await submit(client, app, await task_request(client, app)))
    c = app.state.coordinator
    calls = []

    async def assess(task_id, purpose, payload, schema, **_):
        calls.append(payload["trusted_execution_evidence"])
        return verification_report(payload["criteria"], len(calls) == 1)

    c.models.ask = assess
    planner = Planner(c)
    arguments = (
        result["task_id"],
        c.registry.get(result["selection"]["contract"]),
        c.request(result["task_id"])["input"],
        result["result"]["output"],
        result["result"]["evidence"],
    )
    assert await planner.verify(*arguments)
    assert await planner.verify(*arguments)
    assert len(calls) == 1
    row = c.store.db.execute(
        "SELECT result FROM actions WHERE task_id=?", (result["task_id"],)
    ).fetchone()
    changed = parse_json(row["result"])
    changed["value"]["bytes_written"] += 1
    c.store.db.execute(
        "UPDATE actions SET result=? WHERE task_id=?", (encode(changed), result["task_id"])
    )
    assert not await planner.verify(*arguments)
    assert len(calls) == 2 and digest(calls[0]) != digest(calls[1])


def test_criterion_verdicts_require_exact_coverage_and_known_evidence():
    criteria = [{"id": "first"}, {"id": "second"}]
    report = verification_report(criteria)
    assert criterion_verdicts(report, criteria, {"candidate"})
    report["criteria"][1]["disposition"] = "insufficient_evidence"
    assert not criterion_verdicts(report, criteria, {"candidate"})
    report["criteria"][1]["evidence_refs"] = ["unverified"]
    with pytest.raises(LasaError, match="verification_failed"):
        criterion_verdicts(report, criteria, {"candidate"})
    with pytest.raises(LasaError, match="verification_failed"):
        criterion_verdicts(verification_report(criteria[:1]), criteria, {"candidate"})


async def test_artifact_material_rejects_other_task_or_corrupt_snapshot(services):
    async def handler(context):
        result = await FakeRuntime().run(context)
        artifact = context.coordinator.snapshot_artifact(
            context.task_id, "text/plain", "verified snapshot"
        )
        result["artifact_ids"] = [artifact["artifact_id"]]
        return result

    client, app = await services(runtime=FakeRuntime(handler))
    c = app.state.coordinator
    first = await settled(client, await submit(client, app, await task_request(client, app)))
    second = await settled(client, await submit(client, app, await task_request(client, app)))
    first_id = first["result"]["artifacts"][0]["artifact_id"]
    second_id = second["result"]["artifacts"][0]["artifact_id"]
    with pytest.raises(LasaError, match="verification_failed"):
        verification_material(c, first["task_id"], artifact_ids=[second_id])
    c.store.db.execute("UPDATE artifacts SET content=? WHERE id=?", (b"corrupt", first_id))
    with pytest.raises(LasaError, match="verification_failed"):
        verification_material(c, first["task_id"], artifact_ids=[first_id])
