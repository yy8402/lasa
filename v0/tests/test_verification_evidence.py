"""Durable execution facts support verification without overriding its verdict."""

import json
from pathlib import Path

import pytest

from lasa_service.contracts import canonical, digest, parse_json
from lasa_service.errors import LasaError
from lasa_service.evidence import MAX_BYTES, append_evidence, verification_material
from lasa_service.planning import Planner
from lasa_service.store import encode

from .conftest import FakeRuntime, settled, submit, task_request


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

    async def assess(task_id, purpose, payload, schema):
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
        return {
            "passed": performed and accept,
            "reason": "Recorded evidence assessed independently.",
        }

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
    page = (await client.get(response.headers["Location"] + "/events")).json()
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

    async def assess(task_id, purpose, payload, schema):
        calls.append(payload["trusted_execution_evidence"])
        return {"passed": len(calls) == 1, "reason": "Each distinct durable fact set is assessed."}

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
