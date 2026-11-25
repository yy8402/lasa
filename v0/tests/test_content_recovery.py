"""Recovery attempts stay within content, authority, and dispatch boundaries."""

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from lasa_service.capabilities import reference
from lasa_service.config import Configuration
from lasa_service.content_security import Transfer
from lasa_service.contracts import canonical, digest
from lasa_service.errors import LasaError
from lasa_service.gateway import TaskGateway
from lasa_service.store import Store

from .conftest import (
    FakeRuntime,
    documents,
    example,
    settled,
    submit,
    task_request,
)
from .protocol_helpers import verification_report
from .test_content_security import configure_inspection, policy_for, verdict
from .test_source_outcomes import read_workflow, register_read

MARKER = "SYNTHETIC-OPTIONAL-CONTEXT"
ATTEMPT_INPUT = {
    "objective": "Complete the required verification.",
    "requirements": [
        {"id": "check", "description": "Verify the objective.", "acceptance": ["Return evidence."]}
    ],
    "context": MARKER,
}


def declared_context(raw):
    definition = example("capability-attempt")
    original = reference(definition)
    definition["version"] = "1.0.1"
    definition["input_schema"]["properties"]["context"]["x-lasa-optional-context"] = True
    ref = reference(definition)
    registry = Path(raw["contract_publishers"][0]["trusted_registry_file"])
    registry.write_text(json.dumps([*json.loads(registry.read_text()), definition]))
    policy = policy_for(raw)
    policy.write_text(policy.read_text().replace(json.dumps(original), json.dumps(ref)))
    raw = json.loads(json.dumps(raw).replace(json.dumps(original), json.dumps(ref)))
    raw["verifiers"].append({"contract": ref, "verifier_id": "task-attempt-v1"})
    return raw


def records(app, kind):
    return [
        json.loads(row[0])
        for row in app.state.coordinator.store.db.execute(
            "SELECT document FROM audit WHERE kind=? ORDER BY rowid", (kind,)
        )
    ]


@pytest.mark.parametrize("mode,limit", [("enforce", 1), ("enforce", 0), ("observe", 1)])
async def test_model_recovery_dispatches_only_the_permitted_candidate(
    services, tmp_path, mode, limit
):
    raw = declared_context(documents(tmp_path))
    configure_inspection(raw, "model", "request", mode=mode)
    raw.setdefault("limits", {})["content_recovery"] = {
        "max_candidate_revisions_per_transfer": limit
    }
    inspections, calls = [], []

    async def scanner(request):
        candidate = json.loads(request.content)
        inspections.append(candidate)
        if len(inspections) == 1 and mode == "enforce" and limit:
            return httpx.Response(503)
        return verdict(
            candidate,
            verdict="hard_deny" if MARKER in json.dumps(candidate["content"]) else "permit",
        )

    async def provider(request):
        body = json.loads(request.content)
        calls.append(body)
        if body.get("text", {}).get("format", {}).get("name") == "lasa_verification":
            return httpx.Response(
                200,
                json={
                    "output": [
                        {
                            "type": "message",
                            "content": [
                                {
                                    "type": "output_text",
                                    "text": json.dumps(
                                        verification_report(
                                            json.loads(body["input"][-2]["content"][0]["text"])[
                                                "criteria"
                                            ]
                                        )
                                    ),
                                }
                            ],
                        }
                    ],
                    "usage": {"total_tokens": 4},
                },
            )
        return httpx.Response(200, json={"output": [], "usage": {"total_tokens": 4}})

    async def execute(context):
        gateway = TaskGateway(context)
        try:
            await gateway.start()
            async with httpx.AsyncClient() as worker:
                reply = await worker.post(
                    gateway.url + "/model/responses",
                    headers={
                        "Authorization": "Bearer " + gateway.token,
                    },
                    json={
                        "model": context.coordinator.config.executor()["model"],
                        "input": [
                            {
                                "role": "user",
                                "content": [
                                    {
                                        "type": "input_text",
                                        "text": canonical(context.model_prompt()).decode(),
                                    }
                                ],
                            }
                        ],
                    },
                )
            if gateway.failure.done():
                raise gateway.failure.result()
            assert reply.status_code == 200
            return await FakeRuntime().run(context)
        finally:
            await gateway.close()

    client, app = await services(
        raw=raw,
        runtime=FakeRuntime(execute),
        model_transport=httpx.MockTransport(provider),
        inspection_transport=httpx.MockTransport(scanner),
    )
    c = app.state.coordinator
    if mode == "enforce" and limit:
        c.planner.verifier = None
    task = await settled(
        client,
        await submit(
            client,
            app,
            await task_request(client, app, profile="task.attempt", inputs=ATTEMPT_INPUT),
        ),
    )
    if mode == "observe":
        assert task["status"] == "completed" and MARKER in json.dumps(calls[0])
        assert len(inspections) == len(calls) == 1 and not records(app, "content_recovery")
        assert not records(app, "model_input_revision")
    elif not limit:
        assert task["problem"]["code"] == "disclosure_denied" and not calls
        assert len(inspections) == 1 and not records(app, "content_recovery")
        assert not records(app, "model_input_revision")
    else:
        assert task["status"] == "completed" and len(calls) == 2
        assert MARKER not in json.dumps(calls) and ATTEMPT_INPUT["objective"] in json.dumps(calls)
        assert len(inspections) == 4
        assert inspections[0]["inspection_digest"] == inspections[1]["inspection_digest"]
        assert len({value["inspection_id"] for value in inspections}) == 4
        assert MARKER not in json.dumps(inspections[-1])
        audit = records(app, "content_recovery")
        assert [value["action"] for value in audit] == ["inspection_retry", "candidate_revision"]
        assert len({value["transfer_id"] for value in audit}) == 1
        assert MARKER not in json.dumps(audit)
        (receipt,) = records(app, "model_input_revision")
        verifier = json.loads(calls[-1]["input"][-2]["content"][0]["text"])
        (step_input,) = verifier["trusted_execution_evidence"]["step_inputs"]
        (approved,) = [
            row
            for row in records(app, "content_decision")
            if row["transfer_id"] == receipt["transfer_id"]
            and row["reason_code"] == "policy_permit"
        ]
        assert any(
            row["transfer_id"] == receipt["transfer_id"] and row["outcome"] == "delivered"
            for row in records(app, "content_transfer")
        )
        original_plan = json.loads(c.store.task(task["task_id"])[0]["plan"])
        revised = {key: value for key, value in ATTEMPT_INPUT.items() if key != "context"}
        assert original_plan["inputs"][receipt["step_id"]] == ATTEMPT_INPUT
        assert verifier["input"] == revised
        assert step_input == {
            "step_id": receipt["step_id"],
            "content": revised,
            **verifier["input_revision"],
        }
        assert receipt["admitted_input_digest"] == digest(ATTEMPT_INPUT)
        assert receipt["input_digest"] == digest(revised)
        assert receipt["model_request_digest"] == approved["payload_digest"] == digest(calls[0])
        assert receipt["operation_id"] == approved["operation_id"]
        assert MARKER not in json.dumps(receipt)


async def test_delegate_recovery_keeps_receiver_and_required_input(services, tmp_path):
    raw = declared_context(documents(tmp_path / "parent", peer=True))
    raw["routing"]["preferred_executor"] = "peer"
    configure_inspection(raw, "delegates", "request")
    child_raw = declared_context(documents(tmp_path / "child", "layer2"))
    _, child = await services(raw=child_raw)
    posts = []
    transport = httpx.ASGITransport(app=child)

    async def capture(request):
        if request.method == "POST" and request.url.path.endswith("/tasks"):
            posts.append(json.loads(await request.aread()))
        return await transport.handle_async_request(request)

    async def scanner(request):
        body = json.loads(request.content)
        return verdict(
            body, verdict="hard_deny" if MARKER in json.dumps(body["content"]) else "permit"
        )

    client, app = await services(
        raw=raw,
        peer_transport=httpx.MockTransport(capture),
        inspection_transport=httpx.MockTransport(scanner),
    )
    task = await settled(
        client,
        await submit(
            client,
            app,
            await task_request(client, app, profile="task.attempt", inputs=ATTEMPT_INPUT),
        ),
    )
    assert task["status"] == "completed", task
    (sent,) = posts
    assert sent["input"] == {key: value for key, value in ATTEMPT_INPUT.items() if key != "context"}
    assert "delegation" not in sent and "authorization_ref" not in sent
    assert [value["action"] for value in records(app, "content_recovery")] == ["candidate_revision"]


@pytest.mark.parametrize("dependent", [False, True])
async def test_connector_recovery_preserves_schema_and_replay_identity(
    services, tmp_path, dependent
):
    raw = configure_inspection(documents(tmp_path), "connectors", "request")
    register_read(raw)
    connector_config = raw["executors"][0]["connectors"][0]
    connector_config["args"].append("--optional-note")
    operation = connector_config["operations"][0]
    operation["optional_context_arguments"] = ["note"]
    schema = operation["input_schema"]
    schema["properties"]["note"] = {"type": "string"}
    if dependent:
        connector_config["args"].append("--required-with-report")
        schema["dependentRequired"] = {"report_id": ["note"]}
    calls = []

    async def scanner(request):
        body = json.loads(request.content)
        return verdict(
            body, verdict="hard_deny" if MARKER in json.dumps(body["content"]) else "permit"
        )

    async def execute(context):
        args = {"report_id": "guide.md", "note": MARKER}
        for _ in range(2):
            await context.coordinator.broker.call(
                context.task_id, "source-read", "documents.read", args
            )
        return await read_workflow(context, no_operation=True)

    client, app = await services(
        raw=raw, runtime=FakeRuntime(execute), inspection_transport=httpx.MockTransport(scanner)
    )
    connector, _ = app.state.coordinator.broker.operations["documents.read"]

    async def call(_, arguments, _remaining, *, before_use):
        before_use()
        calls.append(arguments)
        return {"text": "Verified source text."}

    connector.call = call
    task = await settled(
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
    if dependent:
        assert task["problem"]["code"] == "disclosure_denied" and not calls
    else:
        assert task["status"] == "completed", task
        assert calls == [{"report_id": "guide.md"}]


async def test_intake_recovery_counts_against_the_admitted_task(services, tmp_path):
    raw = configure_inspection(documents(tmp_path), "caller", "request")
    configure_inspection(raw, "caller", "response")
    raw.setdefault("limits", {})["content_recovery"] = {"max_actions_per_task": 1}
    calls = []

    async def scanner(request):
        value = json.loads(request.content)
        calls.append(value["channel"])
        return (
            verdict(value) if calls == ["caller.request", "caller.request"] else httpx.Response(503)
        )

    client, app = await services(raw=raw, inspection_transport=httpx.MockTransport(scanner))
    task = await settled(client, await submit(client, app, await task_request(client, app)))
    assert task["problem"]["code"] == "content_gateway_unavailable"
    assert task["problem"]["instance"] == "urn:lasa:request"
    assert calls == ["caller.request", "caller.request", "candidate.release"]
    (reservation,) = records(app, "content_recovery")
    assert reservation["task_id"] == task["task_id"] and reservation["channel"] == "caller.request"


async def test_parallel_checks_share_a_task_recovery_budget(services, tmp_path):
    raw = configure_inspection(documents(tmp_path), "model", "request")
    raw.setdefault("limits", {})["content_recovery"] = {"max_actions_per_task": 1}
    simultaneous = asyncio.Event()
    calls = []

    async def scanner(request):
        calls.append(json.loads(request.content))
        if len(calls) == 2:
            simultaneous.set()
        await simultaneous.wait()
        return httpx.Response(503)

    async def execute(context):
        handler = context.coordinator.content
        result = await asyncio.gather(
            *(
                handler.check(
                    Transfer(
                        "reasoning.request",
                        "model:fixture",
                        "execution",
                        str(index),
                        context.task_id,
                    ),
                    {"input": [index]},
                    projection={"input": [index]},
                )
                for index in range(2)
            ),
            return_exceptions=True,
        )
        assert all(
            isinstance(item, LasaError) and item.code == "content_gateway_unavailable"
            for item in result
        )
        return await FakeRuntime().run(context)

    client, app = await services(
        raw=raw, runtime=FakeRuntime(execute), inspection_transport=httpx.MockTransport(scanner)
    )
    task = await settled(client, await submit(client, app, await task_request(client, app)))
    assert task["status"] == "completed"
    assert len(calls) == 3 and len(records(app, "content_recovery")) == 1


def test_reservation_survives_process_restart_and_intake_adoption(tmp_path):
    root = tmp_path / "store"
    record = {"task_id": None, "transfer_id": "transfer-fixture", "action": "inspection_retry"}
    store = Store(root)
    assert store.reserve_content_recovery(record, per_transfer=1, per_task=1)
    store.close()
    store = Store(root)
    try:
        assert not store.reserve_content_recovery(record, per_transfer=1, per_task=1)
        with store.transaction():
            store.adopt_intake_recovery("task-fixture", record["transfer_id"])
        assert not store.reserve_content_recovery(
            {**record, "task_id": "task-fixture", "transfer_id": "transfer-another"},
            per_transfer=1,
            per_task=1,
        )
    finally:
        store.close()


@pytest.mark.parametrize("limit", [-1, True, 2])
def test_rejects_invalid_service_recovery_limits(tmp_path, limit):
    raw = documents(tmp_path)
    raw.setdefault("limits", {})["content_recovery"] = {
        "max_candidate_revisions_per_transfer": limit
    }
    with pytest.raises(LasaError):
        Configuration.from_document(raw)
