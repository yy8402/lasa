import asyncio
import copy
import json
from pathlib import Path

import pytest

from lasa_service.contracts import canonical
from lasa_service.errors import LasaError
from lasa_service.planning import check_plan
from lasa_service.store import zero

from .conftest import (
    FakeRuntime,
    documents,
    example,
    new_session,
    settled,
    submit,
    task_request,
    token,
)


async def test_received_evaluating_then_admitted_and_verified(services):
    entered = asyncio.Event()
    resume = asyncio.Event()

    async def handler(context):
        assert context.document["status"] == "executing" and "admission" in context.document
        entered.set()
        await resume.wait()
        return await FakeRuntime().run(context)

    client, app = await services(runtime=FakeRuntime(handler))
    request = await task_request(client, app)
    response = await submit(client, app, request)
    assert response.json()["status"] == "evaluating" and "admission" not in response.json()
    await entered.wait()
    resume.set()
    result = await settled(client, response)
    assert result["status"] == "completed"
    app.state.coordinator.contracts.validate("Task", result)


@pytest.mark.parametrize(
    "change,code",
    [
        ("authority", "authority_denied"),
        ("budget", "capacity_exhausted"),
        ("content", "disclosure_denied"),
        ("offer", "offer_changed"),
    ],
)
async def test_receiver_admission_rejects_forged_or_expanded_request(services, change, code):
    client, app = await services()
    request = await task_request(client, app)
    if change == "authority":
        request["authorization_ref"] = "model-granted-authority"
    if change == "budget":
        request["requested_limits"]["budget"]["model_calls"] += 1
    if change == "content":
        request["diagnostics"] = "content"
    if change == "offer":
        request["selection"]["offer_revision"] = "old-revision"
    response = await submit(client, app, request)
    assert response.json()["code"] == code, response.text
    assert not app.state.coordinator.jobs


async def test_no_hidden_queue_one_active_task_per_session(services):
    started = asyncio.Event()
    finish = asyncio.Event()

    async def handler(context):
        started.set()
        await finish.wait()
        return await FakeRuntime().run(context)

    client, app = await services(runtime=FakeRuntime(handler))
    sid = await new_session(client, app)
    one = await submit(client, app, await task_request(client, app), sid)
    await started.wait()
    two = await submit(client, app, await task_request(client, app), sid)
    assert two.status_code == 409 and two.json()["code"] == "session_busy"
    finish.set()
    assert (await settled(client, one))["status"] == "completed"


async def test_permission_revocation_blocks_tool_before_effect(services):
    entered = asyncio.Event()
    resume = asyncio.Event()

    async def handler(context):
        entered.set()
        await resume.wait()
        await context.coordinator.broker.call(
            context.task_id,
            "action-write",
            "workspace.write",
            {"relative_path": "output.txt", "text": "blocked"},
        )
        return await FakeRuntime().run(context)

    client, app = await services(runtime=FakeRuntime(handler))
    response = await submit(client, app, await task_request(client, app))
    await entered.wait()
    path = Path(app.state.coordinator.config.document["authorization"]["policy_file"])
    policy = json.loads(path.read_text())
    policy["principals"][0]["rules"] = []
    path.write_text(json.dumps(policy))
    resume.set()
    result = await settled(client, response)
    assert result["status"] == "failed"
    assert not (app.state.coordinator.workspace(result["session_id"]).root / "output.txt").exists()


async def test_unknown_semantic_precondition_fails_closed_without_execution(services, tmp_path):
    raw = documents(tmp_path)
    path = Path(raw["contract_publishers"][0]["trusted_registry_file"])
    definition = example("capability-attempt")
    definition["version"] = "1.0.1"
    definition["preconditions"].append(
        {
            "kind": "semantic_review",
            "description": "Unknown execution premise",
            "criterion": "Access to an unproven resource",
            "evidence_required": ["verified access"],
        }
    )
    from lasa_service.capabilities import reference

    old = raw["published_contracts"][1]
    new = reference(definition)
    path.write_text(json.dumps([definition]))
    encoded = json.dumps(raw).replace(json.dumps(old), json.dumps(new))
    raw = json.loads(encoded)
    raw["verifiers"].append({"contract": new, "verifier_id": "task-attempt-v1"})
    policy_path = Path(raw["authorization"]["policy_file"])
    policy_path.write_text(policy_path.read_text().replace(json.dumps(old), json.dumps(new)))
    runtime = FakeRuntime()
    client, app = await services(raw=raw, runtime=runtime)
    response = await submit(client, app, await task_request(client, app))
    result = await settled(client, response)
    assert result["status"] == "rejected" and runtime.prompts == []


async def test_independent_verification_can_reject_schema_valid_claim(services):
    async def reject(*args):
        return False

    client, app = await services(verifier=reject)
    result = await settled(client, await submit(client, app, await task_request(client, app)))
    assert (
        result["status"] == "failed"
        and result["problem"]["code"] == "verification_failed"
        and "result" not in result
    )
    c = app.state.coordinator
    events = c.diagnostics.page(result["task_id"], {"subject": "alice"})["events"]
    rejection = next(
        e for e in events if e["kind"] == "verification" and e["payload"]["release"] == "rejected"
    )
    assert (
        rejection["payload"]["checks"][0]["summary"]
        == "Independent verifier rejected the candidate."
    )


async def test_task_and_events_are_owner_scoped(services):
    client, app = await services()
    response = await submit(client, app, await task_request(client, app))
    await settled(client, response)
    headers = {"Authorization": "Bearer " + token("bob", app.state.coordinator.config.service_id)}
    assert (await client.get(response.headers["Location"], headers=headers)).status_code == 404
    assert (
        await client.get(response.headers["Location"] + "/events", headers=headers)
    ).status_code == 404


async def test_clarification_revision_and_idempotent_answer(services):
    async def handler(context):
        answer = await context.coordinator.request_input(context.task_id, "Supply a name.")
        assert answer["answer"] == "Ada"
        return await FakeRuntime().run(context)

    client, app = await services(runtime=FakeRuntime(handler))
    request = await task_request(client, app)
    response = await submit(client, app, request)
    for _ in range(100):
        current = await client.get(response.headers["Location"])
        if current.json()["status"] == "awaiting_input":
            break
        await asyncio.sleep(0.005)
    question = current.json()["question"]
    body = {
        "operation_id": "answer-operation",
        "question_id": question["question_id"],
        "question_revision": question["revision"],
        "answer": "Ada",
    }
    url = response.headers["Location"] + "/inputs"
    missing = await client.post(url, json=body, headers={"Idempotency-Key": "answer-key"})
    assert missing.status_code == 428
    headers = {"Idempotency-Key": "answer-key", "If-Match": current.headers["etag"]}
    duplicate = {**body, "operation_id": "other-answer"}
    answer, concurrent = await asyncio.gather(
        client.post(url, json=body, headers=headers),
        client.post(url, json=duplicate, headers={**headers, "Idempotency-Key": "other-answer"}),
    )
    assert answer.status_code == 202
    assert concurrent.status_code in {409, 412}
    result = await settled(client, response)
    assert result["status"] == "completed"
    assert result["result"]["usage"]["input_bytes"] == len(canonical(request["input"])) + len(
        canonical("Ada")
    )
    replay = await client.post(url, json=body, headers=headers)
    assert replay.status_code == 202


async def test_plan_dag_coverage_and_aggregate_reservation(services):
    client, app = await services()
    c = app.state.coordinator
    request = await task_request(client, app)
    response = await submit(client, app, request)
    result = await settled(client, response)
    row, _ = c.store.task(result["task_id"])
    plan = json.loads(row["plan"])["document"]
    check_plan(plan, c.registry, request["requested_limits"]["budget"])
    cycle = copy.deepcopy(plan)
    cycle["steps"][0]["depends_on"] = [cycle["steps"][0]["step_id"]]
    with pytest.raises(LasaError):
        check_plan(cycle, c.registry, request["requested_limits"]["budget"])
    over = copy.deepcopy(plan)
    over["steps"][0]["allocation"]["budget"]["model_calls"] = request["requested_limits"]["budget"][
        "model_calls"
    ]
    with pytest.raises(LasaError):
        check_plan(over, c.registry, request["requested_limits"]["budget"])
    amount = zero()
    amount["model_calls"] = request["requested_limits"]["budget"]["model_calls"]
    with pytest.raises(LasaError):
        c.store.reserve(
            result["task_id"], "overspend", "test", amount, request["requested_limits"]["budget"]
        )


async def test_narrow_binding_cannot_use_broad_caller_resource_policy(services, tmp_path):
    raw = documents(tmp_path)
    for binding in raw["bindings"]:
        binding["approved_resources"] = [{"resource": "workspace:other", "actions": ["read"]}]

    async def handler(context):
        c = context.coordinator
        assert not c.permits(context.task_id, "workspace.read", "workspace:self", "read")
        with pytest.raises(LasaError, match="authority_denied"):
            await c.broker.call(
                context.task_id, "forbidden-read", "workspace.read", {"relative_path": "data.txt"}
            )
        return await FakeRuntime().run(context)

    client, app = await services(raw=raw, runtime=FakeRuntime(handler))
    assert (await settled(client, await submit(client, app, await task_request(client, app))))[
        "status"
    ] == "completed"


@pytest.mark.parametrize("dimension", ["tool_calls", "artifact_bytes"])
async def test_active_step_cannot_spend_sibling_or_integration_budget(
    services, tmp_path, dimension
):
    raw = documents(tmp_path)
    raw["limits"]["max_task_budget"][dimension] = 1
    raw["limits"]["integration_reserve"][dimension] = 0
    path = Path(raw["authorization"]["policy_file"])
    policy = json.loads(path.read_text())
    for principal in policy["principals"]:
        for rule in principal["rules"]:
            rule["budget"][dimension] = 1
    path.write_text(json.dumps(policy))

    async def planner(c, task_id, request, peer_catalog, requirements):
        base = {
            "requirement_ids": [r["requirement_id"] for r in requirements],
            "depends_on": [],
            "contract_digest": request["selection"]["contract"]["digest"],
            "input_json": canonical(request["input"]).decode(),
            "local_assessment": "sufficient",
            "assessment_summary": "Two independently bounded steps.",
        }
        return {"steps": [{**base, "step_id": "step-one"}, {**base, "step_id": "step-two"}]}

    calls = []

    async def handler(context):
        if context.binding is None:
            assert context.coordinator.broker._authorized(context.task_id) == set()
            return await FakeRuntime().run(context)
        assert context.limits["budget"][dimension] == 0
        if dimension == "tool_calls":
            with pytest.raises(LasaError, match="capacity_exhausted"):
                await context.coordinator.broker.call(
                    context.task_id,
                    "write-attempt",
                    "workspace.write",
                    {"relative_path": "blocked.txt", "text": "bad"},
                )
        else:
            with pytest.raises(LasaError, match="capacity_exhausted"):
                context.coordinator.snapshot_artifact(context.task_id, "text/plain", "x")
        calls.append(True)
        return await FakeRuntime().run(context)

    client, app = await services(raw=raw, planner=planner, runtime=FakeRuntime(handler))
    result = await settled(client, await submit(client, app, await task_request(client, app)))
    assert result["status"] == "completed" and calls


async def test_http_errors_follow_problem_contract(services):
    client, app = await services()
    base = app.state.coordinator.config.document["service"]["base_url"]
    missing = await client.get(base + "/tasks/unknown-task")
    assert missing.status_code == 404 and missing.headers["content-type"].startswith(
        "application/problem+json"
    )
    app.state.coordinator.contracts.validate("Problem", missing.json())
    unknown = await client.get(base + "/unknown-route")
    assert unknown.status_code == 404
    app.state.coordinator.contracts.validate("Problem", unknown.json())
