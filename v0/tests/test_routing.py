import json
from pathlib import Path

import httpx
import pytest

from lasa_service.capabilities import reference
from lasa_service.config import packaged_defaults
from lasa_service.contracts import canonical
from lasa_service.routing import decide

from .conftest import (
    FakeRuntime,
    add_delegation_grant,
    deterministic_planner,
    documents,
    example,
    new_session,
    operator_get,
    settled,
    submit,
    task_request,
)
from .protocol_helpers import verification_report


@pytest.mark.parametrize(
    "local,peer,preference,expected",
    [
        ("sufficient", "matched", "local", "local"),
        ("sufficient", "matched", "peer", "peer"),
        ("sufficient", "unknown", "peer", "local"),
        ("sufficient", "not_configured", "peer", "local"),
        ("insufficient", "matched", "local", "peer"),
        ("insufficient", "not_claimed", "peer", "none"),
        ("insufficient", "unknown", "peer", "none"),
        ("insufficient", "not_configured", "local", "none"),
    ],
)
def test_route_selection_uses_controller_eligibility(local, peer, preference, expected):
    assert decide(local, peer, {"preferred_executor": preference}) == expected


async def test_parent_reports_no_effect_when_delegate_attempts_a_write(services, tmp_path):
    async def write(context):
        await context.coordinator.broker.call(
            context.task_id,
            "child-write",
            "workspace.write",
            {"relative_path": "proof.txt", "text": "Denied cross-domain write"},
        )

    _, child = await services(
        raw=documents(tmp_path / "child", "layer2"), runtime=FakeRuntime(write)
    )
    raw = documents(tmp_path / "parent", peer=True)
    raw["routing"]["preferred_executor"] = "peer"
    client, app = await services(raw=raw, peer_transport=httpx.ASGITransport(app=child))
    result = await settled(client, await submit(client, app, await task_request(client, app)))
    assert result["status"] == "failed"
    assert result["problem"]["code"] == "authority_denied"
    assert result["problem"]["effect_disposition"] == "none"
    (delegate,) = app.state.coordinator.store.children(result["task_id"])
    receiver = child.state.coordinator
    _, task = receiver.store.task(delegate["task_id"])
    assert not (receiver.workspace(task["session_id"]).root / "proof.txt").exists()


async def review_plan(c, task_id, request, contracts, requirements):
    ref = next(
        x["contract"]
        for x in c.config.document["verifiers"]
        if x["verifier_id"] == "design-review-v1"
    )
    return {
        "steps": [
            {
                "step_id": "step-review",
                "requirement_ids": [r["requirement_id"] for r in requirements],
                "depends_on": [],
                "contract_digest": ref["digest"],
                "input_json": canonical(
                    {
                        "design": request["input"].get("context", "The parent verifies outcomes."),
                        "criteria": [
                            {
                                "id": "criterion-accountability",
                                "description": "Check parent accountability.",
                            }
                        ],
                    }
                ).decode(),
            }
        ]
    }


def publish_only_attempt(raw):
    raw["published_contracts"] = [
        x for x in raw["published_contracts"] if x["id"].endswith("/task.attempt")
    ]
    return raw


async def test_peer_pinned_authority_and_verified_predecessor_output(services, tmp_path):
    child_raw = publish_only_attempt(documents(tmp_path / "child", "layer2"))
    runtime = FakeRuntime()
    _, child = await services(raw=child_raw, runtime=runtime)

    async def plan(c, task_id, request, contracts, requirements):
        review = (await review_plan(c, task_id, request, contracts, requirements))["steps"][0]
        main = (await deterministic_planner(c, task_id, request, contracts, requirements))["steps"][
            0
        ]
        return {
            "steps": [{**review, "requirement_ids": []}, {**main, "depends_on": ["step-review"]}]
        }

    raw = documents(tmp_path / "parent", peer=True)
    raw["routing"]["preferred_executor"] = "peer"
    client, app = await services(
        raw=raw, planner=plan, peer_transport=httpx.ASGITransport(app=child)
    )
    parent = app.state.coordinator
    result = await settled(client, await submit(client, app, await task_request(client, app)))
    assert result["status"] == "completed", result
    (receipt,) = parent.store.children(result["task_id"])
    receiver = child.state.coordinator
    request = receiver.request(receipt["task_id"])
    assert receiver.authority(receipt["task_id"])["authorization_ref"] == "default"
    assert "authorization_ref" not in request and "delegation" not in request
    assert request["imports"] == runtime.prompts[0]["imports"]
    (entry,) = request["imports"]
    assert entry["label"] == "step-review"
    assert set(entry) == {"label", "contract", "output", "output_digest"}
    assert entry["output"]["coverage"][0]["evidence"] == "The parent verifies outcomes."
    assert runtime.prompts[0]["input"]["requirements"][0]["id"] == "requirement-main"


async def test_delegation_delivers_only_selected_session_artifact(services, tmp_path):
    definition = example("capability-attempt")
    definition["id"] = definition["id"].replace("task.attempt", "artifact.attempt")
    schema = definition["input_schema"]
    schema["properties"]["snapshot"] = {
        "type": "object",
        "properties": {"artifact_id": {"type": "string"}, "digest": {"type": "string"}},
        "required": ["artifact_id", "digest"],
        "additionalProperties": False,
    }
    schema["required"].append("snapshot")
    predicate = {
        "kind": "artifact_present",
        "description": "Use the exact text snapshot.",
        "input_field": "snapshot",
        "media_type": "text/plain",
    }

    definition["preconditions"].append(predicate)
    ref = reference(definition)

    def configure(raw, child=False):
        registry = Path(raw["contract_publishers"][0]["trusted_registry_file"])
        registry.write_text(json.dumps([*json.loads(registry.read_text()), definition]))
        binding = next(x for x in raw["bindings"] if x["contract"]["id"].endswith("/task.attempt"))
        raw["bindings"].append({**binding, "binding_id": "artifact-attempt", "contract": ref})
        raw["verifiers"].append({"contract": ref, "verifier_id": "task-attempt-v1"})
        if child:
            raw["published_contracts"] = [ref]
        else:
            raw["published_contracts"].append(ref)
            raw["routing"]["preferred_executor"] = "peer"
        path = Path(raw["authorization"]["policy_file"])
        policy = json.loads(path.read_text())
        for principal in policy["principals"]:
            for rule in principal["rules"]:
                rule["contracts"].append(ref)
                add_delegation_grant(raw, rule, ref)
        path.write_text(json.dumps(policy))
        return raw

    async def create_snapshot(context):
        result = await FakeRuntime().run(context)
        for text in ("Use this snapshot.", "Keep this snapshot private."):
            artifact = context.coordinator.snapshot_artifact(context.task_id, "text/plain", text)
            result["artifact_ids"].append(artifact["artifact_id"])
        return result

    leaf = FakeRuntime()
    _, child = await services(
        raw=configure(documents(tmp_path / "child", "layer2"), True), runtime=leaf
    )
    client, app = await services(
        raw=configure(documents(tmp_path / "parent", peer=True)),
        runtime=FakeRuntime(create_snapshot),
        peer_transport=httpx.ASGITransport(app=child),
    )
    session_id = await new_session(client, app)
    first = await task_request(client, app)
    source = await settled(client, await submit(client, app, first, session_id))
    assert source["status"] == "completed", source
    selected, private = source["result"]["artifacts"]
    for snapshot in (selected, private):
        assert snapshot["source_task_id"] == source["task_id"]
    inputs = {
        **first["input"],
        "snapshot": {key: selected[key] for key in ("artifact_id", "digest")},
    }
    out_of_scope = await task_request(client, app, profile="artifact.attempt", inputs=inputs)
    other = await settled(client, await submit(client, app, out_of_scope))
    assert not app.state.coordinator.store.children(other["task_id"]) and not leaf.prompts
    second = await task_request(client, app, profile="artifact.attempt", inputs=inputs)
    completed = await settled(client, await submit(client, app, second, session_id))
    assert completed["status"] == "completed", completed
    assert leaf.prompts[0]["input_artifacts"] == [
        {"manifest": selected, "text": "Use this snapshot."}
    ]


@pytest.mark.parametrize("preference", ["local", "peer"])
async def test_two_service_http_preferences_and_diagnostics(services, tmp_path, preference):
    child_client, child_app = await services(raw=documents(tmp_path / "child", "layer2"))
    raw = documents(tmp_path / "parent", peer=True)
    raw["routing"]["preferred_executor"] = preference
    runtime = FakeRuntime()
    client, app = await services(
        raw=raw, runtime=runtime, peer_transport=httpx.ASGITransport(app=child_app)
    )
    result = await settled(client, await submit(client, app, await task_request(client, app)))
    assert result["status"] == "completed", result
    assert result["result"]["effect_disposition"] == "none"
    children = app.state.coordinator.store.children(result["task_id"])
    assert bool(children) == (preference == "peer")
    events = (
        await operator_get(
            client, app, raw["service"]["base_url"] + "/tasks/" + result["task_id"], "/events"
        )
    ).json()["events"]
    routing = next(x for x in events if x["kind"] == "routing")["payload"]
    assert routing["selected_executor"] == preference
    report = (
        await operator_get(
            client, app, raw["service"]["base_url"] + "/tasks/" + result["task_id"], "/delegations"
        )
    ).json()
    assert bool(report["children"]) == (preference == "peer")
    if preference == "peer":
        assert report["children"][0]["task_id"] == children[0]["task_id"]
        assert report["children"][0]["service_id"] == child_app.state.coordinator.config.service_id
    if preference == "peer":
        call = next(
            x
            for x in events
            if x["kind"] == "call"
            and x["payload"]["call_type"] == "child"
            and x["payload"]["phase"] == "finished"
        )
        assert call["payload"]["peer_service_id"] == child_app.state.coordinator.config.service_id
        assert call["payload"]["child_task_id"] == children[0]["task_id"]


async def test_unclaimed_typed_contract_does_not_become_an_attempt(services, tmp_path):
    raw_child = publish_only_attempt(documents(tmp_path / "child", "layer2"))
    _, child_app = await services(raw=raw_child)
    raw = documents(tmp_path / "parent", peer=True)
    raw["bindings"] = [x for x in raw["bindings"] if x["contract"]["id"].endswith("/task.attempt")]
    client, app = await services(
        raw=raw, planner=review_plan, peer_transport=httpx.ASGITransport(app=child_app)
    )
    result = await settled(client, await submit(client, app, await task_request(client, app)))
    assert result["status"] == "rejected" and result["problem"]["code"] == "unsupported_contract"
    assert not app.state.coordinator.store.children(result["task_id"])


async def test_peer_capability_without_parent_local_binding(services, tmp_path):
    child_client, child_app = await services(raw=documents(tmp_path / "child", "layer2"))
    raw = documents(tmp_path / "parent", peer=True)
    raw["bindings"] = [x for x in raw["bindings"] if x["contract"]["id"].endswith("/task.attempt")]
    client, app = await services(
        raw=raw, planner=review_plan, peer_transport=httpx.ASGITransport(app=child_app)
    )
    result = await settled(client, await submit(client, app, await task_request(client, app)))
    assert result["status"] == "completed", result
    assert app.state.coordinator.store.children(result["task_id"])[0]["request"]["selection"][
        "contract"
    ]["id"].endswith("/design.review")


async def test_unreachable_peer_is_unknown_and_cannot_trigger_fallback(services, tmp_path):
    async def unavailable(request):
        return httpx.Response(503, json={"unavailable": True})

    raw = documents(tmp_path, peer=True)
    raw["bindings"] = [x for x in raw["bindings"] if x["contract"]["id"].endswith("/task.attempt")]
    client, app = await services(
        raw=raw, planner=review_plan, peer_transport=httpx.MockTransport(unavailable)
    )
    result = await settled(client, await submit(client, app, await task_request(client, app)))
    assert result["status"] == "rejected" and not app.state.coordinator.store.children(
        result["task_id"]
    )
    events = (
        await operator_get(
            client, app, raw["service"]["base_url"] + "/tasks/" + result["task_id"], "/events"
        )
    ).json()["events"]
    assert events[0]["payload"]["peer_assessment"] == "unknown"


async def test_explicit_attempt_can_report_unable(services, tmp_path):
    async def unable(context):
        return {
            "output": {
                "disposition": "unable",
                "reason": "Cannot supply the review.",
                "unsatisfied_requirements": [
                    x["id"] for x in context.prompt["input"]["requirements"]
                ],
            },
            "evidence": [
                {
                    "criterion_id": "honest-disposition",
                    "disposition": "passed",
                    "summary": "Explicit inability.",
                    "artifact_ids": [],
                }
            ],
            "artifact_ids": [],
        }

    _, child_app = await services(
        raw=publish_only_attempt(documents(tmp_path / "child", "layer2")),
        runtime=FakeRuntime(unable),
    )
    raw = documents(tmp_path / "parent", peer=True)
    raw["routing"]["preferred_executor"] = "peer"
    client, app = await services(raw=raw, peer_transport=httpx.ASGITransport(app=child_app))
    result = await settled(client, await submit(client, app, await task_request(client, app)))
    assert result["status"] == "completed"
    assert result["result"]["output"]["disposition"] == "unable"


@pytest.mark.parametrize("tamper", ["request", "artifact"])
async def test_parent_rejects_mismatched_child_or_corrupt_artifact(services, tmp_path, tamper):
    async def artifact_result(context):
        c = context.coordinator
        manifest = c.snapshot_artifact(context.task_id, "text/plain", "proof")
        result = await FakeRuntime().run(context)
        result["artifact_ids"] = [manifest["artifact_id"]]
        return result

    child_client, child_app = await services(
        raw=documents(tmp_path / "child", "layer2"), runtime=FakeRuntime(artifact_result)
    )
    transport = httpx.ASGITransport(app=child_app)

    class TamperTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            response = await transport.handle_async_request(request)
            content = await response.aread()
            if tamper == "artifact" and "/artifacts/" in request.url.path:
                return httpx.Response(200, content=b"wrong", request=request)
            if (
                tamper == "request"
                and request.method == "GET"
                and "/tasks/" in request.url.path
                and "/artifacts/" not in request.url.path
            ):
                data = json.loads(content)
                if data.get("status") == "completed":
                    data["request_digest"] = "sha256:" + "0" * 64
                return httpx.Response(
                    response.status_code, json=data, headers=response.headers, request=request
                )
            return httpx.Response(
                response.status_code, content=content, headers=response.headers, request=request
            )

    raw = documents(tmp_path / "parent", peer=True)
    raw["routing"]["preferred_executor"] = "peer"
    client, app = await services(raw=raw, peer_transport=TamperTransport())
    result = await settled(client, await submit(client, app, await task_request(client, app)))
    assert result["status"] == ("indeterminate" if tamper == "request" else "failed")
    assert "result" not in result
    assert result["problem"]["effect_disposition"] == ("unknown" if tamper == "request" else "none")


@pytest.mark.parametrize(
    "field,value",
    [
        ("delegation", {"recipient_service_id": "https://elsewhere.example.net"}),
        ("authorization_ref", "configured-rule"),
        ("diagnostics", "content"),
    ],
)
async def test_receiver_rejects_provider_fields_from_authenticated_peer(
    services, tmp_path, field, value
):
    from .conftest import token

    client, app = await services(raw=documents(tmp_path, "layer2"))
    client.headers["Authorization"] = "Bearer " + token(
        "peer-layer1", app.state.coordinator.config.service_id
    )
    request = await task_request(client, app)
    request[field] = value
    response = await submit(client, app, request)
    assert response.status_code == 400 and response.json()["code"] == "invalid_input"
    assert not app.state.coordinator.jobs


@pytest.mark.parametrize(
    "predicate,state",
    [
        (
            {
                "kind": "budget_minimum",
                "description": "Requires unavailable capacity",
                "resource": "model_calls",
                "minimum": 1000,
            },
            "unavailable",
        ),
        (
            {
                "kind": "resource_authorized",
                "description": "Requires a restricted resource",
                "resource": "private:unavailable",
                "actions": ["read"],
            },
            "denied",
        ),
        (
            {
                "kind": "semantic_review",
                "description": "Unknown premise",
                "criterion": "Unproven access",
                "evidence_required": ["verified access"],
            },
            "unknown",
        ),
    ],
)
async def test_claimed_but_unsuitable_peer_uses_admissible_local_without_fallback(
    services, tmp_path, predicate, state
):
    child_raw = documents(tmp_path / "child", "layer2")
    path = Path(child_raw["authorization"]["policy_file"])
    policy = json.loads(path.read_text())
    for principal in policy["principals"]:
        for rule in principal["rules"]:
            rule["offer_preconditions"] = [predicate]
    path.write_text(json.dumps(policy))
    child_client, child_app = await services(raw=child_raw)
    raw = documents(tmp_path / "parent", peer=True)
    raw["routing"]["preferred_executor"] = "peer"
    client, app = await services(raw=raw, peer_transport=httpx.ASGITransport(app=child_app))
    result = await settled(client, await submit(client, app, await task_request(client, app)))
    assert result["status"] == "completed" and not app.state.coordinator.store.children(
        result["task_id"]
    )
    event = next(
        x
        for x in (
            await operator_get(
                client, app, raw["service"]["base_url"] + "/tasks/" + result["task_id"], "/events"
            )
        ).json()["events"]
        if x["kind"] == "routing"
    )
    assert (
        event["payload"]["peer_assessment"] == state
        and event["payload"]["selected_executor"] == "local"
    )


async def test_receiver_applies_offer_additional_preconditions(services, tmp_path):
    raw = documents(tmp_path)
    path = Path(raw["authorization"]["policy_file"])
    policy = json.loads(path.read_text())
    policy["principals"][0]["rules"][0]["offer_preconditions"] = [
        {
            "kind": "resource_authorized",
            "description": "Requires an absent resource.",
            "resource": "private:absent",
            "actions": ["read"],
        }
    ]
    path.write_text(json.dumps(policy))
    runtime = FakeRuntime()
    client, app = await services(raw=raw, runtime=runtime)
    result = await settled(client, await submit(client, app, await task_request(client, app)))
    assert result["status"] == "rejected" and not runtime.prompts


@pytest.mark.parametrize("use_defaults, valid_review", [(False, True), (True, True), (True, False)])
async def test_last_assessment_usage_is_accounted_before_child_admission(
    services, tmp_path, use_defaults, valid_review
):
    _, child_app = await services(raw=documents(tmp_path / "child", "layer2"))
    raw = documents(tmp_path / "parent", peer=True)
    raw["routing"]["preferred_executor"] = "peer"
    if use_defaults:
        for key in ("assessment_budget", "max_task_budget", "integration_reserve"):
            raw["limits"].pop(key)
    else:
        raw["limits"]["max_task_budget"]["model_tokens"] = 200000
        raw["limits"]["assessment_budget"]["model_tokens"] = 100000
    budget = raw["limits"].get("max_task_budget", packaged_defaults()["limits"]["max_task_budget"])
    path = Path(raw["authorization"]["policy_file"])
    policy = json.loads(path.read_text())
    for p in policy["principals"]:
        for rule in p["rules"]:
            rule["budget"] = budget
    path.write_text(json.dumps(policy))
    calls = []

    async def model(request):
        body = json.loads(request.content)
        payload = json.loads(body["input"][-1]["content"][0]["text"])
        calls.append(len(request.content))
        if "original_request" in payload:
            value = verification_report(payload["criteria"], evidence="step:step-main")
            if not valid_review:
                value["criteria"][0]["criterion_id"] = "unassigned"
        else:
            assert not ({"local_bindings", "peer_offers"} & payload.keys())
            value = {
                "steps": [
                    {
                        "step_id": "step-main",
                        "requirement_ids": [x["requirement_id"] for x in payload["requirements"]],
                        "depends_on": [],
                        "contract_digest": payload["request"]["contract"]["digest"],
                        "input_json": canonical(payload["request"]["input"]).decode(),
                    }
                ]
            }
        return httpx.Response(
            200,
            json={
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": json.dumps(value)}],
                    }
                ],
                "usage": {"total_tokens": 100},
            },
        )

    client, app = await services(
        raw=raw,
        peer_transport=httpx.ASGITransport(app=child_app),
        model_transport=httpx.MockTransport(model),
    )
    app.state.coordinator.planner.proposal = None
    result = await settled(client, await submit(client, app, await task_request(client, app)))
    assert len(calls) == 2
    c = app.state.coordinator
    if not valid_review:
        assert result["status"] == "rejected"
        assert result["problem"]["code"] == "verification_failed"
        assert not c.store.children(result["task_id"])
        return
    assert result["status"] == "completed", (result, calls)
    row, _ = c.store.task(result["task_id"])
    plan = json.loads(row["plan"])["document"]
    reserve = c.config.document["limits"]["integration_reserve"]
    assert plan["steps"][0]["allocation"]["budget"]["model_calls"] == (
        budget["model_calls"] - reserve["model_calls"] - len(calls)
    )
