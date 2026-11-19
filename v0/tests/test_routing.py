import copy
import json
from pathlib import Path

import httpx
import pytest

from lasa_service.contracts import canonical
from lasa_service.routing import decide

from .conftest import FakeRuntime, documents, settled, submit, task_request


@pytest.mark.parametrize("preference,expected", [("local", "local"), ("peer", "peer")])
def test_both_suitable_preference(preference, expected):
    assert (
        decide(
            "sufficient",
            "matched",
            {"preferred_executor": preference, "unclaimed_peer_fallback": "attempt"},
            configured=True,
            generic_available=True,
        )
        == expected
    )


@pytest.mark.parametrize("preference", ["local", "peer"])
@pytest.mark.parametrize("fallback", ["reject", "attempt"])
@pytest.mark.parametrize("local", ["sufficient", "insufficient", "unknown"])
def test_no_peer_ignores_both_settings(preference, fallback, local):
    assert (
        decide(
            local,
            "not_configured",
            {"preferred_executor": preference, "unclaimed_peer_fallback": fallback},
            configured=False,
            generic_available=True,
        )
        == "local"
    )


@pytest.mark.parametrize(
    "local,peer,fallback,generic,expected",
    [
        ("sufficient", "unknown", "attempt", True, "local"),
        ("sufficient", "unavailable", "attempt", True, "local"),
        ("sufficient", "not_claimed", "attempt", True, "local"),
        ("insufficient", "matched", "reject", False, "peer"),
        ("unknown", "matched", "reject", False, "peer"),
        ("insufficient", "not_claimed", "attempt", True, "attempt"),
        ("insufficient", "not_claimed", "reject", True, "none"),
        ("insufficient", "not_claimed", "attempt", False, "none"),
        ("insufficient", "unknown", "attempt", True, "none"),
        ("insufficient", "unavailable", "attempt", True, "none"),
        ("insufficient", "denied", "attempt", True, "none"),
        ("unknown", "not_claimed", "attempt", True, "none"),
    ],
)
def test_exact_fallback_conjunction(local, peer, fallback, generic, expected):
    assert (
        decide(
            local,
            peer,
            {"preferred_executor": "peer", "unclaimed_peer_fallback": fallback},
            configured=True,
            generic_available=generic,
        )
        == expected
    )


async def review_plan(c, task_id, request, peer_catalog, requirements):
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
                "local_assessment": "sufficient",
                "assessment_summary": "Review supplied text using the exact review outcome contract.",
            }
        ]
    }


def publish_only_attempt(raw):
    raw["published_contracts"] = [
        x for x in raw["published_contracts"] if x["id"].endswith("/task.attempt")
    ]
    return raw


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
    children = app.state.coordinator.store.children(result["task_id"])
    assert bool(children) == (preference == "peer")
    events = (
        await client.get(raw["service"]["base_url"] + "/tasks/" + result["task_id"] + "/events")
    ).json()["events"]
    routing = next(x for x in events if x["kind"] == "routing")["payload"]
    assert routing["selected_executor"] == preference
    report = (
        await client.get(
            raw["service"]["base_url"] + "/tasks/" + result["task_id"] + "/delegations"
        )
    ).json()
    assert bool(report["children"]) == (preference == "peer")
    if preference == "peer":
        assert report["children"][0]["trace"]["task_id"] == children[0]["task_id"]
        assert all(
            e["service_id"] == child_app.state.coordinator.config.service_id
            for e in report["children"][0]["trace"]["events"]
        )
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


@pytest.mark.parametrize("fallback", ["reject", "attempt"])
async def test_local_insufficient_fresh_unclaimed_fallback(services, tmp_path, fallback):
    raw_child = publish_only_attempt(documents(tmp_path / "child", "layer2"))
    child_client, child_app = await services(raw=raw_child)
    raw = documents(tmp_path / "parent", peer=True)
    raw["bindings"] = [x for x in raw["bindings"] if x["contract"]["id"].endswith("/task.attempt")]
    raw["routing"]["unclaimed_peer_fallback"] = fallback
    client, app = await services(
        raw=raw, planner=review_plan, peer_transport=httpx.ASGITransport(app=child_app)
    )
    result = await settled(client, await submit(client, app, await task_request(client, app)))
    children = app.state.coordinator.store.children(result["task_id"])
    assert bool(children) == (fallback == "attempt"), result
    if fallback == "reject":
        assert result["status"] == "rejected"
    else:
        assert result["status"] == "completed", result
        assert children[0]["request"]["selection"]["contract"]["id"].endswith("/task.attempt")
        assert "design.review" in children[0]["request"]["input"]["context"]


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
        await client.get(raw["service"]["base_url"] + "/tasks/" + result["task_id"] + "/events")
    ).json()["events"]
    assert events[0]["payload"]["peer_assessment"] == "unknown"


async def test_fallback_unable_does_not_fulfill_required_review(services, tmp_path):
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

    child_client, child_app = await services(
        raw=publish_only_attempt(documents(tmp_path / "child", "layer2")),
        runtime=FakeRuntime(unable),
    )
    raw = documents(tmp_path / "parent", peer=True)
    raw["bindings"] = [x for x in raw["bindings"] if x["contract"]["id"].endswith("/task.attempt")]
    client, app = await services(
        raw=raw, planner=review_plan, peer_transport=httpx.ASGITransport(app=child_app)
    )
    result = await settled(client, await submit(client, app, await task_request(client, app)))
    assert result["status"] == "failed" and "result" not in result


@pytest.mark.parametrize("tamper", ["request", "artifact"])
async def test_parent_rejects_mismatched_child_or_corrupt_artifact(services, tmp_path, tamper):
    async def artifact_result(context):
        c = context.coordinator
        await c.broker.call(
            context.task_id,
            "write",
            "workspace.write",
            {"relative_path": "proof.txt", "text": "proof"},
        )
        manifest = c.snapshot_artifact(context.task_id, "proof", "text/plain", "proof")
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
    assert result["status"] in {"failed", "indeterminate"} and "result" not in result


@pytest.mark.parametrize("tamper", ["loop", "digest", "sender"])
async def test_receiver_rejects_forged_delegation(services, tmp_path, tamper):
    from lasa_service.contracts import request_digest

    from .conftest import token

    raw = documents(tmp_path, "layer2")
    client, app = await services(raw=raw)
    parent = "https://identity.example.net/services/layer1"
    client.headers["Authorization"] = "Bearer " + token(
        "peer-layer1", app.state.coordinator.config.service_id
    )
    request = await task_request(client, app)
    request["delegation"] = {
        "delegation_id": "delegation-forged",
        "root_task_id": "task-parent",
        "parent_service_id": parent,
        "parent_task_id": "task-parent",
        "step_id": "step-main",
        "requirement_ids": ["requirement-main"],
        "ancestry": [parent],
        "remaining_hops": request["requested_limits"]["max_hops"],
        "request_digest": request_digest(request),
        "allocation": copy.deepcopy(request["requested_limits"]),
        "disclosed_artifacts": [],
        "authority_ceiling": {
            "resources": [{"resource": "workspace:self", "actions": ["read"]}],
            "allowed_effects": ["workspace.read"],
            "allowed_disclosure_services": [],
            "allowed_delegated_contracts": [],
            "content_diagnostics_allowed": False,
        },
    }
    if tamper == "loop":
        request["delegation"]["ancestry"] = [app.state.coordinator.config.service_id, parent]
    if tamper == "digest":
        request["delegation"]["request_digest"] = "sha256:" + "0" * 64
    if tamper == "sender":
        request["delegation"]["parent_service_id"] = "https://identity.example.net/services/other"
    response = await submit(client, app, request)
    assert response.status_code in (403, 422), response.text
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
    raw["routing"]["unclaimed_peer_fallback"] = "attempt"
    client, app = await services(raw=raw, peer_transport=httpx.ASGITransport(app=child_app))
    result = await settled(client, await submit(client, app, await task_request(client, app)))
    assert result["status"] == "completed" and not app.state.coordinator.store.children(
        result["task_id"]
    )
    event = next(
        x
        for x in (
            await client.get(raw["service"]["base_url"] + "/tasks/" + result["task_id"] + "/events")
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


async def test_last_assessment_usage_is_accounted_before_child_admission(services, tmp_path):
    child_client, child_app = await services(raw=documents(tmp_path / "child", "layer2"))
    raw = documents(tmp_path / "parent", peer=True)
    raw["routing"]["preferred_executor"] = "peer"
    raw["limits"]["max_task_budget"]["model_tokens"] = 200000
    raw["limits"]["assessment_budget"]["model_tokens"] = 100000
    path = Path(raw["authorization"]["policy_file"])
    policy = json.loads(path.read_text())
    for p in policy["principals"]:
        for rule in p["rules"]:
            rule["budget"]["model_tokens"] = 200000
    path.write_text(json.dumps(policy))
    calls = []

    async def model(request):
        body = json.loads(request.content)
        payload = json.loads(body["input"][-1]["content"][0]["text"])
        calls.append(payload)
        if "original_request" in payload:
            value = {"passed": True, "reason": "Plan covers the original required outcome."}
        else:
            value = {
                "steps": [
                    {
                        "step_id": "step-main",
                        "requirement_ids": [x["requirement_id"] for x in payload["requirements"]],
                        "depends_on": [],
                        "contract_digest": payload["request"]["contract"]["digest"],
                        "input_json": canonical(payload["request"]["input"]).decode(),
                        "local_assessment": "sufficient",
                        "assessment_summary": "Supplied text work is supported.",
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
    assert result["status"] == "completed", result
    assert len(calls) == 2
    row, _ = app.state.coordinator.store.task(result["task_id"])
    plan = json.loads(row["plan"])["document"]
    assert plan["steps"][0]["allocation"]["budget"]["model_calls"] == 8
