import json
from pathlib import Path

import httpx
import pytest

from lasa_service.contracts import digest, parse_json

from .conftest import (
    FakeRuntime,
    add_delegation_grant,
    delegation_grant,
    deterministic_planner,
    documents,
    settled,
    submit,
    task_request,
)
from .test_routing import publish_only_attempt, review_plan


class DownstreamTransport(httpx.AsyncBaseTransport):
    def __init__(self, apps):
        self.peers = {host: httpx.ASGITransport(app=app) for host, app in apps.items()}
        self.calls = []
        self.unavailable = set()
        self.lose_response = set()

    async def handle_async_request(self, request):
        host, path = request.url.host, request.url.path
        self.calls.append((host, request.method, path))
        if host in self.unavailable:
            raise httpx.ConnectError("peer unavailable", request=request)
        response = await self.peers[host].handle_async_request(request)
        if request.method == "POST" and (host, path.rsplit("/", 1)[-1]) in self.lose_response:
            await response.aread()
            await response.aclose()
            raise httpx.ReadError("response lost after receipt", request=request)
        return response

    def submissions(self):
        return [
            host
            for host, method, path in self.calls
            if method == "POST" and path.endswith("/tasks")
        ]


def peer_settings(service, credential_ref):
    return {
        "expected_service_id": service["id"],
        "descriptor_url": service["base_url"].rstrip("/") + "/descriptor",
        "allowed_base_url": service["base_url"],
        "credential_ref": credential_ref,
        "authorization_ref": "default",
        "request_timeout_seconds": 2,
    }


async def setup_peers(
    services, tmp_path, *, contracts_by_peer=None, planner=None, only_attempt=False
):
    workers, runtimes = {}, {}
    raw = documents(tmp_path / "parent", peer=True)
    for layer in ("layer2", "layer3"):
        child = documents(tmp_path / layer, layer)
        if only_attempt:
            publish_only_attempt(child)
        host = layer + ".example.net"
        runtime = FakeRuntime()
        _, workers[host] = await services(raw=child, runtime=runtime)
        runtimes[host] = runtime
        if layer == "layer3":
            raw["peers"].append(peer_settings(child["service"], "env:PEER_LAYER3_TOKEN"))
    path = Path(raw["authorization"]["policy_file"])
    policy = json.loads(path.read_text())
    for principal in policy["principals"]:
        for rule in principal["rules"]:
            rule["delegation_grants"] = []
            for contract in raw["published_contracts"]:
                add_delegation_grant(raw, rule, contract)
            if contracts_by_peer:
                rule["delegation_grants"] = [
                    grant
                    for grant in rule["delegation_grants"]
                    if grant["contract"]["id"].rsplit("/", 1)[-1]
                    in contracts_by_peer[grant["receiver_service_id"].rsplit("/", 1)[-1]]
                ]
    path.write_text(json.dumps(policy))
    raw["routing"]["preferred_executor"] = "peer"
    if only_attempt:
        raw["bindings"] = [
            binding
            for binding in raw["bindings"]
            if binding["contract"]["id"].endswith("/task.attempt")
        ]
        raw["routing"]["unclaimed_peer_fallback"] = "attempt"
    transport = DownstreamTransport(workers)
    client, app = await services(raw=raw, planner=planner, peer_transport=transport)
    return client, app, workers, runtimes, transport


@pytest.mark.parametrize("primary", ["available", "offline", "fails_preflight"])
async def test_two_peers_choose_by_priority_and_preflight(services, tmp_path, primary):
    client, app, _, _, transport = await setup_peers(services, tmp_path)
    coordinator = app.state.coordinator
    first, second = "layer2.example.net", "layer3.example.net"
    if primary == "offline":
        transport.unavailable.add(first)
    elif primary == "fails_preflight":

        def drop_primary(point, task_id):
            if point == "after_admission":
                transport.unavailable.add(first)

        coordinator.fault = drop_primary

    result = await settled(client, await submit(client, app, await task_request(client, app)))
    assert result["status"] == "completed", result
    assert transport.submissions() == [first if primary == "available" else second]


@pytest.mark.parametrize("share_predecessor", [True, False])
async def test_two_peers_scope_each_step_and_recover_lost_responses(
    services, tmp_path, share_predecessor
):
    async def plan(c, task_id, request, peer_catalog, requirements):
        review = await review_plan(c, task_id, request, peer_catalog, requirements)
        main = await deterministic_planner(c, task_id, request, peer_catalog, requirements)
        return {"steps": [review["steps"][0], {**main["steps"][0], "depends_on": ["step-review"]}]}

    client, app, workers, runtimes, transport = await setup_peers(
        services,
        tmp_path,
        planner=plan,
        contracts_by_peer={"layer2": {"design.review"}, "layer3": {"task.attempt"}},
    )
    first, second = "layer2.example.net", "layer3.example.net"
    parent = app.state.coordinator
    downstream = workers[second].state.coordinator
    reviews, checklists, checks = [], [], []

    async def assess_parent(
        task_id, purpose, payload, schema, *, candidate_output, instruction, **_
    ):
        material = payload["trusted_execution_evidence"]
        dependencies = material.get("dependencies", [])
        if material["step_id"] is None:
            planned = parse_json(parent.store.task(task_id)[0]["plan"])["inputs"]
            assert "trusted_execution_evidence.step_inputs" in instruction
            assert material["step_inputs"] == [
                {"step_id": key, "input_digest": digest(planned[key]), "content": planned[key]}
                for key in ("step-review", "step-main")
            ]
            for key, host in (("step-review", first), ("step-main", second)):
                assert planned[key] == runtimes[host].prompts[0]["input"]
        else:
            assert "step_inputs" not in material
        if payload["contract"]["ref"]["id"].endswith("/design.review"):
            assert dependencies == []
            reviews.append((payload["contract"]["ref"], candidate_output))
        else:
            contract, review_output = reviews[0]
            expected = [
                {
                    "source": "receiver_verified_step",
                    "service_id": parent.config.service_id,
                    "task_id": task_id,
                    "step_id": "step-review",
                    "contract": contract,
                    "executor": "peer",
                    "depends_on": [],
                    "output_digest": digest(review_output),
                    "content": review_output,
                }
            ]
            if material["step_id"] is None:
                expected.append(
                    {
                        "source": "receiver_verified_step",
                        "service_id": parent.config.service_id,
                        "task_id": task_id,
                        "step_id": "step-main",
                        "contract": payload["contract"]["ref"],
                        "executor": "peer",
                        "depends_on": ["step-review"],
                        "output_digest": digest(checklists[0]),
                        "content": checklists[0],
                    }
                )
            else:
                checklists.append(candidate_output)
            assert dependencies == expected
            checks.append(("parent", material["step_id"]))
        return {"passed": True, "reason": "Verified against the recorded workflow evidence."}

    async def assess_downstream(task_id, purpose, payload, schema, **_):
        request = downstream.request(task_id)
        envelope = request["delegation"]
        (dependency,) = payload["trusted_execution_evidence"]["dependencies"]
        assert dependency == {
            "source": "authenticated_parent_request",
            "service_id": parent.config.service_id,
            "task_id": envelope["parent_task_id"],
            "step_id": "step-review",
            "delegation_id": envelope["delegation_id"],
            "request_digest": envelope["request_digest"],
            "output_digest": digest(reviews[0][1]),
            "content": reviews[0][1],
        }
        checks.append(("downstream", None))
        return {"passed": True, "reason": "Verified against the authenticated review output."}

    for receiver, assess in [(parent, assess_parent), (downstream, assess_downstream)]:
        receiver.planner.verifier = None
        receiver.models.ask = assess

    if not share_predecessor:
        path = Path(app.state.coordinator.config.document["authorization"]["policy_file"])
        policy = json.loads(path.read_text())
        rule = policy["principals"][0]["rules"][0]
        for grant in rule["delegation_grants"]:
            if grant["receiver_service_id"].endswith("/layer3"):
                grant["disclosure_resources"] = []
        path.write_text(json.dumps(policy))
    transport.lose_response.update({(second, "sessions"), (second, "tasks")})
    response = await submit(client, app, await task_request(client, app))
    result = await settled(client, response)

    if not share_predecessor:
        assert result["status"] == "failed" and result["problem"]["code"] == "disclosure_denied", (
            result
        )
        assert transport.submissions() == [first]
        assert not any(host == second and method == "POST" for host, method, _ in transport.calls)
        assert checks == []
        return

    assert result["status"] == "completed", result
    assert checks == [("downstream", None), ("parent", "step-main"), ("parent", None)]
    assert result["result"]["usage"]["delegations"] == 2
    assert transport.submissions() == [first, second]
    assert [
        host for host, method, path in transport.calls if method == "GET" and "/operations/" in path
    ] == [second, second]
    children = app.state.coordinator.store.children(result["task_id"])
    assert len(children) == 2
    for child, host, contract in zip(
        children, (first, second), ("design.review", "task.attempt"), strict=True
    ):
        receiver = workers[host].state.coordinator
        assert child["service_id"] == receiver.config.service_id
        assert child["request"]["delegation"]["recipient_service_id"] == receiver.config.service_id
        assert child["request"]["selection"]["contract"]["id"].endswith("/" + contract)
        assert len(runtimes[host].prompts) == 1
        assert receiver.store.db.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 1
    assert "step-review" in runtimes[second].prompts[0]["delegated_dependencies"]
    report = (await client.get(response.headers["Location"] + "/delegations")).json()
    assert [item["trace"]["task_id"] for item in report["children"]] == [
        item["task_id"] for item in children
    ]
    row, _ = parent.store.task(result["task_id"])
    planned = parse_json(row["plan"])["inputs"]
    audit = parent.store.db.execute(
        "SELECT document FROM audit WHERE task_id=? AND kind='verification_material' "
        "ORDER BY rowid DESC LIMIT 1",
        (result["task_id"],),
    ).fetchone()
    assert parse_json(audit["document"])["step_inputs"] == [
        {"step_id": key, "input_digest": digest(planned[key])}
        for key in ("step-review", "step-main")
    ]


async def test_unreachable_second_peer_prevents_generic_fallback(services, tmp_path):
    client, app, _, _, transport = await setup_peers(
        services, tmp_path, planner=review_plan, only_attempt=True
    )
    transport.unavailable.add("layer3.example.net")
    result = await settled(client, await submit(client, app, await task_request(client, app)))

    assert result["status"] == "rejected", result
    assert result["problem"]["code"] == "peer_unavailable"
    assert transport.submissions() == []


async def test_onward_grants_preserve_ancestry_and_decrement_hops(services, tmp_path):
    root = documents(tmp_path / "root", peer=True)
    middle = documents(tmp_path / "middle", "layer2")
    leaf = documents(tmp_path / "leaf", "layer3")
    contract = next(
        ref for ref in root["published_contracts"] if ref["id"].endswith("/task.attempt")
    )
    middle_id = middle["service"]["id"]
    leaf_policy_path = Path(leaf["authorization"]["policy_file"])
    leaf_policy = json.loads(leaf_policy_path.read_text())
    leaf_policy["trusted_delegator_service_ids"] = [middle_id]
    leaf_policy["principals"][2].update(subject="peer-layer2", service_id=middle_id)
    leaf_policy_path.write_text(json.dumps(leaf_policy))
    _, leaf_app = await services(raw=leaf)

    middle["peers"] = [
        peer_settings(root["service"], "env:UPSTREAM_TOKEN"),
        peer_settings(leaf["service"], "env:LEAF_TOKEN"),
    ]
    middle["routing"]["preferred_executor"] = "peer"
    middle_policy_path = Path(middle["authorization"]["policy_file"])
    middle_policy = json.loads(middle_policy_path.read_text())
    middle_rule = middle_policy["principals"][2]["rules"][0]
    add_delegation_grant(middle, middle_rule, contract)
    middle_policy_path.write_text(json.dumps(middle_policy))
    middle_transport = DownstreamTransport({"layer3.example.net": leaf_app})
    _, middle_app = await services(raw=middle, peer_transport=middle_transport)

    root["routing"]["preferred_executor"] = "peer"
    root_policy_path = Path(root["authorization"]["policy_file"])
    root_policy = json.loads(root_policy_path.read_text())
    root_rule = root_policy["principals"][0]["rules"][0]
    root_rule["delegation_grants"].extend(
        delegation_grant(middle_id, service["id"], contract, root_rule)
        for service in (root["service"], leaf["service"])
    )
    root_policy_path.write_text(json.dumps(root_policy))
    client, app = await services(raw=root, peer_transport=httpx.ASGITransport(app=middle_app))

    result = await settled(client, await submit(client, app, await task_request(client, app)))

    assert result["status"] == "completed", result
    assert result["result"]["usage"]["delegations"] == 2
    assert {host for host, _, _ in middle_transport.calls} == {"layer3.example.net"}
    (child,) = app.state.coordinator.store.children(result["task_id"])
    (grandchild,) = middle_app.state.coordinator.store.children(child["task_id"])
    envelope = grandchild["request"]["delegation"]
    assert envelope["ancestry"] == [root["service"]["id"], middle_id]
    assert envelope["remaining_hops"] == 0
