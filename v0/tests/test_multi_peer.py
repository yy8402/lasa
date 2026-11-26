import asyncio
import json
from pathlib import Path

import httpx
import pytest

from lasa_service.capabilities import epoch, instant
from lasa_service.contracts import digest, parse_json

from .conftest import (
    FakeRuntime,
    add_delegation_grant,
    deterministic_planner,
    documents,
    operator_get,
    settled,
    submit,
    task_request,
)
from .protocol_helpers import verification_report
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
        "execution_key_ref": "env:LASA_EXECUTION_KEY",
        "request_timeout_seconds": 2,
    }


async def setup_peers(
    services, tmp_path, *, contracts_by_peer=None, planner=None, only_attempt=False, local=True
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
    if not local:
        raw["bindings"] = [
            binding
            for binding in raw["bindings"]
            if not binding["contract"]["id"].endswith("/task.attempt")
        ]
    transport = DownstreamTransport(workers)
    client, app = await services(raw=raw, planner=planner, peer_transport=transport)
    return client, app, workers, runtimes, transport


@pytest.mark.parametrize("local", [True, False])
async def test_caller_delegation_restriction_blocks_peer_routes(services, tmp_path, local):
    client, app, _, _, transport = await setup_peers(services, tmp_path, local=local)
    request = await task_request(client, app)
    restricted = await settled(client, await submit(client, app, request | {"delegation": "none"}))
    assert transport.calls == []
    coordinator = app.state.coordinator
    authority = coordinator.authority(restricted["task_id"])
    assert authority["limits"]["budget"]["delegations"] == 0
    assert authority["delegation_grants"] == []
    if local:
        assert restricted["status"] == "completed", restricted
    else:
        assert restricted["status"] == "rejected", restricted
        assert restricted["problem"]["code"] == "processing_unavailable"

    allowed = await task_request(client, app)
    result = await settled(client, await submit(client, app, allowed | {"delegation": "policy"}))
    assert result["status"] == "completed", result
    assert len(transport.submissions()) == 1


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
    async def plan(c, task_id, request, contracts, requirements):
        review = await review_plan(c, task_id, request, contracts, requirements)
        main = await deterministic_planner(c, task_id, request, contracts, requirements)
        return {
            "steps": [
                {**review["steps"][0], "requirement_ids": []},
                {**main["steps"][0], "depends_on": ["step-review"]},
            ]
        }

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
        return verification_report(payload["criteria"])

    async def assess_downstream(task_id, purpose, payload, schema, **_):
        request = downstream.request(task_id)
        (dependency,) = payload["trusted_execution_evidence"]["dependencies"]
        assert dependency == {
            "source": "authenticated_consumer_request",
            "step_id": "step-review",
            "contract": reviews[0][0],
            "request_digest": digest(request),
            "output_digest": digest(reviews[0][1]),
            "content": reviews[0][1],
        }
        checks.append(("downstream", None))
        return verification_report(payload["criteria"])

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
    assert app.state.coordinator.store.usage(result["task_id"])["delegations"] == 2
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
        assert receiver.request(child["task_id"]) == child["request"]
        assert child["request"]["selection"]["contract"]["id"].endswith("/" + contract)
        assert len(runtimes[host].prompts) == 1
        assert receiver.store.db.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 1
    assert runtimes[second].prompts[0]["imports"][0]["label"] == "step-review"
    report = (await operator_get(client, app, response.headers["Location"], "/delegations")).json()
    assert [item["task_id"] for item in report["children"]] == [
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


async def test_unclaimed_and_unreachable_peers_preserve_distinct_outcomes(services, tmp_path):
    client, app, _, _, transport = await setup_peers(
        services, tmp_path, planner=review_plan, only_attempt=True
    )
    transport.unavailable.add("layer3.example.net")
    result = await settled(client, await submit(client, app, await task_request(client, app)))

    assert result["status"] == "rejected", result
    assert result["problem"]["code"] == "service_unavailable"
    assert transport.submissions() == []


async def test_inbound_peer_cannot_delegate_onward_or_write(services, tmp_path):
    root = documents(tmp_path / "root", peer=True)
    middle = documents(tmp_path / "middle", "layer2")
    leaf = documents(tmp_path / "leaf", "layer3")
    middle["peers"] = [peer_settings(leaf["service"], "env:LEAF_TOKEN")]
    middle["routing"]["preferred_executor"] = "peer"
    root["routing"]["preferred_executor"] = "peer"
    middle_policy_path = Path(middle["authorization"]["policy_file"])
    middle_policy = json.loads(middle_policy_path.read_text())
    middle_rule = middle_policy["principals"][2]["rules"][0]
    for contract in middle["published_contracts"]:
        add_delegation_grant(middle, middle_rule, contract)
    middle_policy_path.write_text(json.dumps(middle_policy))
    middle_transport = DownstreamTransport({})

    async def handle(context):
        c = context.coordinator
        authority = c.authority(context.task_id)
        assert authority["limits"]["budget"]["delegations"] == 0
        assert authority["delegation_grants"] == []
        assert not c.permits(context.task_id, "workspace.write", "workspace:self", "update")
        return await FakeRuntime().run(context)

    _, middle_app = await services(
        raw=middle, peer_transport=middle_transport, runtime=FakeRuntime(handle)
    )
    client, app = await services(raw=root, peer_transport=httpx.ASGITransport(app=middle_app))
    result = await settled(client, await submit(client, app, await task_request(client, app)))
    assert result["status"] == "completed", result
    assert app.state.coordinator.store.usage(result["task_id"])["delegations"] == 1
    assert middle_transport.calls == []


async def recursive_chain(
    services,
    tmp_path,
    depth,
    *,
    mismatch=False,
    reenter=False,
    root_cap=None,
    root_fanout=1,
    maximum=None,
    planner=None,
):
    raws = [documents(tmp_path / f"layer{n}", f"layer{n}") for n in range(1, depth + 2)]
    edges = list(zip(range(depth), range(1, depth + 1), strict=True))
    if reenter:
        edges[-1] = (depth - 1, 0)
    for index, raw in enumerate(raws):
        raw["routing"]["preferred_executor"] = "peer"
        path = Path(raw["authorization"]["policy_file"])
        policy = json.loads(path.read_text())
        caller, incoming = policy["principals"][0], policy["principals"][2]
        if index == 0:
            raw["limits"]["max_children"] = root_fanout
            raw["limits"]["max_task_budget"]["model_calls"] = 18
            caller["rules"][0]["budget"]["model_calls"] = 18
            if maximum is not None:
                raw["limits"]["max_derived_descendants"] = maximum
            if root_cap is not None:
                raw["limits"]["max_derived_descendants"] = root_cap
                caller["rules"][0]["subtree_cap"] = root_cap
        if index > 0:
            upstream = raws[index - 1]["service"]["id"]
            incoming.update(subject=f"peer-layer{index}", service_id=upstream)
            incoming["rules"][0]["onward_fanout"] = int(index < depth)
            if root_cap is not None and index < depth:
                incoming["rules"][0]["subtree_cap"] = depth - index
        elif reenter:
            incoming.update(
                subject=f"peer-layer{depth}", service_id=raws[depth - 1]["service"]["id"]
            )
        receiver = next((receiver for sender, receiver in edges if sender == index), None)
        if receiver is not None:
            raw["peers"] = [peer_settings(raws[receiver]["service"], "env:NEXT_TOKEN")]
            rule = (caller if index == 0 else incoming)["rules"][0]
            for contract in raw["published_contracts"]:
                add_delegation_grant(raw, rule, contract)
            descendant_depth = depth - index - 1
            if descendant_depth:
                terms = {"max_fanout": 1, "min_verification_margin_ms": 20000}
                if root_cap is not None:
                    terms["subtree_cap"] = descendant_depth
                if mismatch and index == 0:
                    if root_cap is None:
                        terms["min_verification_margin_ms"] += 1
                    else:
                        terms["subtree_cap"] -= 1
                for grant in rule["delegation_grants"]:
                    grant["execution"] = terms
        path.write_text(json.dumps(policy))
    if mismatch:
        raws[0]["bindings"] = []

    transport = DownstreamTransport({})
    apps = []
    clients = []
    for index, raw in enumerate(raws):
        client, app = await services(
            raw=raw, peer_transport=transport, planner=planner if index == 0 else None
        )
        apps.append(app)
        clients.append(client)
        transport.peers[httpx.URL(raw["service"]["base_url"]).host] = httpx.ASGITransport(app=app)
    return clients[0], apps, transport


@pytest.mark.parametrize(
    ("depth", "reenter", "cap"),
    [
        (0, False, None),
        (1, False, None),
        (2, False, None),
        (3, False, None),
        (3, True, None),
        (3, False, 3),
    ],
)
async def test_recursive_limits_and_lost_acknowledgement(services, tmp_path, depth, reenter, cap):
    client, apps, transport = await recursive_chain(
        services, tmp_path, depth, reenter=reenter, root_cap=cap
    )
    if depth >= 2:
        transport.lose_response.add(("layer3.example.net", "tasks"))
    result = await settled(
        client, await submit(client, apps[0], await task_request(client, apps[0]))
    )
    assert result["status"] == "completed", result
    expected = [f"layer{n}.example.net" for n in range(2, depth + 2)]
    if reenter:
        expected[-1] = "layer1.example.net"
    assert transport.submissions() == expected
    root = apps[0].state.coordinator
    assert root.store.usage(result["task_id"])["delegations"] == int(depth > 0)
    assert "execution_commitment" not in json.dumps(result)
    parent = result["task_id"]
    for index, app in enumerate(apps[:depth]):
        c = app.state.coordinator
        (child,) = c.store.children(parent)
        assert c.store.usage(parent)["delegations"] == 1
        assert c.authority(parent).get("subtree_cap") == (depth - index if cap else None)
        assert child.get("subtree_charge") == (depth - index if cap else None)
        assert c.store.subtree_usage(parent) == (depth - index if cap else 0)
        child_deadline = child["request"]["requested_limits"]["deadline"]
        assert epoch(c.authority(parent)["limits"]["deadline"]) - epoch(child_deadline) >= 30
        assert "subtree" not in json.dumps(child["request"])
        parent = child["task_id"]


@pytest.mark.parametrize("cap", [None, 3])
async def test_incompatible_recursive_terms_stop_before_dispatch(services, tmp_path, cap):
    client, apps, transport = await recursive_chain(
        services, tmp_path, 3, mismatch=True, root_cap=cap
    )
    request = await task_request(client, apps[0])
    result = await settled(client, await submit(client, apps[0], request))
    assert result["status"] == "rejected", result
    assert not any(method == "POST" for _, method, _ in transport.calls)
    assert all(not app.state.coordinator.store.active() for app in apps)


@pytest.mark.parametrize(
    ("depth", "cap", "maximum", "seconds", "expected"),
    [(1, 1, 1, 120, 1), (2, None, 1, 120, 0), (1, None, None, 15, 0)],
)
async def test_default_bound_and_early_child_deadline(
    services, tmp_path, depth, cap, maximum, seconds, expected
):
    import time

    client, apps, transport = await recursive_chain(
        services, tmp_path, depth, root_cap=cap, maximum=maximum
    )
    body = await task_request(client, apps[0])
    body["requested_limits"]["deadline"] = instant(time.time() + seconds)
    result = await settled(client, await submit(client, apps[0], body))
    assert result["status"] == "completed", result
    root = apps[0].state.coordinator
    assert "subtree_cap" not in root.authority(result["task_id"])
    assert len(transport.submissions()) == expected
    assert root.store.subtree_usage(result["task_id"]) == 0


async def test_rejected_child_still_counts_against_both_limits(services, tmp_path):
    client, apps, transport = await recursive_chain(services, tmp_path, 3, root_cap=3)
    original = transport.handle_async_request

    async def reject(request):
        if request.method == "POST" and request.url.path.endswith("/tasks"):
            return httpx.Response(422, json={"code": "precondition_failed"})
        return await original(request)

    transport.handle_async_request = reject
    result = await settled(
        client, await submit(client, apps[0], await task_request(client, apps[0]))
    )
    assert result["status"] == "failed", result
    store = apps[0].state.coordinator.store
    (child,) = store.children(result["task_id"])
    assert child["state"] == "rejected"
    assert store.usage(result["task_id"])["delegations"] == 1
    assert store.subtree_usage(result["task_id"]) == 3


@pytest.mark.parametrize(("fanout", "cap"), [(2, None), (1, None), (2, 3), (2, 4)])
async def test_recursive_siblings_reserve_direct_children_and_optional_cap(
    services, tmp_path, fanout, cap
):
    async def split(c, task_id, request, contracts, requirements):
        plan = await deterministic_planner(c, task_id, request, contracts, requirements)
        (step,) = plan["steps"]
        return {
            "steps": [
                {
                    **step,
                    "step_id": item["id"],
                    "requirement_ids": [item["id"]],
                    "input_json": json.dumps({**request["input"], "requirements": [item]}),
                }
                for item in request["input"]["requirements"]
            ]
        }

    client, apps, transport = await recursive_chain(
        services, tmp_path, 2, root_fanout=fanout, root_cap=cap, planner=split
    )
    original = transport.handle_async_request
    entered = 0
    both_dispatched = asyncio.Event()

    async def synchronize(request):
        nonlocal entered
        if (
            request.method == "POST"
            and request.url.path.endswith("/tasks")
            and request.url.host == "layer2.example.net"
        ):
            entered += 1
            if entered == 2:
                both_dispatched.set()
            await both_dispatched.wait()
        return await original(request)

    transport.handle_async_request = synchronize
    body = await task_request(client, apps[0])
    body["input"]["requirements"].append(
        {
            **body["input"]["requirements"][0],
            "id": "requirement-second",
        }
    )
    result = await settled(client, await submit(client, apps[0], body))
    if fanout == 1 or cap == 3:
        assert result["status"] == "rejected", result
        assert result["problem"]["code"] == "capacity_exhausted"
        assert entered == 0
        return
    assert result["status"] == "completed", result
    assert both_dispatched.is_set()
    assert (
        sorted(transport.submissions()) == ["layer2.example.net"] * 2 + ["layer3.example.net"] * 2
    )
    store = apps[0].state.coordinator.store
    assert store.usage(result["task_id"])["delegations"] == 2
    assert store.subtree_usage(result["task_id"]) == (cap or 0)


async def test_recursive_cancellation_quarantines_late_leaf_result(services, tmp_path):
    client, apps, transport = await recursive_chain(services, tmp_path, 2)
    leaf = apps[-1].state.coordinator
    entered, finish, released = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def execute(context):
        entered.set()
        await finish.wait()
        return await FakeRuntime().run(context)

    def observe(point, _task_id):
        if point == "after_release":
            released.set()

    leaf.runtime.handler = execute
    leaf.fault = observe
    original = transport.handle_async_request

    async def complete_before_cancel(request):
        if request.url.host == "layer3.example.net" and request.url.path.endswith("/cancel"):
            finish.set()
            async with asyncio.timeout(2):
                await released.wait()
        return await original(request)

    transport.handle_async_request = complete_before_cancel
    app = apps[0]
    response = await submit(client, app, await task_request(client, app))
    async with asyncio.timeout(4):
        await entered.wait()
    location = response.headers["Location"]
    current = await client.get(location)
    cancel = await client.post(
        location + "/cancel",
        json={"operation_id": "cancel-recursive"},
        headers={"Idempotency-Key": "cancel-recursive", "If-Match": current.headers["etag"]},
    )
    assert cancel.status_code == 202, cancel.text
    result = await settled(client, response)
    assert result["status"] == "cancelled", result
    assert "result" not in result and released.is_set()
    (child,) = app.state.coordinator.store.children(result["task_id"])
    (late,) = apps[1].state.coordinator.store.children(child["task_id"])
    assert child["state"] == "cancelled" and late["state"] == "completed"
    assert "result_state" not in late
