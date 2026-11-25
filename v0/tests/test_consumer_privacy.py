import asyncio
import json
from pathlib import Path

import httpx
import pytest

from lasa_service.contracts import digest
from lasa_service.errors import LasaError

from .conftest import FakeRuntime, operator_get, settled, submit, task_request
from .test_multi_peer import setup_peers


async def test_consumer_observes_same_outcome_through_either_delegate(services, tmp_path):
    client, app, workers, _, transport = await setup_peers(services, tmp_path)
    outcomes = []
    for unavailable in (set(), {"layer2.example.net"}):
        transport.unavailable = unavailable
        response = await submit(client, app, await task_request(client, app))
        result = await settled(client, response)
        assert result["status"] == "completed", result
        location = response.headers["Location"]
        events = (await client.get(location + "/events")).json()
        control = (await client.get(location, params={"view": "control"})).json()
        assert (await client.get(location + "/delegations")).status_code == 404
        operator_path = location.replace("/tasks/", "/operator/tasks/") + "/delegations"
        assert (await client.get(operator_path)).status_code == 403
        assert (
            await client.get(operator_path.replace("/delegations", "/events"))
        ).status_code == 403
        private = (await operator_get(client, app, location, "/delegations")).json()
        (child,) = private["children"]
        assert child["service_id"] in {
            worker.state.coordinator.config.service_id for worker in workers.values()
        }
        transcript = json.dumps([response.json(), result, events, control])
        for identifier in (child["service_id"], child["task_id"], child["delegation_id"]):
            assert identifier not in transcript
        payload = result["result"]
        receipt = payload["receipt"]
        assert receipt["service_id"] == result["service_id"]
        assert receipt["result_digest"] == digest(
            {k: v for k, v in payload.items() if k != "receipt"}
        )
        outcomes.append(
            (payload["output"], payload["evidence"], events["events"], control["status"])
        )
    assert outcomes[0] == outcomes[1]


@pytest.mark.parametrize("field", ["output", "artifact", "evidence", "artifact_metadata"])
async def test_consumer_release_blocks_delegate_identity_in_content(services, tmp_path, field):
    client, app, _, runtimes, transport = await setup_peers(services, tmp_path)

    async def execute(context):
        result = await FakeRuntime().run(context)
        identity = context.coordinator.config.service_id
        if field == "output":
            result["output"]["summary"] = identity
        elif field == "evidence":
            result["evidence"][0]["summary"] = identity
        else:
            text = identity if field == "artifact" else "Safe attachment bytes."
            item = context.coordinator.snapshot_artifact(context.task_id, "text/plain", text)
            result["artifact_ids"].append(item["artifact_id"])
        return result

    if field == "artifact_metadata":
        exchange = transport.handle_async_request

        async def add_provider_metadata(request):
            response = await exchange(request)
            if (
                request.method != "GET"
                or "/tasks/" not in request.url.path
                or "/artifacts/" in request.url.path
            ):
                return response
            body = json.loads(await response.aread())
            if result := body.get("result"):
                result["artifacts"][0]["media_type"] = "text/plain; provider=layer2"
                result["receipt"]["result_digest"] = digest(
                    {key: value for key, value in result.items() if key != "receipt"}
                )
            return httpx.Response(response.status_code, json=body, headers=response.headers)

        transport.handle_async_request = add_provider_metadata

    runtimes["layer2.example.net"].handler = execute
    response = await submit(client, app, await task_request(client, app))
    task = await settled(client, response)
    if field == "evidence":
        assert task["status"] == "completed"
        assert task["result"]["evidence"][0]["summary"] == "Criterion verification recorded."
    else:
        assert task["status"] == "failed" and task["problem"]["code"] == "disclosure_denied"
        assert "result" not in task
    assert "layer2" not in json.dumps(task)


@pytest.mark.parametrize("scenario", ["rejected", "lost-ack", "cancelled", "late-result"])
async def test_equivalent_private_receiver_failures_and_recovery(services, tmp_path, scenario):
    client, app, workers, runtimes, transport = await setup_peers(services, tmp_path)
    public = []
    for host in workers:
        transport.unavailable = set(workers) - {host}
        transport.calls.clear()
        entered, allow_finish, released = asyncio.Event(), asyncio.Event(), asyncio.Event()
        receiver = workers[host].state.coordinator
        if scenario == "rejected":

            def reject(point, _task_id, *, private_hostname=host):
                if point == "after_receipt":
                    raise LasaError("precondition_failed", 422, detail=private_hostname)

            receiver.fault = reject
        if scenario == "lost-ack":
            transport.lose_response = {(host, "sessions"), (host, "tasks")}
        if scenario == "late-result":

            def confirm_release(point, _task_id, *, finished=released):
                if point == "after_release":
                    finished.set()

            receiver.fault = confirm_release

        async def handler(context, *, started=entered, continue_work=allow_finish):
            started.set()
            if scenario in {"cancelled", "late-result"}:
                await continue_work.wait()
            return await FakeRuntime().run(context)

        exchange = transport.handle_async_request

        async def allow_late_completion(
            request, *, start=allow_finish, done=released, send=exchange
        ):
            if (
                scenario == "late-result"
                and request.method == "POST"
                and request.url.path.endswith("/cancel")
            ):
                start.set()
                async with asyncio.timeout(2):
                    await done.wait()
            return await send(request)

        transport.handle_async_request = allow_late_completion
        runtimes[host].handler = handler
        response = await submit(client, app, await task_request(client, app))
        location = response.headers["Location"]
        if scenario in {"cancelled", "late-result"}:
            async with asyncio.timeout(4):
                await entered.wait()
            task = await client.get(location)
            operation_id = "cancel-" + response.json()["task_id"]
            cancelled = await client.post(
                location + "/cancel",
                json={"operation_id": operation_id},
                headers={"Idempotency-Key": operation_id, "If-Match": task.headers["etag"]},
            )
            assert cancelled.status_code == 202
        result = await settled(client, response)
        status = {
            "rejected": "failed",
            "lost-ack": "completed",
            "cancelled": "cancelled",
            "late-result": "cancelled",
        }[scenario]
        assert result["status"] == status, result
        assert ("result" in result) == (scenario == "lost-ack")
        events = (await client.get(location + "/events")).raise_for_status().json()["events"]
        assert transport.submissions() == [host]
        (child,) = app.state.coordinator.store.children(result["task_id"])
        assert child["service_id"] == receiver.config.service_id
        if scenario == "lost-ack":
            assert [
                selected
                for selected, method, path in transport.calls
                if method == "GET" and "/operations/" in path
            ] == [host, host]
        if scenario == "late-result":
            assert child["state"] == "completed" and "result_state" not in child
        for secret in (host, child["service_id"], child["session_id"], child["task_id"]):
            assert secret not in json.dumps([result, events])
        public.append((events, result.get("problem"), result.get("result", {}).get("output")))
        transport.handle_async_request = exchange
    assert public[0] == public[1]


async def test_incompatible_peer_is_rejected_before_any_consumer_mutation(services, tmp_path):
    client, app, workers, _, transport = await setup_peers(services, tmp_path)
    app.state.coordinator.config.document["bindings"] = []
    exchange = transport.handle_async_request

    async def incompatible(request):
        response = await exchange(request)
        if request.url.path.endswith("/descriptor"):
            descriptor = json.loads(await response.aread())
            descriptor["protocols"][0]["wire_schema_digest"] = "sha256:" + "0" * 64
            return httpx.Response(200, json=descriptor)
        return response

    transport.handle_async_request = incompatible
    location = await submit(client, app, await task_request(client, app))
    result = await settled(client, location)
    assert result["status"] == "rejected", result
    assert not any(method == "POST" for _, method, _ in transport.calls)
    assert all(not worker.state.coordinator.store.active() for worker in workers.values())


async def test_catalog_and_single_offer_publish_only_consumer_terms(services, tmp_path):
    client, app, workers, _, _ = await setup_peers(services, tmp_path)
    c = app.state.coordinator
    base = c.config.document["service"]["base_url"]
    provider = workers["layer2.example.net"].state.coordinator.config.service_id
    policy_path = Path(c.config.document["authorization"]["policy_file"])
    policy = json.loads(policy_path.read_text())
    rule = policy["principals"][0]["rules"][0]
    rule["authorization_ref"] = "private-policy-" + provider
    rule["resources"].append({"resource": "private-route:" + provider, "actions": ["read"]})
    rule["offer_preconditions"] = [
        {
            "kind": "resource_authorized",
            "description": "Check the delegated private resource at " + provider,
            "resource": "private-route:" + provider,
            "actions": ["read"],
        },
        {
            "kind": "budget_minimum",
            "description": "Required when calling " + provider,
            "resource": "tool_calls",
            "minimum": 2,
        },
    ]
    policy_path.write_text(json.dumps(policy))
    catalog = (await client.get(base + "/capabilities")).raise_for_status().json()
    (offer,) = catalog["offers"]
    single = (
        (await client.get(base + "/capabilities/" + offer["offer_id"])).raise_for_status().json()
    )
    assert single == offer
    c.contracts.validate("OfferCatalog", catalog)
    c.contracts.validate("CapabilityOffer", single)
    transcript = json.dumps([catalog, single])
    for private_value in (
        provider,
        "private-route:",
        "private-policy-",
        "authorization_ref",
        "resources",
    ):
        assert private_value not in transcript
    assert any(
        item["resource"] == "tool_calls" and item["minimum"] == 2
        for item in offer["restrictions"]["additional_preconditions"]
    )
    assert offer["contract"] and offer["max_budget"] and offer["valid_until"]
