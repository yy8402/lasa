import json
from pathlib import Path

import httpx
import pytest

from lasa_service.errors import LasaError
from lasa_service.processing import APPROVED_PROCESSING, DOMAIN_ONLY

from .conftest import FakeRuntime, configuration, documents, settled, submit, task_request
from .test_content_security import configure_inspection, verdict
from .test_multi_peer import DownstreamTransport

DOMAIN = "urn:lasa:security-domain:fixture"


def qualification(raw, members, *, domain_only=False, qualified=True):
    path = Path(raw["authorization"]["policy_file"])
    policy = json.loads(path.read_text())
    account = policy["principals"][0]
    account["domain_only"] = domain_only
    account["rules"][0]["processing_modes"] = [APPROVED_PROCESSING, DOMAIN_ONLY]
    config = configuration(raw)
    policy["processing_domain"] = {
        "id": DOMAIN,
        "qualified_config": config.revision if qualified else "sha256:" + "0" * 64,
        "qualified_deployment": config.document["service"]["deployment_revision"],
        "qualified_contracts": config.document["published_contracts"],
        "members": members,
    }
    path.write_text(json.dumps(policy))
    return path


async def request_for(client, app, mode):
    request = await task_request(client, app)
    response = await client.get(str(client.base_url).rstrip("/") + "/capabilities")
    offer = next(
        offer
        for offer in response.json()["offers"]
        if offer["contract"] == request["selection"]["contract"]
        and offer["processing"]["mode"] == mode
    )
    request["selection"].update(offer_id=offer["offer_id"], offer_revision=offer["revision"])
    return request, offer


async def test_offer_and_receipts_pin_processing_terms(services, tmp_path):
    raw = documents(tmp_path)
    raw["discovery_cache"]["page_size"] = 20
    qualification(raw, [], qualified=False)
    client, app = await services(raw=raw)
    base = str(client.base_url).rstrip("/")
    offers = (await client.get(base + "/capabilities")).json()["offers"]
    assert {offer["processing"]["mode"] for offer in offers} == {APPROVED_PROCESSING}
    path = qualification(raw, [], domain_only=True)
    request, offer = await request_for(client, app, DOMAIN_ONLY)
    terms = {"mode": DOMAIN_ONLY, "domain": DOMAIN}
    assert offer["processing"] == terms
    assert (await client.get(base + "/capabilities/" + offer["offer_id"])).json() == offer
    assert all(
        item["processing"] == terms
        for item in (await client.get(base + "/capabilities")).json()["offers"]
    )
    response = await submit(client, app, request)
    outcome = await settled(client, response)
    assert outcome["status"] == "completed", outcome
    receipt = outcome["result"]["receipt"]
    assert receipt["selection"] == request["selection"] and receipt["processing"] == terms
    policy = json.loads(path.read_text())
    del policy["processing_domain"]
    path.write_text(json.dumps(policy))
    operation = (await client.get(base + "/operations/" + request["operation_id"])).json()
    assert operation["selection"] == request["selection"] and operation["processing"] == terms


async def test_outside_intake_inspector_receives_no_task_content(services, tmp_path):
    raw = configure_inspection(documents(tmp_path), "caller", "request")
    raw["discovery_cache"]["page_size"] = 20
    qualification(raw, [])
    examined = []

    async def scan(request):
        body = json.loads(request.content)
        examined.append(body)
        return verdict(body)

    client, app = await services(raw=raw, inspection_transport=httpx.MockTransport(scan))
    strict, _ = await request_for(client, app, DOMAIN_ONLY)
    denied = await submit(client, app, strict)
    assert denied.status_code == 503 and denied.json()["code"] == "processing_unavailable"
    assert examined == []
    approved, _ = await request_for(client, app, APPROVED_PROCESSING)
    outcome = await settled(client, await submit(client, app, approved))
    assert outcome["status"] == "completed", outcome
    assert len(examined) == 1


@pytest.mark.parametrize("available", [True, False])
async def test_model_fallback_checks_boundary_at_dispatch(services, tmp_path, available):
    raw = documents(tmp_path)
    raw["discovery_cache"]["page_size"] = 20
    inside = raw["executors"][0]
    raw["default_executor"] = inside["id"]
    outside = {**inside, "id": "outside", "provider_base_url": "https://external.example.net/v1"}
    raw["executors"].append(outside)
    qualification(raw, ["model:" + inside["id"]])
    calls = []

    async def model(request):
        calls.append(request.url.host)
        if request.url.host != "external.example.net" and not available:
            return httpx.Response(503)
        return httpx.Response(200, json={"output": [], "usage": {"total_tokens": 1}})

    async def execute(context):
        c = context.coordinator
        payload = {"input": [{"role": "user", "content": "synthetic task data"}]}
        try:
            await c.model_client.exchange(context.task_id, inside, payload, "execution")
        except LasaError as exc:
            if exc.code != "peer_unavailable":
                raise
            await c.model_client.exchange(context.task_id, outside, payload, "execution")
        return await FakeRuntime().run(context)

    client, app = await services(
        raw=raw, runtime=FakeRuntime(execute), model_transport=httpx.MockTransport(model)
    )
    strict, _ = await request_for(client, app, DOMAIN_ONLY)
    outcome = await settled(client, await submit(client, app, strict))
    if available:
        assert outcome["status"] == "completed", outcome
    else:
        assert outcome["problem"]["code"] == "processing_unavailable", outcome
    assert len(calls) == 1 and "external.example.net" not in calls
    if not available:
        approved, _ = await request_for(client, app, APPROVED_PROCESSING)
        outcome = await settled(client, await submit(client, app, approved))
        assert outcome["status"] == "completed", outcome
        assert calls[-1] == "external.example.net"


@pytest.mark.parametrize("child_in_domain", [True, False])
async def test_domain_only_router_checks_its_in_domain_childs_fulfillment(
    services, tmp_path, child_in_domain
):
    child_raw = documents(tmp_path / "child", "layer2")
    child_model = child_raw["executors"][0]
    child_model["provider_base_url"] = (
        "https://inside.models.example.net/v1"
        if child_in_domain
        else "https://outside.models.example.net/v1"
    )
    child_policy_path = qualification(
        child_raw,
        ["model:" + child_model["id"]] if child_in_domain else [],
        qualified=child_in_domain,
    )
    child_policy = json.loads(child_policy_path.read_text())
    child_policy["principals"][2]["rules"][0]["processing_modes"] = (
        [APPROVED_PROCESSING, DOMAIN_ONLY] if child_in_domain else [APPROVED_PROCESSING]
    )
    child_policy_path.write_text(json.dumps(child_policy))
    model_calls = []

    async def model(request):
        model_calls.append(request.url.host)
        return httpx.Response(200, json={"output": [], "usage": {"total_tokens": 1}})

    async def execute(context):
        c = context.coordinator
        await c.model_client.exchange(
            context.task_id,
            c.config.executor(),
            {"input": [{"role": "user", "content": "synthetic child work"}]},
            "execution",
        )
        return await FakeRuntime().run(context)

    _, child = await services(
        raw=child_raw, runtime=FakeRuntime(execute), model_transport=httpx.MockTransport(model)
    )
    transport = DownstreamTransport({"layer2.example.net": child})
    raw = documents(tmp_path / "parent", peer=True)
    raw["bindings"] = []
    raw["discovery_cache"]["page_size"] = 20
    qualification(raw, ["peer:" + child_raw["service"]["id"]])
    client, app = await services(raw=raw, peer_transport=transport)

    strict, _ = await request_for(client, app, DOMAIN_ONLY)
    result = await settled(client, await submit(client, app, strict))
    if child_in_domain:
        assert result["status"] == "completed", result
        assert transport.submissions() == ["layer2.example.net"]
        (link,) = app.state.coordinator.store.children(result["task_id"])
        _, child_task = child.state.coordinator.store.task(link["task_id"])
        assert child_task["result"]["receipt"]["processing"] == {
            "mode": DOMAIN_ONLY,
            "domain": DOMAIN,
        }
        assert model_calls == ["inside.models.example.net"]
    else:
        assert result["problem"]["code"] == "processing_unavailable", result
        assert not any(method == "POST" for _, method, _ in transport.calls)
        assert model_calls == []
        approved, _ = await request_for(client, app, APPROVED_PROCESSING)
        result = await settled(client, await submit(client, app, approved))
        assert result["status"] == "completed", result
        assert transport.submissions() == ["layer2.example.net"]
        assert model_calls == ["outside.models.example.net"]
