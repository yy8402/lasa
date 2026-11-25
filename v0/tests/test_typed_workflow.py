import copy
import json
from pathlib import Path

import httpx
import pytest

from lasa_service.capabilities import reference
from lasa_service.config import builtin_capabilities
from lasa_service.contracts import parse_json

from .conftest import documents, settled, submit, task_request
from .protocol_helpers import verification_report
from .test_multi_peer import setup_peers

INPUT = {
    "review": {
        "design": "Check both receivers before starting the parent.",
        "criteria": [{"id": "readiness", "description": "Check receiver readiness ordering."}],
    },
    "checklist": {
        "objective": "Produce the operator checklist from the review.",
        "requirements": [
            {
                "id": "confirm-both",
                "description": "Check both receivers.",
                "acceptance": ["Include both receivers in the readiness gate."],
            }
        ],
    },
}


@pytest.mark.parametrize("mode", ["valid", "forged"])
async def test_typed_workflow_checks_exact_child_receipts(services, tmp_path, mode):
    async def unexpected_planning(*args):
        pytest.fail("A registered workflow must compile without model planning")

    client, app, workers, runtimes, transport = await setup_peers(
        services,
        tmp_path,
        planner=unexpected_planning,
        contracts_by_peer={"layer2": {"design.review"}, "layer3": {"task.attempt"}},
    )
    parent = app.state.coordinator
    workflow = reference(builtin_capabilities()["design.review-checklist"][0])
    parent.config.document["published_contracts"].append(workflow)
    path = Path(parent.config.document["authorization"]["policy_file"])
    policy = json.loads(path.read_text())
    rule = policy["principals"][0]["rules"][0]
    rule["contracts"].append(workflow)
    for grant in rule["delegation_grants"]:
        grant.update(effects=[], resources=[], disclosure_resources=[])
        layer = grant["receiver_service_id"].rsplit("/", 1)[1]
        receiver = workers[layer + ".example.net"].state.coordinator
        policy_path = Path(receiver.config.document["authorization"]["policy_file"])
        receiver_policy = json.loads(policy_path.read_text())
        principal = next(item for item in receiver_policy["principals"] if item["kind"] == "peer")
        pure = copy.deepcopy(principal["rules"][0])
        pure.update(authorization_ref="pure-task", effects=[], resources=[])
        principal["rules"].append(pure)
        policy_path.write_text(json.dumps(receiver_policy))
    path.write_text(json.dumps(policy))

    async def forge(response_request):
        response = await originally(response_request)
        if (
            response_request.method == "GET"
            and response_request.url.host == "layer2.example.net"
            and "/tasks/" in response_request.url.path
            and "view" not in response_request.url.params
        ):
            data = parse_json(await response.aread())
            if data["status"] == "completed":
                data["result"]["receipt"]["operation_id"] = "another-operation"
                await response.aclose()
                return httpx.Response(200, json=data)
        return response

    originally = transport.handle_async_request
    if mode == "forged":
        transport.handle_async_request = forge

    verifies = []

    async def verify(c, task_id, definition, inputs, output, evidence, requirements):
        verifies.append(definition["id"])
        return True

    parent.planner.verifier = verify
    request = await task_request(client, app, profile="design.review-checklist", inputs=INPUT)
    result = await settled(client, await submit(client, app, request))
    if mode == "forged":
        assert result["status"] == "failed" and result["problem"]["code"] == "verification_failed"
        assert transport.submissions() == ["layer2.example.net"]
        assert not verifies
        return
    assert result["status"] == "completed", result
    assert transport.submissions() == ["layer2.example.net", "layer3.example.net"]
    output = result["result"]["output"]
    (review,) = runtimes["layer3.example.net"].prompts[0]["imports"]
    assert review["label"] == "review" and review["output"] == output["review"]
    assert output["checklist"]["disposition"] == "fulfilled"
    assert {x["id"] for x in output["checklist"]["requirement_evidence"]} == {
        "confirm-both",
        "verified-review-handoff",
    }
    assert [identifier.rsplit("/", 1)[-1] for identifier in verifies] == [
        "design.review",
        "task.attempt",
    ]
    assert not parent.runtime.prompts


async def test_verifier_model_override_uses_existing_provider(services, tmp_path):
    raw = documents(tmp_path / "leaf")
    raw["verification"] = {"model": "fast-verifier", "reasoning_effort": "low"}
    bodies = []

    def model(request):
        body = parse_json(request.content)
        bodies.append(body)
        payload = parse_json(body["input"][-2]["content"][0]["text"])
        return httpx.Response(
            200,
            json={
                "output": [
                    {
                        "type": "message",
                        "content": [
                            {
                                "type": "output_text",
                                "text": json.dumps(verification_report(payload["criteria"])),
                            }
                        ],
                    }
                ],
                "usage": {"total_tokens": 12},
            },
        )

    client, app = await services(raw=raw, model_transport=httpx.MockTransport(model))
    app.state.coordinator.planner.verifier = None
    result = await settled(client, await submit(client, app, await task_request(client, app)))
    assert result["status"] == "completed"
    assert [(body["model"], body["reasoning"]) for body in bodies] == [
        ("fast-verifier", {"effort": "low"})
    ]
