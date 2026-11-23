import json
from pathlib import Path

import httpx
import pytest

from lasa_service.capabilities import reference
from lasa_service.config import ConfigurationError, builtin_capabilities
from lasa_service.contracts import digest, parse_json

from .conftest import documents, settled, submit, task_request
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


@pytest.mark.parametrize("mode", ["trusted", "revoked", "forged", "wrong-revision"])
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
    rule["verifier_trust"] = [
        {
            "service_id": grant["receiver_service_id"],
            "contract": grant["contract"],
            "verifier_revision": workers[
                grant["receiver_service_id"].rsplit("/", 1)[-1] + ".example.net"
            ].state.coordinator.config.verifier_revision,
        }
        for grant in rule["delegation_grants"]
    ]
    if mode == "wrong-revision":
        rule["verifier_trust"][0]["verifier_revision"] = digest("other verifier")
    pin = rule["verifier_trust"][0]
    path.write_text(json.dumps(policy))

    def revoke(point, task_id):
        if point == "after_admission":
            rule["verifier_trust"].clear()
            path.write_text(json.dumps(policy))

    async def forge(response_request):
        response = await originally(response_request)
        if (
            response_request.method == "GET"
            and response_request.url.host == "layer2.example.net"
            and "/tasks/" in response_request.url.path
        ):
            data = parse_json(await response.aread())
            if data["status"] == "completed":
                data["result"]["verification_receipt"]["delegation_id"] = "another-delegation"
                await response.aclose()
                return httpx.Response(200, json=data)
        return response

    originally = transport.handle_async_request
    if mode == "revoked":
        parent.fault = revoke
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
    assert runtimes["layer3.example.net"].prompts[0]["delegated_dependencies"] == {
        "review": output["review"]
    }
    assert output["checklist"]["disposition"] == "fulfilled"
    assert {x["id"] for x in output["checklist"]["requirement_evidence"]} == {
        "confirm-both",
        "verified-review-handoff",
    }
    adopted = parent.store.db.execute(
        "SELECT COUNT(*) FROM audit WHERE task_id=? AND kind='trusted_verification_receipt'",
        (result["task_id"],),
    ).fetchone()[0]
    assert (adopted, len(verifies)) == {
        "trusted": (2, 0),
        "revoked": (0, 2),
        "wrong-revision": (1, 1),
    }[mode]
    assert not parent.runtime.prompts

    rule["delegation_grants"].clear()
    rule["verifier_trust"] = [pin]
    path.write_text(json.dumps(policy))
    with pytest.raises(ConfigurationError, match="outbound delegation grant"):
        parent.config.policy()


async def test_verifier_model_override_uses_existing_provider(services, tmp_path):
    raw = documents(tmp_path / "leaf")
    raw["verification"] = {"model": "fast-verifier", "reasoning_effort": "low"}
    bodies = []

    def model(request):
        bodies.append(parse_json(request.content))
        return httpx.Response(
            200,
            json={
                "output": [
                    {
                        "type": "message",
                        "content": [
                            {"type": "output_text", "text": '{"passed":true,"reason":"Verified"}'}
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
