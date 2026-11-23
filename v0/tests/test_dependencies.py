"""Dependency facts affect only their approved binding and retain the offer."""

import copy
import json
import sys
from pathlib import Path

import pytest

from lasa_service.config import Configuration
from lasa_service.errors import LasaError

from .conftest import documents, settled, submit, task_request
from .test_connector_transports import LIMITS, operation


def with_reports(raw):
    resource = {
        "id": "private-report-connector",
        "kind": "mcp-stdio",
        "command": sys.executable,
        "args": ["-u", str((Path(__file__).parent / "fixtures/mcp_server.py").resolve())],
        "secret_env": {},
        "limits": {**LIMITS, "schema_refresh_seconds": 30},
        "operations": [operation()],
    }
    raw["executors"][0]["connectors"] = [resource]
    binding = next(
        item for item in raw["bindings"] if item["contract"]["id"].endswith("/task.attempt")
    )
    binding["required_operations"] = ["reports.inspect"]
    binding["allowed_effects"].append("external.read")
    binding["approved_resources"].append({"resource": "reports:approved", "actions": ["read"]})
    path = Path(raw["authorization"]["policy_file"])
    policy = json.loads(path.read_text())
    rule = policy["principals"][0]["rules"][0]
    rule["effects"].append("external.read")
    rule["resources"].append({"resource": "reports:approved", "actions": ["read"]})
    path.write_text(json.dumps(policy))
    return resource, binding


@pytest.mark.parametrize("state", ["available", "busy", "unavailable", "unauthorized", "unknown"])
async def test_offer_retained_and_unrelated_work_available_for_dependency_states(
    services, tmp_path, state
):
    raw = documents(tmp_path)
    with_reports(raw)
    client, app = await services(raw=raw)
    c = app.state.coordinator
    c.broker.connectors["private-report-connector"].states["reports.inspect"] = state
    filters = {
        "contract_id": "https://contracts.example.net/capabilities/task.attempt",
        "contract_version": "1.0.0",
    }
    before = (await client.get(raw["service"]["base_url"] + "/capabilities", params=filters)).json()
    offer = next(
        item for item in before["offers"] if item["contract"]["id"].endswith("/task.attempt")
    )
    response = await client.get(
        raw["service"]["base_url"] + "/capabilities/" + offer["offer_id"] + "/availability"
    )
    assert response.status_code == 200 and response.json()["state"] == state
    assert "private-report-connector" not in response.text and "inspect_report" not in response.text
    unchanged = (
        await client.get(raw["service"]["base_url"] + "/capabilities", params=filters)
    ).json()
    assert unchanged == before
    body = await task_request(client, app, profile="design.review")
    result = await settled(client, await submit(client, app, body))
    assert result["status"] == "completed"


async def test_current_policy_denies_dependency_without_disabling_service(services, tmp_path):
    raw = documents(tmp_path)
    _, binding = with_reports(raw)
    client, app = await services(raw=raw)
    c = app.state.coordinator
    assert (
        c.broker.binding_state(binding, c.authorization.rules({"subject": "alice"})[0])
        == "available"
    )
    path = Path(raw["authorization"]["policy_file"])
    policy = json.loads(path.read_text())
    policy["principals"][0]["rules"][0]["effects"].remove("external.read")
    path.write_text(json.dumps(policy))
    body = await task_request(client, app)
    availability = await client.get(
        raw["service"]["base_url"]
        + "/capabilities/"
        + body["selection"]["offer_id"]
        + "/availability"
    )
    assert availability.json()["state"] == "unauthorized"
    result = await settled(client, await submit(client, app, body))
    assert result["status"] == "rejected" and result["problem"]["code"] == "authority_denied"
    assert not c.runtime.prompts
    assert c.availability() == "available"


@pytest.mark.parametrize(
    "change",
    ["unknown-operation", "resource-outside-binding", "remote-schema", "literal-auth-header"],
)
def test_invalid_private_scope_or_schema_rejected_before_connector_start(tmp_path, change):
    raw = documents(tmp_path)
    resource, binding = with_reports(raw)
    if change == "unknown-operation":
        binding["required_operations"] = ["not.registered"]
    elif change == "resource-outside-binding":
        binding["approved_resources"] = [{"resource": "workspace:self", "actions": ["read"]}]
    elif change == "remote-schema":
        resource["operations"][0]["input_schema"] = {"$ref": "https://unapproved.example/schema"}
    else:
        resource = {
            "id": "private-json-app",
            "kind": "json-get",
            "base_url": "https://example.net/records",
            "headers": {"Authorization": "literal forbidden secret"},
            "limits": copy.deepcopy(LIMITS),
            "operations": [
                {
                    "operation_id": "reports.inspect",
                    "description": "Read a report.",
                    "task_input_bindings": [],
                    "effect": "external.read",
                    "resource": "reports:approved",
                    "input_schema": {"type": "object"},
                    "argument_constraints": {},
                    "output_schema": {"type": "object"},
                    "response_schema": {"type": "object"},
                    "result_fields": ["title"],
                    "probe_arguments": {},
                    "url": "https://example.net/records",
                }
            ],
        }
    raw["executors"][0]["connectors"] = [resource]
    with pytest.raises((ValueError, LasaError)) as rejected:
        Configuration.from_document(raw, environ={"MODEL_KEY": "test-model-key"})
    if change == "remote-schema":
        assert rejected.value.code == "invalid_input"
    else:
        assert any(
            word in str(rejected.value)
            for word in ["unregistered operation", "cannot authorize", "private references"]
        )
