import ast
import json
import sys
from pathlib import Path

from .conftest import FakeRuntime, documents, settled, submit, task_request


async def test_registered_mcp_tool_runs_through_actual_stdio_and_authority(services, tmp_path):
    raw = documents(tmp_path)
    fixture = Path(__file__).parent / "fixtures/mcp_server.py"
    parsed = ast.parse(fixture.read_text())
    schemas = {
        node.targets[0].id: ast.literal_eval(node.value)
        for node in parsed.body
        if isinstance(node, ast.Assign) and node.targets[0].id in {"INPUT", "OUTPUT"}
    }
    resource = {
        "id": "mcp-reports",
        "kind": "mcp-stdio",
        "limits": {
            "max_queue": 2,
            "request_timeout_seconds": 2,
            "response_bytes": 32768,
            "recovery_interval_seconds": 1,
            "schema_refresh_seconds": 30,
        },
        "command": sys.executable,
        "args": ["-u", str(fixture.resolve())],
        "secret_env": {},
        "operations": [
            {
                "operation_id": "reports.inspect",
                "description": "Read an approved report.",
                "upstream_tool": "inspect_report",
                "upstream_output_schema": schemas["OUTPUT"],
                "result_format": "structured",
                "argument_constraints": {"properties": {"report_id": {"const": "42"}}},
                "task_input_bindings": [],
                "effect": "external.read",
                "resource": "reports:approved",
                "input_schema": schemas["INPUT"],
                "output_schema": schemas["OUTPUT"],
            }
        ],
    }
    Path(raw["executors"][0]["connector_policy_file"]).write_text(
        json.dumps({"connectors": [resource]})
    )
    binding = next(x for x in raw["bindings"] if x["contract"]["id"].endswith("/task.attempt"))
    binding["allowed_effects"].append("external.read")
    binding["required_operations"] = ["reports.inspect"]
    binding["approved_resources"].append({"resource": "reports:approved", "actions": ["read"]})
    path = Path(raw["authorization"]["policy_file"])
    policy = json.loads(path.read_text())
    rule = policy["principals"][0]["rules"][0]
    rule["effects"].append("external.read")
    rule["resources"].append({"resource": "reports:approved", "actions": ["read"]})
    path.write_text(json.dumps(policy))

    async def handler(context):
        value = await context.coordinator.broker.call(
            context.task_id, "inspect-once", "reports.inspect", {"report_id": "42"}
        )
        assert value["output"] == {"text": "Report 42"}
        assert value["evidence_artifact"]["provenance"]["kind"] == "operation-result"
        assert (
            await context.coordinator.broker.call(
                context.task_id, "inspect-once", "reports.inspect", {"report_id": "42"}
            )
            == value
        )
        return await FakeRuntime().run(context)

    client, app = await services(raw=raw, runtime=FakeRuntime(handler))
    result = await settled(client, await submit(client, app, await task_request(client, app)))
    assert result["status"] == "completed" and result["result"]["usage"]["tool_calls"] == 1
