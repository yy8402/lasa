import copy
import json
from pathlib import Path

import httpx
import pytest

from .conftest import FakeRuntime, documents, settled, submit, task_request


async def test_dispatch_attenuates_newly_narrowed_effects_and_resources(services, tmp_path):
    async def child_handler(context):
        c = context.coordinator
        request = c.request(context.task_id)
        ceiling = request["delegation"]["authority_ceiling"]
        assert ceiling["allowed_effects"] == ["workspace.read"]
        assert ceiling["resources"] == [{"resource": "workspace:self", "actions": ["read"]}]
        assert not c.permits(context.task_id, "workspace.write", "workspace:self", "update")
        return await FakeRuntime().run(context)

    child_client, child_app = await services(
        raw=documents(tmp_path / "child", "layer2"), runtime=FakeRuntime(child_handler)
    )
    raw = documents(tmp_path / "parent", peer=True)
    raw["routing"]["preferred_executor"] = "peer"
    client, app = await services(raw=raw, peer_transport=httpx.ASGITransport(app=child_app))
    c = app.state.coordinator

    def narrow(point, task_id):
        if point == "before_child_dispatch":
            path = Path(raw["authorization"]["policy_file"])
            policy = json.loads(path.read_text())
            rule = policy["principals"][0]["rules"][0]
            rule["effects"] = ["workspace.read"]
            rule["resources"] = [{"resource": "workspace:self", "actions": ["read"]}]
            path.write_text(json.dumps(policy))

    c.fault = narrow
    result = await settled(client, await submit(client, app, await task_request(client, app)))
    assert result["status"] == "completed", result


@pytest.mark.parametrize("tamper", ["task_id", "underreported_artifacts", "cumulative_artifacts"])
async def test_child_linkage_and_observed_cumulative_artifact_budget(services, tmp_path, tamper):
    async def child_handler(context):
        manifest = context.coordinator.snapshot_artifact(
            context.task_id, "proof", "text/plain", "abc"
        )
        result = await FakeRuntime().run(context)
        result["artifact_ids"] = [manifest["artifact_id"]]
        return result

    child_client, child_app = await services(
        raw=documents(tmp_path / "child", "layer2"), runtime=FakeRuntime(child_handler)
    )
    inner = httpx.ASGITransport(app=child_app)

    class Alter(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            if request.url.path.endswith("/artifacts/artifact-alias"):
                return httpx.Response(200, content=b"abc", request=request)
            response = await inner.handle_async_request(request)
            content = await response.aread()
            if (
                request.method == "GET"
                and "/tasks/" in request.url.path
                and "/artifacts/" not in request.url.path
            ):
                value = json.loads(content)
                if value.get("status") == "completed":
                    if tamper == "task_id":
                        value["task_id"] = "task-another-operation"
                    elif tamper == "underreported_artifacts":
                        value["result"]["usage"]["artifact_bytes"] = 0
                    else:
                        alias = copy.deepcopy(value["result"]["artifacts"][0])
                        alias["artifact_id"] = "artifact-alias"
                        value["result"]["artifacts"].append(alias)
                        value["result"]["usage"]["artifact_bytes"] = 5
                return httpx.Response(response.status_code, json=value, request=request)
            return httpx.Response(
                response.status_code, content=content, headers=response.headers, request=request
            )

    raw = documents(tmp_path / "parent", peer=True)
    raw["routing"]["preferred_executor"] = "peer"
    client, app = await services(raw=raw, peer_transport=Alter())
    request = await task_request(client, app)
    request["requested_limits"]["budget"]["artifact_bytes"] = 5
    result = await settled(client, await submit(client, app, request))
    assert result["status"] in {"failed", "indeterminate"} and "result" not in result
    assert all(
        r[0] == -1
        for r in app.state.coordinator.store.db.execute(
            "SELECT released FROM artifacts WHERE task_id=?", (result["task_id"],)
        )
    )


async def test_content_diagnostics_redact_and_keep_operation_headers_when_truncated(
    services, tmp_path
):
    raw = documents(tmp_path)
    path = Path(raw["authorization"]["policy_file"])
    policy = json.loads(path.read_text())
    policy["principals"][0]["rules"][0]["content_diagnostics"] = True
    path.write_text(json.dumps(policy))

    async def handler(context):
        c = context.coordinator
        for i in range(5):
            c.diagnostics.call(
                context.task_id,
                "trace-" + str(i),
                "tool",
                "finished",
                {"query": "x" * 20000},
                content={
                    "query": "x" * 20000,
                    "api_key": "test-model-key",
                    "reflection": "test-model-key",
                },
            )
        return await FakeRuntime().run(context)

    client, app = await services(raw=raw, runtime=FakeRuntime(handler))
    request = await task_request(client, app)
    request["diagnostics"] = "content"
    response = await submit(client, app, request)
    result = await settled(client, response)
    events = (await client.get(response.headers["Location"] + "/events")).json()["events"]
    calls = [x for x in events if x["kind"] == "call"]
    assert result["status"] == "completed" and len(calls) == 5
    assert all(
        x["payload"]["operation_id"].startswith("trace-") and x["payload"]["payload_truncated"]
        for x in calls
    )
    assert "test-model-key" not in json.dumps(events)
    policy["principals"][0]["rules"][0]["content_diagnostics"] = False
    path.write_text(json.dumps(policy))
    assert all(
        "content" not in x
        for x in (await client.get(response.headers["Location"] + "/events")).json()["events"]
    )
