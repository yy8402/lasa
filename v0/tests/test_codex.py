import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from lasa_service.api import create_app
from lasa_service.runtime import CodexRuntime

from .conftest import (
    configuration,
    deterministic_verifier,
    documents,
    settled,
    submit,
    task_request,
    token,
)
from .protocol_helpers import sse_final, sse_tool


async def test_readiness_validates_every_executor_and_propagates_secondary_failure(monkeypatch):
    profile = {"image": "test-image", "executable": "codex", "expected_version": "test-version"}
    executors = [{"executor_id": name} for name in ("primary", "secondary")]
    service = SimpleNamespace(
        config=SimpleNamespace(
            document={"executors": executors, "runtime": profile},
        ),
    )
    runtime = CodexRuntime()
    verified, probed = [], []

    async def verify(*args):
        verified.append(args)

    async def start(_, executor, settings):
        assert settings == profile
        probed.append(executor["executor_id"])
        if executor["executor_id"] == "secondary":
            raise RuntimeError("secondary cannot start")

    monkeypatch.setattr(runtime.enclosure, "verify_image", verify)
    monkeypatch.setattr(runtime, "probe_executor", start)
    with pytest.raises(RuntimeError, match="secondary cannot start"):
        await runtime.probe(service)
    assert probed == ["primary", "secondary"]
    assert verified == [("test-image", "codex", "test-version")]


@pytest.mark.integration
async def test_real_codex_can_write_and_read_back_without_tool_discovery(tmp_path, runtime_image):
    raw = documents(tmp_path)
    raw["runtime"]["image"] = runtime_image
    raw["limits"]["max_task_budget"]["model_tokens"] = 500000
    raw["limits"]["integration_reserve"]["model_tokens"] = 100000
    policy = Path(raw["authorization"]["policy_file"])
    data = json.loads(policy.read_text())
    for principal in data["principals"]:
        for rule in principal["rules"]:
            rule["budget"]["model_tokens"] = 500000
    policy.write_text(json.dumps(data))
    prompts = dict(configuration(raw).prompts)
    custom_instruction = "Execute the configured bounded task."
    prompts["execution_developer"] += " " + custom_instruction
    prompt_path = tmp_path / "prompts.json"
    prompt_path.write_text(json.dumps(prompts), encoding="utf-8")
    raw["prompts_file"] = str(prompt_path)
    raw["executors"][0]["provider_base_url"] = "https://model.example.net/v1/"
    cfg = configuration(raw)
    calls = []
    path = "marker.txt"
    text = "Read back through the approved LASA tool."

    async def model(request):
        value = json.loads(request.content)
        calls.append(value)
        assert request.url == "https://model.example.net/v1/responses"
        assert request.headers["Authorization"] == "Bearer test-model-key"
        assert custom_instruction.encode() in request.content
        names = {tool.get("name") for tool in value["tools"] if tool["type"] == "function"}
        assert {"workspace_write", "workspace_read"} <= names
        assert "list_mcp_resources" not in names
        if len(calls) == 1:
            return httpx.Response(
                200,
                content=sse_tool(
                    "workspace_write", {"relative_path": path, "text": text}, 1
                ).replace(b"\n", b"\r\n"),
                headers={"Content-Type": "text/event-stream"},
            )
        if len(calls) == 2:
            return httpx.Response(
                200,
                content=sse_tool("workspace_read", {"relative_path": path}, 2),
                headers={"Content-Type": "text/event-stream"},
            )
        assert len(calls) == 3 and any(
            text in json.dumps(item)
            for item in value["input"]
            if item["type"] == "function_call_output"
        )
        final = {
            "output": {
                "disposition": "fulfilled",
                "summary": "Bounded execution finished.",
                "requirement_evidence": [
                    {
                        "id": "requirement-main",
                        "evidence": "The controlled App Server transport returned the expected typed outcome.",
                    }
                ],
            },
            "evidence": [
                {
                    "criterion_id": "honest-disposition",
                    "disposition": "passed",
                    "summary": "Transport result verified.",
                    "artifact_ids": [],
                }
            ],
            "artifact_ids": [],
        }
        return httpx.Response(
            200,
            content=sse_final(json.dumps(final), 3),
            headers={"Content-Type": "text/event-stream"},
        )

    app = create_app(
        cfg,
        runtime=CodexRuntime(),
        model_transport=httpx.MockTransport(model),
        verifier=deterministic_verifier,
    )
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="https://layer1.example.net",
            headers={"Authorization": "Bearer " + token(audience=cfg.service_id)},
        ) as client:
            response = await submit(client, app, await task_request(client, app))
            result = await settled(client, response)
            assert result["status"] == "completed", result
            assert len(calls) == 3 and result["result"]["usage"]["model_calls"] == 3
            assert result["result"]["effect_disposition"] == "known"
            assert result["result"]["usage"]["tool_calls"] == 2
            workspace = app.state.coordinator.workspace(result["session_id"])
            assert workspace.read(path) == text
            assert not app.state.coordinator.runtime.handles
            assert (
                app.state.coordinator.store.db.execute("SELECT COUNT(*) FROM runtimes").fetchone()[
                    0
                ]
                == 0
            )
            events = (await client.get(response.headers["Location"] + "/events")).json()["events"]
            assert any(x["kind"] == "call" and x["payload"]["call_type"] == "model" for x in events)
            assert "test-model-key" not in json.dumps(events)
