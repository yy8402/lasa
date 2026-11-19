import json
from pathlib import Path

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
from .protocol_helpers import sse_final


@pytest.mark.integration
async def test_real_codex_transport_in_networkless_container_with_controlled_model(
    tmp_path, runtime_image
):
    raw = documents(tmp_path)
    runtime_path = Path(raw["executors"][0]["runtime_profile_file"])
    runtime_data = json.loads(runtime_path.read_text())
    runtime_data["image"] = runtime_image
    runtime_path.write_text(json.dumps(runtime_data))
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

    async def model(request):
        value = json.loads(request.content)
        calls.append(value)
        assert request.url == "https://model.example.net/v1/responses"
        assert request.headers["Authorization"] == "Bearer test-model-key"
        assert custom_instruction.encode() in request.content
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
            200, content=sse_final(json.dumps(final)), headers={"Content-Type": "text/event-stream"}
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
            assert len(calls) == 1 and result["result"]["usage"]["model_calls"] == 1
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
