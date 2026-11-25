"""Failure-injection process: terminate after the workspace effect commits."""

import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import httpx

from lasa_service.api import create_app
from tests.conftest import (
    FakeRuntime,
    configuration,
    deterministic_planner,
    deterministic_verifier,
    documents,
    submit,
    task_request,
    token,
)


async def main():
    root = Path(sys.argv[1])
    raw = documents(root)
    (root / "config.json").write_text(json.dumps(raw))
    cfg = configuration(raw)

    async def handler(context):
        await context.coordinator.broker.call(
            context.task_id,
            "crash-write",
            "workspace.write",
            {"relative_path": "committed.txt", "text": "one committed write"},
        )

    app = create_app(
        cfg,
        runtime=FakeRuntime(handler),
        planner=deterministic_planner,
        verifier=deterministic_verifier,
    )
    async with app.router.lifespan_context(app):
        app.state.coordinator.fault = lambda point, task_id: (
            os._exit(72) if point == "after_effect" else None
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="https://layer1.example.net",
            headers={"Authorization": "Bearer " + token(audience=cfg.service_id)},
        ) as client:
            await submit(client, app, await task_request(client, app))
            await asyncio.sleep(5)
    raise SystemExit(73)


if __name__ == "__main__":
    asyncio.run(main())
