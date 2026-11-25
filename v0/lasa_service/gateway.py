"""Per-task model gateway outside the networkless Codex enclosure."""

import asyncio
import hmac
import secrets
import socket
from contextlib import nullcontext

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from .capabilities import require
from .contracts import parse_json
from .errors import LasaError
from .recovery import capability_context, revise_model_context


def validate_local_tools(value):
    """Allow local calls/discovery, including catalogs loaded later in a turn."""

    def catalog(tools):
        if not isinstance(tools, list):
            raise LasaError("incompatible_protocol")
        for tool in tools:
            if not isinstance(tool, dict):
                raise LasaError("incompatible_protocol")
            kind = tool.get("type")
            if kind == "namespace":
                catalog(tool.get("tools"))
            elif kind == "tool_search":
                if tool.get("execution") != "client":
                    raise LasaError("incompatible_protocol")
            elif kind not in {"function", "custom"}:
                raise LasaError("incompatible_protocol")

    require(
        not any(key in value for key in ["previous_response_id", "conversation"])
        and not value.get("background", False),
        "incompatible_protocol",
        422,
    )

    def inference_only(node):
        if isinstance(node, dict):
            require(
                node.get("type")
                not in {"input_image", "input_file", "input_audio", "computer_screenshot"},
                "authority_denied",
                403,
            )
            for item in node.values():
                inference_only(item)
        elif isinstance(node, list):
            for item in node:
                inference_only(item)

    inference_only(value.get("input", []))
    catalog(value.get("tools", []))
    for item in value.get("input", []):
        if isinstance(item, dict) and item.get("type") in {
            "additional_tools",
            "tool_search_output",
        }:
            if item.get("type") == "tool_search_output" and item.get("execution") != "client":
                raise LasaError("incompatible_protocol")
            catalog(item.get("tools"))


class TaskGateway:
    def __init__(self, context):
        self.context = context
        self.token = secrets.token_urlsafe(32)
        self.failure = asyncio.get_running_loop().create_future()
        self.server = None
        self.worker = None
        self.sockets = []
        self.url = None

    def fail(self, error):
        if not self.failure.done():
            self.failure.set_result(error)

    async def start(self):
        c = self.context.coordinator
        task_id = self.context.task_id
        executor = c.config.executor(self.context.binding)
        prompt = self.context.model_prompt()
        revised_prompt = {
            **prompt,
            "input": capability_context(self.context.definition, prompt["input"]),
        }
        c.diagnostics.register_secret(task_id, self.token)
        app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

        def authenticate(request):
            require(
                hmac.compare_digest(
                    request.headers.get("Authorization", ""), "Bearer " + self.token
                ),
                "authority_denied",
                401,
            )
            c.check_active(task_id)

        async def body(request):
            parts = []
            size = 0
            async for part in request.stream():
                size += len(part)
                require(size <= 1048576, "capacity_exhausted", 413)
                parts.append(part)
            return parse_json(b"".join(parts))

        @app.exception_handler(LasaError)
        async def error(_request, exc):
            self.fail(exc)
            return JSONResponse(exc.public(), status_code=exc.status)

        async def model(request, suffix):
            authenticate(request)
            value = await body(request)
            require(
                isinstance(value, dict) and value.get("model") == executor["model"],
                "verification_failed",
                422,
            )
            validate_local_tools(value)
            value["store"] = False
            value["max_output_tokens"] = min(value.get("max_output_tokens", 3000), 3000)
            result = await c.model_client.exchange(
                task_id,
                executor,
                value,
                "compaction" if suffix.endswith("/compact") else "execution",
                suffix=suffix,
                worker=True,
                revise=revise_model_context(value, prompt, revised_prompt),
            )
            return Response(result.body, media_type=result.media_type)

        @app.post("/model/responses")
        async def responses(request: Request):
            return await model(request, "/responses")

        @app.post("/model/responses/compact")
        async def compact(request: Request):
            return await model(request, "/responses/compact")

        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen(16)
        sock.setblocking(False)
        self.sockets = [sock]
        self.url = f"http://127.0.0.1:{sock.getsockname()[1]}"
        self.server = uvicorn.Server(
            uvicorn.Config(
                app,
                log_level="critical",
                access_log=False,
                lifespan="off",
                timeout_graceful_shutdown=0.1,
            )
        )
        self.server.capture_signals = nullcontext
        self.worker = asyncio.create_task(self.server.serve(sockets=self.sockets))
        for _ in range(100):
            if self.server.started:
                return
            if self.worker.done():
                break
            await asyncio.sleep(0.01)
        raise LasaError("internal_error", 503)

    async def close(self):
        if self.server:
            self.server.should_exit = True
        if self.worker:
            try:
                async with asyncio.timeout(2):
                    await self.worker
            except (TimeoutError, asyncio.CancelledError):
                self.worker.cancel()
                await asyncio.gather(self.worker, return_exceptions=True)
        for sock in self.sockets:
            sock.close()
