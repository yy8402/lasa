"""Per-task model/tool gateway outside the networkless Codex enclosure."""

import asyncio
import hashlib
import hmac
import secrets
import socket
import time
from contextlib import nullcontext

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from .capabilities import require
from .contracts import canonical, parse_json
from .errors import LasaError


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
        self.execution_id = secrets.token_hex(16)
        self.failure = asyncio.get_running_loop().create_future()
        self.server = None
        self.worker = None
        self.sockets = []
        self.client = None
        self.url = None

    def tool_operation_id(self, action_id):
        return "tool-" + hashlib.sha256((self.execution_id + ":" + action_id).encode()).hexdigest()

    def fail(self, error):
        if not self.failure.done():
            self.failure.set_result(error)

    async def start(self):
        c = self.context.coordinator
        task_id = self.context.task_id
        executor = c.config.executor(self.context.binding)
        c.diagnostics.register_secret(task_id, self.token)
        self.client = httpx.AsyncClient(
            trust_env=False, follow_redirects=False, timeout=60, transport=c.model_transport
        )
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
        async def error(request, exc):
            self.fail(exc)
            return JSONResponse(exc.public(), status_code=exc.status)

        @app.get("/broker/tools")
        async def tools(request: Request):
            authenticate(request)
            return {"tools": await c.broker.tools(task_id)}

        @app.post("/broker/call")
        async def call(request: Request):
            authenticate(request)
            value = await body(request)
            require(
                isinstance(value, dict)
                and set(value) == {"name", "action_id", "arguments"}
                and isinstance(value["action_id"], str)
                and len(value["action_id"]) <= 128,
                "invalid_input",
            )
            names = {name.replace(".", "_"): name for name in c.broker._authorized(task_id)}
            require(value["name"] in names, "authority_denied", 403)
            try:
                return await c.broker.call(
                    task_id,
                    self.tool_operation_id(value["action_id"]),
                    names[value["name"]],
                    value["arguments"],
                )
            except LasaError as exc:
                return JSONResponse({"error": exc.public()})

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
            operation = c.begin_model(task_id, value, "execution")
            started = time.monotonic()
            try:
                async with asyncio.timeout(c.remaining_seconds(task_id, operation_id=operation)):
                    upstream = await self.client.send(
                        self.client.build_request(
                            "POST",
                            executor["provider_base_url"].rstrip("/") + suffix,
                            content=canonical(value),
                            headers={
                                "Authorization": "Bearer "
                                + c.config.secret(executor["credential_ref"]),
                                "Content-Type": "application/json",
                            },
                        ),
                        stream=True,
                    )
            except TimeoutError:
                raise LasaError("deadline_exceeded", 422) from None
            except httpx.HTTPError:
                raise LasaError("peer_unavailable", 503) from None
            if upstream.status_code != 200:
                await upstream.aclose()
                raise LasaError("peer_unavailable", 503)
            content_type = upstream.headers.get("Content-Type", "").split(";")[0]
            require(
                content_type in {"text/event-stream", "application/json"},
                "verification_failed",
                502,
            )

            async def stream():
                total = 0
                buffer = b""
                finished = False
                try:
                    async with asyncio.timeout(
                        c.remaining_seconds(task_id, operation_id=operation)
                    ):
                        async for chunk in upstream.aiter_bytes():
                            c.check_active(task_id)
                            total += len(chunk)
                            require(total <= 2097152, "capacity_exhausted", 429)
                            buffer += chunk
                            if content_type == "text/event-stream":
                                while b"\n\n" in buffer:
                                    block, buffer = buffer.split(b"\n\n", 1)
                                    data = b"\n".join(
                                        line[5:].strip()
                                        for line in block.splitlines()
                                        if line.startswith(b"data:")
                                    )
                                    if data and data != b"[DONE]":
                                        event = parse_json(data)
                                        if event.get("type") == "response.completed":
                                            response = event["response"]
                                            visible = [
                                                item
                                                for item in response.get("output", [])
                                                if item.get("type")
                                                in {"message", "function_call", "custom_tool_call"}
                                            ]
                                            c.finish_model(
                                                task_id,
                                                operation,
                                                response.get("usage", {}),
                                                int((time.monotonic() - started) * 1000),
                                                {"output": visible},
                                            )
                                            finished = True
                                    yield block + b"\n\n"
                            else:
                                continue
                        if content_type == "application/json":
                            response = parse_json(buffer)
                            c.finish_model(
                                task_id,
                                operation,
                                response.get("usage", {}),
                                int((time.monotonic() - started) * 1000),
                                {"status": response.get("status")},
                            )
                            finished = True
                            yield buffer
                        require(finished, "verification_failed", 502)
                except TimeoutError:
                    self.fail(LasaError("deadline_exceeded", 422))
                except (httpx.HTTPError, LasaError) as exc:
                    self.fail(
                        exc if isinstance(exc, LasaError) else LasaError("peer_unavailable", 503)
                    )
                finally:
                    await upstream.aclose()

            return StreamingResponse(stream(), media_type=content_type)

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
        if self.client:
            await self.client.aclose()
