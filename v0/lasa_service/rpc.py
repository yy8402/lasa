"""Bounded JSON-RPC transport for a private App Server subprocess."""

import asyncio
import base64
import json

import httpx

from .contracts import parse_json
from .errors import LasaError


class AppServerClient:
    def __init__(self, process, context, *, gateway):
        self.process, self.context = process, context
        self.gateway = gateway
        self.pending = {}
        self.sequence = 0
        self.completed = asyncio.get_running_loop().create_future()
        self.thread_id = None
        self.turn_id = None
        self.answer = None
        self.reader = asyncio.create_task(self._read())
        self.handlers = set()

    async def send(self, message):
        self.process.stdin.write(json.dumps(message, ensure_ascii=False).encode() + b"\n")
        await self.process.stdin.drain()

    async def request(self, method, params):
        self.sequence += 1
        sequence = self.sequence
        future = asyncio.get_running_loop().create_future()
        self.pending[sequence] = future
        try:
            await self.send({"jsonrpc": "2.0", "id": sequence, "method": method, "params": params})
            return await future
        finally:
            self.pending.pop(sequence, None)

    async def _read(self):
        try:
            while line := await self.process.stdout.readline():
                message = parse_json(line)
                if message.get("lasa_gateway") == "request":
                    handler = asyncio.create_task(self._gateway_request(message))
                    self.handlers.add(handler)
                    handler.add_done_callback(self.handlers.discard)
                elif "method" not in message:
                    future = self.pending.get(message.get("id"))
                    if future and not future.done():
                        if "error" in message:
                            future.set_exception(LasaError("verification_failed"))
                        else:
                            future.set_result(message.get("result"))
                elif "id" in message:
                    handler = asyncio.create_task(self._server_request(message))
                    self.handlers.add(handler)
                    handler.add_done_callback(self.handlers.discard)
                else:
                    params = message.get("params", {})
                    method = message["method"]
                    if method == "turn/started":
                        self.turn_id = params["turn"]["id"]
                    elif method == "item/completed":
                        item = params.get("item", {})
                        if item.get("type") == "agentMessage":
                            self.answer = item.get("text")
                    elif method == "turn/completed" and not self.completed.done():
                        if params["turn"]["status"] != "completed" or self.answer is None:
                            self.context.coordinator.store.event(
                                self.context.task_id,
                                "runtime_turn_failure",
                                {
                                    "status": params["turn"]["status"],
                                    "error": params["turn"].get("error"),
                                },
                            )
                            self.completed.set_exception(LasaError("verification_failed"))
                        else:
                            self.completed.set_result(parse_json(self.answer))
            if not self.completed.done():
                self.completed.set_exception(LasaError("verification_failed"))
        except asyncio.CancelledError:
            pass
        except Exception:
            if not self.completed.done():
                self.completed.set_exception(LasaError("verification_failed"))
        finally:
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(LasaError("verification_failed"))

    async def _gateway_request(self, message):
        request_id = message["id"]
        try:
            permitted = {
                ("GET", "/broker/tools"),
                ("POST", "/broker/call"),
                ("POST", "/model/responses"),
                ("POST", "/model/responses/compact"),
            }
            if (message.get("method"), message.get("path")) not in permitted:
                raise LasaError("authority_denied")
            body = base64.b64decode(message["body"], validate=True)
            if len(body) > 1048576:
                raise LasaError("capacity_exhausted")
            async with httpx.AsyncClient(
                trust_env=False, timeout=None, follow_redirects=False
            ) as client:
                async with client.stream(
                    message["method"],
                    self.gateway.url + message["path"],
                    content=body,
                    headers={
                        "Authorization": "Bearer " + self.gateway.token,
                        "Content-Type": "application/json",
                    },
                ) as response:
                    await self.send(
                        {
                            "lasa_gateway": "response",
                            "id": request_id,
                            "status": response.status_code,
                            "content_type": response.headers.get(
                                "Content-Type", "application/json"
                            ),
                        }
                    )
                    async for chunk in response.aiter_bytes():
                        for offset in range(0, len(chunk), 65536):
                            await self.send(
                                {
                                    "lasa_gateway": "chunk",
                                    "id": request_id,
                                    "data": base64.b64encode(
                                        chunk[offset : offset + 65536]
                                    ).decode(),
                                }
                            )
            await self.send({"lasa_gateway": "end", "id": request_id})
        except asyncio.CancelledError:
            raise
        except Exception:
            if not self.completed.done():
                self.completed.set_exception(LasaError("verification_failed"))

    async def _server_request(self, message):
        method = message["method"]
        self.context.coordinator.store.event(
            self.context.task_id, "runtime_request", {"method": method}
        )
        try:
            if method in {
                "item/commandExecution/requestApproval",
                "item/fileChange/requestApproval",
            }:
                result = {"decision": "decline"}
            elif method == "item/permissions/requestApproval":
                result = {"permissions": {}}
            elif method == "item/tool/requestUserInput":
                questions = message.get("params", {}).get("questions", [])
                if not questions or len(questions) > 3:
                    raise LasaError("verification_failed")
                answers = {}
                for question in questions:
                    text = question["question"]
                    choices = [option["label"] for option in question.get("options", [])]
                    if choices:
                        text += "\nChoices: " + "; ".join(choices)
                    answer = await self.context.coordinator.request_input(
                        self.context.task_id, text
                    )
                    answers[question["id"]] = {"answers": [answer["answer"]]}
                result = {"answers": answers}
            elif method == "mcpServer/elicitation/request":
                result = {"action": "decline", "content": None}
            else:
                raise LasaError("verification_failed")
            await self.send({"jsonrpc": "2.0", "id": message["id"], "result": result})
        except Exception as exc:
            await self.send(
                {
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "error": {"code": -32601, "message": "Unsupported runtime request"},
                }
            )
            if not self.completed.done():
                self.completed.set_exception(
                    exc if isinstance(exc, LasaError) else LasaError("verification_failed")
                )

    async def close(self):
        for handler in self.handlers:
            handler.cancel()
        await asyncio.gather(*self.handlers, return_exceptions=True)
        self.reader.cancel()
        await asyncio.gather(self.reader, return_exceptions=True)
        if self.completed.done() and not self.completed.cancelled():
            self.completed.exception()
