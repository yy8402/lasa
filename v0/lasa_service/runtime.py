"""Drive a bounded Codex step through the private launcher."""

import asyncio
from dataclasses import dataclass
from functools import partial

from . import __version__
from .capabilities import require
from .contracts import canonical
from .gateway import TaskGateway
from .launcher_client import LauncherClient, close_stream
from .planning import object_schema, provider_schema
from .rpc import AppServerClient
from .store import identity


@dataclass
class RuntimeHandle:
    attempt_id: str
    gateway: TaskGateway
    writer: asyncio.StreamWriter | None = None
    client: AppServerClient | None = None


class CodexRuntime:
    def __init__(self, config):
        settings = config.document["runtime"]
        self.launcher = LauncherClient(
            settings["launcher_socket"], config.service_id, settings["launcher_instance"]
        )
        self.startup_timeout = settings["startup_timeout_ms"] / 1000
        self.cleanup_timeout = config.document["limits"]["reconciliation_timeout_seconds"]
        self.handles = {}

    async def recover(self, coordinator):
        for row in coordinator.store.runtime_attempts():
            async with asyncio.timeout(self.cleanup_timeout):
                await self.launcher.stop(row["attempt_id"])
            coordinator.store.finish_runtime(row["attempt_id"])

    async def verify_worker(self):
        async with asyncio.timeout(self.startup_timeout):
            await self.launcher.check()

    async def probe(self, coordinator):
        await self.verify_worker()
        for executor in coordinator.config.document["executors"]:
            async with asyncio.timeout(self.startup_timeout):
                await self.launcher.probe(executor["model"])

    async def run(self, context):
        c = context.coordinator
        source_profile = c.registry.source_profile(context.prompt["contract"])
        executor = c.config.executor(context.binding)
        guidance = [
            c.config.prompts["execution_developer"],
            "LASA tools available to this step are callable functions registered "
            "on this thread. Use their advertised names and arguments.",
        ]
        if instruction := context.prompt.get("instruction"):
            guidance.append(instruction)
        if source_profile:
            guidance.append(c.config.prompts["source_execution"])
        gateway = TaskGateway(context)
        attempt_id = identity("attempt")
        c.store.start_runtime(context.task_id, attempt_id)
        handle = RuntimeHandle(attempt_id, gateway)
        self.handles[context.task_id] = handle
        await gateway.start()
        async with asyncio.timeout(self.startup_timeout):
            reader, handle.writer = await self.launcher.launch(
                attempt_id, executor["model"], self.startup_timeout
            )

            async def call_tool(operation_id, tool, arguments):
                name = c.broker.tool_names.get(tool)
                require(name is not None, "authority_denied", 403)
                return await c.broker.call(context.task_id, operation_id, name, arguments)

            client = AppServerClient(
                reader,
                handle.writer,
                gateway=gateway,
                call_tool=call_tool,
                request_input=partial(c.request_input, context.task_id),
                record_event=partial(c.store.event, context.task_id),
            )
            handle.client = client
            await client.request(
                "initialize",
                {
                    "clientInfo": {"name": "lasa-service", "version": __version__},
                    "capabilities": {"experimentalApi": True},
                },
            )
            await client.send({"jsonrpc": "2.0", "method": "initialized"})
            thread = await client.request(
                "thread/start",
                {
                    "model": executor["model"],
                    "modelProvider": "lasa",
                    "cwd": "/workspace",
                    "ephemeral": True,
                    "sandbox": "workspace-write",
                    "approvalPolicy": "never",
                    "dynamicTools": c.broker.tools(context.task_id),
                    "developerInstructions": "\n\n".join(guidance),
                },
            )
            client.thread_id = thread["thread"]["id"]
        output_schema = object_schema(
            {
                "output": object_schema(
                    {"ready_for_verification": {"type": "boolean", "const": True}}
                )
                if source_profile
                else context.definition["output_schema"],
                "evidence": {"type": "array", "items": c.contracts.expanded("Evidence")},
                "artifact_ids": {"type": "array", "items": {"type": "string"}},
            }
        )
        output_schema["properties"]["evidence"]["items"]["properties"]["criterion_id"] = {
            "type": "string",
            "enum": [p["id"] for p in context.definition["postconditions"]],
        }
        await client.request(
            "turn/start",
            {
                "threadId": client.thread_id,
                "input": [{"type": "text", "text": canonical(context.model_prompt()).decode()}],
                "outputSchema": provider_schema(output_schema),
            },
        )
        done, _ = await asyncio.wait(
            [client.completed, gateway.failure], return_when=asyncio.FIRST_COMPLETED
        )
        if gateway.failure in done:
            raise gateway.failure.result()
        return await client.completed

    async def kill(self, task_id):
        handle = self.handles.get(task_id)
        if handle is None:
            return
        try:
            await self.launcher.stop(handle.attempt_id)
        finally:
            if handle.client:
                await handle.client.close()
            if handle.writer:
                await close_stream(handle.writer)
            await handle.gateway.close()
        handle.gateway.context.coordinator.store.finish_runtime(handle.attempt_id)
        self.handles.pop(task_id)
