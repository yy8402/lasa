"""Codex App Server local execution inside a networkless task container."""

import asyncio
import os
import shutil
import signal
from dataclasses import dataclass

import psutil
import tomli_w

from . import __version__
from .contracts import canonical
from .enclosure import Enclosure
from .errors import LasaError
from .gateway import TaskGateway
from .planning import object_schema, provider_schema
from .rpc import AppServerClient
from .store import identity

DISABLED_FEATURES = (
    "shell_tool",
    "unified_exec",
    "shell_snapshot",
    "apps",
    "hooks",
    "plugins",
    "remote_plugin",
    "recommended_plugins",
    "multi_agent_v2",
    "multi_agent_v2_dynamic_tools",
    "computer_use",
    "browser_use",
    "browser_use_external",
    "code_mode",
    "code_mode_host",
    "image_generation",
    "view_image",
    "skill_mcp_dependency_install",
    "skill_search",
    "memories",
    "sleep_tool",
    "goals",
    "unbounded_connection_retries",
    "workspace_dependencies",
    "api_key_model_discovery",
    "api_key_cyber_access_programs",
    "tool_suggest",
    "incremental_tools",
    "request_permissions_tool",
    "enable_request_compression",
)


@dataclass
class RuntimeHandle:
    coordinator: object
    gateway: object
    container_id: str | None = None
    process: object = None
    client: object = None
    stderr: object = None


class CodexRuntime:
    def __init__(self):
        self.enclosure = Enclosure()
        self.handles = {}

    async def recover(self, c):
        recorded = {r["task_id"]: r for r in c.store.db.execute("SELECT * FROM runtimes")}
        for task_id in set(recorded) | set(c.store.active()):
            row = recorded.get(task_id)
            container = row["container_id"] if row else "lasa-" + task_id
            await self.enclosure.remove(container, task_id, c.config.service_id)
            if row and row["pid"]:
                try:
                    process = psutil.Process(row["pid"])
                    if (
                        abs(process.create_time() - row["created"]) > 0.01
                        or os.getpgid(row["pid"]) != row["pid"]
                    ):
                        raise LasaError("internal_error", 503)
                    os.killpg(row["pid"], signal.SIGKILL)
                except (ProcessLookupError, psutil.NoSuchProcess):
                    pass
        c.store.db.execute("DELETE FROM runtimes")

    def directories(self, c, task_id):
        root = c.root / "runtime" / task_id / identity("attempt")
        home = root / "home"
        protected = root / "protected"
        for path in (home, protected, protected / "empty"):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
        (protected / "empty-file").touch()
        return root, home, protected

    def configuration(self, executor):
        return {
            "model": executor["model"],
            "model_provider": "lasa",
            "approval_policy": "never",
            "sandbox_mode": "workspace-write",
            "web_search": "disabled",
            "project_doc_max_bytes": 0,
            "cli_auth_credentials_store": "file",
            "features": dict.fromkeys(DISABLED_FEATURES, False),
            "agents": {"enabled": False},
            "analytics": {"enabled": False},
            "sandbox_workspace_write": {"network_access": False},
            "projects": {"/workspace": {"trust_level": "untrusted"}},
            "model_providers": {
                "lasa": {
                    "name": "LASA controlled model route",
                    "wire_api": "responses",
                    "base_url": "http://127.0.0.1:39231/model",
                    "env_key": "LASA_GATEWAY_TOKEN",
                    "request_max_retries": 0,
                    "stream_max_retries": 0,
                    "supports_websockets": False,
                    "requires_openai_auth": False,
                    "stream_idle_timeout_ms": 60000,
                }
            },
        }

    async def probe(self, c):
        verified_images = set()
        for executor in c.config.document["executors"]:
            settings = c.config.read_private("RuntimeProfile", executor["runtime_profile_file"])
            image = (settings["image"], settings["executable"], settings["expected_version"])
            if image not in verified_images:
                await self.enclosure.verify_image(*image)
                verified_images.add(image)
            await self.probe_executor(c, executor, settings)

    async def probe_executor(self, c, executor, settings):
        task_id = identity("probe")
        root, home, protected = self.directories(c, task_id)
        workspace = root / "workspace"
        workspace.mkdir()
        (home / "config.toml").write_text(tomli_w.dumps(self.configuration(executor)))
        container = None
        try:
            container = await self.enclosure.create(
                image=settings["image"],
                executable=settings["executable"],
                task_id=task_id,
                service_id=c.config.service_id,
                workspace=workspace,
                home=home,
                protected=protected,
                token="readiness-only",
                role="config-check",
            )
            await self.enclosure.run("start", "--attach", container)
        finally:
            if container:
                await self.enclosure.remove(container, task_id, c.config.service_id)
            shutil.rmtree(root)

    async def run(self, context):
        c = context.coordinator
        source_profile = c.registry.source_profile(context.prompt["contract"])
        executor = c.config.executor(context.binding)
        settings = c.config.read_private("RuntimeProfile", executor["runtime_profile_file"])
        root, home, protected = self.directories(c, context.task_id)
        (home / "config.toml").write_text(tomli_w.dumps(self.configuration(executor)))
        gateway = TaskGateway(context)
        handle = RuntimeHandle(c, gateway)
        self.handles[context.task_id] = handle
        await gateway.start()
        mounted_workspace = (
            context.workspace.root
            if "workspace.read" in context.effects
            else root / "empty-workspace"
        )
        mounted_workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
        handle.container_id = await self.enclosure.create(
            image=settings["image"],
            executable=settings["executable"],
            task_id=context.task_id,
            service_id=c.config.service_id,
            workspace=mounted_workspace,
            home=home,
            protected=protected,
            token=gateway.token,
            workspace_readonly=True,
        )
        c.store.db.execute(
            "INSERT INTO runtimes VALUES(?,?,?,?)", (context.task_id, 0, 0.0, handle.container_id)
        )
        handle.stderr = (root / "stderr.log").open("wb")
        handle.process = await asyncio.create_subprocess_exec(
            self.enclosure.docker,
            "start",
            "--attach",
            "--interactive",
            handle.container_id,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=handle.stderr,
            start_new_session=True,
            limit=2097152,
        )
        c.store.db.execute(
            "UPDATE runtimes SET pid=?,created=? WHERE task_id=?",
            (handle.process.pid, psutil.Process(handle.process.pid).create_time(), context.task_id),
        )
        client = AppServerClient(handle.process, context, gateway=gateway)
        handle.client = client
        async with asyncio.timeout(settings["startup_timeout_ms"] / 1000):
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
                    "developerInstructions": c.config.prompts["execution_developer"]
                    + "\n\nLASA tools available to this step are callable functions registered "
                    "on this thread. Use their advertised names and arguments.",
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
        prompt = {
            **context.prompt,
            "outcome_contract": context.definition,
            "required_evidence_criterion_ids": [
                p["id"] for p in context.definition["postconditions"]
            ],
        }
        if source_profile:
            prompt["source_execution"] = c.config.prompts["source_execution"]
        await client.request(
            "turn/start",
            {
                "threadId": client.thread_id,
                "input": [{"type": "text", "text": canonical(prompt).decode()}],
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
        if handle.container_id:
            await self.enclosure.remove(
                handle.container_id, task_id, handle.coordinator.config.service_id
            )
        if handle.process:
            async with asyncio.timeout(5):
                await handle.process.wait()
        if handle.client:
            await handle.client.close()
        if handle.stderr:
            handle.stderr.close()
        await handle.gateway.close()
        handle.coordinator.store.db.execute("DELETE FROM runtimes WHERE task_id=?", (task_id,))
        self.handles.pop(task_id, None)
