"""Hard elapsed-time boundaries, independent of a later absolute deadline.

Blocking runtimes/transports/connectors are controlled cancellation fixtures;
native Codex and MCP integration evidence is maintained in their own suites.
"""

import asyncio
import time
from types import SimpleNamespace

import httpx
import pytest

from lasa_service.capabilities import epoch
from lasa_service.contracts import digest
from lasa_service.gateway import TaskGateway
from lasa_service.planning import VERDICT
from lasa_service.store import encode

from .conftest import FakeRuntime, documents, settled, submit, task_request


def short_limits(tmp_path):
    raw = documents(tmp_path)
    raw["limits"]["integration_reserve"]["wall_time_ms"] = 0
    raw["limits"]["assessment_budget"].update(wall_time_ms=1000, model_tokens=20000)
    raw["limits"]["reconciliation_timeout_seconds"] = 1
    return raw


def cap_step(coordinator, milliseconds=200):
    allocate = coordinator.routing.allocate

    def limited(*args):
        private = allocate(*args)
        for step in private["document"]["steps"]:
            step["allocation"]["budget"]["wall_time_ms"] = milliseconds
        return private

    coordinator.routing.allocate = limited


@pytest.mark.parametrize("boundary", ["task", "step", "uncertain_effect", "cleanup"])
async def test_stalled_runtime_stops_at_allocation(services, tmp_path, boundary):
    entered = asyncio.Event()
    stopped = asyncio.Event()
    cleanup_stopped = asyncio.Event()

    async def handler(context):
        if boundary == "uncertain_effect":
            body = {
                "name": "workspace.write",
                "arguments": {"relative_path": "pending.txt", "text": "uncertain"},
            }
            context.coordinator.store.db.execute(
                "INSERT INTO actions VALUES(?,?,?,?,NULL,?,?)",
                (
                    context.task_id,
                    "pending-write",
                    digest(body),
                    "started",
                    "workspace.write",
                    encode(body),
                ),
            )
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    class Runtime(FakeRuntime):
        async def kill(self, task_id):
            if boundary == "cleanup":
                try:
                    await asyncio.Event().wait()
                finally:
                    cleanup_stopped.set()

    client, app = await services(raw=short_limits(tmp_path), runtime=Runtime(handler))
    c = app.state.coordinator
    if boundary != "task":
        cap_step(c)
    request = await task_request(client, app)
    request["requested_limits"]["budget"]["wall_time_ms"] = {
        "task": 1000,
        "cleanup": 300,
    }.get(boundary, 5000)
    started = time.monotonic()
    response = await submit(client, app, request)
    async with asyncio.timeout(3):
        result = await settled(client, response)
    elapsed = time.monotonic() - started
    assert entered.is_set() and stopped.is_set()
    assert elapsed < (1.7 if boundary in {"task", "cleanup"} else 0.8)
    assert epoch(request["requested_limits"]["deadline"]) > time.time() + 60
    effective = result["admission"]["effective_limits"]["deadline"]
    assert (
        epoch(effective)
        <= epoch(result["received_at"])
        + request["requested_limits"]["budget"]["wall_time_ms"] / 1000
        + 0.001
    )
    if boundary in {"uncertain_effect", "cleanup"}:
        assert result["status"] == "indeterminate"
        assert result["problem"]["effect_disposition"] == "unknown"
        assert result["problem"]["retry"] == "reconcile"
        if boundary == "cleanup":
            assert cleanup_stopped.is_set() and not c.ready
            await c.reconcile_internal(result["task_id"])
            events = c.diagnostics.page(result["task_id"], {"subject": "alice"})["events"]
            assert all(event["kind"] != "resolution" for event in events)
    else:
        assert result["status"] == "failed"
        assert result["problem"]["code"] == "deadline_exceeded"
        assert result["problem"]["effect_disposition"] == "known"
        assert not c.runtime_active
    assert "result" not in result


@pytest.mark.parametrize("phase", ["headers", "stream"])
async def test_stalled_gateway_model_obeys_operation_expiry(services, tmp_path, phase):
    entered = asyncio.Event()
    stopped = asyncio.Event()

    async def block():
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            await block()
            yield b"unreachable"

    async def upstream(request):
        if phase == "headers":
            await block()
        return httpx.Response(200, headers={"Content-Type": "text/event-stream"}, stream=Stream())

    async def handler(context):
        gateway = TaskGateway(context)
        try:
            await gateway.start()
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=gateway.server.config.app),
                base_url=gateway.url,
                headers={"Authorization": "Bearer " + gateway.token},
            ) as model_client:
                await model_client.post(
                    "/model/responses",
                    json={"model": context.coordinator.config.executor()["model"], "input": []},
                )
                raise await gateway.failure
        finally:
            await gateway.close()

    client, app = await services(
        raw=short_limits(tmp_path),
        runtime=FakeRuntime(handler),
        model_transport=httpx.MockTransport(upstream),
    )
    c = app.state.coordinator
    begin = c.begin_model

    def limited(*args):
        operation = begin(*args)
        c.operation_expiries[args[0]][operation] = asyncio.get_running_loop().time() + 0.1
        return operation

    c.begin_model = limited
    request = await task_request(client, app)
    request["requested_limits"]["budget"]["wall_time_ms"] = 5000
    started = time.monotonic()
    response = await submit(client, app, request)
    async with asyncio.timeout(2):
        result = await settled(client, response)
    assert time.monotonic() - started < 1
    assert entered.is_set() and stopped.is_set()
    assert result["status"] == "failed" and result["problem"]["code"] == "deadline_exceeded"
    assert "result" not in result


@pytest.mark.parametrize("boundary", ["assessment", "step"])
async def test_stalled_model_request_is_cancelled(services, tmp_path, boundary):
    entered = asyncio.Event()
    stopped = asyncio.Event()

    async def upstream(request):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    async def ask(c, task_id, purpose):
        await c.models.ask(task_id, purpose, {"question": "Bounded assessment"}, VERDICT)

    async def proposal(c, task_id, request, catalog, requirements):
        await ask(c, task_id, "planning")
        raise AssertionError("Stalled model returned")

    async def handler(context):
        await ask(context.coordinator, context.task_id, "execution")
        raise AssertionError("Stalled model returned")

    raw = short_limits(tmp_path)
    raw["limits"]["assessment_budget"]["wall_time_ms"] = 200
    client, app = await services(
        raw=raw,
        model_transport=httpx.MockTransport(upstream),
        planner=proposal if boundary == "assessment" else None,
        runtime=FakeRuntime(handler),
    )
    c = app.state.coordinator
    cap_step(c)
    request = await task_request(client, app)
    request["requested_limits"]["budget"]["wall_time_ms"] = 5000
    started = time.monotonic()
    response = await submit(client, app, request)
    async with asyncio.timeout(2):
        result = await settled(client, response)
    assert time.monotonic() - started < 0.8
    assert entered.is_set() and stopped.is_set()
    assert result["status"] == ("rejected" if boundary == "assessment" else "failed")
    assert result["problem"]["code"] == "deadline_exceeded"
    assert not c.runtime.prompts if boundary == "assessment" else c.runtime.prompts
    assert "result" not in result


async def test_stalled_tool_connector_is_cancelled_at_step_limit(services, tmp_path):
    entered = asyncio.Event()
    stopped = asyncio.Event()

    class Connector:
        resource = {"id": "fixture-connector"}
        worker = SimpleNamespace(done=lambda: False)

        async def call(self, name, arguments, seconds):
            assert seconds <= 0.2
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                stopped.set()

    async def handler(context):
        c = context.coordinator
        context.binding["required_operations"] = ["approved.inspect"]
        c.broker.operations["approved.inspect"] = (
            Connector(),
            {
                "upstream_tool": "inspect",
                "description": "Read a bounded approved source.",
                "argument_constraints": {},
                "task_input_bindings": [],
                "effect": "workspace.read",
                "resource": "workspace:self",
                "input_schema": {"type": "object", "additionalProperties": False},
                "output_schema": {"type": "object"},
            },
        )
        await c.broker.call(context.task_id, "tool-once", "approved.inspect", {})
        raise AssertionError("Stalled connector returned")

    client, app = await services(raw=short_limits(tmp_path), runtime=FakeRuntime(handler))
    c = app.state.coordinator
    cap_step(c)
    request = await task_request(client, app)
    request["requested_limits"]["budget"]["wall_time_ms"] = 5000
    started = time.monotonic()
    response = await submit(client, app, request)
    async with asyncio.timeout(2):
        result = await settled(client, response)
    assert time.monotonic() - started < 0.8
    assert entered.is_set() and stopped.is_set()
    assert result["status"] == "failed" and result["problem"]["code"] == "deadline_exceeded"
    assert result["problem"]["effect_disposition"] == "known"
    assert not c.store.uncertain(result["task_id"])
    assert "result" not in result
