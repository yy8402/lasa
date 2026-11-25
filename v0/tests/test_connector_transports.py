"""Real stdio/TLS transport fixtures; deployed third-party evidence is separate."""

import ast
import asyncio
import copy
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from lasa_service.connectors import Connector
from lasa_service.errors import LasaError

from .conftest import configuration, documents
from .http_helpers import certificate, live_http

LIMITS = {
    "max_queue": 2,
    "request_timeout_seconds": 2,
    "response_bytes": 32768,
    "recovery_interval_seconds": 0.1,
    "schema_refresh_seconds": 0.1,
}
INPUT = {
    "type": "object",
    "properties": {"report_id": {"type": "string", "maxLength": 128}},
    "required": ["report_id"],
    "additionalProperties": False,
}
OUTPUT = {
    "type": "object",
    "properties": {"text": {"type": "string", "maxLength": 65536}},
    "required": ["text"],
    "additionalProperties": False,
}


async def call_fixture(connector, operation, arguments, seconds):
    return await connector.call(operation, arguments, seconds, before_use=lambda: None)


async def wait_state(connector, name, state):
    for _ in range(100):
        if connector.state(name) == state:
            return
        await asyncio.sleep(0.02)
    raise AssertionError("Connector did not reach " + state)


def operation(name="reports.inspect"):
    return {
        "operation_id": name,
        "description": "Read an approved report.",
        "upstream_tool": "inspect_report",
        "task_input_bindings": [],
        "effect": "external.read",
        "resource": "reports:approved",
        "input_schema": copy.deepcopy(INPUT),
        "upstream_output_schema": copy.deepcopy(OUTPUT),
        "argument_constraints": {"properties": {"report_id": {"enum": ["42", "stall", "large"]}}},
        "output_schema": copy.deepcopy(OUTPUT),
        "result_format": "structured",
    }


@asynccontextmanager
async def actor(tmp_path, resource):
    tmp_path.mkdir(parents=True, exist_ok=True)
    raw = documents(tmp_path)
    config = configuration(raw)
    connector = Connector(config, resource, tmp_path / "private")
    await connector.start()
    try:
        yield connector
    finally:
        await connector.close()
        assert connector.worker.done()


@asynccontextmanager
async def http_mcp(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    tls = certificate(tmp_path)
    state = {
        "schemas": [operation()],
        "calls": [],
        "listed_cursors": [],
        "token": None,
        "seen_authorization": [],
        "cancelled": asyncio.Event(),
        "entered": asyncio.Event(),
        "http_status": 200,
    }
    app = FastAPI()

    @app.post("/mcp")
    async def rpc(request: Request):
        state["seen_authorization"].append(request.headers.get("authorization"))
        if state["http_status"] != 200:
            return Response(status_code=state["http_status"], headers={"Retry-After": "0.5"})
        if state["token"] and request.headers.get("authorization") != "Bearer " + state["token"]:
            return Response(status_code=401)
        value = await request.json()
        method = value["method"]
        if method == "notifications/cancelled":
            state["cancelled"].set()
        if "id" not in value:
            return Response(status_code=202)
        if method == "initialize":
            result = {
                "protocolVersion": value["params"]["protocolVersion"],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "protocol-fixture", "version": "1"},
            }
        elif method == "tools/list":
            cursor = value.get("params", {}).get("cursor")
            state["listed_cursors"].append(cursor)
            index = int(cursor or "0")
            page = state["schemas"][index : index + 1]
            result = {
                "tools": [
                    {
                        "name": op["upstream_tool"],
                        "inputSchema": op["input_schema"],
                        "outputSchema": op["upstream_output_schema"],
                    }
                    for op in page
                ]
            }
            if index + 1 < len(state["schemas"]):
                result["nextCursor"] = str(index + 1)
        elif method == "tools/call":
            state["calls"].append(value)
            name = value["params"]["arguments"]["report_id"]
            if name == "stall":
                state["entered"].set()
                await state["cancelled"].wait()
            text = "x" * 50000 if name == "large" else "Report " + name
            result = {
                "content": [{"type": "text", "text": text}],
                "structuredContent": {"text": text},
                "isError": False,
            }
        else:
            result = {}
        return JSONResponse({"jsonrpc": "2.0", "id": value["id"], "result": result})

    @app.get("/mcp")
    async def stream():
        return Response(status_code=405)

    @app.delete("/mcp")
    async def terminate():
        return Response(status_code=200)

    async with live_http(app, tls=tls) as origin:
        try:
            yield origin, tls, state
        finally:
            state["cancelled"].set()


async def test_stdio_structured_normalization_scope_and_owned_shutdown(tmp_path):
    fixture = Path(__file__).parent / "fixtures/mcp_server.py"
    parsed = ast.parse(fixture.read_text())
    schemas = {
        node.targets[0].id: ast.literal_eval(node.value)
        for node in parsed.body
        if isinstance(node, ast.Assign) and node.targets[0].id in {"INPUT", "OUTPUT"}
    }
    op = operation()
    op.update(
        input_schema=schemas["INPUT"],
        upstream_output_schema=schemas["OUTPUT"],
        output_schema=schemas["OUTPUT"],
    )
    resource = {
        "id": "stdio-reports",
        "kind": "mcp-stdio",
        "command": sys.executable,
        "args": ["-u", str(fixture.resolve())],
        "secret_env": {},
        "limits": LIMITS,
        "operations": [op],
    }
    async with actor(tmp_path, resource) as connector:
        assert connector.state(op["operation_id"]) == "available"
        assert await call_fixture(connector, op["operation_id"], {"report_id": "42"}, 1) == {
            "text": "Report 42"
        }
        with pytest.raises(LasaError, match="authority_denied"):
            await call_fixture(
                connector, op["operation_id"], {"report_id": "outside-approved-scope"}, 1
            )


async def test_http_paged_discovery_drift_and_unrelated_operation_recovery(tmp_path):
    async with http_mcp(tmp_path / "server") as (origin, tls, state):
        second = operation("reports.other")
        second["upstream_tool"] = "other_report"
        state["schemas"].append(second)
        resource = {
            "id": "http-reports",
            "kind": "mcp-http",
            "url": origin + "/mcp",
            "ca_file": str(tls[0]),
            "limits": LIMITS,
            "operations": [operation(), second],
        }
        async with actor(tmp_path / "client", resource) as connector:
            assert (
                connector.state("reports.inspect") == "available" and "1" in state["listed_cursors"]
            )
            state["schemas"][0]["input_schema"]["properties"]["drift"] = {"type": "boolean"}
            await wait_state(connector, "reports.inspect", "unavailable")
            assert connector.state("reports.other") == "available"
            assert await call_fixture(connector, "reports.other", {"report_id": "42"}, 1) == {
                "text": "Report 42"
            }
            state["schemas"][0] = operation()
            await wait_state(connector, "reports.inspect", "available")


async def test_http_token_file_refresh_text_normalization_and_cancellation(tmp_path):
    async with http_mcp(tmp_path / "server") as (origin, tls, state):
        token_file = tmp_path / "token.txt"
        token_file.write_text("first-token")
        state["token"] = "first-token"
        op = operation()
        op["result_format"] = "text"
        resource = {
            "id": "http-reports",
            "kind": "mcp-http",
            "url": origin + "/mcp",
            "ca_file": str(tls[0]),
            "credential_ref": "file:" + str(token_file),
            "limits": LIMITS,
            "operations": [op],
        }
        async with actor(tmp_path / "client", resource) as connector:
            assert await call_fixture(connector, "reports.inspect", {"report_id": "42"}, 1) == {
                "text": "Report 42"
            }
            token_file.write_text("refreshed-token")
            state["token"] = "refreshed-token"
            assert await call_fixture(connector, "reports.inspect", {"report_id": "42"}, 1) == {
                "text": "Report 42"
            }
            task = asyncio.create_task(
                call_fixture(connector, "reports.inspect", {"report_id": "stall"}, 1)
            )
            async with asyncio.timeout(2):
                await state["entered"].wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            async with asyncio.timeout(2):
                await state["cancelled"].wait()
            assert "Bearer refreshed-token" in state["seen_authorization"]


async def test_json_application_projection_credentials_bounds_and_recovery(tmp_path):
    (tmp_path / "server").mkdir()
    tls = certificate(tmp_path / "server")
    state = {"token": "first", "status": 200, "seen": []}
    app = FastAPI()

    @app.get("/records")
    async def records(request: Request):
        state["seen"].append(request.headers.get("authorization"))
        if request.headers.get("authorization") != "Bearer " + state["token"]:
            return Response(status_code=401)
        if state["status"] != 200:
            return Response(status_code=state["status"])
        return {"title": "Source record", "internal": "not projected"}

    async with live_http(app, tls=tls) as origin:
        token_file = tmp_path / "token.txt"
        token_file.write_text("first")
        op = {
            "operation_id": "records.read",
            "description": "Read an approved source record.",
            "task_input_bindings": [],
            "effect": "external.read",
            "resource": "records:approved",
            "url": origin + "/records",
            "input_schema": {"type": "object", "additionalProperties": False},
            "argument_constraints": {},
            "output_schema": {
                "type": "object",
                "properties": {"title": {"type": "string"}},
                "required": ["title"],
                "additionalProperties": False,
            },
            "response_schema": {"type": "object", "required": ["title"]},
            "result_fields": ["title"],
            "probe_arguments": {},
        }
        resource = {
            "id": "record-app",
            "kind": "json-get",
            "base_url": origin + "/records",
            "headers": {},
            "credential_ref": "file:" + str(token_file),
            "ca_file": str(tls[0]),
            "limits": LIMITS,
            "operations": [op],
        }
        async with actor(tmp_path / "client", resource) as connector:
            assert await call_fixture(connector, "records.read", {}, 1) == {
                "title": "Source record"
            }
            token_file.write_text("second")
            state["token"] = "second"
            assert await call_fixture(connector, "records.read", {}, 1) == {
                "title": "Source record"
            }
            state["status"] = 503
            with pytest.raises(LasaError):
                await call_fixture(connector, "records.read", {}, 1)
            assert connector.state("records.read") == "unavailable"
            state["status"] = 200
            await wait_state(connector, "records.read", "available")
            assert "Bearer second" in state["seen"]


async def test_http_unauthorized_and_rate_limited_are_distinct_and_recover(tmp_path):
    async with http_mcp(tmp_path / "server") as (origin, tls, state):
        token = tmp_path / "token.txt"
        token.write_text("wrong")
        state["token"] = "right"
        resource = {
            "id": "http-reports",
            "kind": "mcp-http",
            "url": origin + "/mcp",
            "ca_file": str(tls[0]),
            "credential_ref": "file:" + str(token),
            "limits": LIMITS,
            "operations": [operation()],
        }
        async with actor(tmp_path / "client", resource) as connector:
            assert connector.state("reports.inspect") == "unauthorized"
            token.write_text("right")
            await wait_state(connector, "reports.inspect", "available")
            state["http_status"] = 429
            with pytest.raises(LasaError):
                await call_fixture(connector, "reports.inspect", {"report_id": "42"}, 1)
            await wait_state(connector, "reports.inspect", "busy")
            requests = len(state["seen_authorization"])
            await asyncio.sleep(0.15)
            assert len(state["seen_authorization"]) == requests
            state["http_status"] = 200
            await wait_state(connector, "reports.inspect", "available")


async def test_queue_is_bounded_and_cancelled_queued_work_is_not_executed(tmp_path):
    async with http_mcp(tmp_path / "server") as (origin, tls, state):
        limits = {**LIMITS, "max_queue": 1}
        resource = {
            "id": "http-reports",
            "kind": "mcp-http",
            "url": origin + "/mcp",
            "ca_file": str(tls[0]),
            "limits": limits,
            "operations": [operation()],
        }
        async with actor(tmp_path / "client", resource) as connector:
            first = asyncio.create_task(
                call_fixture(connector, "reports.inspect", {"report_id": "stall"}, 1)
            )
            async with asyncio.timeout(2):
                await state["entered"].wait()
            second = asyncio.create_task(
                call_fixture(connector, "reports.inspect", {"report_id": "42"}, 0.05)
            )
            await asyncio.sleep(0)
            with pytest.raises(LasaError, match="capacity_exhausted"):
                await call_fixture(connector, "reports.inspect", {"report_id": "42"}, 1)
            with pytest.raises(LasaError, match="deadline_exceeded"):
                await second
            assert len(state["calls"]) == 1
            first.cancel()
            with pytest.raises(asyncio.CancelledError):
                await first
            async with asyncio.timeout(2):
                await state["cancelled"].wait()
            assert await call_fixture(connector, "reports.inspect", {"report_id": "42"}, 1) == {
                "text": "Report 42"
            }
            assert len(state["calls"]) == 2


async def test_schema_refresh_precedes_queued_call_after_refresh_deadline(tmp_path, monkeypatch):
    entered, release = asyncio.Event(), asyncio.Event()
    calls = []

    class Backend:
        refreshes = 0

        async def discover(self):
            self.refreshes += 1
            return {"reports.inspect": "available" if self.refreshes == 1 else "unavailable"}

        async def call(self, operation, arguments, seconds):
            calls.append(arguments["report_id"])
            entered.set()
            await release.wait()
            return {"text": "First report"}

    backend = Backend()

    async def open_backend(self, stack):
        return backend

    monkeypatch.setattr(Connector, "_open", open_backend)
    resource = {"id": "reports", "limits": LIMITS, "operations": [operation()]}
    async with asyncio.timeout(2), actor(tmp_path, resource) as connector:
        first = asyncio.create_task(
            call_fixture(connector, "reports.inspect", {"report_id": "stall"}, 1)
        )
        await entered.wait()
        queued = asyncio.create_task(
            call_fixture(connector, "reports.inspect", {"report_id": "42"}, 1)
        )
        await asyncio.sleep(LIMITS["schema_refresh_seconds"] * 1.5)
        assert connector.queue.qsize() == 1
        release.set()
        assert await first == {"text": "First report"}
        with pytest.raises(LasaError, match="peer_unavailable"):
            await queued
        assert calls == ["stall"]


@pytest.mark.parametrize("transport", ["mcp-stdio", "mcp-http"])
async def test_oversized_frames_or_http_response_fail_within_bound(tmp_path, transport):
    if transport == "mcp-stdio":
        fixture = Path(__file__).parent / "fixtures/mcp_server.py"
        resource = {
            "id": "stdio-reports",
            "kind": transport,
            "command": sys.executable,
            "args": ["-u", str(fixture.resolve())],
            "secret_env": {},
            "limits": {**LIMITS, "response_bytes": 2048},
            "operations": [operation()],
        }
        async with actor(tmp_path / "client", resource) as connector:
            async with asyncio.timeout(2):
                with pytest.raises(LasaError):
                    await call_fixture(connector, "reports.inspect", {"report_id": "large"}, 1)
    else:
        async with http_mcp(tmp_path / "server") as (origin, tls, state):
            resource = {
                "id": "http-reports",
                "kind": transport,
                "url": origin + "/mcp",
                "ca_file": str(tls[0]),
                "limits": {**LIMITS, "response_bytes": 2048},
                "operations": [operation()],
            }
            async with actor(tmp_path / "client", resource) as connector:
                async with asyncio.timeout(2):
                    with pytest.raises(LasaError):
                        await call_fixture(connector, "reports.inspect", {"report_id": "large"}, 1)


async def test_stdio_secret_file_change_restarts_only_owned_connection(tmp_path):
    token = tmp_path / "prefix.txt"
    token.write_text("First ")
    fixture = Path(__file__).parent / "fixtures/mcp_server.py"
    resource = {
        "id": "stdio-reports",
        "kind": "mcp-stdio",
        "command": sys.executable,
        "args": ["-u", str(fixture.resolve())],
        "secret_env": {"REPORT_PREFIX": "file:" + str(token)},
        "limits": LIMITS,
        "operations": [operation()],
    }
    async with actor(tmp_path / "client", resource) as connector:
        assert await call_fixture(connector, "reports.inspect", {"report_id": "42"}, 1) == {
            "text": "First42"
        }
        generation = connector.generation
        token.write_text("Second ")
        for _ in range(100):
            if connector.generation > generation:
                break
            await asyncio.sleep(0.02)
        assert connector.generation > generation
        assert await call_fixture(connector, "reports.inspect", {"report_id": "42"}, 1) == {
            "text": "Second42"
        }
