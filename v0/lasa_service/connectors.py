"""Private, bounded connector actors with explicit per-operation readiness."""

import asyncio
import ssl
import sys
import time
from contextlib import AsyncExitStack
from datetime import timedelta
from email.utils import parsedate_to_datetime

import httpx
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

from .connector_schema import validate
from .contracts import canonical, digest, parse_json
from .errors import LasaError


class ConnectorFailure(LasaError):
    def __init__(self, state="unavailable", *, code=None, retry_after=0):
        code = code or (
            "authority_denied"
            if state == "unauthorized"
            else "capacity_exhausted"
            if state == "busy"
            else "peer_unavailable"
        )
        super().__init__(code, 403 if state == "unauthorized" else 429 if state == "busy" else 503)
        self.state = state
        self.retry_after = max(0, min(3600, retry_after))


class RefreshCredentials(Exception):
    pass


def private_secret(config, reference):
    try:
        return config.secret(reference)
    except (OSError, ValueError):
        raise ConnectorFailure("unauthorized") from None


class RequestWriter:
    """Observe actual wire IDs without depending on private SDK request counters."""

    def __init__(self, inner):
        self.inner, self.requests = inner, {}

    async def send(self, message):
        request = message.message.root
        if getattr(request, "method", None) == "tools/call" and hasattr(request, "id"):
            self.requests[asyncio.current_task()] = request.id
        await self.inner.send(message)

    async def aclose(self):
        await self.inner.aclose()

    async def __aenter__(self):
        await self.inner.__aenter__()
        return self

    async def __aexit__(self, *args):
        return await self.inner.__aexit__(*args)


class PrivateAuthentication(httpx.Auth):
    def __init__(self, config, reference):
        self.config, self.reference = config, reference

    def auth_flow(self, request):
        if self.reference:
            request.headers["Authorization"] = "Bearer " + private_secret(
                self.config, self.reference
            )
        yield request


class BoundedStream(httpx.AsyncByteStream):
    def __init__(self, stream, maximum):
        self.stream, self.maximum = stream, maximum

    async def __aiter__(self):
        total = 0
        async for chunk in self.stream:
            total += len(chunk)
            if total > self.maximum:
                raise ConnectorFailure(code="capacity_exhausted")
            yield chunk

    async def aclose(self):
        await self.stream.aclose()


class BoundedTransport(httpx.AsyncBaseTransport):
    def __init__(self, verify, maximum):
        self.inner = httpx.AsyncHTTPTransport(verify=verify, trust_env=False, retries=0)
        self.maximum = maximum

    async def handle_async_request(self, request):
        response = await self.inner.handle_async_request(request)
        response.stream = BoundedStream(response.stream, self.maximum)
        return response

    async def aclose(self):
        await self.inner.aclose()


def http_failure(response):
    if response.status_code == 429 or (
        response.status_code == 403 and response.headers.get("x-ratelimit-remaining") == "0"
    ):
        value = response.headers.get("retry-after", "0")
        try:
            delay = float(value)
        except ValueError:
            try:
                delay = parsedate_to_datetime(value).timestamp() - time.time()
            except (ValueError, TypeError):
                delay = 0
        if not delay and response.headers.get("x-ratelimit-reset", "").isdigit():
            delay = int(response.headers["x-ratelimit-reset"]) - time.time()
        raise ConnectorFailure("busy", retry_after=delay)
    if response.status_code in {401, 403}:
        raise ConnectorFailure("unauthorized", code="authority_denied")
    if not 200 <= response.status_code < 300:
        raise ConnectorFailure()


class McpBackend:
    def __init__(self, connector, session, writer, fingerprint):
        self.connector, self.session, self.writer, self.fingerprint = (
            connector,
            session,
            writer,
            fingerprint,
        )

    async def discover(self):
        connector = self.connector
        if self.fingerprint != connector.secret_fingerprint():
            raise RefreshCredentials()
        tools, cursors, cursor, total = {}, set(), None, 0
        for _ in range(32):
            page = await self.session.list_tools(cursor=cursor)
            total += len(canonical(page.model_dump(mode="json")))
            if total > connector.limits["response_bytes"]:
                raise ConnectorFailure(code="capacity_exhausted")
            for tool in page.tools:
                if tool.name in tools or len(tools) >= 1024:
                    raise ConnectorFailure(code="verification_failed")
                tools[tool.name] = tool
            cursor = page.nextCursor
            if cursor is None:
                break
            if cursor in cursors:
                raise ConnectorFailure(code="verification_failed")
            cursors.add(cursor)
        else:
            raise ConnectorFailure(code="verification_failed")
        states = {}
        for operation_id, operation in connector.operations.items():
            tool = tools.get(operation["upstream_tool"])
            states[operation_id] = (
                "available"
                if tool is not None
                and canonical(tool.inputSchema) == canonical(operation["input_schema"])
                and canonical(tool.outputSchema) == canonical(operation["upstream_output_schema"])
                else "unavailable"
            )
        return states

    async def call(self, operation, arguments, seconds):
        task = asyncio.current_task()
        try:
            result = await self.session.call_tool(
                operation["upstream_tool"],
                arguments,
                read_timeout_seconds=timedelta(seconds=seconds),
            )
        except asyncio.CancelledError:
            request_id = self.writer.requests.get(task)
            if request_id is not None:
                notification = asyncio.create_task(
                    self.session.send_notification(
                        types.ClientNotification(
                            types.CancelledNotification(
                                method="notifications/cancelled",
                                params=types.CancelledNotificationParams(
                                    requestId=request_id,
                                    reason="LASA caller cancelled or allocation expired",
                                ),
                            )
                        )
                    )
                )
                try:
                    async with asyncio.timeout(1):
                        await asyncio.shield(notification)
                finally:
                    if not notification.done():
                        notification.cancel()
                    await asyncio.gather(notification, return_exceptions=True)
            raise
        finally:
            self.writer.requests.pop(task, None)
        if len(canonical(result.model_dump(mode="json"))) > self.connector.limits["response_bytes"]:
            raise ConnectorFailure(code="capacity_exhausted")
        if result.isError:
            raise LasaError("verification_failed", 422)
        if operation["upstream_output_schema"] is not None:
            validate(operation["upstream_output_schema"], result.structuredContent)
        if operation["result_format"] == "structured":
            if result.structuredContent is None:
                raise ConnectorFailure(code="verification_failed")
            return validate(operation["output_schema"], result.structuredContent)
        if not result.content or any(item.type != "text" for item in result.content):
            raise ConnectorFailure(code="verification_failed")
        return validate(
            operation["output_schema"], {"text": "\n".join(item.text for item in result.content)}
        )


class JsonGetBackend:
    def __init__(self, connector, client):
        self.connector, self.client = connector, client

    async def discover(self):
        states = {}
        for operation_id, operation in self.connector.operations.items():
            if self.connector.retry_at.get(operation_id, 0) > time.monotonic():
                states[operation_id] = "busy"
                continue
            try:
                await self.call(
                    operation,
                    operation["probe_arguments"],
                    self.connector.limits["request_timeout_seconds"],
                )
                states[operation_id] = "available"
            except ConnectorFailure as exc:
                states[operation_id] = exc.state
                self.connector.record_failure(operation_id, exc)
            except (LasaError, httpx.HTTPError, ValueError):
                states[operation_id] = "unavailable"
        return states

    async def call(self, operation, arguments, seconds):
        if any(not isinstance(value, (str, int, float, bool)) for value in arguments.values()):
            raise LasaError("invalid_input")
        async with self.client.stream(
            "GET", operation["url"], params=arguments, timeout=seconds
        ) as response:
            http_failure(response)
            chunks, total = [], 0
            async for chunk in response.aiter_bytes():
                total += len(chunk)
                if total > self.connector.limits["response_bytes"]:
                    raise ConnectorFailure(code="capacity_exhausted")
                chunks.append(chunk)
            value = parse_json(b"".join(chunks))
        validate(operation["response_schema"], value)
        fields = operation["result_fields"]

        def project(item):
            if not isinstance(item, dict) or not set(fields) <= set(item):
                raise ConnectorFailure(code="verification_failed")
            return {name: item[name] for name in fields}

        projected = [project(item) for item in value] if isinstance(value, list) else project(value)
        return validate(operation["output_schema"], projected)


class Connector:
    """One owner for SDK contexts, bounded queued calls, and recovery without replay."""

    def __init__(self, config, resource, root):
        self.config, self.resource, self.root = config, resource, root
        self.limits = resource["limits"]
        self.operations = {op["operation_id"]: op for op in resource["operations"]}
        self.states = dict.fromkeys(self.operations, "unknown")
        self.queue = asyncio.Queue(maxsize=self.limits["max_queue"])
        self.worker = None
        self.ready = None
        self.client = None
        self.closed = False
        self.active = None
        self.retry_at = {}
        self.generation = 0

    def state(self, operation_id):
        state = self.states.get(operation_id, "unavailable")
        return "busy" if state == "available" and self.queue.full() else state

    def secret_fingerprint(self):
        references = self.resource.get("secret_env", {})
        return digest(
            {name: private_secret(self.config, reference) for name, reference in references.items()}
        )

    def record_failure(self, operation_id, error):
        self.states[operation_id] = error.state
        if error.state == "busy":
            self.retry_at[operation_id] = time.monotonic() + max(
                error.retry_after, self.limits["recovery_interval_seconds"]
            )

    async def start(self):
        self.ready = asyncio.get_running_loop().create_future()
        self.worker = asyncio.create_task(self._serve(), name="connector:" + self.resource["id"])
        try:
            async with asyncio.timeout(self.limits["request_timeout_seconds"] + 2):
                await asyncio.shield(self.ready)
        except TimeoutError:
            self.states = dict.fromkeys(self.operations, "unknown")

    async def close(self):
        self.closed = True
        if self.worker:
            self.worker.cancel()
            if self.client:
                async with asyncio.timeout(2):
                    await self.client.aclose()
            try:
                async with asyncio.timeout(5):
                    await asyncio.shield(self.worker)
            except asyncio.CancelledError:
                if not self.worker.done():
                    raise
            except TimeoutError:
                raise LasaError("peer_unavailable", 503) from None
        self._drain()

    def _drain(self):
        while not self.queue.empty():
            _, _, _, future = self.queue.get_nowait()
            if not future.done():
                future.set_exception(ConnectorFailure())

    async def call(self, operation_id, arguments, seconds):
        if self.closed or self.state(operation_id) != "available":
            raise ConnectorFailure(self.state(operation_id))
        operation = self.operations[operation_id]
        validate(operation["input_schema"], arguments, "invalid_input", 400)
        validate(operation["argument_constraints"], arguments, "authority_denied", 403)
        future = asyncio.get_running_loop().create_future()
        end = asyncio.get_running_loop().time() + min(
            seconds, self.limits["request_timeout_seconds"]
        )
        try:
            self.queue.put_nowait((operation_id, arguments, end, future))
        except asyncio.QueueFull:
            raise ConnectorFailure("busy", code="capacity_exhausted") from None
        try:
            async with asyncio.timeout_at(end):
                return await future
        except TimeoutError:
            future.cancel()
            raise LasaError("deadline_exceeded", 422) from None

    async def _open(self, stack):
        resource = self.resource
        if resource["kind"] == "mcp-stdio":
            home = self.root / "connectors" / resource["id"]
            home.mkdir(parents=True, exist_ok=True, mode=0o700)
            env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(home)}
            env.update(
                {
                    name: private_secret(self.config, reference)
                    for name, reference in resource["secret_env"].items()
                }
            )
            log = stack.enter_context((home / "stderr.log").open("ab"))
            streams = await stack.enter_async_context(
                stdio_client(
                    StdioServerParameters(
                        command=sys.executable,
                        args=[
                            "-m",
                            "lasa_service.stdio_guard",
                            "--max-bytes",
                            str(self.limits["response_bytes"]),
                            "--",
                            resource["command"],
                            *resource["args"],
                        ],
                        env=env,
                        cwd=str(home),
                    ),
                    errlog=log,
                )
            )
            writer = RequestWriter(streams[1])
            session = await stack.enter_async_context(ClientSession(streams[0], writer))
            await session.initialize()
            return McpBackend(self, session, writer, self.secret_fingerprint())
        verify = (
            ssl.create_default_context(cafile=resource["ca_file"])
            if "ca_file" in resource
            else True
        )
        self.client = await stack.enter_async_context(
            httpx.AsyncClient(
                transport=BoundedTransport(verify, self.limits["response_bytes"]),
                auth=PrivateAuthentication(self.config, resource.get("credential_ref")),
                headers=resource.get("headers", {}),
                trust_env=False,
                follow_redirects=False,
                timeout=self.limits["request_timeout_seconds"],
            )
        )
        if resource["kind"] == "json-get":
            return JsonGetBackend(self, self.client)
        streams = await stack.enter_async_context(
            streamable_http_client(resource["url"], http_client=self.client)
        )
        writer = RequestWriter(streams[1])
        session = await stack.enter_async_context(ClientSession(streams[0], writer))
        await session.initialize()
        return McpBackend(self, session, writer, self.secret_fingerprint())

    def _ready(self):
        if not self.ready.done():
            self.ready.set_result(None)

    async def _serve(self):
        try:
            while not self.closed:
                try:
                    async with AsyncExitStack() as stack:
                        async with asyncio.timeout(self.limits["request_timeout_seconds"]):
                            backend = await self._open(stack)
                            self.states = await backend.discover()
                            self.generation += 1
                        self._ready()
                        refresh_at = time.monotonic() + self.limits["schema_refresh_seconds"]
                        while not self.closed:
                            until_refresh = refresh_at - time.monotonic()
                            if until_refresh <= 0:
                                async with asyncio.timeout(self.limits["request_timeout_seconds"]):
                                    self.states = await backend.discover()
                                refresh_at = (
                                    time.monotonic() + self.limits["schema_refresh_seconds"]
                                )
                                continue
                            try:
                                async with asyncio.timeout(until_refresh):
                                    operation_id, arguments, end, future = await self.queue.get()
                            except TimeoutError:
                                continue
                            if future.cancelled():
                                continue
                            if self.state(operation_id) != "available":
                                future.set_exception(ConnectorFailure(self.state(operation_id)))
                                continue
                            seconds = end - asyncio.get_running_loop().time()
                            if seconds <= 0:
                                future.set_exception(LasaError("deadline_exceeded", 422))
                                continue
                            self.active = asyncio.create_task(
                                backend.call(self.operations[operation_id], arguments, seconds)
                            )
                            future.add_done_callback(
                                lambda f, call=self.active: call.cancel() if f.cancelled() else None
                            )
                            try:
                                async with asyncio.timeout_at(end):
                                    value = await self.active
                                if not future.done():
                                    future.set_result(value)
                            except asyncio.CancelledError:
                                if not future.cancelled():
                                    if self.closed:
                                        future.cancel()
                                    else:
                                        future.set_exception(ConnectorFailure())
                                    raise
                                if asyncio.current_task().cancelling():
                                    raise
                            except ConnectorFailure as exc:
                                self.record_failure(operation_id, exc)
                                refresh_at = max(
                                    self.retry_at.get(operation_id, 0),
                                    min(
                                        refresh_at,
                                        time.monotonic() + self.limits["recovery_interval_seconds"],
                                    ),
                                )
                                if not future.done():
                                    future.set_exception(exc)
                            except LasaError as exc:
                                if not future.done():
                                    future.set_exception(exc)
                            except TimeoutError:
                                if not future.done():
                                    future.set_exception(LasaError("deadline_exceeded", 422))
                            except Exception:
                                if not future.done():
                                    future.set_exception(ConnectorFailure())
                                raise
                            finally:
                                self.active = None
                except asyncio.CancelledError:
                    raise
                except RefreshCredentials:
                    self.states = dict.fromkeys(self.operations, "unknown")
                except Exception as exc:
                    errors, seen, failure = [exc], set(), ConnectorFailure()
                    while errors and len(seen) < 32:
                        error = errors.pop()
                        if id(error) in seen:
                            continue
                        seen.add(id(error))
                        if isinstance(error, ConnectorFailure):
                            failure = error
                            break
                        if isinstance(error, httpx.HTTPStatusError):
                            try:
                                http_failure(error.response)
                            except ConnectorFailure as mapped:
                                failure = mapped
                                break
                        errors.extend(getattr(error, "exceptions", []))
                        errors.extend(
                            e for e in [error.__cause__, error.__context__] if e is not None
                        )
                    for operation_id in self.operations:
                        self.record_failure(operation_id, failure)
                finally:
                    self.client = None
                    self._ready()
                    self._drain()
                if not self.closed:
                    await asyncio.sleep(
                        max(
                            self.limits["recovery_interval_seconds"],
                            max(self.retry_at.values(), default=0) - time.monotonic(),
                        )
                    )
        finally:
            if self.active:
                self.active.cancel()
                await asyncio.gather(self.active, return_exceptions=True)
            self.states = dict.fromkeys(self.operations, "unavailable")
            self._drain()
