"""Target LASA HTTP API; discovery and task authority share one receiver identity."""

import base64
import hashlib
import re
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from starlette.exceptions import HTTPException

from .capabilities import require
from .contracts import parse_json
from .coordinator import Coordinator
from .errors import LasaError

MAX_AFTER_SEQUENCE = 9007199254740990


def create_app(
    config,
    *,
    runtime=None,
    peer_transport=None,
    model_transport=None,
    inspection_transport=None,
    planner=None,
    verifier=None,
):
    if runtime is None:
        from .runtime import CodexRuntime

        runtime = CodexRuntime(config)
    c = Coordinator(
        config,
        runtime,
        peer_transport=peer_transport,
        model_transport=model_transport,
        inspection_transport=inspection_transport,
        planner=planner,
        verifier=verifier,
    )

    @asynccontextmanager
    async def lifespan(_app):
        try:
            await c.start()
            yield
        finally:
            await c.close()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.coordinator = c

    @app.exception_handler(LasaError)
    async def error(_request, exc):
        headers = {"Cache-Control": "no-store"}
        if exc.status == 401:
            headers["WWW-Authenticate"] = "Bearer"
        return JSONResponse(
            exc.public(),
            status_code=exc.status,
            media_type="application/problem+json",
            headers=headers,
        )

    @app.exception_handler(HTTPException)
    async def http_error(_request, exc):
        error = LasaError(
            "not_found" if exc.status_code == 404 else "invalid_input", exc.status_code
        )
        return JSONResponse(
            error.public(),
            status_code=exc.status_code,
            media_type="application/problem+json",
            headers={**(exc.headers or {}), "Cache-Control": "no-store"},
        )

    @app.exception_handler(Exception)
    async def unexpected(_request, _exc):
        return JSONResponse(
            LasaError("internal_error", 500).public(),
            status_code=500,
            media_type="application/problem+json",
            headers={"Cache-Control": "no-store"},
        )

    c.discovery.mount(app)
    prefix = urlsplit(config.document["service"]["base_url"]).path.rstrip("/")

    def principal(request):
        return c.authentication.authenticate_headers(request.headers)

    def query_integer(request, name, default, minimum, maximum):
        try:
            value = int(request.query_params.get(name, default))
        except ValueError:
            raise LasaError("invalid_input") from None
        require(minimum <= value <= maximum, "invalid_input")
        return value

    async def mutation(request, schema):
        p = principal(request)
        key = request.headers.get("Idempotency-Key", "")
        require(re.fullmatch(r"[!-~]{1,128}", key) is not None, "invalid_input")
        require(
            request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            == "application/json",
            "invalid_input",
        )
        parts = []
        size = 0
        async for part in request.stream():
            size += len(part)
            require(
                size <= config.document["limits"]["max_task_budget"]["input_bytes"] + 65536,
                "capacity_exhausted",
                413,
            )
            parts.append(part)
        body = parse_json(b"".join(parts))
        c.contracts.validate(schema, body)
        return p, body, key

    def response(document, status=200, *, audience=None):
        if "question" in document:
            row, _ = c.store.task(document["task_id"], audience["subject"])
            c.check_read_authority(row, audience)
        if "result" in document:
            c.check_release_read(document["task_id"], "result", document["result"], audience)
        headers = {"Cache-Control": "no-store"}
        if "task_id" in document:
            headers.update(
                ETag='"' + str(document["revision"]) + '"',
                Location=config.document["service"]["base_url"].rstrip("/")
                + "/tasks/"
                + document["task_id"],
            )
        else:
            headers["Location"] = (
                config.document["service"]["base_url"].rstrip("/")
                + "/sessions/"
                + document["session_id"]
            )
        return JSONResponse(document, status_code=status, headers=headers)

    @app.get("/health/live")
    async def live():
        return {"status": "alive"}

    @app.get("/health/ready")
    async def ready(request: Request):
        principal(request)
        require(c.availability() != "unavailable", "capacity_exhausted", 503)
        return {"status": "ready"}

    @app.post(prefix + "/sessions")
    async def create_session(request: Request):
        p, body, key = await mutation(request, "CreateSession")
        return response(*c.create_session(p, body, key, "POST " + request.url.path))

    @app.get(prefix + "/sessions/{session_id}")
    async def session(session_id: str, request: Request):
        return response(c.store.session(session_id, principal(request)["subject"])[1])

    @app.post(prefix + "/sessions/{session_id}/tasks")
    async def submit(session_id: str, request: Request):
        p, body, key = await mutation(request, "TaskRequest")
        return response(
            *await c.submit(p, session_id, body, key, "POST " + request.url.path), audience=p
        )

    @app.get(prefix + "/tasks/{task_id}")
    async def task(task_id: str, request: Request):
        p = principal(request)
        row, document = c.store.task(task_id, p["subject"])
        if request.query_params.get("view") == "control":
            return response(c.task_disposition(row, document, p))
        return response(document, audience=p)

    @app.post(prefix + "/tasks/{task_id}/inputs")
    async def answer(task_id: str, request: Request):
        p, body, key = await mutation(request, "TaskInput")
        return response(
            *await c.mutation(
                p,
                task_id,
                body,
                key,
                "POST " + request.url.path,
                request.headers.get("If-Match"),
                "input",
            ),
            audience=p,
        )

    @app.post(prefix + "/tasks/{task_id}/cancel")
    async def cancel(task_id: str, request: Request):
        p, body, key = await mutation(request, "CancelTask")
        return response(
            *await c.mutation(
                p,
                task_id,
                body,
                key,
                "POST " + request.url.path,
                request.headers.get("If-Match"),
                "cancel",
            ),
            audience=p,
        )

    @app.post(prefix + "/tasks/{task_id}/reconcile")
    async def reconcile(task_id: str, request: Request):
        p, body, key = await mutation(request, "ReconcileTask")
        return response(
            *await c.reconcile(p, task_id, body, key, "POST " + request.url.path), audience=p
        )

    @app.get(prefix + "/operations/{operation_id}")
    async def operation(operation_id: str, request: Request):
        p = principal(request)
        row = c.store.db.execute(
            "SELECT * FROM operations WHERE owner=? AND operation_id=?",
            (p["subject"], operation_id),
        ).fetchone()
        require(row is not None, "not_found", 404)
        value = {
            "operation_id": operation_id,
            "request_digest": row["digest"],
            "resource_type": row["kind"],
            "resource_id": row["resource_id"],
            "http_status": row["status"],
        }
        c.contracts.validate("OperationReceipt", value)
        return JSONResponse(value, headers={"Cache-Control": "no-store"})

    @app.get(prefix + "/tasks/{task_id}/delegations")
    async def delegations(task_id: str, request: Request):
        after = query_integer(request, "after_sequence", "0", 0, MAX_AFTER_SEQUENCE)
        return JSONResponse(
            await c.diagnostics.children_report(task_id, principal(request), after),
            headers={"Cache-Control": "no-store"},
        )

    @app.get(prefix + "/tasks/{task_id}/events")
    async def events(task_id: str, request: Request):
        after = query_integer(request, "after_sequence", "0", 0, MAX_AFTER_SEQUENCE)
        limit = query_integer(request, "limit", "50", 1, 100)
        return JSONResponse(
            await c.diagnostics.release_page(task_id, principal(request), after, limit),
            headers={"Cache-Control": "no-store"},
        )

    @app.get(prefix + "/tasks/{task_id}/artifacts/{artifact_id}")
    async def artifact(task_id: str, artifact_id: str, request: Request):
        p = principal(request)
        c.store.task(task_id, p["subject"])
        row = c.store.db.execute(
            "SELECT * FROM artifacts WHERE id=? AND task_id=? AND released=1",
            (artifact_id, task_id),
        ).fetchone()
        require(row is not None, "not_found", 404)
        data = bytes(row["content"])
        manifest = parse_json(row["manifest"])
        checksum = hashlib.sha256(data)
        require(
            "sha256:" + checksum.hexdigest() == manifest["digest"],
            "verification_failed",
            500,
        )
        c.check_release_read(task_id, artifact_id, data, p)
        return Response(
            data,
            media_type=manifest["media_type"],
            headers={
                "Cache-Control": "no-store",
                "Content-Digest": "sha-256=:" + base64.b64encode(checksum.digest()).decode() + ":",
            },
        )

    return app
