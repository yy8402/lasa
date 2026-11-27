"""Target LASA HTTP API; discovery and task authority share one receiver identity."""

import asyncio
import base64
import hashlib
import hmac
import re
import secrets
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from starlette.exceptions import HTTPException

from .capabilities import require
from .consumer import artifact_release, require_public_data, task_view
from .contracts import canonical, parse_json
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
    admission_gate=None,
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
    pending_writes = 0

    def admission_mode():
        try:
            mode = admission_gate.read_text().strip()
        except OSError:
            return "closed"
        return mode if mode in {"open", "drain"} else "closed"

    if admission_gate is not None:

        @app.middleware("http")
        async def gate(request, call_next):
            nonlocal pending_writes
            if request.method in {"GET", "HEAD", "OPTIONS"}:
                return await call_next(request)
            mode = admission_mode()
            if mode == "closed" or (
                mode == "drain"
                and not request.url.path.endswith(("/inputs", "/cancel", "/reconcile"))
            ):
                error = LasaError("capacity_exhausted", 503)
                return JSONResponse(
                    error.public(),
                    status_code=503,
                    media_type="application/problem+json",
                    headers={"Cache-Control": "no-store", "Retry-After": "5"},
                )
            pending_writes += 1
            try:
                return await call_next(request)
            finally:
                pending_writes -= 1

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
    history_key = secrets.token_bytes(32)

    def principal(request, *, operator=False):
        identity = c.authentication.authenticate_headers(request.headers)
        require((identity["kind"] == "operator") == operator, "authority_denied", 403)
        return identity

    def query_integer(request, name, default, minimum, maximum):
        try:
            value = int(request.query_params.get(name, default))
        except ValueError:
            raise LasaError("invalid_input") from None
        require(minimum <= value <= maximum, "invalid_input")
        return value

    def sign_history_cursor(owner, encoded):
        return hmac.digest(
            history_key, canonical([config.service_id, owner, encoded]), "sha256"
        ).hex()

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
        if schema == "TaskRequest":
            c.contracts.validate_task_request(body, caller=p["kind"] == "user")
        else:
            c.contracts.validate(schema, body)
        return p, body, key

    def response(document, status=200, *, audience=None):
        if "question" in document:
            question = document["question"]
            c.check_release_read(
                document["task_id"],
                "conversation:question:" + question["question_id"],
                question,
                audience,
            )
        if "result" in document:
            c.check_release_read(document["task_id"], "result", document["result"], audience)
        if audience:
            document = c.contracts.validate("ConsumerTask", task_view(c.store, document))
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

    if admission_gate is not None:

        @app.get("/health/drain", include_in_schema=False)
        async def drain_status(request: Request):
            principal(request, operator=True)
            return JSONResponse(
                {
                    "mode": admission_mode(),
                    "writes": pending_writes,
                    "tasks": len(set(c.store.active()) | c.jobs.keys()),
                },
                headers={"Cache-Control": "no-store"},
            )

    @app.post(prefix + "/sessions")
    async def create_session(request: Request):
        p, body, key = await mutation(request, "CreateSession")
        return response(*c.create_session(p, body, key, "POST " + request.url.path))

    @app.get(prefix + "/sessions/{session_id}")
    async def session(session_id: str, request: Request):
        return response(c.store.session(session_id, principal(request)["id"])[1])

    @app.post(prefix + "/sessions/{session_id}/tasks")
    async def submit(session_id: str, request: Request):
        p, body, key = await mutation(request, "TaskRequest")
        return response(
            *await c.submit(p, session_id, body, key, "POST " + request.url.path), audience=p
        )

    @app.get(prefix + "/tasks")
    async def list_tasks(request: Request):
        p = principal(request)
        require(p["kind"] == "user", "authority_denied", 403)
        limit = query_integer(request, "limit", "25", 1, 100)
        before = None
        if cursor := request.query_params.get("cursor"):
            require(re.fullmatch(r"[A-Za-z0-9_-]{1,400}\.[0-9a-f]{64}", cursor), "invalid_input")
            encoded, signature = cursor.split(".")
            require(
                hmac.compare_digest(signature, sign_history_cursor(p["id"], encoded)),
                "invalid_input",
            )
            before = parse_json(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        elif "cursor" in request.query_params:
            raise LasaError("invalid_input")
        rows = c.store.task_history(p["id"], limit + 1, before)
        items = [{**row, "contract": parse_json(row["contract"])} for row in rows[:limit]]
        titles = await asyncio.gather(*(c.visible_title(p, item["task_id"]) for item in items))
        for item, title in zip(items, titles, strict=True):
            item["title"] = c.released_title(p, item["task_id"], title)
        next_cursor = None
        if len(rows) > limit:
            last = items[-1]
            encoded = (
                base64.urlsafe_b64encode(canonical([last["received_at"], last["task_id"]]))
                .decode()
                .rstrip("=")
            )
            next_cursor = encoded + "." + sign_history_cursor(p["id"], encoded)
        return JSONResponse(
            {"tasks": items, "next_cursor": next_cursor}, headers={"Cache-Control": "no-store"}
        )

    @app.get(prefix + "/tasks/{task_id}")
    async def task(task_id: str, request: Request):
        p = principal(request)
        row, document = c.store.task(task_id, p["id"])
        if request.query_params.get("view") == "control":
            c.check_task_identity(row, p)
            return response(
                c.contracts.validate(
                    "ConsumerTaskDisposition", task_view(c.store, document, control=True)
                )
            )
        return response(document, audience=p)

    @app.get(prefix + "/tasks/{task_id}/conversation")
    async def conversation(task_id: str, request: Request):
        p = principal(request)
        require(p["kind"] == "user", "authority_denied", 403)
        after = query_integer(request, "after_sequence", "0", 0, MAX_AFTER_SEQUENCE)
        limit = query_integer(request, "limit", "8", 1, 32)
        return JSONResponse(
            await c.conversation(p, task_id, after, limit), headers={"Cache-Control": "no-store"}
        )

    @app.post(prefix + "/tasks/{task_id}/follow-ups")
    async def follow_up(task_id: str, request: Request):
        p, body, key = await mutation(request, "TaskRequest")
        require(p["kind"] == "user", "authority_denied", 403)
        return response(
            *await c.follow_up(p, task_id, body, key, "POST " + request.url.path), audience=p
        )

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
            (p["id"], operation_id),
        ).fetchone()
        require(row is not None, "not_found", 404)
        value = {
            "operation_id": operation_id,
            "request_digest": row["digest"],
            "resource_type": row["kind"],
            "resource_id": row["resource_id"],
            "http_status": row["status"],
        }
        if row["kind"] == "task":
            _, task = c.store.task(row["resource_id"], p["id"])
            value.update(selection=task["selection"], processing=task["processing"])
        c.contracts.validate("OperationReceipt", value)
        return JSONResponse(value, headers={"Cache-Control": "no-store"})

    @app.get(prefix + "/operator/tasks/{task_id}/delegations")
    async def delegations(task_id: str, request: Request):
        return JSONResponse(
            c.diagnostics.children_report(task_id, principal(request, operator=True)),
            headers={"Cache-Control": "no-store"},
        )

    @app.get(prefix + "/operator/tasks/{task_id}/events")
    async def operator_events(task_id: str, request: Request):
        after = query_integer(request, "after_sequence", "0", 0, MAX_AFTER_SEQUENCE)
        limit = query_integer(request, "limit", "50", 1, 100)
        return JSONResponse(
            c.diagnostics.page(task_id, principal(request, operator=True), after, limit),
            headers={"Cache-Control": "no-store"},
        )

    @app.get(prefix + "/tasks/{task_id}/events")
    async def events(task_id: str, request: Request):
        p = principal(request)
        row, _ = c.store.task(task_id, p["id"])
        c.check_task_identity(row, p)
        after = query_integer(request, "after_sequence", "0", 0, MAX_AFTER_SEQUENCE)
        limit = query_integer(request, "limit", "50", 1, 100)
        entries = [
            dict(item)
            for item in c.store.db.execute(
                "SELECT sequence,status FROM consumer_events WHERE task_id=? AND sequence>? "
                "ORDER BY sequence LIMIT ?",
                (task_id, after, limit),
            )
        ]
        page = {
            "task_id": task_id,
            "events": entries,
            "next_sequence": (entries[-1]["sequence"] if entries else after) + 1,
        }
        return JSONResponse(
            c.contracts.validate("ConsumerEventPage", page), headers={"Cache-Control": "no-store"}
        )

    @app.get(prefix + "/tasks/{task_id}/artifacts/{artifact_id}")
    async def artifact(task_id: str, artifact_id: str, request: Request):
        p = principal(request)
        c.store.task(task_id, p["id"])
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
        public_artifact = artifact_release(manifest, data)
        c.check_release_read(task_id, artifact_id, public_artifact, p, artifact=True)
        require_public_data(c, task_id, public_artifact)
        return Response(
            data,
            media_type=manifest["media_type"],
            headers={
                "Cache-Control": "no-store",
                "Content-Digest": "sha-256=:" + base64.b64encode(checksum.digest()).decode() + ":",
            },
        )

    return app
