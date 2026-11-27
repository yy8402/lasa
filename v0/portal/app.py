"""Browser routes bound to a portal session and its native user token."""

import asyncio
import hashlib
import hmac
import logging
import re
import time
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import uuid4
from weakref import WeakValueDictionary

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from jinja2 import Environment, FileSystemLoader, select_autoescape

from lasa_service.contracts import digest, parse_json, protocol_contracts
from lasa_service.errors import LasaError

from .client import MESSAGES, IdentityProvider, Native, resource, validate_input
from .config import PortalError, https_url
from .state import State, now, opaque
from .submission import Submissions

ROOT = Path(__file__).parent
SESSION = "__Host-lasa_portal"
LOGIN = "__Host-lasa_login"
LOGGER = logging.getLogger("lasa.portal")
RETURN_ROUTE = re.compile(
    r"/(?:new|tasks(?:/[A-Za-z0-9][A-Za-z0-9._-]{2,127})?|submissions/[0-9a-f]{32})?"
)
STRONG_ETAG = re.compile(r'"[0-9]{1,16}"')
ACTION_SCHEMA = {"inputs": "TaskInput", "cancel": "CancelTask"}


def secure_cookie(response, key, value, lifetime, *, same_site="strict"):
    response.set_cookie(
        key, value, max_age=lifetime, secure=True, httponly=True, samesite=same_site, path="/"
    )


def clear_cookie(response, key):
    secure_cookie(response, key, "", 0)


def problem(request, error):
    payload = {
        "code": error.code,
        "message": error.message,
        "request_id": request.state.request_id,
        **({"field": error.field} if error.field else {}),
    }
    return JSONResponse(
        payload,
        status_code=error.status,
        headers={"Retry-After": str(error.retry_after)} if error.retry_after else {},
    )


def safe_route(value):
    return value if RETURN_ROUTE.fullmatch(value or "") else "/new"


def integer(request, name, default, low, high):
    try:
        value = int(request.query_params.get(name, default))
    except ValueError:
        value = -1
    if not low <= value <= high:
        raise PortalError(400, "invalid_query", "Check the requested page.")
    return value


class Portal:
    def __init__(self, settings, state, issuer, native):
        self.settings = settings
        self.state = state
        self.issuer = issuer
        self.native = native
        self.submissions = Submissions(state, native, settings)
        self.refresh_locks = WeakValueDictionary()
        self.requests = asyncio.Semaphore(settings.max_concurrency)
        self.rates = {}

    async def session(self, request):
        cookie = request.cookies.get(SESSION)
        session = self.state.session(cookie)
        if not session:
            raise PortalError(401, "sign_in_required", "Sign in to continue.")
        if session["tokens"]["exp"] <= now() + 5:
            key = session["id"]
            lock = self.refresh_locks.setdefault(key, asyncio.Lock())
            async with lock:
                session = self.state.session(cookie)
                if not session:
                    raise PortalError(401, "sign_in_required", "Sign in to continue.")
                if session["tokens"]["exp"] <= now() + 5:
                    try:
                        tokens = await self.issuer.refresh(session["tokens"])
                    except PortalError as error:
                        if error.status == 401:
                            self.state.delete_session(cookie)
                        raise
                    tokens["retention"] = session["tokens"]["retention"]
                    if not self.state.update_tokens(key, tokens):
                        raise PortalError(401, "sign_in_required", "Sign in to continue.")
                    session["tokens"] = tokens
        return session

    def rate(self, owner, write):
        window = now() // 60
        if len(self.rates) > self.settings.max_sessions * 4:
            self.rates = {key: value for key, value in self.rates.items() if key[2] == window}
        key = owner, write, window
        count = self.rates.get(key, 0)
        if count >= (30 if write else 180):
            raise PortalError(429, "rate_limit", "Try again shortly.", retry_after=10)
        self.rates[key] = count + 1

    async def authenticate(self, request, *, write=False):
        session = await self.session(request)
        if write and (
            request.headers.get("Origin") != self.settings.public_origin
            or not hmac.compare_digest(
                request.headers.get("X-CSRF-Token", "").encode(), session["csrf"].encode()
            )
        ):
            raise PortalError(403, "csrf", "Reload the page to continue.")
        self.rate(session["owner"], write)
        return session

    async def body(self, request):
        if (
            request.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            != "application/json"
        ):
            raise PortalError(415, "invalid_input", "Send a JSON request.")
        data = bytearray()
        try:
            async with asyncio.timeout(self.settings.timeout_seconds):
                async for chunk in request.stream():
                    if len(data) + len(chunk) > self.settings.body_bytes:
                        raise PortalError(
                            413, "input_size", "This request exceeds the input limit."
                        )
                    data.extend(chunk)
            return parse_json(data)
        except (LasaError, TimeoutError):
            raise PortalError(400, "invalid_input", "The request body is invalid.") from None


def create_app(settings, *, native_transport=None, issuer_transport=None):
    origin_host = https_url(settings.public_origin, origin=True).netloc
    templates = Environment(
        loader=FileSystemLoader(ROOT / "templates"), autoescape=select_autoescape(["html"])
    )
    assets = {}
    for name, media_type in (("portal.css", "text/css"), ("portal.js", "text/javascript")):
        data = (ROOT / "static" / name).read_bytes()
        assets[name] = (data, media_type, hashlib.sha256(data).hexdigest()[:16])

    @asynccontextmanager
    async def lifespan(app):
        state = State(settings)
        try:
            options = {
                "verify": settings.tls_context(),
                "trust_env": False,
                "follow_redirects": False,
                "timeout": settings.timeout_seconds,
            }
            async with (
                httpx.AsyncClient(transport=native_transport, **options) as native,
                httpx.AsyncClient(transport=issuer_transport, **options) as issuer,
            ):
                app.state.portal = Portal(
                    settings,
                    state,
                    IdentityProvider(settings, issuer, transport=issuer_transport),
                    Native(settings, native),
                )
                yield
        finally:
            state.close()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    def view(name, *, status=200, **context):
        return HTMLResponse(
            templates.get_template(name).render(
                css=settings.base_path + "/assets/" + assets["portal.css"][2] + "/portal.css",
                js=settings.base_path + "/assets/" + assets["portal.js"][2] + "/portal.js",
                base_path=settings.base_path,
                **context,
            ),
            status_code=status,
        )

    @app.middleware("http")
    async def boundary(request, call_next):
        request.state.request_id = uuid4().hex
        started = time.monotonic()
        health = request.url.path in {"/health/live", "/health/ready"}
        portal = request.app.state.portal
        if not health and request.headers.get("Host") != origin_host:
            response = problem(request, PortalError(400, "host", "Invalid portal origin."))
        elif portal.requests.locked() and not health:
            response = problem(
                request, PortalError(429, "capacity", "Try again shortly.", retry_after=10)
            )
        elif health:
            response = await call_next(request)
        else:
            async with portal.requests:
                response = await call_next(request)
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        )
        response.headers["X-Request-ID"] = request.state.request_id
        LOGGER.info(
            "request=%s route=%s method=%s status=%s duration_ms=%d",
            request.state.request_id,
            getattr(request.scope.get("route"), "path", "unknown"),
            request.method,
            response.status_code,
            (time.monotonic() - started) * 1000,
        )
        return response

    @app.exception_handler(PortalError)
    async def portal_error(request, error):
        if request.url.path.startswith("/auth/"):
            return view(
                "message.html",
                title="Sign-in",
                message=error.message,
                href=settings.base_path + "/auth/login",
                action="Try sign-in again",
                resume=False,
                status=error.status,
            )
        return problem(request, error)

    @app.exception_handler(Exception)
    async def unexpected(request, _):
        return problem(
            request, PortalError(500, "portal_error", "The portal could not complete this request.")
        )

    @app.get("/health/live")
    async def live():
        return {"status": "alive"}

    @app.get("/health/ready")
    async def ready(request: Request):
        request.app.state.portal.state.db.execute("SELECT 1").fetchone()
        return {"status": "ready"}

    @app.get("/assets/{fingerprint}/{name}")
    async def asset(fingerprint: str, name: str):
        if name not in assets or fingerprint != assets[name][2]:
            raise PortalError(404, "not_found", "That asset is unavailable.")
        data, media_type, _ = assets[name]
        return Response(
            data,
            media_type=media_type,
            headers={"Cache-Control": "public, max-age=31536000, immutable"},
        )

    @app.get("/auth/login")
    async def login(request: Request):
        portal = request.app.state.portal
        transaction = {
            "state": opaque(),
            "nonce": opaque(),
            "verifier": opaque(),
            "next": safe_route(request.query_params.get("next")),
        }
        location = await portal.issuer.login_url(transaction)
        cookie = opaque()
        portal.state.save_login(cookie, transaction)
        response = RedirectResponse(location, status_code=303)
        secure_cookie(response, LOGIN, cookie, settings.login_seconds, same_site="lax")
        return response

    @app.get("/auth/callback")
    async def callback(request: Request):
        portal = request.app.state.portal
        transaction = portal.state.take_login(request.cookies.get(LOGIN))
        supplied_state = request.query_params.get("state", "")
        code = request.query_params.get("code", "")
        if (
            not transaction
            or not hmac.compare_digest(transaction["state"].encode(), supplied_state.encode())
            or not 0 < len(code) <= 4096
            or "error" in request.query_params
        ):
            raise PortalError(
                403, "sign_in_denied", "The sign-in transaction expired or was rejected."
            )
        tokens = await portal.issuer.exchange(transaction, code)
        tokens["retention"] = await portal.native.qualify(tokens["access"])
        cookie = portal.state.create_session(tokens["sub"], tokens, request.cookies.get(SESSION))
        response = view(
            "message.html",
            title="Signed in",
            message="",
            href=settings.base_path + transaction["next"],
            action="Continue",
            resume=True,
        )
        clear_cookie(response, LOGIN)
        secure_cookie(response, SESSION, cookie, settings.session_seconds)
        return response

    @app.post("/auth/logout")
    async def logout(request: Request):
        portal = request.app.state.portal
        session = await portal.authenticate(request, write=True)
        portal.state.delete_session(request.cookies.get(SESSION))
        await portal.issuer.revoke(session["tokens"]["refresh"])
        response = JSONResponse({"signed_out": True})
        clear_cookie(response, SESSION)
        return response

    async def page(request, name, identifier=None):
        portal = request.app.state.portal
        route = safe_route(request.url.path)
        try:
            session = await portal.session(request)
        except PortalError as error:
            if error.status == 401:
                return view(
                    "message.html",
                    title="LASA caller portal",
                    message="",
                    href=str(httpx.URL(settings.base_path + "/auth/login", params={"next": route})),
                    action="Sign in",
                    resume=False,
                )
            raise
        return view(
            "portal.html",
            page=name,
            identifier=identifier,
            csrf=session["csrf"],
            body_bytes=settings.body_bytes,
        )

    @app.get("/")
    @app.get("/new")
    async def new(request: Request):
        return await page(request, "new")

    @app.get("/tasks")
    async def history(request: Request):
        return await page(request, "history")

    @app.get("/tasks/{task_id}")
    async def detail(request: Request, task_id: str):
        return await page(request, "task", resource(task_id))

    @app.get("/submissions/{submission_id}")
    async def recovery(request: Request, submission_id: str):
        return await page(request, "recovery", resource(submission_id))

    @app.get("/api/offers")
    async def offers(request: Request):
        portal = request.app.state.portal
        session = await portal.authenticate(request)
        return {"offers": await portal.native.offers(session["tokens"]["access"])}

    @app.get("/api/submission-ticket")
    async def submission_ticket(request: Request):
        portal = request.app.state.portal
        session = await portal.authenticate(request)
        return portal.state.ticket(session["owner"])

    async def submit_task(request, parent_id=None):
        portal = request.app.state.portal
        session = await portal.authenticate(request, write=True)
        token = session["tokens"]
        value = await portal.submissions.start(
            session["owner"],
            token["access"],
            token["retention"],
            await portal.body(request),
            parent_id=parent_id,
        )
        if value["state"] == "recorded":
            LOGGER.info(
                "request=%s task=%s", request.state.request_id, value["task_url"].split("/")[-1]
            )
            return JSONResponse(value, status_code=202)
        if value["state"] == "rejected":
            return JSONResponse(value, status_code=value["problem"]["status"])
        status = 409 if value["state"] == "checking" else 503
        return JSONResponse(
            value | {"code": "request_in_progress" if status == 409 else "submission_unconfirmed"},
            status_code=status,
            headers={"Retry-After": "2"},
        )

    @app.post("/api/submissions")
    async def submit(request: Request):
        return await submit_task(request)

    @app.post("/api/tasks/{task_id}/follow-ups")
    async def follow_up(request: Request, task_id: str):
        return await submit_task(request, resource(task_id))

    @app.get("/api/submissions/{submission_id}")
    async def submission(request: Request, submission_id: str):
        portal = request.app.state.portal
        session = await portal.authenticate(request)
        return await portal.submissions.read(
            session["owner"], session["tokens"]["access"], resource(submission_id)
        )

    @app.get("/api/tasks")
    async def tasks(request: Request):
        portal = request.app.state.portal
        session = await portal.authenticate(request)
        params = {"limit": integer(request, "limit", 25, 1, 100)}
        if "cursor" in request.query_params:
            params["cursor"] = request.query_params["cursor"]
        result = await portal.native.get(session["tokens"]["access"], "/tasks", params=params)
        if "cursor" not in params:
            result["pending"] = portal.state.unresolved(session["owner"])
        return result

    @app.get("/api/tasks/{task_id}")
    async def task(request: Request, task_id: str):
        portal = request.app.state.portal
        session = await portal.authenticate(request)
        value, etag = await portal.native.task(
            session["tokens"]["access"],
            task_id,
            control=request.query_params.get("view") == "control",
        )
        return JSONResponse(value, headers={"ETag": etag} if etag else {})

    @app.get("/api/tasks/{task_id}/events")
    async def events(request: Request, task_id: str):
        portal = request.app.state.portal
        session = await portal.authenticate(request)
        return await portal.native.get(
            session["tokens"]["access"],
            "/tasks/" + resource(task_id) + "/events",
            schema="ConsumerEventPage",
            params={
                "after_sequence": integer(request, "after_sequence", 0, 0, 9007199254740990),
                "limit": integer(request, "limit", 50, 1, 100),
            },
        )

    @app.get("/api/tasks/{task_id}/conversation")
    async def conversation(request: Request, task_id: str):
        portal = request.app.state.portal
        session = await portal.authenticate(request)
        return await portal.native.conversation(
            session["tokens"]["access"],
            task_id,
            integer(request, "after_sequence", 0, 0, 9007199254740990),
        )

    @app.post("/api/tasks/{task_id}/inputs")
    @app.post("/api/tasks/{task_id}/cancel")
    async def action(request: Request, task_id: str):
        portal = request.app.state.portal
        session = await portal.authenticate(request, write=True)
        token = session["tokens"]["access"]
        kind = request.url.path.rsplit("/", 1)[-1]
        native_path = "/tasks/" + resource(task_id)
        etag = request.headers.get("If-Match", "")
        key = request.headers.get("Idempotency-Key", "")
        if not STRONG_ETAG.fullmatch(etag) or not re.fullmatch(r"[!-~]{1,128}", key):
            raise PortalError(428, "precondition_required", MESSAGES["precondition_required"])
        body = await portal.body(request)
        validate_input(protocol_contracts().expanded(ACTION_SCHEMA[kind]), body)
        try:
            value, revision = await portal.native.mutation(
                token, native_path + "/" + kind, body, key, "ConsumerTask", etag=etag
            )
        except PortalError as error:
            if error.status == 401:
                raise
            try:
                receipt = await portal.native.get(
                    token,
                    "/operations/" + resource(body["operation_id"]),
                    schema="OperationReceipt",
                )
            except PortalError:
                raise error from None
            if (
                receipt["resource_id"] != task_id
                or receipt["resource_type"] != "task"
                or receipt["operation_id"] != body["operation_id"]
                or receipt["request_digest"] != digest(body)
            ):
                raise error from None
            value, revision = await portal.native.task(token, task_id, control=kind == "cancel")
        return JSONResponse(value, status_code=202, headers={"ETag": revision} if revision else {})

    @app.get("/api/tasks/{task_id}/artifacts/{artifact_id}")
    async def artifact(request: Request, task_id: str, artifact_id: str):
        portal = request.app.state.portal
        session = await portal.authenticate(request)
        native = await portal.native.artifact(session["tokens"]["access"], task_id, artifact_id)
        media = native.headers.get("Content-Type", "").split(";", 1)[0]
        suffix = {"text/plain": ".txt", "text/markdown": ".md", "application/json": ".json"}.get(
            media, ""
        )
        return Response(
            native.content,
            media_type="application/octet-stream",
            headers={
                "Content-Digest": native.headers["Content-Digest"],
                "Content-Disposition": f'attachment; filename="{resource(artifact_id)}{suffix}"',
            },
        )

    return app
