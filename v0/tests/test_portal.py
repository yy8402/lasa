import asyncio
import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import sqlite3
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import jwt
import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from lasa_service.contracts import digest

from .conftest import ISSUER, JWK, KEY, FakeRuntime, documents, settled, submit, task_request, token

pytest.importorskip("authlib")
pytest.importorskip("jinja2")

from portal.app import LOGIN, SESSION, create_app  # noqa: E402
from portal.config import Settings  # noqa: E402
from portal.state import now  # noqa: E402

ORIGIN = "https://portal.example.net"
SECRET = "synthetic-confidential-client-secret"


class Issuer:
    """An isolated, interactive authorization server with PKCE and one-use codes."""

    def __init__(self, issuer, audience):
        self.issuer = issuer
        self.audience = audience
        self.client_id = "test-portal-client"
        self.prefix = urlsplit(issuer).path
        self.codes = {}
        self.refresh_tokens = {}
        self.key = KEY
        self.jwk = JWK
        self.bad_nonce = False
        self.bad_audience = False
        self.refresh_count = 0
        self.app = FastAPI()
        self.app.add_api_route(self.prefix + "/.well-known/openid-configuration", self.metadata)
        self.app.add_api_route(self.prefix + "/jwks", self.jwks)
        self.app.add_api_route(self.prefix + "/authorize", self.authorize)
        self.app.add_api_route(self.prefix + "/token", self.exchange, methods=["POST"])
        self.app.add_api_route(self.prefix + "/revoke", self.revoke, methods=["POST"])

    async def metadata(self):
        return {
            "issuer": self.issuer,
            "code_challenge_methods_supported": ["S256"],
            "authorization_endpoint": self.issuer + "/authorize",
            "token_endpoint": self.issuer + "/token",
            "jwks_uri": self.issuer + "/jwks",
            "revocation_endpoint": self.issuer + "/revoke",
        }

    async def jwks(self):
        return {"keys": [self.jwk]}

    async def authorize(self, request: Request):
        query = dict(request.query_params)
        user = query.pop("as_user", None)
        if not user:
            from html import escape

            href = self.prefix + "/authorize?" + urlencode(query)
            return HTMLResponse(
                "<h1>Test identity provider</h1>"
                f'<a href="{escape(href + "&as_user=alice")}">Sign in as Alice</a>'
                f'<a href="{escape(href + "&as_user=bob")}">Sign in as Bob</a>'
            )
        assert query["client_id"] == self.client_id
        assert query["resource"] == self.audience
        assert query["code_challenge_method"] == "S256"
        code = secrets.token_urlsafe(32)
        self.codes[code] = query | {"subject": user}
        return RedirectResponse(
            query["redirect_uri"]
            + "?"
            + urlencode(
                {
                    "code": code,
                    "state": query["state"],
                }
            ),
            status_code=303,
        )

    def response(self, subject, nonce=None):
        refresh = secrets.token_urlsafe(32)
        self.refresh_tokens[refresh] = subject

        def signed(audience, **claims):
            return jwt.encode(
                {
                    "iss": self.issuer,
                    "aud": audience,
                    "sub": subject,
                    "iat": now(),
                    "exp": now() + 3600,
                    "jti": secrets.token_hex(12),
                    **claims,
                },
                self.key,
                algorithm="ES256",
                headers={"kid": self.jwk["kid"]},
            )

        values = {
            "access_token": signed(self.audience + ("/invalid" if self.bad_audience else "")),
            "refresh_token": refresh,
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        if nonce is not None:
            values["id_token"] = signed(
                self.client_id,
                nonce="incorrect" if self.bad_nonce else nonce,
                groups=["lasa-pilot"] if subject != "unassigned" else [],
            )
        return values

    async def exchange(self, request: Request):
        expected = "Basic " + base64.b64encode((self.client_id + ":" + SECRET).encode()).decode()
        assert request.headers["Authorization"] == expected
        fields = {k: v[0] for k, v in parse_qs((await request.body()).decode()).items()}
        if fields["grant_type"] == "refresh_token":
            subject = self.refresh_tokens.pop(fields["refresh_token"], None)
            if subject is None:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            self.refresh_count += 1
            return self.response(subject)
        saved = self.codes.pop(fields["code"], None)
        verifier = (
            base64.urlsafe_b64encode(hashlib.sha256(fields["code_verifier"].encode()).digest())
            .decode()
            .rstrip("=")
        )
        if (
            not saved
            or saved["code_challenge"] != verifier
            or saved["redirect_uri"] != fields["redirect_uri"]
        ):
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        return self.response(saved["subject"], saved["nonce"])

    async def revoke(self, request: Request):
        fields = parse_qs((await request.body()).decode())
        self.refresh_tokens.pop(fields["token"][0], None)
        return {}


class Transport(httpx.AsyncBaseTransport):
    def __init__(self, app):
        self.app = httpx.ASGITransport(app=app)
        self.fault = None
        self.skip_receipts = 0
        self.operations = []

    async def handle_async_request(self, request):
        path = request.url.path
        if request.method == "GET" and "/operations/" in path and self.skip_receipts:
            self.skip_receipts -= 1
            raise httpx.ReadError("synthetic receipt loss", request=request)
        if request.method != "POST" or not path.endswith(("/sessions", "/tasks", "/follow-ups")):
            return await self.app.handle_async_request(request)
        self.operations.append((path, request.headers["Idempotency-Key"]))
        kind = path.rsplit("/", 1)[1].removesuffix("s")
        fault = self.fault
        if fault and fault[0] == kind:
            self.fault = None
            if fault[1] == "before":
                raise httpx.ReadError("synthetic pre-commit loss", request=request)
            await self.app.handle_async_request(request)
            self.skip_receipts = 1
            raise httpx.ReadError("synthetic lost acknowledgement", request=request)
        return await self.app.handle_async_request(request)


async def execute(context):
    inputs = context.prompt["input"]
    goal = inputs.get("objective", "")
    if goal.startswith("Clarify"):
        answer = await context.coordinator.request_input(context.task_id, "Supply an owner.")
        assert answer["answer"] == "Ada"
    elif goal.startswith("Cancel"):
        await asyncio.sleep(15)
    elif goal == "Follow up from the message composer.":
        await asyncio.sleep(5)
        answer = await context.coordinator.request_input(
            context.task_id, "Confirm the follow-up label."
        )
        assert answer["answer"] == "Orchid"
    result = await FakeRuntime().run(context)
    if inputs.get("design") == "The design needs an assigned owner.":
        result["output"]["findings"] = [
            {
                "criterion_id": inputs["criteria"][0]["id"],
                "severity": "warning",
                "observation": "The design needs an assigned owner.",
                "recommendation": "Assign the on-call coordinator.",
            },
        ]
    if goal.startswith("Follow up"):
        assert "Previous released LASA output:" in context.prompt["input"]["context"]
        result["output"]["summary"] = "Used the previous released output."
    if goal.startswith("Unable"):
        result["output"] = {
            "disposition": "unable",
            "reason": "Missing necessary evidence.",
            "unsatisfied_requirements": ["requirement-1"],
        }
    if goal.startswith("Artifact"):
        artifact = context.coordinator.snapshot_artifact(
            context.task_id, "text/plain", "Synthetic download\n"
        )
        result["artifact_ids"] = [artifact["artifact_id"]]
    return result


def settings_at(root, raw, *, origin=ORIGIN):
    root.mkdir()
    names = ("encryption", "journal", "ticket")
    for name in names:
        (root / name).write_text(secrets.token_hex(32))
    secret = root / "client-secret"
    secret.write_text(SECRET)
    return Settings(
        public_origin=origin,
        lasa_url=raw["service"]["base_url"],
        lasa_service_id=raw["service"]["id"],
        issuer=raw["authentication"]["issuer"],
        client_id="test-portal-client",
        client_secret_file=str(secret),
        state_dir=str(root / "store"),
        encryption_key_file=str(root / "encryption"),
        journal_key_file=str(root / "journal"),
        ticket_key_file=str(root / "ticket"),
        assignment_claim="groups",
        assignment_value="lasa-pilot",
        timeout_seconds=1,
    )


@asynccontextmanager
async def harness(
    tmp_path, services, *, origin=ORIGIN, issuer_url=ISSUER, native_url=None, ca=None
):
    raw = documents(tmp_path / "native")
    raw["authentication"]["issuer"] = issuer_url
    if native_url:
        raw["service"]["base_url"] = native_url
    policy_file = Path(raw["authorization"]["policy_file"])
    policy = json.loads(policy_file.read_text())
    alice, bob = policy["principals"][:2]
    alice["rules"][0].update(effects=[], resources=[])
    bob["rules"] = alice["rules"]
    policy_file.write_text(json.dumps(policy))
    native_client, native_app = await services(raw=raw, runtime=FakeRuntime(execute))
    issuer = Issuer(issuer_url, raw["service"]["id"])
    settings = settings_at(tmp_path / "portal", raw, origin=origin)
    transport = Transport(native_app)
    if ca:
        settings = replace(settings, ca_file=str(ca), timeout_seconds=5)
        app = create_app(settings)
    else:
        app = create_app(
            settings,
            native_transport=transport,
            issuer_transport=httpx.ASGITransport(app=issuer.app),
        )
    async with app.router.lifespan_context(app):
        yield app, settings, transport, issuer, native_client, native_app, policy_file


async def login(client, issuer, subject="alice"):
    start = await client.get("/auth/login", params={"next": "/new"})
    assert start.status_code == 303, start.text
    assert "samesite=lax" in start.headers["set-cookie"].lower()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=issuer.app)) as idp:
        authorized = await idp.get(
            start.headers["location"],
            params={
                **dict(httpx.URL(start.headers["location"]).params),
                "as_user": subject,
            },
        )
    return await client.get(authorized.headers["location"])


def browser_client(app, settings):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=settings.public_origin
    )


async def composer(client, objective="Write a synthetic checklist.", page_path="/new"):
    page = await client.get(page_path)
    ticket = await client.get("/api/submission-ticket")
    assert ticket.status_code == 200
    csrf = re.search(r'name="csrf-token" content="([^"]+)', page.text).group(1)
    response = await client.get("/api/offers")
    assert response.status_code == 200, response.text
    (offer,) = response.json()["offers"]
    selection = {key: offer[key] for key in ("offer_id", "catalog_view", "contract")}
    return {
        "ticket": ticket.json()["value"],
        "objective": objective,
        "checks": ["Include one check."],
        "context": "Synthetic context only.",
        "selection": {**selection, "offer_revision": offer["revision"]},
    }, {"Origin": str(client.base_url).rstrip("/"), "X-CSRF-Token": csrf}


async def wait_task(client, path, status):
    for _ in range(200):
        response = await client.get("/api" + path)
        assert response.status_code == 200, response.text
        if response.json()["status"] == status:
            return response
        if response.json()["status"] in {
            "completed",
            "rejected",
            "failed",
            "cancelled",
            "indeterminate",
        }:
            pytest.fail(response.text)
        await asyncio.sleep(0.005)
    pytest.fail("The task failed to reach " + status)


async def test_oidc_roles_replay_csrf_refresh_and_key_rollover(tmp_path, services):
    async with harness(tmp_path, services) as (app, settings, _, issuer, _, native_app, _):
        async with browser_client(app, settings) as client:
            for subject in ("unassigned", "operator", "peer-layer1"):
                denied = await login(client, issuer, subject)
                assert denied.status_code in {401, 403}
                assert SESSION not in client.cookies
            issuer.bad_nonce = True
            assert (await login(client, issuer)).status_code == 403
            issuer.bad_nonce = False
            issuer.bad_audience = True
            assert (await login(client, issuer)).status_code == 403
            issuer.bad_audience = False
            await client.get("/auth/login")
            cookie_before_callback = client.cookies.get(LOGIN)
            assert (await client.get("/auth/callback?code=fake&state=invalid")).status_code == 403
            assert app.state.portal.state.take_login(cookie_before_callback) is None
            signed_in = await login(client, issuer)
            assert signed_in.status_code == 200, signed_in.text
            cookie = next(
                line
                for line in signed_in.headers.get_list("set-cookie")
                if line.startswith(SESSION)
            )
            assert all(
                value in cookie.lower() for value in ("secure", "httponly", "samesite=strict")
            )
            data, headers = await composer(client)
            assert (await client.post("/api/submissions", json=data)).status_code == 403
            assert (
                await client.post(
                    "/api/submissions",
                    json=data,
                    headers=headers | {"Origin": "https://foreign.invalid"},
                )
            ).status_code == 403
            state = app.state.portal.state
            session = state.session(client.cookies.get(SESSION))
            state.update_tokens(session["id"], session["tokens"] | {"exp": now()})
            # The approved receiver and portal both have to recognize the new signing key.
            issuer.key = ec.generate_private_key(ec.SECP256R1())
            issuer.jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(issuer.key.public_key())) | {
                "kid": "next-key",
                "alg": "ES256",
                "use": "sig",
            }
            native_app.state.coordinator.authentication.keys["next-key"] = jwt.PyJWK.from_dict(
                issuer.jwk
            )
            refreshed = await asyncio.gather(*[client.get("/api/tasks") for _ in range(2)])
            assert all(item.status_code == 200 for item in refreshed)
            assert issuer.refresh_count == 1
            assert (await client.post("/auth/logout", headers=headers)).status_code == 200
            assert not issuer.refresh_tokens or state.session(client.cookies.get(SESSION)) is None
            assert (await client.get("/api/tasks")).status_code == 401


@pytest.mark.parametrize(
    ("phase", "when"),
    [("session", "before"), ("session", "after"), ("task", "before"), ("task", "after")],
)
async def test_submission_faults_restore_and_exact_retry(tmp_path, services, phase, when):
    async with harness(tmp_path, services) as (app, settings, transport, issuer, _, native_app, _):
        async with browser_client(app, settings) as client:
            response = await login(client, issuer)
            assert response.status_code == 200, response.text
            data, headers = await composer(client)
            transport.fault = phase, when
            first = await client.post("/api/submissions", json=data, headers=headers)
            assert first.status_code == 503, first.text
            recovery = first.json()["recovery_url"]
            assert (
                await client.post(
                    "/api/submissions", json=data | {"objective": "Changed"}, headers=headers
                )
            ).status_code == 409
            second, duplicate = await asyncio.gather(
                *[client.post("/api/submissions", json=data, headers=headers) for _ in range(2)]
            )
            assert second.status_code in {202, 409}, second.text
            assert duplicate.status_code in {202, 409}, duplicate.text
            recorded = (await client.get("/api" + recovery)).json()
            task = await wait_task(client, recorded["task_url"], "completed")
            assert task.json()["result"]["output"]["disposition"] == "fulfilled"
            store = native_app.state.coordinator.store.db
            assert store.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1
            assert store.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 1
            assert (
                len({key for path, key in transport.operations if path.endswith("/" + phase + "s")})
                == 1
            )
            assert "synthetic checklist" not in "\n".join(app.state.portal.state.db.iterdump())


async def test_clarification_cancellation_unable_and_release_authority(tmp_path, services):
    async with harness(tmp_path, services) as (
        app,
        settings,
        _,
        issuer,
        native_client,
        native_app,
        policy_file,
    ):
        async with browser_client(app, settings) as owner, browser_client(app, settings) as other:
            assert (await login(owner, issuer)).status_code == 200
            assert (await login(other, issuer, "bob")).status_code == 200

            async def start(goal):
                data, headers = await composer(owner, goal)
                started = await owner.post("/api/submissions", json=data, headers=headers)
                assert started.status_code == 202, started.text
                return started.json()["task_url"], headers

            path, headers = await start("Clarify the owner.")
            ready = await wait_task(owner, path, "awaiting_input")
            question = ready.json()["question"]
            payload = {
                "operation_id": "clarification-answer",
                "question_id": question["question_id"],
                "question_revision": question["revision"],
                "answer": "Ada",
            }
            mutation = headers | {"Idempotency-Key": "clarification-answer"}
            stale = await owner.post(
                "/api" + path + "/inputs", json=payload, headers=mutation | {"If-Match": '"1"'}
            )
            assert stale.status_code == 412, stale.text
            conversation_path = path + "/conversation"
            pending = await owner.get("/api" + conversation_path)
            assert pending.json()["title"] == "Clarify the owner"
            assert (await owner.get("/api/tasks")).json()["tasks"][0][
                "title"
            ] == "Clarify the owner"
            paused = pending.json()["work_clock"]
            assert paused["running"] is False and paused["elapsed_ms"] >= 0
            await asyncio.sleep(0.03)
            assert (await owner.get("/api" + conversation_path)).json()["work_clock"] == paused
            assert [turn["kind"] for turn in pending.json()["turns"]] == ["request", "question"]
            store = native_app.state.coordinator.store
            task_id = path.rsplit("/", 1)[1]
            store.add_content_classes(task_id, ["synthetic restricted classification"])
            withheld = await owner.get("/api" + conversation_path)
            assert withheld.status_code == 403
            assert "Clarify the owner." not in withheld.text
            assert (await owner.get("/api/tasks")).json()["tasks"][0]["title"] is None
            store.db.execute(
                "DELETE FROM content_classes WHERE task_id=? AND class=?",
                (task_id, "synthetic restricted classification"),
            )
            result = await owner.post(
                "/api" + path + "/inputs",
                json=payload,
                headers=mutation | {"If-Match": ready.headers["etag"]},
            )
            assert result.status_code == 202, result.text
            complete = await wait_task(owner, path, "completed")
            replay = await owner.post(
                "/api" + path + "/inputs",
                json=payload,
                headers=mutation | {"If-Match": ready.headers["etag"]},
            )
            assert replay.status_code == 202, replay.text
            receipt = complete.json()["result"]["receipt"]
            assert receipt["result_digest"] == digest(
                {k: v for k, v in complete.json()["result"].items() if k != "receipt"}
            )
            events = (await owner.get("/api" + path + "/events")).json()["events"]
            assert [event["sequence"] for event in events] == list(range(1, len(events) + 1))
            assert "awaiting_input" in {event["status"] for event in events}
            transcript = await owner.get("/api" + conversation_path)
            turns = transcript.json()["turns"]
            assert transcript.headers["cache-control"] == "no-store"
            assert transcript.json()["next_after"] is None
            assert [turn["sequence"] for turn in turns] == [1, 2, 3, 4]
            assert [turn["kind"] for turn in turns] == ["request", "question", "reply", "result"]
            assert turns[0]["content"]["objective"] == "Clarify the owner."
            assert turns[1]["content"] == question
            assert turns[2]["content"] == {
                key: payload[key] for key in ("question_id", "question_revision", "answer")
            }
            assert turns[3]["content"] == complete.json()["result"]
            assert (
                turns[3]["work_ms"]
                == transcript.json()["work_clock"]["elapsed_ms"]
                >= paused["elapsed_ms"]
            )
            assert transcript.json()["work_clock"]["running"] is False
            prefix = native_app.state.coordinator.config.document["service"]["base_url"]
            caller = {"Authorization": "Bearer " + issuer.response("alice")["access_token"]}
            first = await native_client.get(
                prefix + conversation_path, params={"limit": 2}, headers=caller
            )
            assert first.json()["turns"] == turns[:2]
            assert first.json()["next_after"] == 2
            rest = await native_client.get(
                prefix + conversation_path, params={"after_sequence": 2, "limit": 2}, headers=caller
            )
            assert rest.json()["turns"] == turns[2:]
            assert rest.json()["next_after"] is None
            assert (await other.get("/api" + path)).status_code == 404
            assert (await other.get("/api" + path + "/events")).status_code == 404
            assert (await other.get("/api" + conversation_path)).status_code == 404
            assert (await other.get("/api/tasks")).json()["tasks"] == []

            # Completion has already won this cancellation race.
            stale_cancel = await owner.post(
                "/api" + path + "/cancel",
                json={"operation_id": "late-cancel"},
                headers=headers
                | {"If-Match": ready.headers["etag"], "Idempotency-Key": "late-cancel"},
            )
            assert stale_cancel.status_code == 412
            assert (await owner.get("/api" + path)).json()["status"] == "completed"

            cancel_path, headers = await start("Cancel the synthetic run.")
            running = await wait_task(owner, cancel_path, "executing")
            stopped = await owner.post(
                "/api" + cancel_path + "/cancel",
                json={"operation_id": "cancel-task"},
                headers=headers
                | {"If-Match": running.headers["etag"], "Idempotency-Key": "cancel-task"},
            )
            assert stopped.status_code == 202, stopped.text
            await wait_task(owner, cancel_path, "cancelled")

            bad_path, _ = await start("Unable to meet the requirement.")
            unable = await wait_task(owner, bad_path, "completed")
            assert unable.json()["result"]["output"]["disposition"] == "unable"

            artifact_path, _ = await start("Artifact from the synthetic executor.")
            artifact_task = await wait_task(owner, artifact_path, "completed")
            (manifest,) = artifact_task.json()["result"]["artifacts"]
            download = "/api" + artifact_path + "/artifacts/" + manifest["artifact_id"]
            response = await owner.get(download)
            assert response.content == b"Synthetic download\n"
            assert response.headers["content-disposition"].startswith("attachment")
            assert (await other.get(download)).status_code == 404

            # Reads use current receiver policy even with the same browser cookie and token.
            policy = json.loads(policy_file.read_text())
            policy["revision"] = "policy-revoked"
            policy["principals"][0]["rules"] = []
            policy_file.write_text(json.dumps(policy))
            assert all(
                item["title"] is None for item in (await owner.get("/api/tasks")).json()["tasks"]
            )
            assert (await owner.get(download)).status_code == 403
            assert (await owner.get("/api" + conversation_path)).status_code == 403
            assert (await owner.get("/api" + artifact_path)).status_code == 403
            assert (await owner.get("/api" + artifact_path + "?view=control")).json()[
                "status"
            ] == "completed"
            cfg = native_app.state.coordinator.config
            client = await native_client.get(
                cfg.document["service"]["base_url"] + artifact_path,
                headers={"Authorization": "Bearer " + token(audience=cfg.service_id)},
            )
            assert client.status_code == 403


async def test_follow_up_native_chain_and_receipt_recovery(tmp_path, services):
    async with harness(tmp_path, services) as (app, settings, transport, issuer, client, native, _):
        async with browser_client(app, settings) as owner, browser_client(app, settings) as other:
            assert (await login(owner, issuer)).status_code == 200
            assert (await login(other, issuer, "bob")).status_code == 200
            initial, headers = await composer(owner)
            initial["run_without_delegation"] = True
            started = await owner.post("/api/submissions", json=initial, headers=headers)
            assert started.status_code == 202, started.text
            path = started.json()["task_url"]
            parent = (await wait_task(owner, path, "completed")).json()
            changed = await owner.post(
                "/api/submissions",
                json=initial | {"run_without_delegation": False},
                headers=headers,
            )
            assert changed.status_code == 409 and changed.json()["code"] == "idempotency_conflict"
            native_base = native.state.coordinator.config.document["service"]["base_url"]
            owner_auth = {"Authorization": "Bearer " + issuer.response("alice")["access_token"]}
            other_auth = {"Authorization": "Bearer " + issuer.response("bob")["access_token"]}
            follow_endpoint = path + "/follow-ups"
            follow, headers = await composer(owner, "Follow up on the previous result.", path)
            blocked = await owner.post("/api" + follow_endpoint, json=follow)
            assert blocked.status_code == 403
            follow_body = {
                "operation_id": "different-follow-up",
                "selection": follow["selection"],
                "input": {
                    "objective": "Follow up again.",
                    "requirements": [
                        {
                            "id": "requirement-1",
                            "description": "Summarize.",
                            "acceptance": ["Summarize."],
                        }
                    ],
                },
            }
            assert (
                await client.post(
                    native_base + follow_endpoint,
                    json=follow_body,
                    headers=other_auth | {"Idempotency-Key": "different"},
                )
            ).status_code == 404

            transport.fault = ("follow-up", "after")
            uncertain = await owner.post("/api" + follow_endpoint, json=follow, headers=headers)
            assert uncertain.status_code == 503, uncertain.text
            recovery = uncertain.json()["recovery_url"]
            await asyncio.sleep(2)
            record = await owner.get("/api" + recovery)
            assert record.json().get("task_url") == path, record.text
            replay = await owner.post("/api" + follow_endpoint, json=follow, headers=headers)
            assert replay.status_code == 202 and replay.json()["task_url"] == path
            assert sum(route.endswith("/follow-ups") for route, _ in transport.operations) == 1
            thread = (await owner.get("/api" + path + "/conversation")).json()
            child_id = thread["latest_task_id"]
            assert child_id != parent["task_id"]
            assert thread["latest_delegation"] == "none"
            child_path = "/tasks/" + child_id
            child = (await wait_task(owner, child_path, "completed")).json()
            assert child["session_id"] == parent["session_id"]
            assert child["result"]["output"]["summary"] == "Used the previous released output."

            stale = await client.post(
                native_base + follow_endpoint,
                json=follow_body,
                headers=owner_auth | {"Idempotency-Key": "different"},
            )
            assert stale.status_code == 409, stale.text
            second = await client.post(
                native_base + child_path + "/follow-ups",
                json=follow_body
                | {
                    "input": {**follow_body["input"], "objective": "Another synthetic turn."},
                    "delegation": "policy",
                },
                headers=owner_auth | {"Idempotency-Key": "different"},
            )
            assert second.status_code == 202, second.text
            latest_id = second.json()["task_id"]
            await wait_task(owner, "/tasks/" + latest_id, "completed")

            turns = []
            after = 0
            while after is not None:
                page = (
                    await client.get(
                        native_base + child_path + "/conversation",
                        params={"after_sequence": after, "limit": 3},
                        headers=owner_auth,
                    )
                ).json()
                assert page["task_id"] == parent["task_id"]
                assert page["title"] == "Write a synthetic checklist"
                assert page["latest_task_id"] == latest_id and page["follow_up_processing"]
                assert page["latest_delegation"] == "policy"
                turns.extend(page["turns"])
                after = page["next_after"]
            assert [(t["task_id"], t["kind"]) for t in turns] == [
                (identifier, kind)
                for identifier in (parent["task_id"], child_id, latest_id)
                for kind in ("request", "result")
            ]
            assert [t["sequence"] for t in turns] == list(range(1, 7))
            assert [t["delegation"] for t in turns if t["kind"] == "request"] == [
                "none",
                "none",
                "policy",
            ]
            assert turns[1]["content"] == parent["result"]
            assert turns[2]["content"]["context"] == follow["context"]
            assert turns[3]["content"] == child["result"]
            assert (await other.get("/api" + child_path + "/conversation")).status_code == 404
            history = (await owner.get("/api/tasks")).json()["tasks"]
            assert [row["task_id"] for row in history] == [parent["task_id"]]


def localhost_certificate(root):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    when = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(when - timedelta(minutes=1))
        .not_valid_after(when + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    private, cert = root / "test.key", root / "test.pem"
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return private, cert


async def test_browser_https_task_flow(tmp_path, services):
    playwright = pytest.importorskip("playwright.async_api")
    chrome = os.getenv("LASA_CHROME") or shutil.which("chromium") or shutil.which("google-chrome")
    if chrome is None:
        mac = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        chrome = str(mac) if mac.is_file() else None
    private, cert = localhost_certificate(tmp_path)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        origin = f"https://127.0.0.1:{port}"
        issuer_url = f"https://localhost:{port}/oidc"
        async with harness(
            tmp_path,
            services,
            origin=origin,
            issuer_url=issuer_url,
            native_url=f"https://localhost:{port}/native/lasa/v1",
            ca=cert,
        ) as (
            app,
            _,
            _,
            issuer,
            native_client,
            native_app,
            _,
        ):

            async def site(scope, receive, send):
                path = scope.get("path", "")
                upstream = (
                    issuer.app
                    if path.startswith("/oidc/")
                    else native_app
                    if path.startswith("/native/")
                    else app
                )
                await upstream(scope, receive, send)

            server = uvicorn.Server(
                uvicorn.Config(
                    site,
                    lifespan="off",
                    access_log=False,
                    log_level="warning",
                    ssl_keyfile=str(private),
                    ssl_certfile=str(cert),
                )
            )
            serving = asyncio.create_task(server.serve(sockets=[listener]))
            try:
                for _ in range(100):
                    if server.started:
                        break
                    await asyncio.sleep(0.025)
                assert server.started
                async with playwright.async_playwright() as tools:
                    browser = await tools.chromium.launch(executable_path=chrome)
                    try:

                        async def sign_in(subject, path="/", width=1100, *, mobile=False):
                            context = await browser.new_context(
                                ignore_https_errors=True,
                                viewport={"width": width, "height": 900},
                                is_mobile=mobile,
                                has_touch=mobile,
                            )
                            page = await context.new_page()
                            await page.goto(origin + path)
                            await page.get_by_role("link", name="Sign in", exact=True).click()
                            await page.get_by_role("link", name="Sign in as " + subject).click()
                            await page.wait_for_url(origin + path)
                            return page

                        async def open_keyboard(page):
                            await page.evaluate(
                                """() => {
                                    Object.defineProperties(visualViewport, {
                                        height: {value: 350, configurable: true},
                                        offsetTop: {value: 30, configurable: true},
                                    });
                                    visualViewport.dispatchEvent(new Event("resize"));
                                }"""
                            )
                            await page.wait_for_function(
                                """() => document.documentElement.style
                                    .getPropertyValue("--task-viewport-height") === "350px" """,
                                timeout=5000,
                            )

                        async def expand_request(page):
                            request_turn = page.locator(
                                '#conversation-turns > li[data-kind="request"]'
                            ).first
                            disclosure = request_turn.get_by_text("Request details", exact=True)
                            width = await request_turn.evaluate(
                                "(turn) => turn.getBoundingClientRect().width"
                            )
                            await disclosure.click()
                            await playwright.expect(
                                request_turn.locator("details")
                            ).to_have_attribute("open", "")
                            assert (
                                await request_turn.evaluate(
                                    "(turn) => turn.getBoundingClientRect().width"
                                )
                                == width
                            )
                            return disclosure

                        page = await sign_in("Alice")
                        single_option = page.get_by_text(
                            "Approved processing · Only available option", exact=True
                        )
                        picker = page.get_by_role("combobox", name="Where can LASA process this?")
                        await single_option.wait_for()
                        assert not await picker.is_visible()

                        # Exercise the chooser with two eligible offers from a simulated catalog.
                        approved = await page.evaluate(
                            "async () => (await (await fetch('/api/offers')).json()).offers[0]"
                        )
                        domain_only = {
                            **approved,
                            "offer_id": "offer-domain-only",
                            "revision": "domain-offer-revision",
                            "processing": {
                                "mode": "provider_domain_only",
                                "domain": "urn:lasa:domain:pilot",
                            },
                        }

                        async def offer_catalog(route):
                            await route.fulfill(json={"offers": [approved, domain_only]})

                        async def accept_selection(route):
                            await route.fulfill(
                                status=400, json={"message": "Simulated submission"}
                            )

                        await page.route("**/api/offers", offer_catalog)
                        await page.route("**/api/submissions", accept_selection, times=1)
                        await page.reload()
                        await picker.wait_for()
                        submit_button = page.get_by_role("button", name="Submit task")
                        assert await submit_button.is_disabled()
                        await picker.select_option(label="Domain only · urn:lasa:domain:pilot")
                        await page.get_by_text(
                            "Processing stays within urn:lasa:domain:pilot.", exact=True
                        ).wait_for()
                        await page.get_by_label("What do you want done?").fill("Test selection.")
                        await page.get_by_label("Requirement 1").fill("Send the exact selection.")
                        async with page.expect_request("**/api/submissions") as posted:
                            await submit_button.click()
                        assert (await posted.value).post_data_json["selection"] == {
                            "offer_id": domain_only["offer_id"],
                            "offer_revision": domain_only["revision"],
                            "catalog_view": domain_only["catalog_view"],
                            "contract": domain_only["contract"],
                        }
                        await playwright.expect(page.get_by_role("alert")).to_have_text(
                            "Simulated submission"
                        )
                        await page.unroute("**/api/offers", offer_catalog)
                        await page.reload()
                        await single_option.wait_for()
                        await page.get_by_label("What do you want done?").fill("Clarify the owner.")
                        await page.get_by_label("Requirement 1").fill("Use the confirmed owner.")
                        await page.get_by_text("Options", exact=True).click()
                        await page.get_by_role("checkbox", name="Run without delegation").check()
                        await page.get_by_text("Add context", exact=True).click()
                        await page.get_by_label("What should LASA use?").fill(
                            "Synthetic context.\n"
                            + "\n".join(f"Inventory line {i}." for i in range(75))
                        )
                        if directory := os.getenv("LASA_PORTAL_SCREENSHOTS"):
                            await page.screenshot(path=str(Path(directory) / "composer.png"))
                        release_history = asyncio.Event()
                        requested_history = asyncio.Event()

                        async def wait_to_load_history(route):
                            requested_history.set()
                            await release_history.wait()
                            await route.continue_()

                        await page.route(
                            "**/conversation?after_sequence=0", wait_to_load_history, times=1
                        )
                        await page.get_by_role("button", name="Submit task").click()
                        await page.wait_for_url("**/tasks/task-*")
                        conversation = page.get_by_role("region", name="Task conversation")
                        try:
                            await asyncio.wait_for(requested_history.wait(), 5)
                            await playwright.expect(
                                page.get_by_role("textbox", name="Message LASA")
                            ).to_be_visible()
                            await playwright.expect(
                                page.get_by_role("button", name="Send follow-up")
                            ).to_be_disabled()
                        finally:
                            release_history.set()
                        await conversation.get_by_role("heading", name="LASA asks").wait_for()
                        await conversation.get_by_text("Supply an owner.", exact=True).wait_for(
                            timeout=15000
                        )
                        header = page.locator(".task-header")
                        assert (await header.bounding_box())["height"] <= 56
                        await playwright.expect(
                            page.locator(".task-dock").get_by_role("button", name="Cancel task")
                        ).to_be_visible()
                        await playwright.expect(
                            conversation.get_by_text(re.compile("^Reply by "))
                        ).to_be_visible()
                        await playwright.expect(page.locator("#progress")).to_be_hidden()
                        await playwright.expect(
                            conversation.get_by_text("Use the confirmed owner.", exact=True)
                        ).to_be_hidden()
                        await expand_request(page)
                        bounds = await conversation.locator("#conversation-turns").evaluate(
                            """(turns) => {
                                const user = turns.querySelector('[data-kind="request"]').getBoundingClientRect();
                                const lasa = turns.querySelector('[data-kind="question"]').getBoundingClientRect();
                                return { userLeft: user.left, userRight: user.right, lasaLeft: lasa.left, lasaRight: lasa.right };
                            }"""
                        )
                        assert bounds["userLeft"] > bounds["lasaLeft"]
                        assert abs(bounds["userRight"] - bounds["lasaRight"]) < 2
                        path = urlsplit(page.url).path
                        desktop_scroll = page.get_by_role("group", name="Conversation history")
                        await desktop_scroll.evaluate("(pane) => { pane.scrollTop = 150; }")
                        jump = page.get_by_role("button", name="Jump to latest")
                        await jump.wait_for()

                        device = await sign_in("Alice", "/tasks", width=390, mobile=True)
                        await device.get_by_role(
                            "link", name=re.compile("Clarify the owner")
                        ).click()
                        await device.get_by_role(
                            "heading", name="Clarify the owner", exact=True
                        ).wait_for()
                        await device.get_by_text("Supply an owner.", exact=True).wait_for()
                        await device.get_by_role("button", name="Tasks", exact=True).click()
                        drawer = device.get_by_role("dialog", name="Tasks")
                        await drawer.wait_for()
                        await drawer.get_by_text("Needs your input", exact=True).wait_for()
                        await device.keyboard.press("Escape")
                        assert await device.get_by_role(
                            "button", name="Tasks", exact=True
                        ).evaluate("(button) => button === document.activeElement")
                        await device.get_by_role("textbox", name="Reply to LASA").fill("Ada")
                        await open_keyboard(device)
                        keyboard = await device.evaluate(
                            """() => {
                                const dock = document.querySelector(".task-dock").getBoundingClientRect();
                                const send = document.querySelector("#answer-submit").getBoundingClientRect();
                                const field = document.querySelector("#answer").getBoundingClientRect();
                                const pane = document.querySelector("#conversation-scroll");
                                return { dock: dock.bottom, dockHeight: dock.height, sendBottom: send.bottom,
                                    fieldTop: field.top, fieldBottom: field.bottom, history: pane.clientHeight,
                                    documentScroll: scrollY };
                            }"""
                        )
                        assert abs(keyboard["dock"] - 380) < 2, keyboard
                        assert keyboard["fieldTop"] >= 30, keyboard
                        assert keyboard["dockHeight"] <= 64, keyboard
                        assert abs(keyboard["fieldBottom"] - keyboard["sendBottom"]) <= 2, keyboard
                        assert keyboard["sendBottom"] <= 380, keyboard
                        assert keyboard["history"] > 60 and keyboard["documentScroll"] == 0, (
                            keyboard
                        )
                        if directory:
                            await device.screenshot(
                                path=str(Path(directory) / "mobile-keyboard.png")
                            )
                        await device.get_by_role("button", name="Reply to LASA").click()
                        await device.get_by_text("Completed bounded work.", exact=True).wait_for(
                            timeout=20000
                        )
                        await page.get_by_text("Completed bounded work.", exact=True).wait_for()
                        assert await desktop_scroll.evaluate("(pane) => pane.scrollTop") == 150
                        await jump.focus()
                        await page.keyboard.press("Enter")
                        await playwright.expect(jump).to_be_hidden()
                        assert await desktop_scroll.evaluate(
                            """(pane) => pane === document.activeElement &&
                                pane.scrollHeight - pane.scrollTop - pane.clientHeight < 2"""
                        )
                        desktop_dock = page.locator(".task-dock")
                        desktop_message = page.get_by_role("textbox", name="Message LASA")
                        await desktop_message.wait_for()
                        idle = (await desktop_dock.bounding_box())["height"]
                        assert 56 <= idle <= 64
                        await desktop_scroll.evaluate("(pane) => { pane.scrollTop = 150; }")
                        await jump.wait_for()
                        await desktop_message.fill("Line\n" * 12)
                        grown = (await desktop_dock.bounding_box())["height"]
                        assert idle < grown <= 160
                        assert await desktop_scroll.evaluate("(pane) => pane.scrollTop") == 150
                        desktop_options = page.get_by_role("button", name="Options", exact=True)
                        await desktop_options.click()
                        await playwright.expect(
                            page.get_by_role("dialog", name="Task options")
                        ).to_be_visible()
                        assert await page.locator("#follow-up-options").evaluate(
                            "(panel) => panel.matches(':popover-open') && !panel.open"
                        )
                        assert (await desktop_dock.bounding_box())["height"] == grown
                        await page.keyboard.press("Escape")
                        await playwright.expect(desktop_options).to_be_focused()
                        await playwright.expect(desktop_message).to_have_value("Line\n" * 12)
                        await desktop_message.fill("")
                        assert (await desktop_dock.bounding_box())["height"] == idle
                        await device.reload()
                        await device.get_by_text("Completed bounded work.", exact=True).wait_for()
                        transcript = device.locator("#conversation-turns > li")
                        assert await transcript.evaluate_all(
                            "(turns) => turns.map(turn => turn.dataset.kind)"
                        ) == ["request", "question", "reply", "result"]
                        for text in (
                            "Clarify the owner.",
                            "Supply an owner.",
                            "Ada",
                        ):
                            await device.get_by_text(text, exact=True).wait_for()
                        assert await device.get_by_role("textbox", name="Reply to LASA").is_hidden()
                        assert urlsplit(device.url).path == path
                        await (await expand_request(device)).click()
                        receipt_turn = transcript.last
                        toggle = receipt_turn.get_by_role(
                            "button", name=re.compile(r"^Worked for ")
                        )
                        details = receipt_turn.locator(".result-details")
                        assert await receipt_turn.evaluate(
                            """(turn) => {
                                const order = [...turn.children];
                                return order.indexOf(turn.querySelector(".result-toggle"))
                                    < order.indexOf(turn.querySelector(".result-answer"))
                                    && order.indexOf(turn.querySelector(".result-answer"))
                                    < order.indexOf(turn.querySelector(".result-details"));
                            }"""
                        )
                        await playwright.expect(
                            receipt_turn.get_by_text("Fulfilled", exact=True)
                        ).to_be_hidden()
                        await playwright.expect(toggle).to_have_attribute("aria-expanded", "false")
                        await toggle.focus()
                        answer_position = await receipt_turn.locator(".result-answer").evaluate(
                            "(answer) => answer.getBoundingClientRect().top"
                        )
                        await device.keyboard.press("Enter")
                        await playwright.expect(toggle).to_have_attribute("aria-expanded", "true")
                        await playwright.expect(details).to_be_visible()
                        assert (
                            await receipt_turn.locator(".result-answer").evaluate(
                                "(answer) => answer.getBoundingClientRect().top"
                            )
                            == answer_position
                        )
                        await device.keyboard.press("Space")
                        await playwright.expect(toggle).to_have_attribute("aria-expanded", "false")
                        await playwright.expect(details).to_be_hidden()
                        await toggle.click()
                        await playwright.expect(
                            receipt_turn.get_by_text("Fulfilled", exact=True)
                        ).to_be_visible()
                        await receipt_turn.get_by_text("Technical receipt", exact=True).click()
                        await device.get_by_text('"result_digest"', exact=False).wait_for()
                        if directory:
                            await device.screenshot(
                                path=str(Path(directory) / "completed-mobile.png")
                            )
                        message = device.get_by_label("Message LASA")
                        await message.fill("Follow up from the message composer.")
                        await playwright.expect(device.get_by_label("Requirement 1")).to_be_hidden()
                        send = device.get_by_role("button", name="Send follow-up")
                        options = device.get_by_role("button", name="Options", exact=True)
                        delegation_choice = device.get_by_role(
                            "checkbox", name="Run without delegation"
                        )
                        await options.click()
                        await playwright.expect(delegation_choice).to_be_checked()
                        await device.get_by_role("button", name="Done").click()
                        await message.evaluate("(field) => { window.originalComposer = field; }")
                        async with device.expect_request("**/follow-ups") as initial_post:
                            await send.click()
                        clock = device.locator("#task-elapsed")
                        await clock.wait_for()
                        assert await message.evaluate(
                            "(field) => window.originalComposer === field"
                        )
                        await playwright.expect(message).to_have_value("")
                        dock = device.locator(".task-dock")
                        await playwright.expect(
                            dock.get_by_role("button", name="Cancel task")
                        ).to_be_visible()
                        await playwright.expect(
                            device.locator(".task-header #progress, .task-header #cancel")
                        ).to_have_count(0)
                        await playwright.expect(clock).to_have_text(
                            re.compile(r"^[1-9]\d*s$"), timeout=3500
                        )
                        draft = "An unsent follow-up draft."
                        await message.fill(draft)
                        await playwright.expect(send).to_be_disabled()
                        await options.click()
                        await playwright.expect(delegation_choice).to_be_checked()
                        await device.get_by_label("Requirement 1").fill(
                            "Use the preceding released output."
                        )
                        await device.get_by_role("button", name="Done").click()
                        activity = dock.locator("#progress summary")
                        label = activity.get_by_text("Activity", exact=True)
                        assert (await label.bounding_box())["width"] >= 36
                        await activity.click()
                        await playwright.expect(dock.locator(".timeline li")).to_have_text(
                            ["Checking request", "Accepted", "Running"]
                        )
                        await device.get_by_text(
                            "Confirm the follow-up label.", exact=True
                        ).wait_for()
                        await playwright.expect(message).to_be_hidden()
                        await playwright.expect(dock.locator("#progress")).to_be_hidden()
                        await device.get_by_role("textbox", name="Reply to LASA").fill("Orchid")
                        await device.get_by_role("button", name="Reply to LASA").click()
                        await device.get_by_text(
                            "Used the previous released output.", exact=True
                        ).wait_for(timeout=20000)
                        await playwright.expect(clock).to_be_hidden()
                        await playwright.expect(message).to_have_value(draft)
                        await playwright.expect(send).to_be_enabled()
                        await playwright.expect(
                            device.get_by_role("button", name="Jump to latest")
                        ).to_be_hidden()
                        follow_result = device.locator('[data-kind="result"]').last
                        await playwright.expect(
                            follow_result.locator(".result-toggle")
                        ).to_have_text(re.compile(r"^Worked for [1-9]\d*s$"))
                        await playwright.expect(
                            follow_result.get_by_text("Acceptance checks", exact=True)
                        ).to_be_hidden()
                        request_turn = transcript.nth(4)
                        await request_turn.get_by_text("Request details", exact=True).click()
                        await playwright.expect(
                            request_turn.get_by_text("Run without delegation", exact=True)
                        ).to_be_visible()
                        await playwright.expect(transcript).to_have_count(8)
                        await follow_result.locator(".result-toggle").click()
                        await playwright.expect(follow_result.locator(".timeline li")).to_have_text(
                            [
                                "Checking request",
                                "Accepted",
                                "Running",
                                "Needs your input",
                                "Running",
                                "Completed",
                            ]
                        )
                        await follow_result.locator(".result-toggle").click()
                        snapshot = await device.evaluate(
                            """async () => {
                                const page = await (await fetch('/api' + location.pathname + '/conversation?after_sequence=4')).json();
                                return page.turns;
                            }"""
                        )
                        assert (
                            snapshot[0]["content"]["requirements"][0]["id"]
                            == "respond-to-follow-up"
                        )
                        assert "context" not in snapshot[0]["content"]
                        assert snapshot[0]["delegation"] == "none"
                        await message.fill("Follow up on the result.")
                        await playwright.expect(send).to_be_enabled()
                        await options.click()
                        sheet = device.get_by_role("dialog", name="Task options")
                        await playwright.expect(sheet).to_be_visible()
                        await delegation_choice.uncheck()
                        assert await sheet.evaluate("(panel) => panel.matches(':modal')")
                        await open_keyboard(device)
                        await playwright.expect(device.get_by_label("Requirement 1")).to_have_value(
                            "Use the preceding released output."
                        )
                        await device.get_by_label("Requirement 1").focus()
                        await device.wait_for_function(
                            """() => {
                                const fields = document.querySelector("#follow-up-options .options-fields");
                                const bounds = fields.getBoundingClientRect();
                                const input = document.activeElement.getBoundingClientRect();
                                const sheet = document.querySelector("#follow-up-options").getBoundingClientRect();
                                const done = document.querySelector("#options-close").getBoundingClientRect();
                                return input.top >= bounds.top && input.bottom <= bounds.bottom
                                    && Math.abs(sheet.bottom - 380) < 2 && done.bottom < 380;
                            }""",
                            timeout=5000,
                        )
                        await sheet.get_by_role("button", name="Done").click()
                        await playwright.expect(sheet).to_be_hidden()
                        await playwright.expect(options).to_be_focused()
                        await playwright.expect(message).to_have_value("Follow up on the result.")

                        async def drop_follow_up_ack(route):
                            response = await route.fetch()
                            assert response.status == 202
                            await route.abort("failed")

                        await device.route("**/follow-ups", drop_follow_up_ack, times=1)
                        async with device.expect_request("**/follow-ups") as unconfirmed_post:
                            await send.click()
                        recovery = device.get_by_role("link", name="Check original submission")
                        await playwright.expect(recovery).to_be_visible()
                        await playwright.expect(message).to_have_value("Follow up on the result.")
                        first_payload = (await initial_post.value).post_data_json
                        uncertain_payload = (await unconfirmed_post.value).post_data_json
                        assert uncertain_payload["ticket"] != first_payload["ticket"]
                        async with device.expect_request("**/follow-ups") as repeated_post:
                            await send.click()
                        assert (await repeated_post.value).post_data_json == uncertain_payload
                        await playwright.expect(
                            device.get_by_text("Used the previous released output.", exact=True)
                        ).to_have_count(2, timeout=20000)
                        assert await message.evaluate(
                            "(field) => window.originalComposer === field"
                        )
                        await playwright.expect(recovery).to_be_hidden()
                        assert urlsplit(device.url).path == path
                        await device.reload()
                        await playwright.expect(
                            device.get_by_role("heading", name="You followed up")
                        ).to_have_count(2)
                        await options.click()
                        await playwright.expect(delegation_choice).not_to_be_checked()
                        await sheet.get_by_role("button", name="Done").click()
                        assert await device.locator("#conversation-turns > li").count() == 10
                        await playwright.expect(
                            device.get_by_role("heading", name="Clarify the owner", exact=True)
                        ).to_be_visible()
                        await device.goto(origin + "/new")
                        await device.get_by_label("What do you want done?").fill(
                            "Unable to meet the requirement."
                        )
                        await device.get_by_label("Requirement 1").fill(
                            "Include a validated owner."
                        )
                        await device.get_by_role("button", name="Submit task").click()
                        unable_turn = device.locator('#conversation-turns li[data-kind="result"]')
                        await playwright.expect(
                            unable_turn.get_by_role("heading", name="Unable to fulfill")
                        ).to_be_visible()
                        await playwright.expect(
                            unable_turn.get_by_text("Missing necessary evidence.")
                        ).to_be_visible()
                        await playwright.expect(
                            unable_turn.get_by_text("Include a validated owner.", exact=True)
                        ).to_be_visible()
                        await playwright.expect(
                            unable_turn.get_by_text("requirement-1", exact=True)
                        ).to_have_count(0)
                        native_client.headers["Authorization"] = (
                            "Bearer " + issuer.response("alice")["access_token"]
                        )
                        review = await task_request(
                            native_client,
                            native_app,
                            profile="design.review",
                            inputs={
                                "design": "The design needs an assigned owner.",
                                "criteria": [
                                    {"id": "owner-check", "description": "Check ownership."}
                                ],
                            },
                        )
                        released = await settled(
                            native_client, await submit(native_client, native_app, review)
                        )
                        await device.goto(origin + "/tasks/" + released["task_id"])
                        await device.get_by_role(
                            "heading", name="Check ownership", exact=True
                        ).wait_for()
                        result_turn = device.locator('#conversation-turns li[data-kind="result"]')
                        await playwright.expect(
                            result_turn.get_by_role("heading", name="Findings")
                        ).to_be_visible()
                        await playwright.expect(
                            result_turn.get_by_text("Assign the on-call coordinator.", exact=True)
                        ).to_be_visible()
                        await playwright.expect(
                            result_turn.get_by_role("heading", name="Review coverage")
                        ).to_be_hidden()
                        await playwright.expect(message).to_be_visible()
                        await playwright.expect(send).to_be_disabled()
                        second = await sign_in("Bob", path)
                        await second.get_by_text("That task or resource is unavailable.").wait_for()
                        await second.goto(origin + "/tasks")
                        await second.get_by_text("Your tasks will appear here.").wait_for()
                    finally:
                        await browser.close()
            finally:
                await app.state.portal.native.http.aclose()
                await app.state.portal.issuer.http.aclose()
                server.should_exit = True
                await asyncio.wait_for(serving, 5)


async def test_separate_volume_restart_and_backup_restore(tmp_path, services):
    async with harness(tmp_path, services) as (
        app,
        settings,
        transport,
        issuer,
        _,
        native_app,
        policy,
    ):
        async with browser_client(app, settings) as client:
            assert (await login(client, issuer)).status_code == 200
            data, headers = await composer(client)
            changed = data | {"selection": data["selection"] | {"offer_revision": "expired-offer"}}
            assert (await client.post("/api/submissions", json=changed, headers=headers)).json()[
                "code"
            ] == "offer_changed"
            transport.fault = "task", "after"
            first = await client.post("/api/submissions", json=data, headers=headers)
            assert first.status_code == 503, first.text
            recovery = first.json()["recovery_url"]
            cookies = httpx.Cookies(client.cookies)
            portal_backup = tmp_path / "portal-backup"
            portal_backup.mkdir()
            with sqlite3.connect(portal_backup / "portal.sqlite3") as backup:
                app.state.portal.state.db.backup(backup)
    await asyncio.sleep(2.1)

    def portal_for(directory, native):
        return create_app(
            replace(settings, state_dir=str(directory)),
            native_transport=Transport(native),
            issuer_transport=httpx.ASGITransport(app=issuer.app),
        )

    restarted = portal_for(settings.state_dir, native_app)
    async with (
        restarted.router.lifespan_context(restarted),
        browser_client(restarted, settings) as resumed,
    ):
        resumed.cookies.update(cookies)
        recovered = (await resumed.get("/api" + recovery)).json()
        assert recovered["state"] == "recorded", recovered
        path = recovered["task_url"]
        completed = (await wait_task(resumed, path, "completed")).json()

    coordinator = native_app.state.coordinator
    native_backup = tmp_path / "native-backup"
    native_backup.mkdir()
    private_root = native_backup / "private"
    private_root.mkdir()
    with sqlite3.connect(private_root / "tasks.sqlite3") as db:
        coordinator.store.db.backup(db)
    shutil.copytree(coordinator.config.workspace_root, native_backup / "workspaces")
    raw = documents(tmp_path / "native-restore-config")
    raw["authorization"]["policy_file"] = str(policy)
    raw["storage"]["state_root"] = str(native_backup)
    _, restored_native = await services(raw=raw, runtime=FakeRuntime(execute))
    assert (
        restored_native.state.coordinator.config.workspace_root / completed["session_id"]
    ).is_dir()

    Path(settings.ticket_key_file).write_text(secrets.token_hex(32))
    restored = portal_for(portal_backup, restored_native)
    async with (
        restored.router.lifespan_context(restored),
        browser_client(restored, settings) as resumed,
    ):
        resumed.cookies.update(cookies)
        assert (await resumed.get("/api" + recovery)).json()["task_url"] == path
        assert (await resumed.get("/api" + path)).json()["result"]["receipt"] == completed[
            "result"
        ]["receipt"]
        assert (await resumed.post("/api/submissions", json=data, headers=headers)).json()[
            "code"
        ] == "ticket_expired"
