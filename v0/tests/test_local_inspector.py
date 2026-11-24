import json
from contextlib import asynccontextmanager
from subprocess import CompletedProcess, TimeoutExpired

import httpx
import pytest

from inspector import server
from lasa_service.contracts import digest

TOKEN = "synthetic-inspection-token-for-tests"
AUTH = {"Authorization": "Bearer " + TOKEN}


def inspection(content=None, **overrides):
    if content is None:
        content = {"input": ["Synthetic text", {"client_key": "sample\ntext"}]}
    return {
        "version": "1",
        "inspection_id": "inspection-test",
        "binding_revision": digest({"mode": "enforce"}),
        "policy_revision": digest({}),
        "gateway_policy_revision": "english-dlp-v1",
        "channel": "reasoning.request",
        "purpose": "execution",
        "media_type": "application/json",
        "inspection_digest": digest(content),
        "content": content,
        **overrides,
    }


@pytest.fixture
def inspector_client():
    @asynccontextmanager
    async def connect(analyze):
        app = server.create_app(
            token=TOKEN.encode(),
            gateway_id="local-dlp",
            policy_revision="english-dlp-v1",
            presidio_url="http://presidio.test",
            transport=httpx.MockTransport(analyze),
        )
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="https://inspection.test"
            ) as client,
        ):
            yield client

    return connect


async def test_health_requires_authentication_and_reports_pins(inspector_client, monkeypatch):
    def health(request):
        assert request.url.path == "/health"
        return httpx.Response(200)

    monkeypatch.setattr(server.os, "access", lambda *_: True)
    async with inspector_client(health) as client:
        assert (await client.get("/health/ready")).status_code == 401
        response = await client.get("/health/ready", headers=AUTH)
    assert response.status_code == 200
    assert response.json() == {"gateway_id": "local-dlp", "policy_revision": "english-dlp-v1"}


async def test_bad_envelopes_never_reach_detectors(inspector_client, monkeypatch):
    def unexpected(_):
        pytest.fail("Malformed or unauthorized request reached a detector")

    monkeypatch.setattr(server, "scan_credentials", unexpected)
    async with inspector_client(unexpected) as client:
        assert (await client.post("/inspect", json=inspection())).status_code == 401
        for document, expected in (
            (inspection(inspection_digest=digest({})), 400),
            (inspection(content={"instructions": "private"}), 400),
            (inspection(version="2"), 400),
            (inspection(gateway_policy_revision="other-revision"), 409),
        ):
            reply = await client.post("/inspect", json=document, headers=AUTH)
            assert reply.status_code == expected
            assert reply.content == b""
        reply = await client.post(
            "/inspect",
            json=inspection(content={"input": "a" * server.MAX_SCAN_BYTES}),
            headers=AUTH,
        )
        assert reply.json()["reason_codes"] == ["scan_size_limit"]
        assert reply.json()["verdict"] == "indeterminate"


@pytest.mark.parametrize(
    ("analysis", "scanner_exit", "verdict", "reasons"),
    [
        ([], 0, "permit", []),
        ([{"entity_type": "EMAIL_ADDRESS", "score": 0.8}], 0, "hard_deny", ["pii_detected"]),
        ([], 42, "hard_deny", ["credential_detected"]),
        ([], 2, "indeterminate", ["betterleaks_unavailable"]),
        ({"invalid": True}, 0, "indeterminate", ["presidio_unavailable"]),
        (None, 42, "hard_deny", ["presidio_unavailable", "credential_detected"]),
    ],
)
async def test_detector_verdicts_are_bounded_and_bound_to_the_request(
    inspector_client, monkeypatch, analysis, scanner_exit, verdict, reasons
):
    def analyze(request):
        assert request.method == "POST" and request.url.path == "/analyze"
        assert "authorization" not in request.headers
        assert json.loads(request.content) == {
            "text": "input\nSynthetic text\nclient_key\nsample\ntext",
            "language": "en",
            "entities": list(server.PII_ENTITIES),
            "score_threshold": 0.5,
        }
        return httpx.Response(503 if analysis is None else 200, json=analysis)

    def run(command, **options):
        assert "--ignore-gitleaks-allow" in command and "--validation" not in command
        assert options["timeout"] < 2 and options["env"] == {}
        assert options["stdout"] == options["stderr"] == server.subprocess.DEVNULL
        assert b'"client_key":"sample\\ntext"' in options["input"]
        assert options["input"].endswith(b"sample\ntext")
        return CompletedProcess(command, scanner_exit)

    monkeypatch.setattr(server.subprocess, "run", run)
    document = inspection()
    async with inspector_client(analyze) as client:
        reply = await client.post("/inspect", json=document, headers=AUTH)
    assert reply.status_code == 200
    assert reply.json() == {
        "version": "1",
        "gateway_id": "local-dlp",
        "gateway_policy_revision": document["gateway_policy_revision"],
        "inspection_id": document["inspection_id"],
        "inspection_digest": document["inspection_digest"],
        "verdict": verdict,
        "reason_codes": reasons,
    }


def test_betterleaks_timeout_is_indeterminate(monkeypatch):
    def expired(command, **options):
        raise TimeoutExpired(command, options["timeout"])

    monkeypatch.setattr(server.subprocess, "run", expired)
    assert server.scan_credentials(b"synthetic") is None
