"""Local verdict-only HTTPS gateway for Presidio and Betterleaks."""

import argparse
import asyncio
import json
import logging
import os
import re
import secrets
import subprocess
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI, Request, Response
from starlette.requests import ClientDisconnect

from lasa_service.content_security import MAX_INSPECTION_REQUEST_BYTES, PROJECTION_FIELDS
from lasa_service.contracts import canonical, digest, parse_json, protocol_contracts
from lasa_service.errors import LasaError

MAX_SCAN_BYTES = 128 * 1024
MAX_ANALYSIS_BYTES = 256 * 1024
SCAN_TIMEOUT = 1.5
PII_ENTITIES = ("CREDIT_CARD", "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN")
PII_THRESHOLD = 0.5
BETTERLEAKS = "/usr/bin/betterleaks"
LEAK_FOUND = 42
ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", re.ASCII)
MEDIA_TYPES = {"application/json", "text/plain", "text/markdown", "text/event-stream"}
AUDIT = logging.getLogger("uvicorn.error")


def projection_text(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield key
            yield from projection_text(value)
    elif isinstance(node, list):
        for value in node:
            yield from projection_text(value)


async def scan_pii(presidio, text):
    try:
        async with asyncio.timeout(SCAN_TIMEOUT):
            async with presidio.stream(
                "POST",
                "/analyze",
                json={
                    "text": text,
                    "language": "en",
                    "entities": PII_ENTITIES,
                    "score_threshold": PII_THRESHOLD,
                },
            ) as reply:
                reply.raise_for_status()
                data = bytearray()
                async for chunk in reply.aiter_bytes():
                    if len(data) + len(chunk) > MAX_ANALYSIS_BYTES:
                        return None
                    data.extend(chunk)
            findings = parse_json(data)
        if not isinstance(findings, list) or any(
            not isinstance(finding, dict)
            or finding.get("entity_type") not in PII_ENTITIES
            or type(finding.get("score")) not in (int, float)
            or not PII_THRESHOLD <= finding["score"] <= 1
            for finding in findings
        ):
            return None
        return bool(findings)
    except (TimeoutError, httpx.HTTPError, LasaError):
        return None


def scan_credentials(data):
    try:
        run = subprocess.run(
            [BETTERLEAKS, "stdin", "--exit-code", str(LEAK_FOUND), "--ignore-gitleaks-allow"],
            input=data,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd="/",
            env={},
            timeout=SCAN_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if run.returncode in (0, LEAK_FOUND):
        return run.returncode == LEAK_FOUND
    return None


async def inspect(presidio, content):
    wire = canonical(content)
    if len(wire) > MAX_SCAN_BYTES:
        return "indeterminate", ["scan_size_limit"]
    text = "\n".join(projection_text(content))
    # Include both structured assignments and decoded strings such as multiline PEM blocks.
    credentials = wire + b"\n" + text.encode()
    pii, secret = await asyncio.gather(
        scan_pii(presidio, text), asyncio.to_thread(scan_credentials, credentials)
    )
    reasons = []
    for result, detected, unavailable in (
        (pii, "pii_detected", "presidio_unavailable"),
        (secret, "credential_detected", "betterleaks_unavailable"),
    ):
        if result is True:
            reasons.append(detected)
        elif result is None:
            reasons.append(unavailable)
    if pii or secret:
        return "hard_deny", reasons
    if reasons:
        return "indeterminate", reasons
    return "permit", reasons


async def read_request(request, contracts):
    if (
        request.headers.get("content-type") != "application/json"
        or "content-encoding" in request.headers
    ):
        raise LasaError("unsupported_media_type", 415)
    body = bytearray()
    try:
        async with asyncio.timeout(2):
            async for chunk in request.stream():
                if len(body) + len(chunk) > MAX_INSPECTION_REQUEST_BYTES:
                    raise LasaError("inspection_limit", 413)
                body.extend(chunk)
    except (TimeoutError, ClientDisconnect):
        raise LasaError("incomplete_inspection", 400) from None
    document = contracts.validate("ContentInspectionRequest", parse_json(body))
    if (
        document["media_type"] not in MEDIA_TYPES
        or document["content"].keys() - PROJECTION_FIELDS[document["channel"]]
        or digest(document["content"]) != document["inspection_digest"]
    ):
        raise LasaError("invalid_inspection", 400)
    return document


def create_app(*, token, gateway_id, policy_revision, presidio_url, transport=None):
    expected_auth = b"Bearer " + token
    contracts = protocol_contracts()

    @asynccontextmanager
    async def lifespan(app):
        async with httpx.AsyncClient(
            base_url=presidio_url,
            transport=transport,
            trust_env=False,
            follow_redirects=False,
            timeout=SCAN_TIMEOUT,
        ) as presidio:
            app.state.presidio = presidio
            yield

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    def authenticated(request):
        values = request.headers.getlist("authorization")
        return len(values) == 1 and secrets.compare_digest(
            values[0].encode("latin-1"), expected_auth
        )

    @app.get("/health/ready")
    async def ready(request: Request):
        if not authenticated(request):
            return Response(status_code=401)
        try:
            async with asyncio.timeout(SCAN_TIMEOUT):
                async with app.state.presidio.stream("GET", "/health") as reply:
                    healthy = reply.status_code == 200 and os.access(BETTERLEAKS, os.X_OK)
        except (TimeoutError, httpx.HTTPError):
            healthy = False
        if not healthy:
            return Response(status_code=503)
        return {"gateway_id": gateway_id, "policy_revision": policy_revision}

    @app.post("/inspect")
    async def inspect_content(request: Request):
        if not authenticated(request):
            return Response(status_code=401)
        try:
            document = await read_request(request, contracts)
        except LasaError as error:
            return Response(status_code=error.status)
        if document["gateway_policy_revision"] != policy_revision:
            return Response(status_code=409)
        verdict, reasons = await inspect(app.state.presidio, document["content"])
        response = {
            "version": "1",
            "gateway_id": gateway_id,
            "gateway_policy_revision": policy_revision,
            "inspection_id": document["inspection_id"],
            "inspection_digest": document["inspection_digest"],
            "verdict": verdict,
            "reason_codes": reasons,
        }
        AUDIT.info("inspection %s", json.dumps(response, separators=(",", ":")))
        return response

    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway-id", required=True)
    parser.add_argument("--policy-revision", required=True)
    parser.add_argument("--presidio-url", required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--tls-cert", type=Path, required=True)
    parser.add_argument("--tls-key", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()
    if not all(ID_PATTERN.fullmatch(value) for value in (args.gateway_id, args.policy_revision)):
        parser.error("Invalid gateway ID or policy revision")
    url = httpx.URL(args.presidio_url)
    if (
        url.scheme not in {"http", "https"}
        or not url.host
        or url.userinfo
        or url.path != "/"
        or url.query
        or url.fragment
    ):
        parser.error("Presidio URL must be an HTTP or HTTPS origin")
    try:
        token = args.token_file.read_bytes().strip()
    except OSError:
        parser.error("Cannot read the inspection token file")
    if len(token) < 32 or not re.fullmatch(rb"[\x21-\x7e]+", token):
        parser.error("Use an inspection token of at least 32 printable ASCII bytes without spaces")
    uvicorn.run(
        create_app(
            token=token,
            gateway_id=args.gateway_id,
            policy_revision=args.policy_revision,
            presidio_url=url,
        ),
        host="0.0.0.0",
        port=args.port,
        ssl_certfile=str(args.tls_cert),
        ssl_keyfile=str(args.tls_key),
        access_log=False,
        proxy_headers=False,
        limit_concurrency=16,
    )


if __name__ == "__main__":
    main()
