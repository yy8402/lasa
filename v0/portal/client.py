"""Trusted identity provider and native LASA HTTP clients."""

import asyncio
import base64
import hashlib
import hmac
import re
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path

import httpx
import jwt
from authlib.integrations.base_client import OAuthError
from authlib.integrations.httpx_client import AsyncOAuth2Client

from lasa_service.contracts import (
    DELEGATION_MODES,
    digest,
    parse_json,
    protocol_contracts,
    validate_data,
)
from lasa_service.errors import LasaError

from .config import PortalError, https_url
from .state import now

ATTEMPT = parse_json(
    files("lasa_contracts").joinpath("examples/capability-attempt.json").read_bytes()
)
ATTEMPT_REF = {key: ATTEMPT[key] for key in ("id", "version")} | {"digest": digest(ATTEMPT)}
RESOURCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}")
JWT_ALGORITHMS = {"RS256", "ES256", "EdDSA"}
NATIVE_PROTOCOL = "lasa/1.0.0"
REQUIRED_OPERATIONS = {
    "/tasks": "get",
    "/tasks/{task_id}": "get",
    "/tasks/{task_id}/conversation": "get",
    "/tasks/{task_id}/follow-ups": "post",
    "/tasks/{task_id}/events": "get",
    "/sessions": "post",
    "/sessions/{session_id}/tasks": "post",
    "/operations/{operation_id}": "get",
    "/tasks/{task_id}/inputs": "post",
    "/tasks/{task_id}/cancel": "post",
    "/tasks/{task_id}/artifacts/{artifact_id}": "get",
}
MESSAGES = {
    "not_found": "That task or resource is unavailable.",
    "authority_denied": "You do not have access to this content.",
    "disclosure_denied": "The current release policy restricts this content.",
    "offer_changed": "Review the current offer before submitting again.",
    "catalog_changed": "Review the current offers before submitting again.",
    "stale_revision": "The task changed. Review its current state.",
    "task_state_conflict": "This action is no longer available for the task.",
    "precondition_required": "Refresh the current task before continuing.",
    "capacity_exhausted": "LASA is busy. Try again shortly.",
    "idempotency_conflict": "This submission already has different input.",
    "invalid_input": "LASA could not accept this input.",
    "deadline_exceeded": "The task exceeded its deadline.",
    "verification_failed": "LASA could not verify the result.",
    "processing_unavailable": "The selected processing guarantee is currently unavailable.",
    "outcome_unknown": "LASA could not confirm the outcome.",
    "service_unavailable": "LASA is temporarily unavailable.",
}


def resource(value):
    if not isinstance(value, str) or not RESOURCE_ID.fullmatch(value):
        raise PortalError(404, "not_found", "That resource is unavailable.")
    return value


def epoch(value):
    return datetime.fromisoformat(value).astimezone(UTC).timestamp()


def validated(name, value):
    try:
        return protocol_contracts().validate(name, value)
    except LasaError:
        raise PortalError(502, "native_protocol", "LASA returned an invalid response.") from None


async def bounded_response(client, method, url, *, limit, seconds, **kwargs):
    async with asyncio.timeout(seconds), client.stream(method, url, **kwargs) as result:
        data = bytearray()
        async for chunk in result.aiter_bytes():
            if len(data) + len(chunk) > limit:
                raise PortalError(502, "upstream_size", "The upstream response exceeded its limit.")
            data.extend(chunk)
        headers = {
            key: value
            for key, value in result.headers.items()
            if key not in {"content-encoding", "content-length"}
        }
        return httpx.Response(
            result.status_code, headers=headers, content=bytes(data), request=result.request
        )


def json_document(response):
    try:
        return parse_json(response.content)
    except LasaError:
        raise PortalError(502, "native_protocol", "The upstream response was invalid.") from None


class IdentityProvider:
    def __init__(self, settings, http, *, transport=None):
        self.settings = settings
        self.http = http
        self.transport = transport
        self.secret = Path(settings.client_secret_file).read_text().strip()
        if not self.secret:
            raise ValueError("The portal OAuth client secret is empty")
        self.origin = https_url(settings.issuer).netloc

    async def metadata(self):
        try:
            result = await bounded_response(
                self.http,
                "GET",
                self.settings.issuer + "/.well-known/openid-configuration",
                limit=65536,
                seconds=self.settings.timeout_seconds,
            )
            if result.status_code != 200:
                raise ValueError()
            config = json_document(result)
            if config["issuer"] != self.settings.issuer or "S256" not in config.get(
                "code_challenge_methods_supported", []
            ):
                raise ValueError()
            for key in (
                "authorization_endpoint",
                "token_endpoint",
                "jwks_uri",
                "revocation_endpoint",
            ):
                if key == "revocation_endpoint" and key not in config:
                    continue
                if https_url(config[key]).netloc != self.origin:
                    raise ValueError()
            return config
        except (httpx.HTTPError, TimeoutError, KeyError, TypeError, ValueError, PortalError):
            raise PortalError(
                503, "issuer_unavailable", "Sign-in is temporarily unavailable."
            ) from None

    def oauth(self):
        return AsyncOAuth2Client(
            self.settings.client_id,
            self.secret,
            scope=self.settings.scope,
            redirect_uri=self.settings.callback,
            code_challenge_method="S256",
            token_endpoint_auth_method="client_secret_basic",
            verify=self.settings.tls_context(),
            transport=self.transport,
            trust_env=False,
            follow_redirects=False,
            timeout=self.settings.timeout_seconds,
        )

    async def login_url(self, transaction):
        metadata = await self.metadata()
        async with self.oauth() as oauth:
            url, _ = oauth.create_authorization_url(
                metadata["authorization_endpoint"],
                state=transaction["state"],
                code_verifier=transaction["verifier"],
                nonce=transaction["nonce"],
                **{self.settings.audience_parameter: self.settings.lasa_service_id},
            )
        return url

    async def keys(self, metadata):
        response = await bounded_response(
            self.http,
            "GET",
            metadata["jwks_uri"],
            limit=65536,
            seconds=self.settings.timeout_seconds,
        )
        response.raise_for_status()
        return json_document(response)["keys"]

    def verify(self, token, keys, audience, *, access=False):
        if not isinstance(token, str) or len(token) > 16384:
            raise ValueError()
        header = jwt.get_unverified_header(token)
        alg = header["alg"]
        if alg not in JWT_ALGORITHMS or any(k in header for k in ("jku", "x5u", "crit")):
            raise ValueError()
        matching = [
            key
            for key in keys
            if key.get("kid") == header["kid"]
            and key.get("alg", alg) == alg
            and key.get("use", "sig") == "sig"
        ]
        if len(matching) != 1:
            raise ValueError()
        claims = jwt.decode(
            token,
            jwt.PyJWK.from_dict(matching[0], algorithm=alg).key,
            algorithms=[alg],
            issuer=self.settings.issuer,
            audience=audience,
            options={
                "require": ["iss", "aud", "sub", "iat", "exp", *(["jti"] if access else [])],
                "strict_aud": access,
            },
        )
        if (
            not isinstance(claims["sub"], str)
            or not claims["sub"]
            or type(claims["exp"]) is not int
        ):
            raise ValueError()
        return claims, alg

    def access_tokens(self, values, keys, subject, prior_refresh=None):
        if values.get("token_type", "").lower() != "bearer":
            raise ValueError()
        claims, _ = self.verify(
            values["access_token"], keys, self.settings.lasa_service_id, access=True
        )
        if claims["sub"] != subject:
            raise ValueError()
        refresh = values.get("refresh_token", prior_refresh)
        if refresh is not None and (not isinstance(refresh, str) or len(refresh) > 32768):
            raise ValueError()
        return {
            "access": values["access_token"],
            "refresh": refresh,
            "exp": claims["exp"],
            "sub": subject,
        }

    async def exchange(self, transaction, code):
        metadata = await self.metadata()
        try:
            async with asyncio.timeout(self.settings.timeout_seconds), self.oauth() as oauth:
                values = await oauth.fetch_token(
                    metadata["token_endpoint"],
                    grant_type="authorization_code",
                    code=code,
                    code_verifier=transaction["verifier"],
                    **{self.settings.audience_parameter: self.settings.lasa_service_id},
                )
            keys = await self.keys(metadata)
            claims, algorithm = self.verify(values["id_token"], keys, self.settings.client_id)
            if claims.get("nonce") != transaction["nonce"] or (
                ("azp" in claims or (isinstance(claims["aud"], list) and len(claims["aud"]) > 1))
                and claims.get("azp") != self.settings.client_id
            ):
                raise ValueError()
            if at_hash := claims.get("at_hash"):
                hashed = jwt.get_algorithm_by_name(algorithm).compute_hash_digest(
                    values["access_token"].encode()
                )
                expected = (
                    base64.urlsafe_b64encode(hashed[: len(hashed) // 2]).rstrip(b"=").decode()
                )
                if not hmac.compare_digest(at_hash, expected):
                    raise ValueError()
            if claim := self.settings.assignment_claim:
                assigned = claims.get(claim)
                if self.settings.assignment_value not in (
                    assigned if isinstance(assigned, list) else [assigned]
                ):
                    raise ValueError()
            return self.access_tokens(values, keys, claims["sub"])
        except (
            OAuthError,
            httpx.HTTPError,
            TimeoutError,
            ValueError,
            TypeError,
            KeyError,
            jwt.PyJWTError,
            NotImplementedError,
        ):
            raise PortalError(
                403, "sign_in_denied", "LASA could not verify this sign-in."
            ) from None

    async def refresh(self, tokens):
        metadata = await self.metadata()
        if not tokens["refresh"]:
            raise PortalError(401, "sign_in_required", "Sign in again to continue.")
        try:
            async with asyncio.timeout(self.settings.timeout_seconds), self.oauth() as oauth:
                values = await oauth.refresh_token(
                    metadata["token_endpoint"],
                    refresh_token=tokens["refresh"],
                    **{self.settings.audience_parameter: self.settings.lasa_service_id},
                )
            return self.access_tokens(
                values, await self.keys(metadata), tokens["sub"], tokens["refresh"]
            )
        except (
            OAuthError,
            httpx.HTTPError,
            TimeoutError,
            ValueError,
            TypeError,
            KeyError,
            jwt.PyJWTError,
        ):
            raise PortalError(401, "sign_in_required", "Sign in again to continue.") from None

    async def revoke(self, refresh):
        if not refresh:
            return
        try:
            metadata = await self.metadata()
            if endpoint := metadata.get("revocation_endpoint"):
                async with asyncio.timeout(self.settings.timeout_seconds), self.oauth() as oauth:
                    await oauth.revoke_token(
                        endpoint, token=refresh, token_type_hint="refresh_token"
                    )
        except (OAuthError, httpx.HTTPError, TimeoutError, PortalError):
            # The local session is already invalidated.
            return


class Native:
    def __init__(self, settings, http):
        self.settings = settings
        self.http = http

    async def request(self, token, method, path, *, limit=1024 * 1024, **kwargs):
        headers = {"Authorization": "Bearer " + token, **kwargs.pop("headers", {})}
        try:
            result = await bounded_response(
                self.http,
                method,
                self.settings.lasa_url + path,
                headers=headers,
                seconds=self.settings.timeout_seconds,
                limit=limit,
                **kwargs,
            )
        except (httpx.HTTPError, TimeoutError):
            raise PortalError(503, "native_exchange", "LASA could not be reached.") from None
        if 200 <= result.status_code < 300:
            return result
        if result.status_code == 401:
            raise PortalError(401, "sign_in_required", "Sign in again to continue.")
        if not 400 <= result.status_code <= 599:
            raise PortalError(502, "native_protocol", "LASA returned an unexpected response.")
        try:
            code = validated("Problem", json_document(result))["code"]
        except PortalError:
            code = "native_exchange"
        code = code if re.fullmatch(r"[a-z_]{1,64}", code) else "native_exchange"
        retry = result.headers.get("Retry-After", "")
        raise PortalError(
            result.status_code,
            code,
            MESSAGES.get(code, "LASA could not complete this request."),
            retry_after=min(int(retry), 30)
            if retry.isascii() and retry.isdigit() and len(retry) <= 6
            else None,
        )

    async def get(self, token, path, *, schema=None, **kwargs):
        result = await self.request(token, "GET", path, **kwargs)
        value = json_document(result)
        return validated(schema, value) if schema else value

    async def qualify(self, token):
        descriptor = await self.get(token, "/descriptor", schema="ServiceDescriptor")
        identity = descriptor["authentication"]
        protocol = next(
            (p for p in descriptor["protocols"] if p["version"] == NATIVE_PROTOCOL), None
        )
        if (
            descriptor["service_id"] != self.settings.lasa_service_id
            or identity.get("issuer") != self.settings.issuer
            or identity.get("mode", "jwt") != "jwt"
            or identity["audience"] != self.settings.lasa_service_id
            or not protocol
            or protocol["base_url"] != self.settings.lasa_url
            or protocol["openapi_url"] != self.settings.lasa_url + "/openapi.json"
            or descriptor["catalog_url"] != self.settings.lasa_url + "/capabilities"
            or protocol["wire_schema_digest"] != digest(protocol_contracts().bundle)
            or "consumer-events" not in protocol["features"]
            or not set(protocol["required_features"])
            <= {"consumer-events", "clarification", "artifacts"}
            or descriptor["idempotency_retention_seconds"] > self.settings.journal_seconds
        ):
            raise PortalError(503, "native_configuration", "The LASA receiver is incompatible.")
        api = await self.get(token, "/openapi.json", limit=1024 * 1024)
        paths = api.get("paths", {}) if isinstance(api, dict) else {}
        if not isinstance(paths, dict) or any(
            not isinstance(paths.get(path), dict) or method not in paths[path]
            for path, method in REQUIRED_OPERATIONS.items()
        ):
            raise PortalError(
                503, "native_configuration", "The LASA receiver lacks required task routes."
            )
        if "CallerTaskRequest" not in api.get("components", {}).get("schemas", {}):
            raise PortalError(
                503, "native_configuration", "The LASA receiver lacks per-task delegation controls."
            )
        # The list route proves that this token maps to a native user, including for empty history.
        await self.get(token, "/tasks", params={"limit": 1})
        return descriptor["idempotency_retention_seconds"]

    def eligible(self, offer):
        processing = offer["processing"]
        return (
            offer["contract"] == ATTEMPT_REF
            and not offer["restrictions"]["allowed_effects"]
            and processing.get("domain") in {None, *self.settings.allowed_processing_domains}
            and epoch(offer["valid_until"]) > now()
        )

    async def offers(self, token):
        result = []
        cursor = None
        catalog = None
        seen = set()
        for _ in range(100):
            page = await self.get(
                token,
                "/capabilities",
                schema="OfferCatalog",
                params={
                    "contract_id": ATTEMPT_REF["id"],
                    "contract_version": ATTEMPT_REF["version"],
                    **({"cursor": cursor} if cursor else {}),
                },
            )
            current = page["catalog_view"], page["revision"]
            if catalog is not None and current != catalog:
                break
            catalog = current
            result.extend(offer for offer in page["offers"] if self.eligible(offer))
            cursor = page["next_cursor"]
            if cursor is None:
                return result
            if cursor in seen:
                break
            seen.add(cursor)
        raise PortalError(409, "catalog_changed", MESSAGES["catalog_changed"])

    async def select(self, token, selection):
        route = "/capabilities/" + resource(selection["offer_id"])
        offer = await self.get(token, route, schema="CapabilityOffer")
        current = {
            "offer_id": offer["offer_id"],
            "offer_revision": offer["revision"],
            "catalog_view": offer["catalog_view"],
            "contract": offer["contract"],
        }
        if not self.eligible(offer) or selection != current:
            raise PortalError(409, "offer_changed", MESSAGES["offer_changed"])
        await self.get(token, route + "/availability", schema="Availability")
        return offer

    async def mutation(self, token, path, body, key, schema, etag=None):
        request = await self.request(
            token,
            "POST",
            path,
            json=body,
            headers={"Idempotency-Key": key, **({"If-Match": etag} if etag else {})},
        )
        if request.status_code != (201 if schema == "Session" else 202):
            raise PortalError(
                502, "native_protocol", "LASA returned an unexpected mutation response."
            )
        return validated(schema, json_document(request)), request.headers.get("ETag")

    async def task(self, token, task_id, *, control=False):
        response = await self.request(
            token,
            "GET",
            "/tasks/" + resource(task_id),
            params={"view": "control"} if control else {},
        )
        body = validated(
            "ConsumerTaskDisposition" if control else "ConsumerTask", json_document(response)
        )
        if body["task_id"] != task_id or body["service_id"] != self.settings.lasa_service_id:
            raise PortalError(502, "native_protocol", "LASA returned an unexpected task.")
        return body, response.headers.get("ETag")

    async def conversation(self, token, task_id, after):
        page = await self.get(
            token,
            "/tasks/" + resource(task_id) + "/conversation",
            limit=9 * 1024 * 1024,
            params={"after_sequence": after, "limit": 4},
        )
        require_page = PortalError(
            502, "native_protocol", "LASA returned an invalid conversation page."
        )
        if (
            not isinstance(page, dict)
            or set(page)
            != {
                "task_id",
                "title",
                "latest_task_id",
                "latest_delegation",
                "follow_up_processing",
                "turns",
                "next_after",
                "work_clock",
            }
            or page["title"] is not None
            and (not isinstance(page["title"], str) or not 1 <= len(page["title"]) <= 64)
            or page["follow_up_processing"] is not None
            and not isinstance(page["follow_up_processing"], dict)
            or page["latest_delegation"] not in DELEGATION_MODES
            or not isinstance(page["turns"], list)
            or len(page["turns"]) > 4
        ):
            raise require_page
        clock = page["work_clock"]
        if clock is not None and (
            not isinstance(clock, dict)
            or set(clock) != {"elapsed_ms", "running"}
            or type(clock["elapsed_ms"]) is not int
            or clock["elapsed_ms"] < 0
            or type(clock["running"]) is not bool
        ):
            raise require_page
        resource(page["task_id"])
        resource(page["latest_task_id"])
        for turn in page["turns"]:
            if (
                not isinstance(turn, dict)
                or set(turn)
                != {"sequence", "task_id", "kind", "content"}
                | ({"work_ms"} if turn.get("kind") == "result" else set())
                | ({"delegation"} if turn.get("kind") == "request" else set())
                or type(turn["sequence"]) is not int
                or turn["sequence"] <= after
                or turn["kind"] not in ("request", "question", "reply", "result")
                or not isinstance(turn["content"], dict)
                or turn["kind"] == "request"
                and turn["delegation"] not in DELEGATION_MODES
                or turn.get("work_ms") is not None
                and (type(turn["work_ms"]) is not int or turn["work_ms"] < 0)
            ):
                raise require_page
            resource(turn["task_id"])
            after = turn["sequence"]
        if page["next_after"] is not None and (
            len(page["turns"]) != 4 or page["next_after"] != after
        ):
            raise require_page
        return page

    async def artifact(self, token, task_id, artifact_id):
        path = "/tasks/" + resource(task_id) + "/artifacts/" + resource(artifact_id)
        response = await self.request(token, "GET", path, limit=self.settings.artifact_bytes)
        expected = (
            "sha-256=:" + base64.b64encode(hashlib.sha256(response.content).digest()).decode() + ":"
        )
        if response.headers.get("Content-Digest") != expected:
            raise PortalError(
                502, "artifact_digest", "The released download failed its integrity check."
            )
        return response


def validate_input(schema, value):
    try:
        return validate_data(schema, value)
    except LasaError:
        raise PortalError(
            400, "invalid_input", "Check the task fields and their size limits."
        ) from None
