"""Bearer credential verification and receiver-owned policy resolution."""

import asyncio
import hmac
import re
import time
from pathlib import Path

import httpx
import jwt

from .contracts import digest, parse_json, protocol_contracts
from .errors import LasaError
from .grants import grant_key, intersect_grants


def jwt_workload_identity(token, expected_service_id):
    """Read the outbound identity pin. Only the receiver verifies the signature."""
    header = jwt.get_unverified_header(token)
    claims = jwt.decode(token, options={"verify_signature": False})
    identity = {key: claims.get(key) for key in ("iss", "sub", "aud")}
    if (
        header.get("alg") not in ("ES256", "EdDSA", "RS256")
        or not token.rsplit(".", 1)[-1]
        or not all(isinstance(value, str) and value for value in identity.values())
        or identity["aud"] != expected_service_id
    ):
        raise ValueError("Invalid peer JWT identity")
    return identity


WORKLOAD_IDENTITY_HEADER = "LASA-Workload-Identity"


def validate_static_token(token):
    if not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", token):
        raise ValueError("Invalid static token")


def static_workload_identity(subject, caller_service_id, receiver_service_id):
    return {
        "mode": "static_token",
        "sub": subject,
        "service_id": caller_service_id,
        "aud": receiver_service_id,
    }


def peer_workload_identity(token, peer, sender_service_id):
    authentication = peer.get("authentication", {"mode": "jwt"})
    receiver_service_id = peer["expected_service_id"]
    if authentication["mode"] == "jwt":
        return jwt_workload_identity(token, receiver_service_id)
    validate_static_token(token)
    return static_workload_identity(
        authentication["subject"], sender_service_id, receiver_service_id
    )


def static_token_digest(service_id, token):
    return digest([service_id, token])


STATIC_TOKEN_REGISTRY_MAX_BYTES = 131072


def read_static_tokens(path):
    with Path(path).open("rb") as source:
        data = source.read(STATIC_TOKEN_REGISTRY_MAX_BYTES + 1)
    if len(data) > STATIC_TOKEN_REGISTRY_MAX_BYTES:
        raise ValueError("Static token registry is too large")
    registry = protocol_contracts().validate("StaticTokenRegistry", parse_json(data))
    tokens = registry["tokens"]
    if len({entry["digest"] for entry in tokens}) != len(tokens):
        raise ValueError("Duplicate static token digest")
    return registry


class Authentication:
    def __init__(self, config):
        self.config = config
        self.keys = {}

    async def start(self):
        settings = self.config.document["authentication"]
        if self.config.auth_mode == "static_token":
            await asyncio.to_thread(read_static_tokens, settings["tokens_file"])
            return
        if "jwks_file" in settings:
            document = parse_json(await asyncio.to_thread(Path(settings["jwks_file"]).read_bytes))
        else:
            async with (
                asyncio.timeout(10),
                httpx.AsyncClient(trust_env=False, follow_redirects=False) as client,
                client.stream("GET", settings["jwks_url"]) as response,
            ):
                response.raise_for_status()
                content = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(content) + len(chunk) > 65536:
                        raise ValueError("JWKS too large")
                    content.extend(chunk)
                document = parse_json(content)
        if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
            raise ValueError("Expected a JWKS object with a keys array")
        for key in document["keys"]:
            if (
                not isinstance(key, dict)
                or not isinstance(key.get("kid"), str)
                or not key["kid"]
                or key.get("alg") not in settings["allowed_algorithms"]
                or key.get("use", "sig") != "sig"
                or key["kid"] in self.keys
            ):
                raise ValueError("Invalid or duplicate signing key")
            self.keys[key["kid"]] = jwt.PyJWK.from_dict(key)
        if not self.keys:
            raise ValueError("No signing keys")

    def authenticate_headers(self, headers):
        return self.authenticate(
            headers.get("Authorization"), workload_pin=headers.get(WORKLOAD_IDENTITY_HEADER)
        )

    def authenticate(self, authorization, *, workload_pin=None):
        try:
            if not authorization or not authorization.startswith("Bearer "):
                raise ValueError("missing token")
            token = authorization[7:]
            if self.config.auth_mode == "static_token":
                subject, expiry = self.static_identity(token)
            else:
                subject, expiry = self.jwt_identity(token)
            principal = next(
                p for p in self.config.policy()["principals"] if p["subject"] == subject
            )
            if self.config.auth_mode == "static_token" and principal["kind"] == "peer":
                identity = static_workload_identity(
                    subject, principal["service_id"], self.config.service_id
                )
                if not hmac.compare_digest(workload_pin or "", digest(identity)):
                    raise ValueError("Static peer credential does not match the workload pin")
            elif workload_pin is not None:
                raise ValueError("Unexpected static peer workload pin")
            return {
                "subject": principal["subject"],
                "kind": principal["kind"],
                **({"service_id": principal["service_id"]} if "service_id" in principal else {}),
                "token_expiry": expiry,
            }
        except (jwt.PyJWTError, LasaError, OSError, ValueError, KeyError, StopIteration, TypeError):
            raise LasaError("authority_denied", 401) from None

    def jwt_identity(self, token):
        header = jwt.get_unverified_header(token)
        settings = self.config.document["authentication"]
        if header.get("alg") not in settings["allowed_algorithms"] or any(
            k in header for k in ["jku", "x5u", "crit"]
        ):
            raise ValueError("untrusted token header")
        key = self.keys[header["kid"]]
        if key.algorithm_name != header["alg"]:
            raise ValueError("algorithm mismatch")
        claims = jwt.decode(
            token,
            key,
            algorithms=settings["allowed_algorithms"],
            audience=self.config.service_id,
            issuer=settings["issuer"],
            options={"require": ["iss", "sub", "aud", "exp", "iat", "jti"], "strict_aud": True},
        )
        return claims["sub"], claims["exp"]

    def static_identity(self, token):
        validate_static_token(token)
        candidate = static_token_digest(self.config.service_id, token)
        registry = read_static_tokens(self.config.document["authentication"]["tokens_file"])
        entry = next(e for e in registry["tokens"] if hmac.compare_digest(e["digest"], candidate))
        if entry["expires_at"] <= time.time():
            raise ValueError("Expired static token")
        return entry["subject"], entry["expires_at"]


class Authorization:
    def __init__(self, config):
        self.config = config

    def rules(self, principal):
        policy = self.config.policy()
        for record in policy["principals"]:
            if record["subject"] == principal["subject"]:
                return record["rules"]
        raise LasaError("authority_denied", 403)

    def rule(self, principal, reference):
        for rule in self.rules(principal):
            if rule["authorization_ref"] == reference:
                return rule
        raise LasaError("authority_denied", 403)

    def context_revision(self, principal):
        return digest({"policy": self.config.policy()["revision"], "rules": self.rules(principal)})

    def resolve(self, principal, request, offer, registry, *, deadline_ceiling=None):
        from .capabilities import epoch, instant, require
        from .contracts import request_digest

        rule = self.rule(principal, request["authorization_ref"])
        ref = request["selection"]["contract"]
        require(ref in rule["contracts"], "authority_denied", 403)
        definition = registry.input(ref, request["input"])
        limits = request["requested_limits"]
        service = self.config.document["limits"]
        maximum = {
            key: min(rule["budget"][key], offer["max_budget"][key], service["max_task_budget"][key])
            for key in rule["budget"]
        }
        require(
            all(limits["budget"][key] <= maximum[key] for key in maximum), "capacity_exhausted", 429
        )
        require(
            limits["max_hops"] <= min(rule["max_hops"], offer["max_hops"], service["max_hops"]),
            "authority_denied",
            403,
        )
        require(
            time.time()
            < epoch(limits["deadline"])
            <= time.time()
            + maximum["wall_time_ms"] / 1000
            + self.config.document["limits"]["max_clock_skew_seconds"],
            "deadline_exceeded",
            422,
        )
        allowed_effects = sorted(
            set(rule["effects"])
            & set(offer["restrictions"]["allowed_effects"])
            & set(definition["max_effects"])
        )
        require("external.write" not in allowed_effects, "authority_denied", 403)
        envelope = request.get("delegation")
        require("dependency_results" not in request or envelope, "authority_denied", 403)
        require(not envelope or not registry.is_workflow(ref), "authority_denied", 403)
        if envelope:
            require(
                principal["kind"] == "peer"
                and principal.get("service_id") == envelope["parent_service_id"]
                and envelope["recipient_service_id"] == self.config.service_id
                and principal["service_id"]
                in self.config.policy()["trusted_delegator_service_ids"],
                "authority_denied",
                403,
            )
            require(
                self.config.service_id not in envelope["ancestry"]
                and envelope["ancestry"][-1] == envelope["parent_service_id"]
                and len(envelope["ancestry"]) + envelope["remaining_hops"] <= 32,
                "precondition_failed",
                422,
            )
            require(
                envelope["request_digest"] == request_digest(request)
                and envelope["allocation"] == limits
                and envelope["remaining_hops"] == limits["max_hops"],
                "authority_denied",
                403,
            )
        import copy

        effective_limits = copy.deepcopy(limits)
        effective_deadline = min(
            epoch(limits["deadline"]), time.time() + limits["budget"]["wall_time_ms"] / 1000
        )
        if deadline_ceiling is not None:
            effective_deadline = min(effective_deadline, epoch(deadline_ceiling))
        require(effective_deadline > time.time(), "deadline_exceeded", 422)
        effective_limits["deadline"] = instant(effective_deadline)
        result = {
            "selected_offer": copy.deepcopy(offer),
            "decision_id": "authority-"
            + digest(
                {
                    "principal": principal["subject"],
                    "policy": self.context_revision(principal),
                    "request": request_digest(request),
                }
            )[7:39],
            "authorization_ref": request["authorization_ref"],
            "principal_id": principal["subject"],
            "receiver_service_id": self.config.service_id,
            "request_digest": request_digest(request),
            "contract": ref,
            "valid_until": instant(min(effective_deadline, principal["token_expiry"])),
            "resources": [
                {
                    "resource": r["resource"],
                    "actions": sorted(
                        set(r["actions"])
                        & set(
                            next(
                                (
                                    x["actions"]
                                    for x in offer["restrictions"]["resources"]
                                    if x["resource"] == r["resource"]
                                ),
                                [],
                            )
                        )
                    ),
                }
                for r in rule["resources"]
            ],
            "allowed_effects": allowed_effects,
            "delegation_grants": rule["delegation_grants"],
            "limits": effective_limits,
            "content_diagnostics_allowed": rule["content_diagnostics"],
        }
        if rule.get("verifier_trust") and not envelope:
            result["verifier_trust"] = rule["verifier_trust"]
        if envelope:
            ceiling = envelope["authority_ceiling"]
            result["allowed_effects"] = sorted(
                set(result["allowed_effects"]) & set(ceiling["allowed_effects"])
            )
            result["resources"] = [
                {
                    "resource": r["resource"],
                    "actions": sorted(
                        set(r["actions"])
                        & set(
                            next(
                                (
                                    x["actions"]
                                    for x in ceiling["resources"]
                                    if x["resource"] == r["resource"]
                                ),
                                [],
                            )
                        )
                    ),
                }
                for r in result["resources"]
            ]
            result["resources"] = [r for r in result["resources"] if r["actions"]]
            grants = ceiling["delegation_grants"]
            require(
                len(grants) == len({grant_key(grant) for grant in grants}), "authority_denied", 403
            )
            result["delegation_grants"] = intersect_grants(result["delegation_grants"], grants)
            result["content_diagnostics_allowed"] &= ceiling["content_diagnostics_allowed"]
        require(
            request["diagnostics"] != "content" or result["content_diagnostics_allowed"],
            "disclosure_denied",
            403,
        )
        return result
