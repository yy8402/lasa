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
                "id": "principal-"
                + digest(
                    [
                        self.config.document["authentication"].get("issuer"),
                        subject,
                        principal["kind"],
                        principal.get("service_id"),
                    ]
                )[7:],
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


def permits_peer_effects(grant, offer):
    advertised = set(offer["restrictions"]["allowed_effects"])
    return advertised <= (set(grant["effects"]) & {"workspace.read", "external.read"})


class Authorization:
    def __init__(self, config):
        self.config = config

    def rules(self, principal):
        policy = self.config.policy()
        for record in policy["principals"]:
            if (
                record["subject"] == principal["subject"]
                and record["kind"] == principal["kind"]
                and record.get("service_id") == principal.get("service_id")
            ):
                rules = record["rules"]
                if record["kind"] == "peer":
                    rules = [
                        {**rule, "execution_key_ref": record["execution_key_ref"]} for rule in rules
                    ]
                if record.get("domain_only"):
                    from .processing import DOMAIN_ONLY, modes

                    return [
                        {**rule, "processing_modes": [DOMAIN_ONLY]}
                        for rule in rules
                        if DOMAIN_ONLY in modes(rule)
                    ]
                return rules
        raise LasaError("authority_denied", 403)

    def rule(self, principal, reference):
        for rule in self.rules(principal):
            if rule["authorization_ref"] == reference:
                return rule
        raise LasaError("authority_denied", 403)

    def context_revision(self, principal):
        return digest({"policy": self.config.policy()["revision"], "rules": self.rules(principal)})

    def resolve(self, principal, request, offer, registry, *, received_at):
        from .capabilities import epoch, instant, require
        from .grants import (
            configured_grants,
            execution_commitment,
            peer_execution,
            select_recursion,
            task_fanout,
        )
        from .processing import DOMAIN_ONLY, check, qualified_domain

        reference = offer["authorization_ref"]
        rule = self.rule(principal, reference)
        ref = request["selection"]["contract"]
        require(ref in rule["contracts"], "authority_denied", 403)
        registry.input(ref, request["input"])
        service = self.config.document["limits"]
        maximum = offer["max_budget"]
        requested = request.get("requested_limits", {})
        requested_budget = requested.get("budget", maximum)
        peer = principal["kind"] == "peer"
        fanout = task_fanout(self.config, rule, peer=peer)
        grants = configured_grants(self.config, rule)
        if peer:
            require(
                offer["execution_commitment"]
                == execution_commitment(
                    self.config.execution_key(rule["execution_key_ref"]),
                    principal["service_id"],
                    self.config.service_id,
                    offer,
                    peer_execution(self.config, rule, fanout, grants),
                ),
                "offer_changed",
                409,
            )
            require("deadline" in requested, "deadline_exceeded", 422)
        budget = {
            **requested_budget,
            "delegations": fanout,
        }
        require(all(budget[key] <= maximum[key] for key in maximum), "capacity_exhausted", 429)
        receipt_time = epoch(received_at)
        deadline = receipt_time + budget["wall_time_ms"] / 1000
        if requested.get("deadline"):
            absolute = epoch(requested["deadline"])
            require(
                absolute
                <= receipt_time
                + maximum["wall_time_ms"] / 1000
                + service["max_clock_skew_seconds"],
                "deadline_exceeded",
                422,
            )
            deadline = min(deadline, absolute)
        require(deadline > time.time(), "deadline_exceeded", 422)
        policy = self.config.policy()
        domain_only = offer["processing"]["mode"] == DOMAIN_ONLY
        domain = qualified_domain(self.config, policy) if domain_only else None
        if domain_only:
            members = set(domain["members"]) if domain else set()
            grants = [
                grant for grant in grants if "peer:" + grant["receiver_service_id"] in members
            ]
        grants, subtree_cap = select_recursion(
            self.config,
            rule,
            fanout,
            grants,
            min(budget["wall_time_ms"], round((epoch(instant(deadline)) - receipt_time) * 1000)),
            peer=peer,
        )
        if peer and registry.is_workflow(ref):
            require(bool(grants), "authority_denied", 403)
        imports = request.get("imports", [])
        require(
            len({item["label"] for item in imports}) == len(imports)
            and all(item["output_digest"] == digest(item["output"]) for item in imports),
            "precondition_failed",
            422,
        )
        allowed_effects = offer["restrictions"]["allowed_effects"]
        require("external.write" not in allowed_effects, "authority_denied", 403)
        authority = {
            "selected_offer": offer,
            "decision_id": "authority-"
            + digest(
                {
                    "principal": principal["id"],
                    "policy": self.context_revision(principal),
                    "request": digest(request),
                }
            )[7:39],
            "authorization_ref": reference,
            "principal_id": principal["id"],
            "receiver_service_id": self.config.service_id,
            "request_digest": digest(request),
            "contract": ref,
            "valid_until": instant(min(deadline, principal["token_expiry"])),
            "resources": offer["resources"],
            "allowed_effects": allowed_effects,
            "delegation_grants": grants,
            **({"subtree_cap": subtree_cap} if subtree_cap is not None else {}),
            "limits": {
                "budget": dict(budget),
                "deadline": instant(deadline),
            },
            "content_diagnostics_allowed": rule["content_diagnostics"],
        }
        if domain_only:
            authority["processing_members"] = list(domain["members"]) if domain else []
        check(self.config, policy, rule, authority)
        return authority
