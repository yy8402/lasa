"""Evaluate and record content decisions at service-owned transfer boundaries."""

import asyncio
import hashlib
import sqlite3
import ssl
from dataclasses import dataclass

import httpx

from .capabilities import instant, require
from .contracts import canonical, digest, parse_json
from .errors import LasaError
from .store import identity

UNKNOWN = frozenset({"unknown"})
MAX_CONTENT_BYTES = 4 * 1024 * 1024
INSPECTION_TIMEOUT_SECONDS = 2
MAX_INSPECTION_REQUEST_BYTES = 4 * 1024 * 1024
MAX_INSPECTION_RESPONSE_BYTES = 4096
CONTENT_RETENTION_SECONDS = 86400
CREDENTIAL_FIELDS = {
    "authorization",
    "api_key",
    "token",
    "secret",
    "password",
    "private_key",
    "encrypted_content",
}


def has_credential_fields(value):
    if isinstance(value, dict):
        return any(
            key.lower() in CREDENTIAL_FIELDS or has_credential_fields(item)
            for key, item in value.items()
        )
    return isinstance(value, list) and any(has_credential_fields(item) for item in value)


PROJECTION_FIELDS = {
    "reasoning.request": {"input"},
    "reasoning.response": {"output", "deltas"},
    "candidate.release": {"output", "text"},
    "caller.request": {"input", "attachments", "answer", "dependencies"},
    "caller.response": {"question", "content"},
    "delegation.request": {"input", "dependencies", "attachments"},
    "delegation.response": {"output", "text", "content"},
    "tool.invoke": {"arguments"},
    "tool.result": {"output"},
}


def payload_digest(value):
    if isinstance(value, bytes):
        return "sha256:" + hashlib.sha256(value).hexdigest()
    return digest(value)


def new_client(profile, transport):
    verify = ssl.create_default_context(cafile=profile["ca_file"]) if "ca_file" in profile else True
    return httpx.AsyncClient(
        verify=verify, transport=transport, follow_redirects=False, trust_env=False
    )


@dataclass(frozen=True)
class Transfer:
    channel: str
    destination: str
    purpose: str
    operation_id: str
    task_id: str | None = None
    source: str | tuple[str, ...] | None = None
    connector: str | None = None
    operation: str | None = None


class ContentSecurity:
    def __init__(self, coordinator, transport):
        self.c = coordinator
        self.inspection_revision = digest(coordinator.config.document.get("content_security", {}))
        self.bindings = coordinator.config.inspection
        self.recovery = coordinator.config.document["limits"]["content_recovery"]
        self.clients = {
            key: new_client(profile, transport) for key, profile in self.bindings.profiles.items()
        }

    async def close(self):
        await asyncio.gather(*(client.aclose() for client in self.clients.values()))

    def disclosure(self):
        try:
            return self.c.config.policy().get("content_disclosure", {})
        except (OSError, ValueError, LasaError):
            raise LasaError("content_gateway_unavailable", 503) from None

    def legacy_release_revision(self, disclosure_revision):
        return digest({"inspection": self.inspection_revision, "disclosure": disclosure_revision})

    def release_scope(self, *, artifact, disclosure_revision):
        binding = self.bindings.defaults["caller"]["response"]
        enforced = None
        if binding.fields["mode"] == "enforce":
            enforced = self.bindings.profiles[binding.profile_for(artifact=artifact)]
        return digest({"enforced_inspection": enforced, "disclosure": disclosure_revision})

    def adopt_release_scopes(self):
        # Only a legacy grant valid under this exact configuration can acquire a scope.
        policy = digest(self.disclosure())
        self.c.store.db.execute(
            "INSERT INTO content_release_scopes SELECT task_id,component, "
            "CASE WHEN component='result' THEN ? ELSE ? END "
            "FROM content_releases WHERE policy_revision=? "
            "ON CONFLICT(task_id,component) DO NOTHING",
            (
                self.release_scope(artifact=False, disclosure_revision=policy),
                self.release_scope(artifact=True, disclosure_revision=policy),
                self.legacy_release_revision(policy),
            ),
        )

    @staticmethod
    def source_classes(source, disclosure):
        sources = source if isinstance(source, tuple) else (source,)
        labels = disclosure.get("source_classes", {})
        return {label for key in sources for label in labels.get(key, UNKNOWN)}

    def remember_source(self, task_id, decision):
        self.c.store.add_content_classes(task_id, decision["source_classes"])

    def record(self, decision, kind="content_decision"):
        try:
            self.c.store.event(decision["task_id"], kind, decision)
        except sqlite3.Error:
            raise LasaError("content_gateway_unavailable", 503) from None

    def outcome(self, decision, outcome):
        self.record(
            {
                "task_id": decision["task_id"],
                "transfer_id": decision["transfer_id"],
                "operation_id": decision["operation_id"],
                "outcome": outcome,
                "timestamp": instant(),
            },
            "content_transfer",
        )

    def contains_secret(self, value, task_id):
        secrets = set(self.c.config.secrets.values())
        secrets.update(self.c.diagnostics.active_secrets.get(task_id, ()))
        secrets.discard("")

        def scan(node):
            if isinstance(node, str):
                return any(secret in node for secret in secrets)
            if isinstance(node, list):
                return any(scan(item) for item in node)
            if isinstance(node, dict):
                return any(scan(key) or scan(item) for key, item in node.items())
            return False

        return scan(value)

    def sanitize_projection(self, value):
        # Keep reserved credential/protocol fields out of external inspection.
        if isinstance(value, list):
            return [self.sanitize_projection(item) for item in value]
        if isinstance(value, dict):
            return {
                key: self.sanitize_projection(item)
                for key, item in value.items()
                if key.lower() not in CREDENTIAL_FIELDS | {"reasoning", "instructions"}
            }
        return value

    def check_local(self, transfer, value, media_type, scoped, classes):
        if media_type not in {
            "application/json",
            "text/plain",
            "text/markdown",
            "text/event-stream",
        }:
            return "media_type_denied"
        try:
            wire = value if isinstance(value, bytes) else canonical(value)
            if len(wire) > MAX_CONTENT_BYTES:
                return "content_limit"
            if not classes <= set(scoped):
                return "content_class_denied"
            if isinstance(value, bytes):
                value = parse_json(wire) if media_type == "application/json" else wire.decode()
            if self.contains_secret(value, transfer.task_id) or (
                transfer.channel == "tool.result" and has_credential_fields(value)
            ):
                return "known_secret"
        except (UnicodeError, ValueError, RecursionError, LasaError):
            return "invalid_content"
        return None

    async def check(
        self,
        transfer,
        value,
        *,
        projection,
        media_type="application/json",
        remaining=None,
        defer_permit=False,
        wire=None,
    ):
        if remaining is None:
            clock = asyncio.get_running_loop().time
            deadline = clock() + 2 * INSPECTION_TIMEOUT_SECONDS
            remaining = lambda: deadline - clock()  # noqa: E731
        decision = await self.evaluate(
            transfer, value, projection, media_type, remaining, defer_permit, wire
        )
        return self.finish(decision)

    async def check_request(self, transfer, value, *, project, remaining, revise=None):
        decision = await self.evaluate(
            transfer, value, project(value), "application/json", remaining, False, None
        )
        if (
            revise is not None
            and decision["mode"] == "enforce"
            and decision["reason_code"] in {"gateway_hard_deny", "known_secret"}
            and remaining() > 0
            and self.reserve_recovery(decision, "candidate_revision")
        ):
            try:
                revised = revise(value)
            except LasaError:
                revised = value
            if revised != value:
                value = revised
                decision = await self.evaluate(
                    transfer,
                    value,
                    project(value),
                    "application/json",
                    remaining,
                    False,
                    None,
                    candidate_revision=1,
                )
        return value, self.finish(decision)

    def reserve_recovery(self, decision, action):
        record = {
            key: decision[key]
            for key in (
                "task_id",
                "transfer_id",
                "operation_id",
                "channel",
                "payload_digest",
                "candidate_revision",
                "reason_code",
            )
        }
        record.update(action=action, timestamp=instant())
        if "inspection_id" in decision:
            record["inspection_id"] = decision["inspection_id"]
        if action == "candidate_revision":
            record["adjustment"] = "omit_optional_context"
        limit = {
            "inspection_retry": "max_inspection_retries_per_transfer",
            "candidate_revision": "max_candidate_revisions_per_transfer",
        }[action]
        try:
            return self.c.store.reserve_content_recovery(
                record,
                per_transfer=self.recovery[limit],
                per_task=self.recovery["max_actions_per_task"],
            )
        except sqlite3.Error:
            raise LasaError("content_gateway_unavailable", 503) from None

    def ensure_current(self, decision):
        require(digest(self.disclosure()) == decision["policy_revision"], "disclosure_denied", 403)

    async def evaluate(
        self,
        transfer,
        value,
        projection,
        media_type,
        remaining,
        defer_permit,
        wire,
        *,
        candidate_revision=0,
    ):
        disclosure = self.disclosure()
        policy_revision = digest(disclosure)
        source_classes = self.source_classes(transfer.source, disclosure)
        classes = source_classes | (
            self.c.store.content_classes(transfer.task_id) if transfer.task_id else set()
        )
        destinations = disclosure.get("destinations", {})
        binding = self.bindings.resolve(
            transfer.channel,
            transfer.destination,
            connector=transfer.connector,
            operation=transfer.operation,
        )
        mode = binding.fields["mode"]
        artifact = transfer.purpose == "artifact"
        profile_id = binding.profile_for(artifact=artifact)
        decision = {
            "service_id": self.c.config.service_id,
            "task_id": transfer.task_id,
            "operation_id": transfer.operation_id,
            "transfer_id": "transfer-"
            + digest(
                [
                    transfer.task_id,
                    transfer.channel,
                    transfer.destination,
                    transfer.purpose,
                    transfer.operation_id,
                ]
            )[7:],
            "candidate_revision": candidate_revision,
            "channel": transfer.channel,
            "destination": transfer.destination,
            "purpose": transfer.purpose,
            "policy_revision": policy_revision,
            "binding_revision": binding.revision,
            "mode": mode,
            "mode_origin": binding.origins["mode"],
            "source_classes": sorted(source_classes),
            "payload_digest": payload_digest(value if wire is None else wire),
            "timestamp": instant(),
        }
        if transfer.channel == "candidate.release":
            decision["release_scope"] = self.release_scope(
                artifact=artifact, disclosure_revision=policy_revision
            )
        profile = self.bindings.profiles[profile_id] if profile_id is not None else None
        if profile is not None:
            decision.update(
                profile_id=profile_id,
                gateway_id=profile["gateway_id"],
                gateway_policy_revision=profile["policy_revision"],
            )
        reason = self.check_local(
            transfer,
            value,
            media_type,
            destinations.get(transfer.destination, UNKNOWN),
            classes,
        )
        verdict = "hard_deny" if reason else "permit"
        if verdict == "permit" and profile is not None:
            disclosed = classes <= set(destinations.get("inspection:" + profile_id, UNKNOWN))
            scanned, retryable = await self.inspect(
                decision, profile, projection, media_type, remaining, disclosed=disclosed
            )
            if (
                mode == "enforce"
                and retryable
                and remaining() > 0
                and digest(self.disclosure()) == policy_revision
                and self.reserve_recovery(scanned, "inspection_retry")
            ):
                scanned, _ = await self.inspect(
                    decision, profile, projection, media_type, remaining, disclosed=disclosed
                )
            gateway_verdict, gateway_reason = scanned["verdict"], scanned["reason_code"]
            if mode == "enforce" and gateway_verdict != "permit":
                verdict, reason = gateway_verdict, gateway_reason
            elif digest(self.disclosure()) != policy_revision:
                verdict, reason = "hard_deny", "disclosure_policy_changed"
        decision.update(verdict=verdict, reason_code=reason or "policy_permit")
        if verdict != "permit" or not defer_permit:
            self.record(decision)
        return decision

    def finish(self, decision):
        if decision["verdict"] != "permit":
            self.outcome(decision, "blocked")
            instance = "urn:lasa:" + decision["transfer_id"]
            if decision["verdict"] == "indeterminate":
                raise LasaError("content_gateway_unavailable", 503, instance=instance)
            detail = (
                "Supply corrected input that can be disclosed under the task policy."
                if decision["channel"] == "caller.request"
                else None
            )
            raise LasaError("disclosure_denied", 403, instance=instance, detail=detail)
        return decision

    async def inspect(
        self,
        decision,
        profile,
        projection,
        media_type,
        remaining,
        *,
        disclosed,
    ):
        selected = self.sanitize_projection(
            {
                key: projection[key]
                for key in PROJECTION_FIELDS[decision["channel"]]
                if key in projection
            }
        )
        metadata = {
            **decision,
            "inspection_id": identity("inspection"),
            "inspection_digest": digest(selected),
        }

        def outcome(verdict, reason, *, retryable=False):
            result = {**metadata, "verdict": verdict, "reason_code": reason}
            self.record(result)
            return result, retryable

        try:
            credential = self.c.config.secret(profile["credential_ref"], label="Inspection profile")
        except (OSError, ValueError):
            return outcome("indeterminate", "invalid_or_unavailable_gateway")
        if not selected or not disclosed or self.contains_secret(selected, decision["task_id"]):
            return outcome("hard_deny", "scanner_disclosure_denied")
        request = {
            "version": "1",
            **{
                key: metadata[key]
                for key in (
                    "inspection_id",
                    "binding_revision",
                    "policy_revision",
                    "gateway_policy_revision",
                    "channel",
                    "purpose",
                    "inspection_digest",
                )
            },
            "media_type": media_type,
            "content": selected,
        }
        raw = canonical(request)
        limit = min(INSPECTION_TIMEOUT_SECONDS, remaining())
        if len(raw) > MAX_INSPECTION_REQUEST_BYTES or limit <= 0:
            return outcome("indeterminate", "inspection_limit")
        self.c.contracts.validate("ContentInspectionRequest", request)
        self.record({**metadata, "verdict": "permit", "reason_code": "scanner_disclosure"})
        try:
            async with asyncio.timeout(limit):
                async with self.clients[profile["id"]].stream(
                    "POST",
                    profile["url"],
                    content=raw,
                    headers={
                        "Authorization": "Bearer " + credential,
                        "Content-Type": "application/json",
                    },
                ) as reply:
                    reply.raise_for_status()
                    require(reply.status_code == 200, "content_gateway_unavailable", 503)
                    buffer = bytearray()
                    async for chunk in reply.aiter_bytes():
                        require(
                            len(buffer) + len(chunk) <= MAX_INSPECTION_RESPONSE_BYTES,
                            "content_gateway_unavailable",
                            503,
                        )
                        buffer.extend(chunk)
                    response = self.c.contracts.validate(
                        "ContentInspectionResponse", parse_json(buffer)
                    )
            require(
                all(
                    response[key] == metadata[key]
                    for key in (
                        "inspection_id",
                        "gateway_id",
                        "gateway_policy_revision",
                        "inspection_digest",
                    )
                ),
                "content_gateway_unavailable",
                503,
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in {408, 502, 503, 504}:
                return outcome("indeterminate", "gateway_transient_failure", retryable=True)
            return outcome("indeterminate", "invalid_or_unavailable_gateway")
        except (TimeoutError, httpx.TimeoutException, httpx.NetworkError) as exc:
            cause = exc.__cause__
            while cause is not None:
                if isinstance(cause, ssl.SSLError):
                    return outcome("indeterminate", "invalid_or_unavailable_gateway")
                cause = cause.__cause__
            return outcome("indeterminate", "gateway_transient_failure", retryable=True)
        except (httpx.HTTPError, LasaError, ValueError):
            return outcome("indeterminate", "invalid_or_unavailable_gateway")
        verdict = response["verdict"]
        return outcome(
            verdict,
            "gateway_" + verdict,
            retryable=verdict == "indeterminate"
            and bool(response["reason_codes"])
            and set(response["reason_codes"])
            <= {"scanner_unavailable", "presidio_unavailable", "betterleaks_unavailable"},
        )
