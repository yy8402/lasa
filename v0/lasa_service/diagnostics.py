"""Always-on bounded operation evidence; separately authorized content disclosure."""

from .capabilities import instant
from .contracts import canonical, digest, parse_json
from .errors import LasaError
from .store import identity, zero


class Diagnostics:
    def __init__(self, coordinator):
        self.coordinator = coordinator
        self.active_secrets = {}

    def register_secret(self, task_id, secret):
        self.active_secrets.setdefault(task_id, set()).add(secret)

    def forget_secrets(self, task_id):
        self.active_secrets.pop(task_id, None)

    def redact(self, value, task_id=None):
        secrets = sorted(
            {
                *self.coordinator.config.secrets.values(),
                *self.active_secrets.get(task_id, ()),
            }
            - {""},
            key=lambda secret: (-len(secret), secret),
        )

        def clean(node):
            if isinstance(node, str):
                for secret in secrets:
                    node = node.replace(secret, "[REDACTED]")
                return node
            if isinstance(node, list):
                return [clean(x) for x in node]
            if isinstance(node, dict):
                return {
                    key: "[REDACTED]"
                    if key.lower()
                    in {
                        "authorization",
                        "api_key",
                        "token",
                        "secret",
                        "password",
                        "private_key",
                        "encrypted_content",
                    }
                    else clean(item)
                    for key, item in node.items()
                }
            return node

        return clean(value)

    def emit(self, task_id, kind, payload, content=None, parent=None):
        c = self.coordinator
        row, _ = c.store.task(task_id)
        sequence = c.store.db.execute(
            "SELECT COALESCE(MAX(sequence),0)+1 FROM events WHERE task_id=?", (task_id,)
        ).fetchone()[0]
        event = {
            "event_id": identity("event"),
            "service_id": c.config.service_id,
            "task_id": task_id,
            "sequence": sequence,
            "timestamp": instant(),
            "causal_parent_event_id": parent,
            "kind": kind,
            "payload": self.redact(payload, task_id),
            "redacted": True,
        }
        request = parse_json(row["request"])
        authority = parse_json(row["authority"])
        if (
            content is not None
            and request["diagnostics"] == "content"
            and authority["content_diagnostics_allowed"]
        ):
            cleaned = canonical(self.redact(content, task_id))
            available = max(0, 65536 - c.store.diagnostic_bytes(task_id))
            text = cleaned[: min(8192, available)].decode(errors="ignore")
            if text:
                event["content"] = {
                    "media_type": "application/json",
                    "text": text,
                }
            if "payload_truncated" in event["payload"]:
                event["payload"]["payload_truncated"] = len(text.encode()) < len(cleaned)
        c.config.contracts.validate("DiagnosticEvent", event)
        c.store.db.execute(
            "INSERT INTO events VALUES(?,?,?)", (task_id, sequence, canonical(event).decode())
        )
        return event["event_id"]

    def call(
        self,
        task_id,
        operation_id,
        call_type,
        phase,
        inputs,
        *,
        reserved=None,
        usage=None,
        output=None,
        content=None,
    ):
        payload = {
            "operation_id": operation_id,
            "call_type": call_type,
            "phase": phase,
            "input_digest": digest(inputs),
            "input_bytes": len(canonical(inputs)),
            "output_digest": digest(output) if output is not None else None,
            "output_bytes": len(canonical(output)) if output is not None else 0,
            "reserved": reserved or zero(),
            "usage": usage or zero(),
            "payload_truncated": False,
        }
        if isinstance(inputs, dict) and inputs.get("purpose") in {
            "planning",
            "execution",
            "verification",
        }:
            payload["purpose"] = inputs["purpose"]
        if call_type == "child":
            payload["contract"] = inputs["selection"]["contract"]
            payload["peer_service_id"] = inputs["delegation"]["recipient_service_id"]
            child = next(
                (
                    x
                    for x in self.coordinator.store.children(task_id)
                    if x["delegation_id"] == operation_id
                ),
                None,
            )
            if child and "task_id" in child:
                payload["child_task_id"] = child["task_id"]
        return self.emit(task_id, "call", payload, content)

    def page(self, task_id, principal, after=0, limit=50):
        c = self.coordinator
        row, _ = c.store.task(task_id, principal["subject"])
        try:
            allowed = c.authorization.rule(
                principal, parse_json(row["request"])["authorization_ref"]
            )["content_diagnostics"]
        except (LasaError, OSError, ValueError):
            allowed = False
        events = [
            parse_json(r[0])
            for r in c.store.db.execute(
                "SELECT document FROM events WHERE task_id=? AND sequence>? ORDER BY sequence LIMIT ?",
                (task_id, after, limit),
            )
        ]
        if not allowed:
            for event in events:
                event.pop("content", None)
        return {
            "task_id": task_id,
            "events": events,
            "next_sequence": events[-1]["sequence"] + 1 if events else after + 1,
        }

    async def children_report(self, task_id, principal, after=0):
        import asyncio

        c = self.coordinator
        row, _ = c.store.task(task_id, principal["subject"])
        children = c.store.children(task_id)
        try:
            content = (
                c.authorization.rule(principal, parse_json(row["request"])["authorization_ref"])[
                    "content_diagnostics"
                ]
                and parse_json(row["request"])["diagnostics"] == "content"
            )
        except (LasaError, OSError, ValueError):
            content = False

        async def report(child):
            summary = {key: child[key] for key in ["delegation_id", "service_id", "state"]}
            if "task_id" in child:
                summary["task_id"] = child["task_id"]
            try:
                if "task_id" not in child:
                    raise LasaError("peer_unavailable", 503)
                async with asyncio.timeout(5):
                    peer = await c.delegation.peer_for(child)
                    binding = child["peer_binding"]
                    url = (
                        binding["base_url"]
                        + "/tasks/"
                        + child["task_id"]
                        + "/events?after_sequence="
                        + str(after)
                        + "&limit=100"
                    )
                    page, status, _ = await peer.request("GET", url, binding=binding)
                    if status != 200:
                        raise LasaError("peer_unavailable", 503)
                    c.contracts.validate("EventPage", page, "incompatible_protocol", 502)
                    if page["task_id"] != child["task_id"]:
                        raise LasaError("verification_failed", 502)
                    for event in page["events"]:
                        if event["service_id"] != child["service_id"]:
                            raise LasaError("verification_failed", 502)
                        if not content:
                            event.pop("content", None)
                    summary["trace"] = self.redact(page, task_id)
            except (LasaError, TimeoutError) as exc:
                summary["problem"] = (
                    exc if isinstance(exc, LasaError) else LasaError("peer_unavailable", 503)
                ).public()
            return summary

        return {
            "task_id": task_id,
            "children": await asyncio.gather(*(report(child) for child in children)),
        }
