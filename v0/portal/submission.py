"""Idempotent session allocation and receipt-driven task submission."""

import hmac

from lasa_service.contracts import canonical, digest, protocol_contracts
from lasa_service.errors import LasaError
from lasa_service.preconditions import request_input_size

from .client import ATTEMPT, ATTEMPT_REF, epoch, resource, validate_input
from .config import PortalError
from .state import now, opaque

DEFINITE_REJECTIONS = {
    "offer_changed",
    "catalog_changed",
    "invalid_input",
    "capacity_exhausted",
    "processing_unavailable",
    "content_blocked",
    "deadline_exceeded",
    "not_found",
    "task_state_conflict",
    "session_busy",
    "authority_denied",
    "disclosure_denied",
}


def form_body(data, operation_id, *, follow_up=False):
    if not isinstance(data, dict) or set(data) - {
        "ticket",
        "selection",
        "objective",
        "checks",
        "context",
        "run_without_delegation",
    }:
        raise PortalError(400, "invalid_input", "Check the submitted fields.")
    checks = data.get("checks", [])
    if not isinstance(checks, list) or len(checks) > 32:
        raise PortalError(
            400, "invalid_input", "Provide up to 32 acceptance checks.", field="checks"
        )
    if not checks and not follow_up:
        raise PortalError(
            400, "invalid_input", "Add at least one acceptance check.", field="checks"
        )
    if any(not isinstance(check, str) or not check.strip() for check in checks):
        raise PortalError(400, "invalid_input", "Fill in each acceptance check.", field="checks")
    goal = data.get("objective")
    if not isinstance(goal, str) or not goal.strip():
        raise PortalError(400, "invalid_input", "Enter an objective.", field="objective")
    context = data.get("context", "")
    if not isinstance(context, str):
        raise PortalError(400, "invalid_input", "Enter text as context.", field="context")
    inputs = {
        "objective": goal,
        "requirements": [
            {"id": f"requirement-{i}", "description": check, "acceptance": [check]}
            for i, check in enumerate(checks, 1)
        ]
        or [
            {
                "id": "respond-to-follow-up",
                "description": "Address the follow-up request.",
                "acceptance": [
                    "The response directly addresses the message and any constraints it states."
                ],
            }
        ],
        **({"context": context} if context else {}),
    }
    validate_input(ATTEMPT["input_schema"], inputs)
    body = {"operation_id": operation_id, "selection": data.get("selection"), "input": inputs}
    if "run_without_delegation" in data:
        local_only = data["run_without_delegation"]
        if type(local_only) is not bool:
            raise PortalError(
                400, "invalid_input", "Choose whether LASA can delegate.", field="no-delegation"
            )
        body["delegation"] = "none" if local_only else "policy"
    try:
        protocol_contracts().validate_task_request(body, caller=True)
    except LasaError:
        raise PortalError(400, "invalid_offer", "Select a current task offer.") from None
    if body["selection"]["contract"] != ATTEMPT_REF:
        raise PortalError(400, "invalid_offer", "Select a current general task offer.")
    return body


def public(submission_id, record):
    return {
        "state": record["state"],
        "recovery_url": "/submissions/" + submission_id,
        **(
            {"task_url": "/tasks/" + record.get("root_id", record["task_id"])}
            if "task_id" in record
            else {}
        ),
        **({"problem": record["problem"]} if "problem" in record else {}),
    }


class Submissions:
    def __init__(self, state, native, settings):
        self.state = state
        self.native = native
        self.settings = settings

    def phase(self, body):
        return {
            "operation_id": body["operation_id"],
            "key": opaque(),
            "fingerprint": self.state.fingerprint(digest(body)),
            "sent": False,
        }

    async def start(self, owner, token, retention, data, *, parent_id=None):
        if not isinstance(data, dict):
            raise PortalError(400, "invalid_input", "Check the submitted fields.")
        ticket = self.state.read_ticket(data.get("ticket"), owner)
        submission_id = ticket["id"]
        operation_id = "portal-task-" + submission_id
        body = form_body(data, operation_id, follow_up=parent_id is not None)
        record = self.state.submission(owner, submission_id)
        if record is None:
            offer = await self.native.select(token, body["selection"])
            if (
                request_input_size(body) > offer["max_budget"]["input_bytes"]
                or len(canonical(body)) > self.settings.body_bytes
            ):
                raise PortalError(
                    413, "input_size", "This input exceeds the selected offer's limit."
                )
            session_body = {
                "operation_id": "portal-session-" + submission_id,
                "label": "Portal task",
            }
            target = {"session": self.phase(session_body)}
            if parent_id:
                parent, _ = await self.native.task(token, parent_id, control=True)
                thread = await self.native.conversation(token, parent_id, 9007199254740990)
                if thread["follow_up_processing"] is None or thread["latest_task_id"] != parent_id:
                    raise PortalError(
                        409, "task_state_conflict", "Open the latest released result to follow up."
                    )
                target = {
                    "parent_id": parent_id,
                    "root_id": thread["task_id"],
                    "session_id": resource(parent["session_id"]),
                }
            record = self.state.reserve(
                owner,
                submission_id,
                {
                    "state": "checking",
                    "selection": body["selection"],
                    **target,
                    "task": self.phase(body),
                    "retry_until": min(ticket["exp"], now() + retention),
                },
            )
        if record.get("parent_id") != parent_id or not hmac.compare_digest(
            record["task"]["fingerprint"], self.state.fingerprint(digest(body))
        ):
            raise PortalError(
                409, "idempotency_conflict", "This submission already has different input."
            )
        return await self.advance(owner, token, submission_id, record, body)

    async def read(self, owner, token, submission_id):
        record = self.state.submission(owner, submission_id)
        if record is None:
            raise PortalError(404, "not_found", "That submission is unavailable.")
        return await self.advance(owner, token, submission_id, record, None)

    async def receipt(self, token, phase, kind, selection=None):
        try:
            value = await self.native.get(
                token, "/operations/" + resource(phase["operation_id"]), schema="OperationReceipt"
            )
        except PortalError as error:
            if error.status == 404 and error.code == "not_found":
                return None
            raise
        if (
            value["resource_type"] != kind
            or value["operation_id"] != phase["operation_id"]
            or value["http_status"] != (201 if kind == "session" else 202)
            or selection is not None
            and value.get("selection") != selection
            or not hmac.compare_digest(
                phase["fingerprint"], self.state.fingerprint(value["request_digest"])
            )
        ):
            raise PortalError(502, "receipt_mismatch", "LASA returned an unexpected receipt.")
        return resource(value["resource_id"])

    async def advance(self, owner, token, submission_id, record, body):
        if record["state"] in {"recorded", "rejected"}:
            return public(submission_id, record)
        if record.get("lease", 0) > now():
            return public(submission_id, {**record, "state": "checking"})
        if body is None and record.get("next_check", 0) > now():
            return public(submission_id, record)
        record["lease"] = now() + self.settings.timeout_seconds * 10
        record["state"] = "checking"

        def save():
            self.state.save_submission(owner, submission_id, record)

        save()
        try:
            await self.advance_session(token, record, body is not None, save)
            if "session_id" in record:
                await self.advance_task(token, record, body, save)
            if "task_id" in record:
                record["state"] = "recorded"
            elif record["state"] != "rejected":
                record["state"] = "unconfirmed"
        except PortalError as error:
            record["state"] = "unconfirmed"
            if error.status == 401:
                raise
        finally:
            record.pop("lease", None)
            record["next_check"] = now() + 2
            save()
        return public(submission_id, record)

    async def advance_session(self, token, record, can_post, save):
        if "session_id" in record:
            return
        phase = record["session"]
        session_id = await self.receipt(token, phase, "session") if phase["sent"] else None
        if session_id:
            session = await self.native.get(token, "/sessions/" + session_id, schema="Session")
        elif can_post and now() < record["retry_until"]:
            body = {"operation_id": phase["operation_id"], "label": "Portal task"}
            session = await self.send(token, record, phase, body, "/sessions", "Session", save)
        else:
            return
        if session:
            if session["service_id"] != self.settings.lasa_service_id or (
                session_id is not None and session["session_id"] != session_id
            ):
                raise PortalError(502, "native_protocol", "LASA returned an unexpected session.")
            record["session_id"] = resource(session["session_id"])
            record["retry_until"] = min(record["retry_until"], epoch(session["retention_until"]))
            save()

    async def advance_task(self, token, record, body, save):
        if record["state"] == "rejected":
            return
        phase = record["task"]
        task_id = (
            await self.receipt(token, phase, "task", record["selection"]) if phase["sent"] else None
        )
        if task_id:
            record["task_id"] = task_id
        elif body is not None and now() < record["retry_until"]:
            parent_id = record.get("parent_id")
            path = (
                "/tasks/" + parent_id + "/follow-ups"
                if parent_id
                else "/sessions/" + record["session_id"] + "/tasks"
            )
            task = await self.send(token, record, phase, body, path, "ConsumerTask", save)
            if task:
                if (
                    task["session_id"] != record["session_id"]
                    or task["operation_id"] != phase["operation_id"]
                    or task["service_id"] != self.settings.lasa_service_id
                    or task["selection"] != record["selection"]
                    or not parent_id
                    and not hmac.compare_digest(
                        phase["fingerprint"], self.state.fingerprint(task["request_digest"])
                    )
                ):
                    raise PortalError(502, "native_protocol", "LASA returned an unexpected task.")
                record["task_id"] = resource(task["task_id"])

    async def send(self, token, record, phase, body, path, schema, save):
        was_sent = phase["sent"]
        phase["sent"] = True
        save()
        try:
            result, _ = await self.native.mutation(token, path, body, phase["key"], schema)
            return result
        except PortalError as error:
            kind = "session" if schema == "Session" else "task"
            recovered = await self.receipt(
                token, phase, kind, record["selection"] if kind == "task" else None
            )
            if recovered:
                if kind == "session":
                    return await self.native.get(token, "/sessions/" + recovered, schema="Session")
                record["task_id"] = recovered
            elif not was_sent and error.code in DEFINITE_REJECTIONS and error.status < 500:
                record["state"] = "rejected"
                record["problem"] = {
                    "status": error.status,
                    "code": error.code,
                    "message": error.message,
                }
            elif error.status == 401:
                raise
            return None
