"""Bounded child operations, receiver ceilings, result verification, and reconciliation."""

import asyncio
import copy
import hashlib
import time

from . import PROTOCOL_VERSION
from .auth import permits_peer_effects
from .capabilities import epoch, require
from .consumer import artifact_release, artifact_view, require_public_data
from .content_security import Transfer, task_inspection
from .contracts import canonical, digest, parse_json, request_digest
from .errors import LasaError
from .grants import execution_terms, find_grant, intersect_grants, subtree_charge
from .preconditions import check_inputs, request_input_size, restrict
from .recovery import omit_fields, optional_context
from .store import TERMINAL, encode, identity, zero

CONTENT_FAILURES = {"disclosure_denied", "content_gateway_unavailable"}


class DelegationController:
    def __init__(self, coordinator):
        self.coordinator = coordinator

    def save(self, child):
        self.coordinator.store.save_child(child)

    async def peer_for(self, child):
        self.coordinator.check_processing(child["parent_task_id"], "peer:" + child["service_id"])
        peer = self.coordinator.peers.get(child["service_id"])
        binding = child["peer_binding"]
        require(
            peer is not None and binding["protocol"] == PROTOCOL_VERSION, "peer_unavailable", 503
        )
        if peer.base is None:
            await peer.negotiate()
        require(peer.base == binding["base_url"], "peer_unavailable", 503)
        return peer

    async def receipt(self, peer, binding, body, kind, processing=None):
        receipt, status, _ = await peer.request(
            "GET", binding["base_url"] + "/operations/" + body["operation_id"], binding=binding
        )
        if status != 200:
            return None
        self.coordinator.contracts.validate(
            "OperationReceipt", receipt, "incompatible_protocol", 502
        )
        require(
            receipt["request_digest"] == digest(body)
            and receipt["resource_type"] == kind
            and receipt["operation_id"] == body["operation_id"]
            and receipt["http_status"] == (202 if kind == "task" else 201),
            "verification_failed",
            502,
        )
        if kind == "task":
            require(
                receipt["selection"] == body["selection"] and receipt["processing"] == processing,
                "verification_failed",
                502,
            )
        return receipt["resource_id"]

    async def create(self, peer, binding, url, body, kind, check, processing=None):
        expected = 202 if kind == "task" else 201
        uncertain = False
        for _ in range(2):
            check()
            try:
                value, status, _ = await peer.request(
                    "POST", url, body, body["operation_id"], binding=binding
                )
                content_refused = (
                    kind == "task"
                    and isinstance(value, dict)
                    and value.get("code") in CONTENT_FAILURES
                )
                if status == expected or (
                    not uncertain and ((400 <= status < 500 and status != 408) or content_refused)
                ):
                    return value, status
            except LasaError:
                pass
            uncertain = True
            try:
                resource_id = await self.receipt(peer, binding, body, kind, processing)
                if resource_id:
                    control = "?view=control" if kind == "task" else ""
                    value, status, _ = await peer.request(
                        "GET",
                        binding["base_url"] + f"/{kind}s/" + resource_id + control,
                        binding=binding,
                    )
                    if status == 200:
                        require(value.get(kind + "_id") == resource_id, "verification_failed", 502)
                        return value, expected
            except LasaError as exc:
                if exc.code in {"verification_failed", "incompatible_protocol"}:
                    raise
        raise LasaError("peer_unavailable", 503)

    def scope(self, task_id, step, contract, peer, execution):
        c = self.coordinator
        c.check_active(task_id)
        c.check_processing(task_id, "peer:" + peer.service_id)
        authority = c.authority(task_id)
        rule = c.current_rule(task_id)
        require(
            authority["limits"]["budget"]["delegations"] > 0
            and peer.service_id != c.config.service_id,
            "precondition_failed",
            422,
        )
        grants = intersect_grants(authority["delegation_grants"], rule["delegation_grants"])
        grant = find_grant(grants, c.config.service_id, peer.service_id, contract)
        require(grant is not None, "disclosure_denied", 403)
        require(
            execution_terms(grant) == execution,
            "offer_changed",
            409,
        )
        ceiling = c.current_ceiling(task_id)
        cap = authority.get("subtree_cap")
        if cap is not None:
            require(rule.get("subtree_cap") == cap, "offer_changed", 409)
            require(c.store.subtree_usage(task_id) <= cap, "capacity_exhausted", 429)
        require(
            all(
                used <= ceiling[key] for key, used in c.store.usage(task_id, reserved=True).items()
            ),
            "capacity_exhausted",
            429,
        )
        scoped = restrict(authority, rule["effects"], rule["resources"])
        scoped = restrict(scoped, grant["effects"], grant["resources"])
        scoped["limits"] = step["allocation"]
        return scoped, grant

    def prepare_inputs(
        self, task_id, step, peer, offer, inputs, prior_artifacts, dependency_resources, execution
    ):
        c = self.coordinator
        scoped, grant = self.scope(task_id, step, offer["contract"], peer, execution)
        terms = offer["restrictions"]
        require(
            permits_peer_effects(grant, offer),
            "authority_denied",
            403,
        )
        scoped = restrict(scoped, terms["allowed_effects"], scoped["resources"])
        scoped["resources"] = [resource for resource in scoped["resources"] if resource["actions"]]
        artifacts = check_inputs(
            c,
            task_id,
            c.registry.input(offer["contract"], inputs),
            inputs,
            scoped,
            terms["additional_preconditions"],
            prior_artifacts=prior_artifacts,
        )
        sources = dependency_resources | {
            item["manifest"].get("provenance", {}).get("resource", "workspace:self")
            for item in artifacts
        }
        require(sources <= set(grant["disclosure_resources"]), "disclosure_denied", 403)
        return [
            {"manifest": artifact_view(item["manifest"]), "text": item["text"]}
            for item in artifacts
        ]

    async def execute(self, task_id, step, inputs, predecessors, prior_artifacts, imports):
        c = self.coordinator
        request = c.request(task_id)
        row, _ = c.store.task(task_id)
        private_plan = parse_json(row["plan"])
        routes = private_plan["offers"][step["step_id"]]
        authority = c.authority(task_id)
        allocation = step["allocation"]
        require(
            time.time() < epoch(allocation["deadline"]) <= c.routing.child_deadline(authority),
            "deadline_exceeded",
            422,
        )
        delegated_input = inputs
        dependency_resources = {
            resource for item in imports for resource in item.get("resources", ())
        }

        failure = LasaError("peer_unavailable", 503)
        for route in routes:
            peer = c.peers[route["service_id"]]
            execution = route["execution"]
            try:
                self.scope(task_id, step, route["offer"]["contract"], peer, execution)
                async with asyncio.timeout(peer.settings["request_timeout_seconds"]):
                    offer = await peer.refresh_offer(route["offer"])
                require(peer.matches_execution(offer, execution), "offer_changed", 409)
                self.prepare_inputs(
                    task_id,
                    step,
                    peer,
                    offer,
                    delegated_input,
                    prior_artifacts,
                    dependency_resources,
                    execution,
                )
                binding = peer.binding()
                break
            except LasaError as exc:
                failure = exc
            except TimeoutError:
                failure = LasaError("peer_unavailable", 503)
        else:
            raise failure

        if offer["revision"] != route["offer"]["revision"]:
            c.store.event(
                task_id,
                "peer_offer_renewed",
                {
                    "step_id": step["step_id"],
                    "previous_revision": route["offer"]["revision"],
                    "revision": offer["revision"],
                },
            )
        delegation_id = identity("delegation")
        base = binding["base_url"]
        body = {
            "operation_id": delegation_id + "-task",
            "selection": {
                "contract": offer["contract"],
                "offer_id": offer["offer_id"],
                "offer_revision": offer["revision"],
                "catalog_view": offer["catalog_view"],
            },
            "input": delegated_input,
            "requested_limits": {
                "deadline": allocation["deadline"],
                "budget": {
                    key: value
                    for key, value in allocation["budget"].items()
                    if key != "delegations"
                },
            },
        }
        if imports:
            body["imports"] = [
                {
                    "label": item["step_id"] if "step_id" in item else item["label"],
                    **{key: item[key] for key in ("contract", "output", "output_digest")},
                }
                for item in imports
            ]
            require_public_data(c, task_id, body["imports"])
        assigned = set(step["requirement_ids"])
        requirements = [
            item
            for item in private_plan["document"]["requirements"]
            if item["requirement_id"] in assigned
        ]
        cap = authority.get("subtree_cap")
        charge = subtree_charge(execution, cap)
        child = {
            "delegation_id": delegation_id,
            "parent_task_id": task_id,
            "service_id": peer.service_id,
            "processing": offer["processing"],
            **({"subtree_charge": charge} if charge is not None else {}),
            "peer_binding": binding,
            "state": "reserved",
            "dispatched": False,
            "imported_artifacts": [],
            "step_contract": step["contract"],
            "step_id": step["step_id"],
        }
        amount = copy.deepcopy(allocation["budget"])
        amount["delegations"] = 1
        with c.store.transaction():
            c.store.settle(task_id, "step-reservation-" + step["step_id"], zero())
            details = {"step_id": step["step_id"]}
            if charge is not None:
                details["subtree_charge"] = charge
            c.reserve(task_id, delegation_id, "child", amount, details, subtree_cap=cap)
            self.save(child)
        try:
            c.hit("before_child_dispatch", task_id)
            artifacts = self.prepare_inputs(
                task_id,
                step,
                peer,
                offer,
                delegated_input,
                prior_artifacts,
                dependency_resources,
                execution,
            )
            if artifacts:
                body["attachments"] = artifacts
            require(
                request_input_size(body) <= allocation["budget"]["input_bytes"],
                "capacity_exhausted",
                429,
            )
            optional = optional_context(c.registry.get(offer["contract"])["input_schema"])

            def revise(candidate):
                revised_input = omit_fields(candidate["input"], optional)
                visible = self.prepare_inputs(
                    task_id,
                    step,
                    peer,
                    offer,
                    revised_input,
                    prior_artifacts,
                    dependency_resources,
                    execution,
                )
                revised = {**candidate, "input": revised_input}
                revised.pop("attachments", None)
                if visible:
                    revised["attachments"] = visible
                return revised

            body, dispatch = await c.content.check_request(
                Transfer(
                    "delegation.request",
                    "peer:" + peer.service_id,
                    "task",
                    delegation_id,
                    task_id,
                    request["selection"]["contract"]["id"],
                ),
                body,
                project=task_inspection,
                revise=revise
                if isinstance(delegated_input, dict) and optional & delegated_input.keys()
                else None,
                remaining=lambda: min(
                    c.remaining_seconds(task_id), epoch(allocation["deadline"]) - time.time()
                ),
            )
            delegated_input = body["input"]
            artifacts = body.get("attachments", [])
            input_bytes = request_input_size(body)
            require(input_bytes <= allocation["budget"]["input_bytes"], "capacity_exhausted", 429)

            def check_submission():
                c.check_active(task_id)
                c.check_processing(task_id, "peer:" + peer.service_id)
                require(time.time() < epoch(allocation["deadline"]), "deadline_exceeded", 422)
                c.content.ensure_current(dispatch)
                visible = self.prepare_inputs(
                    task_id,
                    step,
                    peer,
                    offer,
                    delegated_input,
                    prior_artifacts,
                    dependency_resources,
                    execution,
                )
                require(visible == artifacts, "authority_denied", 403)

            check_submission()
            session_body = {
                "operation_id": delegation_id + "-session",
                "label": "Delegated " + step["step_id"],
            }
            child["session_operation_id"] = session_body["operation_id"]
            self.save(child)
            async with asyncio.timeout(epoch(allocation["deadline"]) - time.time()):
                value, status = await self.create(
                    peer,
                    binding,
                    base + "/sessions",
                    session_body,
                    "session",
                    check_submission,
                )
            require(status == 201, "peer_unavailable", 503)
            c.contracts.validate("Session", value, "incompatible_protocol", 502)
            require(value["service_id"] == child["service_id"], "incompatible_protocol", 502)
            child["session_id"] = value["session_id"]
            child["state"] = "session_created"
            self.save(child)
            check_submission()
            child["request"] = body
            child["state"] = "submitting"
            child["dispatched"] = True
            self.save(child)
            c.diagnostics.call(
                task_id,
                delegation_id,
                "child",
                "started",
                body,
                reserved=amount,
                content={"service_id": child["service_id"], "request": body},
            )
            try:
                async with asyncio.timeout(epoch(allocation["deadline"]) - time.time()):
                    value, status = await self.create(
                        peer,
                        binding,
                        base + "/sessions/" + child["session_id"] + "/tasks",
                        body,
                        "task",
                        check_submission,
                        child["processing"],
                    )
            except (LasaError, asyncio.CancelledError, TimeoutError):
                c.content.outcome(dispatch, "delivery_unknown")
                raise
            c.content.outcome(dispatch, "delivered")
            if status != 202:
                self.settle_child(child, state="rejected", effect="none", usage=zero())
                code = value.get("code") if isinstance(value, dict) else None
                if code in c.contracts.schemas["Problem"]["properties"]["code"]["enum"]:
                    raise LasaError(code, status)
                raise LasaError("peer_unavailable", status)
            c.contracts.validate(
                "ConsumerTaskDisposition" if "effect_disposition" in value else "ConsumerTask",
                value,
                "incompatible_protocol",
                502,
            )
            self.check_linkage(child, value)
            child["task_id"] = value["task_id"]
            self.save(child)
            c.hit("after_child_dispatch", task_id)
            _, parent = c.check_active(task_id)
            parent["status"] = "waiting_child"
            c.store.save_task(parent)
            async with asyncio.timeout(epoch(allocation["deadline"]) - time.time()):
                control = await self.wait_for_child(child, peer, lambda: c.check_active(task_id))
            if child["effect_disposition"] == "unknown":
                raise LasaError("child_outcome_unknown", 503, effect="unknown")
            if child["state"] != "completed":
                raise LasaError(
                    control.get("problem", {}).get("code", "verification_failed"),
                    control.get("problem", {}).get("status", 422),
                )
            child["result_state"] = "pending"
            self.save(child)
            value = await self.fetch_result(child, peer, control)
            result = value["result"]
            c.registry.check_output(
                offer["contract"], delegated_input, result["output"], result["evidence"]
            )
            require(
                len(canonical(result["output"])) <= allocation["budget"]["output_bytes"],
                "verification_failed",
                502,
            )
            source = "peer:" + peer.service_id
            receive = await c.content.check(
                Transfer("delegation.response", source, "result", delegation_id, task_id, source),
                result,
                projection={"output": result},
                remaining=lambda: c.remaining_seconds(task_id),
            )
            c.content.remember_source(task_id, receive)
            c.content.outcome(receive, "accepted")
            child["upstream_artifact_ids"] = [
                artifact["artifact_id"] for artifact in result["artifacts"]
            ]
            self.save(child)
            artifact_ids = []
            artifact_map = {}
            downloaded = 0
            for manifest in result["artifacts"]:
                require(manifest["source_task_id"] == child["task_id"], "verification_failed", 502)
                url = base + "/tasks/" + child["task_id"] + "/artifacts/" + manifest["artifact_id"]
                async with peer.client.stream(
                    "GET", url, headers=peer.authentication_headers(binding)
                ) as response:
                    require(response.status_code == 200, "verification_failed", 502)
                    parts = []
                    size = 0
                    async for part in response.aiter_bytes():
                        size += len(part)
                        require(
                            size <= manifest["bytes"]
                            and downloaded + size <= allocation["budget"]["artifact_bytes"],
                            "verification_failed",
                            502,
                        )
                        parts.append(part)
                    data = b"".join(parts)
                require(
                    len(data) == manifest["bytes"]
                    and "sha256:" + hashlib.sha256(data).hexdigest() == manifest["digest"],
                    "verification_failed",
                    502,
                )
                downloaded += len(data)
                public_artifact = artifact_release(manifest, data)
                received = await c.content.check(
                    Transfer(
                        "delegation.response",
                        source,
                        "artifact",
                        manifest["artifact_id"],
                        task_id,
                        source,
                    ),
                    public_artifact,
                    projection=public_artifact,
                    media_type=manifest["media_type"],
                    remaining=lambda: c.remaining_seconds(task_id),
                )
                c.content.outcome(received, "accepted")
                artifact_id = identity("artifact")
                artifact_map[manifest["artifact_id"]] = artifact_id
                local_manifest = {**manifest, "artifact_id": artifact_id, "source_task_id": task_id}
                if c.registry.source_profile(offer["contract"]):
                    from .outcomes import source_resource

                    local_manifest["provenance"] = {
                        "kind": "operation-result",
                        "service_id": child["service_id"],
                        "operation_id": body["operation_id"],
                        "resource": source_resource(
                            c.registry.source_profile(offer["contract"]), parse_json(data)
                        ),
                        "contract": offer["contract"],
                        "input_digest": digest(delegated_input),
                        "result_digest": manifest["digest"],
                        "sequence": len(artifact_ids) + 1,
                    }
                c.store.db.execute(
                    "INSERT INTO artifacts VALUES(?,?,?,?,-1)",
                    (artifact_id, task_id, encode(local_manifest), data),
                )
                artifact_ids.append(artifact_id)
                child["imported_artifacts"] = artifact_ids
                self.save(child)
            usage = child["charged_budget"]
            c.diagnostics.call(
                task_id,
                delegation_id,
                "child",
                "finished",
                body,
                usage=usage,
                output=result,
                content={"service_id": child["service_id"], "result": result},
            )
            c.finish_delegated_execution(task_id)
            c.check_active(task_id)
            result = copy.deepcopy(result)
            for evidence in result["evidence"]:
                require(
                    set(evidence["artifact_ids"]) <= set(artifact_map), "verification_failed", 502
                )
                evidence["artifact_ids"] = [artifact_map[x] for x in evidence["artifact_ids"]]
            result = {
                "output": result["output"],
                "evidence": result["evidence"],
                "artifact_ids": artifact_ids,
            }
            async with c.peer_verification_locks.setdefault(task_id, asyncio.Lock()):
                require(
                    await c.planner.verify(
                        task_id,
                        c.registry.get(step["contract"]),
                        delegated_input,
                        result["output"],
                        result["evidence"],
                        requirements=requirements,
                        artifact_ids=result["artifact_ids"],
                        step_id=step["step_id"],
                        verified_steps=predecessors,
                    ),
                    "verification_failed",
                    422,
                )
            c.diagnostics.emit(
                task_id,
                "verification",
                {
                    "step_id": step["step_id"],
                    "contract": step["contract"],
                    "request_digest": request_digest(body),
                    "checks": result["evidence"],
                    "release": "accepted",
                },
            )
            for artifact_id in artifact_ids:
                c.store.db.execute(
                    "UPDATE artifacts SET released=0 WHERE id=? AND task_id=?",
                    (artifact_id, task_id),
                )
            child["result_state"] = "verified"
            self.save(child)
            result["verified_input_digest"] = digest(delegated_input)
            scoped, _ = self.scope(task_id, step, offer["contract"], peer, execution)
            result["disclosure_resources"] = sorted(
                dependency_resources
                | {item["resource"] for item in scoped["resources"] if item["actions"]}
            )
            return result
        except (TimeoutError, asyncio.CancelledError):
            if child["dispatched"] and child["state"] not in TERMINAL:
                await asyncio.shield(self.cancel_and_reconcile(child))
            elif not child["dispatched"]:
                self.settle_child(child, state="failed", effect="none", usage=zero())
            raise
        except Exception as exc:
            if child.get("result_state") == "pending":
                code = exc.code if isinstance(exc, LasaError) else None
                child["result_state"] = (
                    "withheld"
                    if code in CONTENT_FAILURES | {"authority_denied"}
                    else "unavailable"
                    if code == "peer_unavailable"
                    else "invalid"
                )
                self.save(child)
            if child["dispatched"] and child["state"] not in TERMINAL:
                child["state"] = "unknown"
                self.save(child)
            elif not child["dispatched"]:
                self.settle_child(child, state="failed", effect="none", usage=zero())
            raise

    @staticmethod
    def task_url(child):
        return child["peer_binding"]["base_url"] + "/tasks/" + child["task_id"]

    async def control(self, child, peer):
        c = self.coordinator
        c.check_processing(child["parent_task_id"], "peer:" + child["service_id"])
        value, status, headers = await peer.request(
            "GET", self.task_url(child) + "?view=control", binding=child["peer_binding"]
        )
        if status == 200:
            c.contracts.validate("ConsumerTaskDisposition", value, "incompatible_protocol", 502)
            self.check_linkage(child, value)
            require(
                value["revision"] >= child.get("control_revision", 0),
                "verification_failed",
                502,
            )
            child["control_revision"] = value["revision"]
            if value["status"] in TERMINAL:
                control_digest = digest(value)
                if child.get("terminal_digest") and child["effect_disposition"] != "unknown":
                    require(control_digest == child["terminal_digest"], "verification_failed", 502)
                child["terminal_digest"] = control_digest
                reservation = c.store.db.execute(
                    "SELECT reserved FROM allocations WHERE task_id=? AND operation_id=?",
                    (child["parent_task_id"], child["delegation_id"]),
                ).fetchone()
                usage = parse_json(reservation["reserved"])
                child["charged_budget"] = usage
                self.settle_child(
                    child, state=value["status"], effect=value["effect_disposition"], usage=usage
                )
            else:
                child["state"] = value["status"]
                self.save(child)
        return value, status, headers

    async def wait_for_child(self, child, peer, check):
        delay = 0.05
        while True:
            check()
            try:
                value, status, _ = await self.control(child, peer)
            except LasaError as exc:
                if exc.code != "peer_unavailable":
                    raise
                status = 503
            if status == 200 and child["state"] in TERMINAL:
                return value
            require(status in {200, 408, 429} or 500 <= status < 600, "child_outcome_unknown", 503)
            await asyncio.sleep(delay)
            delay = min(1, delay * 2)

    async def fetch_result(self, child, peer, control):
        c = self.coordinator
        value, status, _ = await peer.request(
            "GET", self.task_url(child), binding=child["peer_binding"]
        )
        if status != 200:
            code = value.get("code") if isinstance(value, dict) else None
            raise LasaError(
                code if code in CONTENT_FAILURES | {"authority_denied"} else "peer_unavailable",
                status,
            )
        c.contracts.validate("ConsumerTask", value, "incompatible_protocol", 502)
        expected = self.check_linkage(child, value)
        result = value.get("result", {})
        receipt = result.get("receipt", {})
        require(
            value["status"] == "completed"
            and value["revision"] == control["revision"]
            and result["request_digest"] == expected
            and result["contract"] == child["request"]["selection"]["contract"]
            and result["effect_disposition"] == control["effect_disposition"] == "none"
            and receipt
            == {
                "service_id": child["service_id"],
                "task_id": child["task_id"],
                "operation_id": child["request"]["operation_id"],
                "selection": child["request"]["selection"],
                "processing": child["processing"],
                "result_digest": digest({k: v for k, v in result.items() if k != "receipt"}),
            },
            "verification_failed",
            502,
        )
        return value

    @staticmethod
    def check_linkage(child, value):
        request = child["request"]
        expected_digest = request_digest(request)
        require(
            value["task_id"] == child.get("task_id", value["task_id"])
            and value["service_id"] == child["service_id"]
            and value["session_id"] == child["session_id"]
            and value["operation_id"] == request["operation_id"]
            and value["request_digest"] == expected_digest
            and value["selection"] == request["selection"],
            "verification_failed",
            502,
        )
        return expected_digest

    def settle_child(self, child, *, state, effect, usage):
        store = self.coordinator.store
        child.update(state=state, effect_disposition=effect)
        with store.transaction():
            if effect != "unknown":
                if child["dispatched"]:
                    usage = {**usage, "delegations": 1}
                store.settle(child["parent_task_id"], child["delegation_id"], usage)
            self.save(child)

    async def observe(self, child, *, cancel=False):
        c = self.coordinator
        try:
            async with asyncio.timeout(
                c.config.document["limits"]["reconciliation_timeout_seconds"]
            ):
                peer = await self.peer_for(child)
                binding = child["peer_binding"]
                if "task_id" not in child:
                    resource_id = await self.receipt(
                        peer, binding, child["request"], "task", child["processing"]
                    )
                    if resource_id is None:
                        return
                    child["task_id"] = resource_id
                    self.save(child)
                body = {"operation_id": child["delegation_id"] + "-cancel"}
                for _ in range(2):
                    _, status, headers = await self.control(child, peer)
                    if status != 200 or not cancel or child["state"] in TERMINAL:
                        return
                    try:
                        _, status, _ = await peer.request(
                            "POST",
                            self.task_url(child) + "/cancel",
                            body,
                            body["operation_id"],
                            headers.get("etag"),
                            binding=binding,
                        )
                    except LasaError as exc:
                        if exc.code != "peer_unavailable":
                            raise
                        continue
                    if status == 412:
                        continue
                    if status in {200, 202}:
                        await self.wait_for_child(child, peer, lambda: None)
                    return
        except (LasaError, TimeoutError):
            return

    async def cancel_and_reconcile(self, child):
        await self.observe(child, cancel=True)

    async def reconcile_parent(self, task_id):
        await asyncio.gather(
            *(
                self.observe(child, cancel=True)
                for child in self.coordinator.store.children(task_id, pending=True)
            )
        )
