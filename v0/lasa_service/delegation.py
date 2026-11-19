"""Bounded child operations, receiver ceilings, result verification, and reconciliation."""

import asyncio
import copy
import hashlib
import time

from .capabilities import epoch, require
from .contracts import canonical, digest, parse_json, request_digest
from .errors import LasaError
from .evidence import validate_child_readbacks
from .preconditions import check_inputs, request_input_size, restrict
from .routing import fallback_input
from .store import TERMINAL, encode, identity, zero


class DelegationController:
    def __init__(self, coordinator):
        self.coordinator = coordinator

    async def mutate(self, method, url, body, key):
        last = None
        for _ in range(2):
            try:
                value, status, headers = await self.coordinator.peer.request(method, url, body, key)
                if status < 500:
                    return value, status, headers
                last = LasaError("peer_unavailable", 503)
            except LasaError as exc:
                last = exc
        raise last

    def save(self, child):
        self.coordinator.store.save_child(child)

    def current_ceiling(self, task_id, contract):
        c = self.coordinator
        authority = c.authority(task_id)
        request = c.request(task_id)
        rule = c.authorization.rule(c.principal(task_id), request["authorization_ref"])
        require(
            contract in authority["allowed_delegated_contracts"]
            and contract in rule["delegated_contracts"],
            "authority_denied",
            403,
        )
        peer = c.config.peer["expected_service_id"]
        require(
            peer in authority["allowed_disclosure_services"]
            and peer in rule["disclosure_services"],
            "disclosure_denied",
            403,
        )
        ceiling = c.current_ceiling(task_id)
        require(
            all(
                used <= ceiling[key] for key, used in c.store.usage(task_id, reserved=True).items()
            ),
            "capacity_exhausted",
            429,
        )
        resources = [
            {
                "resource": r["resource"],
                "actions": sorted(
                    set(r["actions"])
                    & set(
                        next(
                            (
                                x["actions"]
                                for x in rule["resources"]
                                if x["resource"] == r["resource"]
                            ),
                            [],
                        )
                    )
                ),
            }
            for r in authority["resources"]
        ]
        return {
            "resources": [r for r in resources if r["actions"]],
            "allowed_effects": sorted(set(authority["allowed_effects"]) & set(rule["effects"])),
            "allowed_disclosure_services": sorted(
                set(authority["allowed_disclosure_services"]) & set(rule["disclosure_services"])
            ),
            "allowed_delegated_contracts": [
                x
                for x in authority["allowed_delegated_contracts"]
                if x in rule["delegated_contracts"]
            ],
            "content_diagnostics_allowed": authority["content_diagnostics_allowed"]
            and rule["content_diagnostics"],
        }

    async def execute(self, task_id, step, inputs, dependencies, prior_artifacts):
        c = self.coordinator
        request = c.request(task_id)
        row, _ = c.store.task(task_id)
        private_plan = parse_json(row["plan"])
        selected = private_plan["offers"][step["step_id"]]
        offer = await c.peer.refresh_offer(selected["offer"])
        if offer["revision"] != selected["offer"]["revision"]:
            c.store.event(
                task_id,
                "peer_offer_renewed",
                {
                    "step_id": step["step_id"],
                    "previous_revision": selected["offer"]["revision"],
                    "revision": offer["revision"],
                },
            )
        authority = c.authority(task_id)
        require(
            len(c.store.children(task_id)) < c.config.document["limits"]["max_children"],
            "capacity_exhausted",
            429,
        )
        delegated_input = inputs
        if selected["fallback"]:
            delegated_input = fallback_input(
                c.registry.get(step["contract"]),
                inputs,
                private_plan["document"]["requirements"],
                step["requirement_ids"],
            )
        definition = c.registry.input(offer["contract"], delegated_input)
        allocation = copy.deepcopy(step["allocation"])
        scoped = restrict(
            authority, offer["restrictions"]["allowed_effects"], offer["restrictions"]["resources"]
        )
        scoped["limits"] = allocation
        artifacts = check_inputs(
            c,
            task_id,
            definition,
            delegated_input,
            scoped,
            offer["restrictions"]["additional_preconditions"],
            prior_artifacts=prior_artifacts,
        )
        parent_deadline = authority["limits"]["deadline"]
        remaining = epoch(allocation["deadline"]) - time.time()
        require(
            remaining > 0 and epoch(allocation["deadline"]) < epoch(parent_deadline),
            "deadline_exceeded",
            422,
        )
        delegation_id = identity("delegation")
        ceiling = {
            key: copy.deepcopy(authority[key])
            for key in [
                "resources",
                "allowed_effects",
                "allowed_disclosure_services",
                "allowed_delegated_contracts",
                "content_diagnostics_allowed",
            ]
        }
        rule = c.authorization.rule(c.principal(task_id), request["authorization_ref"])
        require(
            offer["contract"] in authority["allowed_delegated_contracts"]
            and offer["contract"] in rule["delegated_contracts"],
            "authority_denied",
            403,
        )
        require(
            c.config.peer["expected_service_id"] in authority["allowed_disclosure_services"]
            and c.config.peer["expected_service_id"] in rule["disclosure_services"],
            "disclosure_denied",
            403,
        )
        body = {
            "operation_id": delegation_id + "-task",
            "selection": {
                "contract": offer["contract"],
                "offer_id": offer["offer_id"],
                "offer_revision": offer["revision"],
                "catalog_view": offer["catalog_view"],
            },
            "input": delegated_input,
            "requested_limits": allocation,
            "authorization_ref": offer["authorization_ref"],
            "diagnostics": request["diagnostics"]
            if authority["content_diagnostics_allowed"]
            else "metadata",
        }
        if dependencies:
            body["dependency_results"] = dependencies
        ancestry = request.get("delegation", {}).get("ancestry", []) + [c.config.service_id]
        body["delegation"] = {
            "delegation_id": delegation_id,
            "root_task_id": request.get("delegation", {}).get("root_task_id", task_id),
            "parent_service_id": c.config.service_id,
            "parent_task_id": task_id,
            "step_id": step["step_id"],
            "requirement_ids": step["requirement_ids"],
            "ancestry": ancestry,
            "remaining_hops": allocation["max_hops"],
            "request_digest": request_digest(body),
            "allocation": allocation,
            "disclosed_artifacts": artifacts,
            "authority_ceiling": ceiling,
        }
        input_bytes = request_input_size(body)
        require(input_bytes <= allocation["budget"]["input_bytes"], "capacity_exhausted", 429)
        child = {
            "delegation_id": delegation_id,
            "parent_task_id": task_id,
            "service_id": c.config.peer["expected_service_id"],
            "state": "reserved",
            "dispatched": False,
            "imported_artifacts": [],
            "request": body,
            "step_contract": step["contract"],
            "step_id": step["step_id"],
        }
        amount = copy.deepcopy(allocation["budget"])
        amount["delegations"] += 1
        with c.store.transaction():
            c.store.settle(task_id, "step-reservation-" + step["step_id"], zero())
            c.reserve(task_id, delegation_id, "child", amount, {"step_id": step["step_id"]})
            self.save(child)
        c.hit("before_child_dispatch", task_id)
        try:
            session_body = {
                "operation_id": delegation_id + "-session",
                "label": "Delegated " + step["step_id"],
            }
            value, status, _ = await self.mutate(
                "POST", c.peer.base + "/sessions", session_body, session_body["operation_id"]
            )
            require(status == 201, "peer_unavailable", 503)
            c.contracts.validate("Session", value, "incompatible_protocol", 502)
            require(value["service_id"] == child["service_id"], "incompatible_protocol", 502)
            child["session_id"] = value["session_id"]
            child["state"] = "session_created"
            self.save(child)
            body["delegation"]["authority_ceiling"] = self.current_ceiling(
                task_id, offer["contract"]
            )
            if artifacts:
                ceiling = body["delegation"]["authority_ceiling"]
                narrowed = restrict(scoped, ceiling["allowed_effects"], ceiling["resources"])
                require(
                    check_inputs(
                        c,
                        task_id,
                        definition,
                        delegated_input,
                        narrowed,
                        offer["restrictions"]["additional_preconditions"],
                        prior_artifacts=prior_artifacts,
                    )
                    == artifacts,
                    "precondition_failed",
                    422,
                )
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
            value, status, _ = await self.mutate(
                "POST",
                c.peer.base + "/sessions/" + child["session_id"] + "/tasks",
                body,
                body["operation_id"],
            )
            if status != 202:
                child["state"] = "rejected"
                self.save(child)
                raise LasaError("offer_changed" if status == 409 else "peer_unavailable", status)
            self.receive_task(child, value)
            c.hit("after_child_dispatch", task_id)
            _, parent = c.check_active(task_id)
            parent["status"] = "waiting_child"
            c.store.save_task(parent)
            async with asyncio.timeout(max(0.001, epoch(allocation["deadline"]) - time.time())):
                while value["status"] not in TERMINAL:
                    c.check_active(task_id)
                    await asyncio.sleep(0.05)
                    value, status, _ = await c.peer.request(
                        "GET", c.peer.base + "/tasks/" + child["task_id"]
                    )
                    require(status == 200, "child_outcome_unknown", 503)
                    self.receive_task(child, value)
            if child["effect_disposition"] == "unknown":
                raise LasaError("child_outcome_unknown", 503, effect="unknown")
            require(value["status"] == "completed", "verification_failed", 422)
            result = value["result"]
            require(
                all(result["usage"][key] <= allocation["budget"][key] for key in result["usage"]),
                "verification_failed",
                502,
            )
            c.registry.check_output(
                offer["contract"], delegated_input, result["output"], result["evidence"]
            )
            require(
                result["usage"]["input_bytes"] >= input_bytes
                and result["usage"]["output_bytes"] >= len(canonical(result["output"])),
                "verification_failed",
                502,
            )
            artifact_ids = []
            artifact_map = {}
            downloaded = 0
            for manifest in result["artifacts"]:
                require(manifest["source_task_id"] == child["task_id"], "verification_failed", 502)
                url = (
                    c.peer.base
                    + "/tasks/"
                    + child["task_id"]
                    + "/artifacts/"
                    + manifest["artifact_id"]
                )
                async with c.peer.client.stream(
                    "GET", url, headers=c.peer.authentication_headers()
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
                require(downloaded <= result["usage"]["artifact_bytes"], "verification_failed", 502)
                artifact_id = identity("artifact")
                artifact_map[manifest["artifact_id"]] = artifact_id
                local_manifest = {**manifest, "artifact_id": artifact_id, "source_task_id": task_id}
                c.store.db.execute(
                    "INSERT INTO artifacts VALUES(?,?,?,?,-1)",
                    (artifact_id, task_id, encode(local_manifest), data),
                )
                artifact_ids.append(artifact_id)
                child["imported_artifacts"] = artifact_ids
                self.save(child)
            usage = copy.deepcopy(result["usage"])
            usage["delegations"] += 1
            with c.store.transaction():
                c.store.settle(task_id, delegation_id, usage)
                if readbacks := validate_child_readbacks(result):
                    child["workspace_readbacks"] = readbacks
                    self.save(child)
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
            if selected["fallback"]:
                require(result["output"]["disposition"] == "fulfilled", "verification_failed", 422)
                from .coordinator import ExecutionContext

                definition = c.registry.get(step["contract"])
                _, parent = c.store.task(task_id)
                baseline = c.store.usage(task_id, reserved=True)
                ceiling = c.current_ceiling(task_id)
                left = {key: max(0, ceiling[key] - spent) for key, spent in baseline.items()}
                pool = c.store.db.execute(
                    "SELECT reserved FROM allocations WHERE task_id=? AND operation_id='integration-reserve' AND state='reserved'",
                    (task_id,),
                ).fetchone()
                if pool:
                    for key, value in parse_json(pool["reserved"]).items():
                        left[key] += value
                context = ExecutionContext(
                    c,
                    task_id,
                    parent,
                    definition,
                    {
                        "contract": step["contract"],
                        "input": inputs,
                        "attempt_evidence": result["output"],
                        "instruction": c.config.prompts["fallback_conversion"],
                    },
                    {
                        "budget": left,
                        "deadline": request["requested_limits"]["deadline"],
                        "max_hops": 0,
                    },
                    None,
                    [],
                    c.workspace(parent["session_id"]),
                    baseline,
                )
                converted = await c.run_runtime(context)
                c.registry.check_output(
                    step["contract"], inputs, converted["output"], converted["evidence"]
                )
                converted["artifact_ids"] += artifact_ids
                result = converted
            else:
                result = {
                    "output": result["output"],
                    "evidence": result["evidence"],
                    "artifact_ids": artifact_ids,
                }
            require(
                await c.planner.verify(
                    task_id,
                    c.registry.get(step["contract"]),
                    inputs,
                    result["output"],
                    result["evidence"],
                    artifact_ids=result["artifact_ids"],
                    step_id=step["step_id"],
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
            return result
        except (TimeoutError, asyncio.CancelledError):
            if child["dispatched"] and child["state"] not in TERMINAL:
                await asyncio.shield(self.cancel_and_reconcile(child))
            raise
        except Exception:
            if child["dispatched"] and child["state"] not in TERMINAL:
                child["state"] = "unknown"
                self.save(child)
            raise

    def receive_task(self, child, value):
        self.coordinator.contracts.validate("Task", value, "incompatible_protocol", 502)
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
        state = value["status"]
        if state in TERMINAL:
            if state == "completed":
                require(
                    all(
                        value[key]["request_digest"] == expected_digest
                        and value[key]["contract"] == request["selection"]["contract"]
                        for key in ("admission", "result")
                    ),
                    "verification_failed",
                    502,
                )
                effect = value["result"]["effect_disposition"]
            else:
                effect = (
                    "unknown"
                    if state == "indeterminate"
                    else value.get("problem", {}).get("effect_disposition", "unknown")
                )
            child.update(effect_disposition=effect, terminal_digest=digest(value))
        child.update(task_id=value["task_id"], state=state)
        self.save(child)

    async def cancel_and_reconcile(self, child):
        c = self.coordinator
        if "task_id" not in child:
            return
        try:
            async with asyncio.timeout(
                c.config.document["limits"]["reconciliation_timeout_seconds"]
            ):
                url = c.peer.base + "/tasks/" + child["task_id"]
                value, status, headers = await c.peer.request("GET", url)
                if status != 200:
                    return
                self.receive_task(child, value)
                if child["state"] in TERMINAL:
                    return
                body = {"operation_id": child["delegation_id"] + "-cancel"}
                value, status, _ = await c.peer.request(
                    "POST", url + "/cancel", body, body["operation_id"], headers.get("etag")
                )
                while status in (200, 202):
                    self.receive_task(child, value)
                    if child["state"] in TERMINAL:
                        return
                    await asyncio.sleep(0.05)
                    value, status, _ = await c.peer.request("GET", url)
        except (LasaError, TimeoutError):
            return

    async def reconcile_parent(self, task_id):
        c = self.coordinator
        if not c.config.peer:
            return
        children = c.store.children(task_id, pending=True)
        if not children:
            return
        try:
            async with asyncio.timeout(
                c.config.document["limits"]["reconciliation_timeout_seconds"]
            ):
                if not c.peer.base:
                    await c.peer.discover(refresh=True)
                for child in children:
                    if "task_id" not in child:
                        receipt, status, _ = await c.peer.request(
                            "GET", c.peer.base + "/operations/" + child["request"]["operation_id"]
                        )
                        if status != 200:
                            continue
                        c.contracts.validate("OperationReceipt", receipt)
                        require(
                            receipt["request_digest"] == digest(child["request"])
                            and receipt["resource_type"] == "task",
                            "verification_failed",
                            502,
                        )
                        child["task_id"] = receipt["resource_id"]
                        self.save(child)
                    value, status, _ = await c.peer.request(
                        "GET", c.peer.base + "/tasks/" + child["task_id"]
                    )
                    if status != 200:
                        continue
                    self.receive_task(child, value)
        except (LasaError, TimeoutError):
            return
