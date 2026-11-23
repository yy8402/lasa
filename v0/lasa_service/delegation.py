"""Bounded child operations, receiver ceilings, result verification, and reconciliation."""

import asyncio
import copy
import hashlib
import time

from . import PROTOCOL_VERSION
from .auth import static_workload_identity
from .capabilities import epoch, require
from .contracts import canonical, digest, parse_json, request_digest
from .errors import LasaError
from .evidence import validate_child_readbacks
from .grants import find_grant, intersect_grants
from .preconditions import check_inputs, request_input_size, restrict
from .routing import fallback_input
from .store import TERMINAL, encode, identity, zero


class DelegationController:
    def __init__(self, coordinator):
        self.coordinator = coordinator

    def save(self, child):
        self.coordinator.store.save_child(child)

    async def peer_for(self, child):
        peer = self.coordinator.peers.get(child["service_id"])
        binding = child["peer_binding"]
        require(
            peer is not None and binding["protocol"] == PROTOCOL_VERSION, "peer_unavailable", 503
        )
        if peer.base is None:
            await peer.negotiate()
        require(peer.base == binding["base_url"], "peer_unavailable", 503)
        return peer

    async def child_trace(self, child, after):
        require("task_id" in child, "peer_unavailable", 503)
        peer = await self.peer_for(child)
        binding = child["peer_binding"]
        authentication = peer.settings.get("authentication", {})
        issuer = authentication.get("historical_jwt_issuer")
        if issuer and child["state"] in TERMINAL - {"indeterminate"}:
            sender, receiver = self.coordinator.config.service_id, peer.service_id
            subject = authentication["subject"]
            envelope = child["request"]["delegation"]
            if (
                binding["workload"] == {"iss": issuer, "sub": subject, "aud": receiver}
                and envelope["parent_service_id"] == sender
                and envelope["recipient_service_id"] == receiver
            ):
                binding = {
                    **binding,
                    "workload": static_workload_identity(subject, sender, receiver),
                }
        url = binding["base_url"] + "/tasks/" + child["task_id"] + "/events"
        return await peer.request("GET", f"{url}?after_sequence={after}&limit=100", binding=binding)

    async def receipt(self, peer, binding, body, kind):
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
        return receipt["resource_id"]

    async def create(self, peer, binding, url, body, kind, check):
        expected = 202 if kind == "task" else 201
        uncertain = False
        for _ in range(2):
            check()
            try:
                value, status, _ = await peer.request(
                    "POST", url, body, body["operation_id"], binding=binding
                )
                if status == expected or (not uncertain and 400 <= status < 500 and status != 408):
                    return value, status
            except LasaError:
                pass
            uncertain = True
            try:
                resource_id = await self.receipt(peer, binding, body, kind)
                if resource_id:
                    value, status, _ = await peer.request(
                        "GET", binding["base_url"] + f"/{kind}s/" + resource_id, binding=binding
                    )
                    if status == 200:
                        require(value.get(kind + "_id") == resource_id, "verification_failed", 502)
                        return value, expected
            except LasaError as exc:
                if exc.code in {"verification_failed", "incompatible_protocol"}:
                    raise
        raise LasaError("peer_unavailable", 503)

    def scope(self, task_id, step, contract, peer):
        c = self.coordinator
        c.check_active(task_id)
        authority = c.authority(task_id)
        request = c.request(task_id)
        rule = c.authorization.rule(c.principal(task_id), request["authorization_ref"])
        require(
            authority["limits"]["max_hops"] > 0
            and peer.service_id not in c.routing.ancestry(request),
            "precondition_failed",
            422,
        )
        grants = intersect_grants(authority["delegation_grants"], rule["delegation_grants"])
        grant = find_grant(grants, c.config.service_id, peer.service_id, contract)
        origin = find_grant(grants, c.config.service_id, peer.service_id, step["contract"])
        require(grant is not None and origin is not None, "disclosure_denied", 403)
        ceiling = c.current_ceiling(task_id)
        require(
            all(
                used <= ceiling[key] for key, used in c.store.usage(task_id, reserved=True).items()
            ),
            "capacity_exhausted",
            429,
        )
        scoped = restrict(authority, rule["effects"], rule["resources"])
        scoped = restrict(scoped, grant["effects"], grant["resources"])
        scoped["resources"] = [resource for resource in scoped["resources"] if resource["actions"]]
        scoped["limits"] = step["allocation"]
        reachable = {peer.service_id}
        onward = []
        for _ in range(step["allocation"]["max_hops"]):
            edges = [
                edge
                for edge in grants
                if edge["sender_service_id"] in reachable
                and edge["receiver_service_id"]
                not in [*c.routing.ancestry(request), peer.service_id]
                and edge not in onward
            ]
            onward.extend(edges)
            reachable = {edge["receiver_service_id"] for edge in edges}
            if not reachable:
                break
        scoped["delegation_grants"] = onward
        scoped["content_diagnostics_allowed"] &= rule["content_diagnostics"]
        disclosures = set(grant["disclosure_resources"]) & set(origin["disclosure_resources"])
        return scoped, disclosures

    def prepare_inputs(
        self, task_id, step, peer, offer, inputs, prior_artifacts, dependency_resources
    ):
        c = self.coordinator
        scoped, disclosures = self.scope(task_id, step, offer["contract"], peer)
        terms = offer["restrictions"]
        scoped = restrict(scoped, terms["allowed_effects"], terms["resources"])
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
        require(sources <= disclosures, "disclosure_denied", 403)
        ceiling = {
            key: scoped[key]
            for key in (
                "resources",
                "allowed_effects",
                "delegation_grants",
                "content_diagnostics_allowed",
            )
        }
        return ceiling, artifacts

    async def execute(
        self, task_id, step, inputs, predecessors, prior_artifacts, dependency_resources
    ):
        c = self.coordinator
        request = c.request(task_id)
        row, _ = c.store.task(task_id)
        private_plan = parse_json(row["plan"])
        selected = private_plan["offers"][step["step_id"]]
        authority = c.authority(task_id)
        allocation = step["allocation"]
        require(
            len(c.store.children(task_id)) < c.config.document["limits"]["max_children"],
            "capacity_exhausted",
            429,
        )
        require(
            time.time() < epoch(allocation["deadline"]) < epoch(authority["limits"]["deadline"]),
            "deadline_exceeded",
            422,
        )
        delegated_input = inputs
        if selected["fallback"]:
            delegated_input = fallback_input(
                c.registry.get(step["contract"]),
                inputs,
                private_plan["document"]["requirements"],
                step["requirement_ids"],
            )
            rule = c.authorization.rule(c.principal(task_id), request["authorization_ref"])
            grants = intersect_grants(authority["delegation_grants"], rule["delegation_grants"])
            eligible = [
                peer
                for peer in c.peers.values()
                if peer.service_id not in c.routing.ancestry(request)
                and find_grant(grants, c.config.service_id, peer.service_id, step["contract"])
            ]
            require(
                [peer.service_id for peer in eligible] == selected["absence_peers"],
                "authority_denied",
                403,
            )
            for peer in eligible:
                snapshot = await c.routing.catalog(peer, step["contract"])
                require(snapshot is not None and not snapshot["offers"], "offer_changed", 409)

        failure = LasaError("peer_unavailable", 503)
        for route in selected["routes"]:
            peer = c.peers[route["service_id"]]
            try:
                self.scope(task_id, step, route["offer"]["contract"], peer)
                async with asyncio.timeout(peer.settings["request_timeout_seconds"]):
                    offer = await peer.refresh_offer(route["offer"])
                ceiling, artifacts = self.prepare_inputs(
                    task_id,
                    step,
                    peer,
                    offer,
                    delegated_input,
                    prior_artifacts,
                    dependency_resources,
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
            "requested_limits": allocation,
            "authorization_ref": offer["authorization_ref"],
            "diagnostics": request["diagnostics"]
            if authority["content_diagnostics_allowed"]
            else "metadata",
        }
        if predecessors:
            body["dependency_results"] = {
                key: result["output"] for key, result in predecessors.items()
            }
        body["delegation"] = {
            "delegation_id": delegation_id,
            "root_task_id": request.get("delegation", {}).get("root_task_id", task_id),
            "parent_service_id": c.config.service_id,
            "recipient_service_id": peer.service_id,
            "parent_task_id": task_id,
            "step_id": step["step_id"],
            "requirement_ids": step["requirement_ids"],
            "ancestry": c.routing.ancestry(request),
            "remaining_hops": allocation["max_hops"],
            "request_digest": request_digest(body),
            "allocation": allocation,
            "disclosed_artifacts": artifacts,
            "dependency_resources": sorted(dependency_resources),
            "authority_ceiling": ceiling,
        }
        input_bytes = request_input_size(body)
        require(input_bytes <= allocation["budget"]["input_bytes"], "capacity_exhausted", 429)
        child = {
            "delegation_id": delegation_id,
            "parent_task_id": task_id,
            "service_id": peer.service_id,
            "peer_binding": binding,
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
        try:
            c.hit("before_child_dispatch", task_id)
            session_body = {
                "operation_id": delegation_id + "-session",
                "label": "Delegated " + step["step_id"],
            }
            child["session_operation_id"] = session_body["operation_id"]
            self.save(child)
            value, status = await self.create(
                peer,
                binding,
                base + "/sessions",
                session_body,
                "session",
                lambda: c.check_active(task_id),
            )
            require(status == 201, "peer_unavailable", 503)
            c.contracts.validate("Session", value, "incompatible_protocol", 502)
            require(value["service_id"] == child["service_id"], "incompatible_protocol", 502)
            child["session_id"] = value["session_id"]
            child["state"] = "session_created"
            self.save(child)
            ceiling, artifacts = self.prepare_inputs(
                task_id, step, peer, offer, delegated_input, prior_artifacts, dependency_resources
            )
            body["delegation"].update(authority_ceiling=ceiling, disclosed_artifacts=artifacts)
            body["diagnostics"] = (
                request["diagnostics"] if ceiling["content_diagnostics_allowed"] else "metadata"
            )
            body["delegation"]["request_digest"] = request_digest(body)
            input_bytes = request_input_size(body)
            require(input_bytes <= allocation["budget"]["input_bytes"], "capacity_exhausted", 429)

            def check_submission():
                current, visible = self.prepare_inputs(
                    task_id,
                    step,
                    peer,
                    offer,
                    delegated_input,
                    prior_artifacts,
                    dependency_resources,
                )
                require(current == ceiling and visible == artifacts, "authority_denied", 403)

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
            value, status = await self.create(
                peer,
                binding,
                base + "/sessions/" + child["session_id"] + "/tasks",
                body,
                "task",
                check_submission,
            )
            if status != 202:
                self.settle_child(child, state="rejected", effect="none", usage=zero())
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
                    value, status, _ = await peer.request(
                        "GET", base + "/tasks/" + child["task_id"], binding=binding
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
                current_budget = c.current_ceiling(task_id)
                left = {key: max(0, current_budget[key] - spent) for key, spent in baseline.items()}
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
            result["disclosure_resources"] = sorted(
                dependency_resources | {resource["resource"] for resource in ceiling["resources"]}
            )
            return result
        except (TimeoutError, asyncio.CancelledError):
            if child["dispatched"] and child["state"] not in TERMINAL:
                await asyncio.shield(self.cancel_and_reconcile(child))
            elif not child["dispatched"]:
                self.settle_child(child, state="failed", effect="none", usage=zero())
            raise
        except Exception:
            if child["dispatched"] and child["state"] not in TERMINAL:
                child["state"] = "unknown"
                self.save(child)
            elif not child["dispatched"]:
                self.settle_child(child, state="failed", effect="none", usage=zero())
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
        child["task_id"] = value["task_id"]
        if state not in TERMINAL:
            child["state"] = state
            self.save(child)
            return
        usage = None
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
            usage = copy.deepcopy(value["result"]["usage"])
            usage["delegations"] += 1
        else:
            effect = (
                "unknown"
                if state == "indeterminate"
                else value.get("problem", {}).get("effect_disposition", "unknown")
            )
        child["terminal_digest"] = digest(value)
        self.settle_child(child, state=state, effect=effect, usage=usage)

    def settle_child(self, child, *, state, effect, usage):
        store = self.coordinator.store
        child.update(state=state, effect_disposition=effect)
        with store.transaction():
            if effect != "unknown":
                row = store.db.execute(
                    "SELECT reserved FROM allocations WHERE task_id=? AND operation_id=?",
                    (child["parent_task_id"], child["delegation_id"]),
                ).fetchone()
                reserved = parse_json(row["reserved"])
                store.settle(
                    child["parent_task_id"],
                    child["delegation_id"],
                    usage if usage is not None else reserved,
                )
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
                    resource_id = await self.receipt(peer, binding, child["request"], "task")
                    if resource_id is None:
                        return
                    child["task_id"] = resource_id
                    self.save(child)
                url = binding["base_url"] + "/tasks/" + child["task_id"]
                value, status, headers = await peer.request("GET", url, binding=binding)
                if status != 200:
                    return
                self.receive_task(child, value)
                if not cancel or child["state"] in TERMINAL:
                    return
                body = {"operation_id": child["delegation_id"] + "-cancel"}
                value, status, _ = await peer.request(
                    "POST",
                    url + "/cancel",
                    body,
                    body["operation_id"],
                    headers.get("etag"),
                    binding=binding,
                )
                while status in (200, 202):
                    self.receive_task(child, value)
                    if child["state"] in TERMINAL:
                        return
                    await asyncio.sleep(0.05)
                    value, status, _ = await peer.request("GET", url, binding=binding)
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
