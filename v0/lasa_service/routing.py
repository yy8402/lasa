"""Deterministic routing from verified claim, capacity, and authority facts."""

import asyncio
import copy
import time

from .auth import permits_peer_effects
from .capabilities import epoch, instant, reference, require
from .contracts import canonical, digest, parse_json
from .errors import LasaError
from .grants import (
    execution_terms,
    find_grant,
    intersect_grants,
    margin_with_clock_uncertainty,
    subtree_charge,
)
from .planning import check_allocation, check_responsibilities
from .preconditions import check_inputs, restrict
from .processing import DOMAIN_ONLY, permits_child


def decide(local, peer, policy):
    if peer == "matched" and (local != "sufficient" or policy["preferred_executor"] == "peer"):
        return "peer"
    return "local" if local == "sufficient" else "none"


class RoutingController:
    def __init__(self, coordinator):
        self.coordinator = coordinator

    async def catalog(self, peer, contract=None):
        try:
            if contract is None:
                return await peer.discover()
            return await peer.discover(refresh=True, contract=contract)
        except (LasaError, TimeoutError):
            return None

    async def suitability(self, peer, task_id, offer, inputs, authority, rule, grant, count):
        c = self.coordinator
        try:
            if not peer.matches_execution(offer, execution_terms(grant)):
                return "denied"
            if not permits_peer_effects(grant, offer) or not permits_child(authority, offer):
                return "denied"
            terms = offer["restrictions"]
            imports = c.request(task_id).get("imports", [])
            candidate = restrict(authority, rule["effects"], rule["resources"])
            candidate = restrict(candidate, grant["effects"], grant["resources"])
            candidate = restrict(candidate, terms["allowed_effects"], candidate["resources"])
            candidate["limits"] = dict(authority["limits"])
            used = c.store.usage(task_id, reserved=True)
            reserve = c.config.document["limits"]["integration_reserve"]
            if used["delegations"] + 1 > authority["limits"]["budget"]["delegations"]:
                return "unavailable"
            candidate["limits"]["budget"] = {
                key: min(
                    offer["max_budget"].get(key, 0),
                    max(
                        0, (authority["limits"]["budget"][key] - used[key] - reserve[key]) // count
                    ),
                )
                for key in used
            }
            if self.child_deadline(authority) <= time.time():
                return "unavailable"
            artifacts = check_inputs(
                c,
                task_id,
                c.registry.get(offer["contract"]),
                inputs,
                candidate,
                terms["additional_preconditions"],
            )
            size = len(canonical(inputs)) + sum(
                len(canonical(items)) for items in (imports, artifacts) if items
            )
            if size > candidate["limits"]["budget"]["input_bytes"]:
                return "unavailable"
            if any(
                item["manifest"].get("provenance", {}).get("resource", "workspace:self")
                not in grant["disclosure_resources"]
                for item in artifacts
            ):
                return "denied"
            async with asyncio.timeout(peer.settings["request_timeout_seconds"]):
                await peer.definition(offer)
                state = await peer.availability(offer)
            return {"available": "matched", "unauthorized": "denied"}.get(state, state)
        except LasaError as exc:
            if exc.code in {"authority_denied", "disclosure_denied"}:
                return "denied"
            if exc.code == "capacity_exhausted":
                return "unavailable"
            return "unknown"
        except TimeoutError:
            return "unknown"

    async def match(self, peer, snapshot, ref, task_id, inputs, authority, rule, grant, count):
        if snapshot is None:
            return "unknown", None
        if not snapshot["offers"]:
            return "not_claimed", None
        states = set()
        for offer in sorted(snapshot["offers"], key=lambda offer: offer["offer_id"]):
            if offer["contract"] != ref:
                continue
            state = await self.suitability(
                peer, task_id, offer, inputs, authority, rule, grant, count
            )
            if state == "matched":
                return state, {
                    "service_id": peer.service_id,
                    "offer": offer,
                    "execution": execution_terms(grant),
                    "catalog_revision": snapshot["revision"],
                }
            states.add(state)
        return self.assessment(states), None

    @staticmethod
    def assessment(states):
        if states == {"not_claimed"}:
            return "not_claimed"
        return next(
            (
                state
                for state in ("matched", "busy", "denied", "unknown", "unavailable")
                if state in states
            ),
            "unknown",
        )

    async def prepare(self, task_id, request):
        c = self.coordinator
        authority = c.authority(task_id)
        rule = c.current_rule(task_id)
        grants = intersect_grants(authority["delegation_grants"], rule["delegation_grants"])
        remaining = authority["limits"]["budget"]["delegations"]
        outbound = {
            grant["receiver_service_id"]
            for grant in grants
            if grant["sender_service_id"] == c.config.service_id
        }
        eligible = []
        for peer in c.peers.values():
            if remaining <= 0 or peer.service_id not in outbound:
                continue
            try:
                c.check_processing(task_id, "peer:" + peer.service_id)
            except LasaError as exc:
                if exc.code != "processing_unavailable":
                    raise
                continue
            eligible.append(peer)
        refs = {
            binding["contract"]["digest"]
            for binding in c.config.document["bindings"]
            if binding["contract"] in rule["contracts"]
        }
        eligible_ids = {peer.service_id for peer in eligible}
        refs.update(
            grant["contract"]["digest"]
            for grant in grants
            if grant["sender_service_id"] == c.config.service_id
            and grant["receiver_service_id"] in eligible_ids
        )
        contracts = {
            key: definition
            for key, definition in c.registry.current.items()
            if key in refs
            and c.registry.supported(reference(definition))
            and not c.registry.is_workflow(reference(definition))
        }
        requirements, proposals = await c.planner.propose(task_id, request, contracts)
        check_responsibilities(requirements, proposals)
        refreshed = {}

        async def fresh(peer, ref):
            key = (peer.service_id, ref["digest"])
            if key not in refreshed:
                refreshed[key] = await self.catalog(peer, ref)
            return refreshed[key]

        require(
            len(proposals) <= c.config.document["limits"]["max_plan_steps"],
            "capacity_exhausted",
            429,
        )
        policy = c.config.document["routing"]
        choices = []
        inputs = {}
        offers = {}
        for proposal in proposals:
            definition = c.registry.current.get(proposal["contract_digest"])
            require(definition is not None, "unsupported_contract", 422)
            ref = reference(definition)
            require(not c.registry.is_workflow(ref), "unsupported_contract", 422)
            value = parse_json(proposal["input_json"])
            definition = c.registry.input(ref, value)
            if len(proposals) == 1 and ref == request["selection"]["contract"]:
                require(value == request["input"], "precondition_failed", 422)
            binding = next(
                (item for item in c.config.document["bindings"] if item["contract"] == ref), None
            )
            dependency = c.broker.binding_state(binding, rule, authority) if binding else None
            local = (
                "sufficient"
                if binding and ref in rule["contracts"] and dependency == "available"
                else "insufficient"
            )
            local_failure = None
            if binding and ref in rule["contracts"]:
                try:
                    scoped = restrict(
                        authority, binding["allowed_effects"], binding["approved_resources"]
                    )
                    check_inputs(c, task_id, definition, value, scoped)
                except LasaError as exc:
                    local = "insufficient"
                    local_failure = exc
            candidates = []
            states = set()
            for peer in eligible:
                grant = find_grant(grants, c.config.service_id, peer.service_id, ref)
                if grant is None:
                    continue
                snapshot = await fresh(peer, ref)
                peer_state, route = await self.match(
                    peer,
                    snapshot,
                    ref,
                    task_id,
                    value,
                    authority,
                    rule,
                    grant,
                    len(proposals),
                )
                states.add(peer_state)
                if route:
                    candidates.append(route)
                    if len(candidates) == 2:
                        break
            if states:
                state = self.assessment(states)
            elif not c.peers:
                state = "not_configured"
            else:
                state = "denied"

            choice = decide(local, state, policy)
            routes = candidates if choice == "peer" else []
            selected = routes[0] if routes else None
            reason = (
                "No peer is configured; routing settings are ignored."
                if not c.peers
                else (
                    "Both suitable; configured preference selects " + choice
                    if local == "sufficient" and state == "matched"
                    else "Verified local="
                    + local
                    + ", peer="
                    + state
                    + "; selected "
                    + choice
                    + "."
                )
            )
            evidence = {
                "step_id": proposal["step_id"],
                "requirement_ids": proposal["requirement_ids"],
                "local_assessment": local,
                "peer_assessment": state,
                "catalog_revision": selected["catalog_revision"] if selected else None,
                "offer_revision": selected["offer"]["revision"] if selected else None,
                "authorization_decision_id": authority["decision_id"],
                "policy": policy,
                "selected_executor": choice,
                "contract": ref,
                "decision_reason": reason,
            }
            if selected:
                evidence["peer_service_id"] = selected["service_id"]
            c.diagnostics.emit(task_id, "routing", evidence)
            if choice == "none":
                if authority["selected_offer"]["processing"]["mode"] == DOMAIN_ONLY:
                    raise LasaError("processing_unavailable", 503)
                if binding and state in {"not_configured", "not_claimed", "denied"}:
                    if local_failure:
                        raise local_failure
                    if ref not in rule["contracts"] or dependency == "unauthorized":
                        raise LasaError("authority_denied", 403)
                    if dependency == "busy":
                        raise LasaError("capacity_exhausted", 429)
                    if dependency in {"unknown", "unavailable"}:
                        raise LasaError("peer_unavailable", 503)
                raise LasaError(
                    "authority_denied"
                    if state == "denied"
                    else "capacity_exhausted"
                    if state == "busy"
                    else "peer_unavailable"
                    if state in {"unknown", "unavailable"}
                    else "unsupported_contract",
                    403
                    if state == "denied"
                    else 429
                    if state == "busy"
                    else 503
                    if state in {"unknown", "unavailable"}
                    else 422,
                )
            choices.append((proposal, ref, choice))
            inputs[proposal["step_id"]] = value
            if selected:
                offers[proposal["step_id"]] = routes
        plan = {
            "revision": 1,
            "requirements": requirements,
            "steps": [
                {
                    "step_id": proposal["step_id"],
                    "requirement_ids": proposal["requirement_ids"],
                    "depends_on": proposal["depends_on"],
                    "contract": ref,
                    "executor": choice,
                    "allocation": {},
                    "input_digest": digest(inputs[proposal["step_id"]]),
                }
                for proposal, ref, choice in choices
            ],
            "integration_reserve": copy.deepcopy(
                c.config.document["limits"]["integration_reserve"]
            ),
        }
        selected_contract = request["selection"]["contract"]
        reuse = len(plan["steps"]) == 1 and plan["steps"][0]["contract"] == selected_contract
        required_calls = len(plan["steps"])
        if not reuse and not c.registry.is_workflow(selected_contract):
            required_calls += 1 if c.registry.source_profile(selected_contract) else 2
        plan["integration_reserve"]["model_calls"] = max(
            plan["integration_reserve"]["model_calls"], required_calls
        )
        private = {"document": plan, "inputs": inputs, "offers": offers}
        self.allocate(task_id, private)
        return private

    def allocate(self, task_id, private):
        c = self.coordinator
        authority = c.authority(task_id)
        plan = private["document"]
        steps = plan["steps"]
        reserve = plan["integration_reserve"]
        used = c.store.usage(task_id, reserved=True)
        cap = authority.get("subtree_cap")
        cap_used = c.store.subtree_usage(task_id) if cap is not None else 0
        available = {
            key: authority["limits"]["budget"][key] - used[key] - reserve[key] for key in used
        }
        require(all(value >= 0 for value in available.values()), "capacity_exhausted", 429)
        for step in steps:
            allocation = {
                "budget": {key: value // len(steps) for key, value in available.items()},
                "deadline": authority["limits"]["deadline"],
            }
            allocation["budget"]["delegations"] = 0
            if step["executor"] == "peer":
                selection = private["offers"][step["step_id"]]
                offer = selection[0]["offer"]
                allocation["deadline"] = instant(self.child_deadline(authority))
                allocation["budget"] = {
                    key: min(value, offer["max_budget"].get(key, 0))
                    for key, value in allocation["budget"].items()
                }
                charge = subtree_charge(selection[0]["execution"], cap)
                if cap is not None:
                    require(charge is not None, "offer_changed", 409)
                    cap_used += charge
                require(
                    all(
                        allocation["budget"][item["resource"]] >= item["minimum"]
                        for item in offer["restrictions"]["additional_preconditions"]
                    ),
                    "capacity_exhausted",
                    429,
                )
                selection[1:] = [
                    route
                    for route in selection[1:]
                    if route["offer"]["contract"] == offer["contract"]
                    and subtree_charge(route["execution"], cap) == charge
                    and all(
                        route["offer"]["max_budget"].get(key, 0) >= amount
                        for key, amount in allocation["budget"].items()
                        if key != "delegations"
                    )
                ]
                require(epoch(allocation["deadline"]) > time.time(), "deadline_exceeded", 422)
            step["allocation"] = allocation
        check_allocation(plan, authority["limits"]["budget"], used)
        require(cap is None or cap_used <= cap, "capacity_exhausted", 429)
        return private

    def child_deadline(self, authority):
        limits = self.coordinator.config.document["limits"]
        return epoch(authority["limits"]["deadline"]) - margin_with_clock_uncertainty(limits) / 1000
