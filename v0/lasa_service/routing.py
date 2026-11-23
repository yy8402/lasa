"""Deterministic routing from verified claim, capacity, and authority facts."""

import asyncio
import copy
import time

from .capabilities import epoch, instant, reference, require
from .contracts import canonical, digest, parse_json
from .errors import LasaError
from .grants import find_grant, intersect_grants
from .planning import check_plan
from .preconditions import check_inputs, restrict


def decide(local, peer, policy, *, configured, generic_available=False):
    if not configured:
        return "local"
    if local == "sufficient":
        return "peer" if peer == "matched" and policy["preferred_executor"] == "peer" else "local"
    if peer == "matched":
        return "peer"
    if (
        local == "insufficient"
        and peer == "not_claimed"
        and policy["unclaimed_peer_fallback"] == "attempt"
        and generic_available
    ):
        return "attempt"
    return "none"


def fallback_input(definition, inputs, requirements, ids):
    return {
        "objective": "Attempt the supplied bounded outcome. Report unable if any required outcome or evidence cannot be produced.",
        "requirements": [
            {
                "id": requirement["requirement_id"],
                "description": requirement["description"],
                "acceptance": [item["criterion"] for item in requirement["acceptance"]],
            }
            for requirement in requirements
            if requirement["requirement_id"] in ids
        ],
        "context": canonical({"requested_contract": definition, "input": inputs}).decode(),
    }


class RoutingController:
    def __init__(self, coordinator):
        self.coordinator = coordinator

    def ancestry(self, request):
        return [
            *request.get("delegation", {}).get("ancestry", []),
            self.coordinator.config.service_id,
        ]

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
            terms = offer["restrictions"]
            candidate = restrict(authority, rule["effects"], rule["resources"])
            candidate = restrict(candidate, grant["effects"], grant["resources"])
            candidate = restrict(candidate, terms["allowed_effects"], terms["resources"])
            candidate["limits"] = dict(authority["limits"])
            used = c.store.usage(task_id, reserved=True)
            reserve = c.config.document["limits"]["integration_reserve"]
            candidate["limits"]["budget"] = {
                key: min(
                    offer["max_budget"][key],
                    max(
                        0, (authority["limits"]["budget"][key] - used[key] - reserve[key]) // count
                    ),
                )
                for key in used
            }
            if (
                epoch(authority["limits"]["deadline"]) - reserve["wall_time_ms"] / 1000
                <= time.time()
            ):
                return "unavailable"
            artifacts = check_inputs(
                c,
                task_id,
                c.registry.get(offer["contract"]),
                inputs,
                candidate,
                terms["additional_preconditions"],
            )
            size = len(canonical(inputs)) + (len(canonical(artifacts)) if artifacts else 0)
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
            if (
                offer["contract"] != ref
                or offer["authorization_ref"] != peer.settings["authorization_ref"]
            ):
                continue
            state = await self.suitability(
                peer, task_id, offer, inputs, authority, rule, grant, count
            )
            if state == "matched":
                return state, {
                    "service_id": peer.service_id,
                    "offer": offer,
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
        rule = c.authorization.rule(c.principal(task_id), request["authorization_ref"])
        grants = intersect_grants(authority["delegation_grants"], rule["delegation_grants"])
        ancestry = self.ancestry(request)
        remaining = authority["limits"]["max_hops"]
        outbound = {
            grant["receiver_service_id"]
            for grant in grants
            if grant["sender_service_id"] == c.config.service_id
        }
        eligible = [
            peer
            for peer in c.peers.values()
            if remaining > 0 and peer.service_id in outbound and peer.service_id not in ancestry
        ]
        workflow = c.registry.is_workflow(request["selection"]["contract"])
        planning_offers = []
        if not workflow:
            for peer, snapshot in zip(
                eligible,
                await asyncio.gather(*(self.catalog(peer) for peer in eligible)),
                strict=True,
            ):
                if snapshot:
                    planning_offers.extend(
                        offer
                        for offer in snapshot["offers"]
                        if offer["authorization_ref"] == peer.settings["authorization_ref"]
                        and find_grant(
                            grants, c.config.service_id, peer.service_id, offer["contract"]
                        )
                    )
        requirements, proposals = await c.planner.propose(
            task_id, request, {"offers": planning_offers} if eligible else None
        )
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
        assessments = {}
        offers = {}
        for proposal in proposals:
            definition = c.registry.current.get(proposal["contract_digest"])
            require(definition is not None, "unsupported_contract", 422)
            ref = reference(definition)
            require(not c.registry.is_workflow(ref), "unsupported_contract", 422)
            value = parse_json(proposal["input_json"])
            definition = c.registry.input(ref, value)
            binding = (
                next((x for x in c.config.document["bindings"] if x["contract"] == ref), None)
                if not workflow
                else None
            )
            local = (
                proposal["local_assessment"]
                if binding and ref in rule["contracts"]
                else "insufficient"
            )
            dependency = (
                c.broker.binding_state(binding, rule, authority) if binding else "unavailable"
            )
            if dependency != "available":
                local = "insufficient"
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
            permitted = []
            for peer in eligible:
                grant = find_grant(grants, c.config.service_id, peer.service_id, ref)
                if grant is None:
                    continue
                permitted.append(peer.service_id)
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
            elif remaining and any(
                peer_id in ancestry and find_grant(grants, c.config.service_id, peer_id, ref)
                for peer_id in c.peers
            ):
                state = "ancestor"
            else:
                state = "denied"

            generic = []
            if (
                not workflow
                and local == "insufficient"
                and state == "not_claimed"
                and policy["unclaimed_peer_fallback"] == "attempt"
            ):
                attempt = fallback_input(
                    definition, value, requirements, proposal["requirement_ids"]
                )
                for peer_id in permitted:
                    peer = c.peers[peer_id]
                    for grant in grants:
                        target = grant["contract"]
                        if (
                            grant["sender_service_id"] != c.config.service_id
                            or grant["receiver_service_id"] != peer_id
                            or c.registry.verifiers.get(digest(target)) != "task-attempt-v1"
                        ):
                            continue
                        generic_state, route = await self.match(
                            peer,
                            await fresh(peer, target),
                            target,
                            task_id,
                            attempt,
                            authority,
                            rule,
                            grant,
                            len(proposals),
                        )
                        if route:
                            generic.append(route)
                            break
                        if generic_state != "not_claimed":
                            states.add(generic_state)
                    if len(generic) == 2:
                        break
                if not generic:
                    state = self.assessment(states)

            choice = decide(
                local, state, policy, configured=bool(c.peers), generic_available=bool(generic)
            )
            routes = candidates if choice == "peer" else generic if choice == "attempt" else []
            selected = routes[0] if routes else None
            if choice == "local":
                if local_failure:
                    raise local_failure
                require(
                    binding is not None and ref in rule["contracts"], "unsupported_contract", 422
                )
                require(
                    dependency == "available",
                    "authority_denied"
                    if dependency == "unauthorized"
                    else "capacity_exhausted"
                    if dependency == "busy"
                    else "peer_unavailable",
                    403 if dependency == "unauthorized" else 429 if dependency == "busy" else 503,
                )
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
                "assessment_summary": proposal["assessment_summary"],
                "catalog_revision": selected["catalog_revision"] if selected else None,
                "offer_revision": selected["offer"]["revision"] if selected else None,
                "authorization_decision_id": authority["decision_id"],
                "policy": policy,
                "selected_executor": "peer" if choice in {"peer", "attempt"} else choice,
                "contract": ref,
                "decision_reason": reason,
            }
            if selected:
                evidence["peer_service_id"] = selected["service_id"]
            c.diagnostics.emit(task_id, "routing", evidence)
            if choice == "none":
                raise LasaError(
                    "authority_denied"
                    if state == "denied"
                    else "capacity_exhausted"
                    if state == "busy"
                    else "peer_unavailable"
                    if state in {"unknown", "unavailable"}
                    else "precondition_failed"
                    if state == "ancestor"
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
            assessments[proposal["step_id"]] = proposal
            if selected:
                offers[proposal["step_id"]] = {
                    "routes": routes,
                    "fallback": choice == "attempt",
                    "absence_peers": permitted if choice == "attempt" else [],
                }
        plan = {
            "revision": 1,
            "requirements": requirements,
            "steps": [
                {
                    "step_id": proposal["step_id"],
                    "requirement_ids": proposal["requirement_ids"],
                    "depends_on": proposal["depends_on"],
                    "contract": ref,
                    "executor": "peer" if choice in {"peer", "attempt"} else "local",
                    "allocation": {},
                    "input_digest": digest(inputs[proposal["step_id"]]),
                }
                for proposal, ref, choice in choices
            ],
            "integration_requirement_ids": [r["requirement_id"] for r in requirements],
            "integration_reserve": copy.deepcopy(
                c.config.document["limits"]["integration_reserve"]
            ),
        }
        private = {"document": plan, "inputs": inputs, "assessments": assessments, "offers": offers}
        self.allocate(task_id, private)
        return private

    def allocate(self, task_id, private):
        c = self.coordinator
        authority = c.authority(task_id)
        plan = private["document"]
        steps = plan["steps"]
        reserve = plan["integration_reserve"]
        used = c.store.usage(task_id, reserved=True)
        peer_count = sum(step["executor"] == "peer" for step in steps)
        require(
            peer_count <= c.config.document["limits"]["max_children"], "capacity_exhausted", 429
        )
        available = {
            key: authority["limits"]["budget"][key] - used[key] - reserve[key] for key in used
        }
        available["delegations"] -= peer_count
        require(all(value >= 0 for value in available.values()), "capacity_exhausted", 429)
        for step in steps:
            allocation = {
                "budget": {key: value // len(steps) for key, value in available.items()},
                "deadline": authority["limits"]["deadline"],
                "max_hops": 0,
            }
            if step["executor"] == "peer":
                selection = private["offers"][step["step_id"]]
                offer = selection["routes"][0]["offer"]
                allocation["deadline"] = instant(
                    epoch(authority["limits"]["deadline"]) - reserve["wall_time_ms"] / 1000
                )
                allocation["max_hops"] = min(authority["limits"]["max_hops"] - 1, offer["max_hops"])
                allocation["budget"] = {
                    key: min(value, offer["max_budget"][key])
                    for key, value in allocation["budget"].items()
                }
                selection["routes"][1:] = [
                    route
                    for route in selection["routes"][1:]
                    if route["offer"]["contract"] == offer["contract"]
                    and route["offer"]["max_hops"] >= allocation["max_hops"]
                    and all(
                        route["offer"]["max_budget"][key] >= amount
                        for key, amount in allocation["budget"].items()
                    )
                ]
                require(epoch(allocation["deadline"]) > time.time(), "deadline_exceeded", 422)
            step["allocation"] = allocation
        check_plan(plan, c.registry, authority["limits"]["budget"], used)
        return private
