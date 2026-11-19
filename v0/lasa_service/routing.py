"""Deterministic routing from verified claim, capacity, and authority facts."""

import copy
import time

from .capabilities import epoch, reference, require
from .contracts import canonical, digest, parse_json
from .errors import LasaError
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

    async def suitability(self, task_id, request, offer, inputs, authority, rule, count):
        c = self.coordinator
        if (
            offer["contract"] not in authority["allowed_delegated_contracts"]
            or offer["contract"] not in rule["delegated_contracts"]
            or offer["authorization_ref"] != c.config.peer["authorization_ref"]
            or request["requested_limits"]["max_hops"] <= 0
        ):
            return "denied"
        try:
            terms = offer["restrictions"]
            current = restrict(authority, rule["effects"], rule["resources"])
            candidate = restrict(current, terms["allowed_effects"], terms["resources"])
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
            if len(canonical(inputs)) > candidate["limits"]["budget"]["input_bytes"]:
                return "unavailable"
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
            if artifacts and (
                len(canonical(inputs)) + len(canonical(artifacts))
                > candidate["limits"]["budget"]["input_bytes"]
            ):
                return "unavailable"
            await c.peer.definition(offer)
            state = await c.peer.availability(offer)
            return (
                "matched"
                if state == "available"
                else "denied"
                if state == "unauthorized"
                else state
            )
        except LasaError as exc:
            return (
                "denied"
                if exc.code == "authority_denied"
                else "unavailable"
                if exc.code == "capacity_exhausted"
                else "unknown"
            )
        except TimeoutError:
            return "unknown"

    async def match(self, candidates, task_id, request, inputs, authority, rule, count):
        states = set()
        for offer in candidates:
            state = await self.suitability(task_id, request, offer, inputs, authority, rule, count)
            if state == "matched":
                return state, offer
            states.add(state)
        return next(
            (state for state in ("busy", "denied", "unknown", "unavailable") if state in states),
            "unknown",
        ), None

    async def prepare(self, task_id, request):
        c = self.coordinator
        catalog = None
        if c.config.peer:
            try:
                catalog = await c.peer.discover()
            except (LasaError, TimeoutError):
                catalog = None
        requirements, proposals = await c.planner.propose(task_id, request, catalog)
        refreshed = {}

        async def fresh(ref):
            key = ref["digest"]
            if key not in refreshed:
                try:
                    refreshed[key] = await c.peer.discover(refresh=True, contract=ref)
                except (LasaError, TimeoutError):
                    refreshed[key] = None
            return refreshed[key]

        require(
            len(proposals) <= c.config.document["limits"]["max_plan_steps"],
            "capacity_exhausted",
            429,
        )
        authority = c.authority(task_id)
        rule = c.authorization.rule(c.principal(task_id), request["authorization_ref"])
        policy = c.config.document["routing"]
        choices = []
        inputs = {}
        assessments = {}
        offers = {}
        for proposal in proposals:
            definition = c.registry.current.get(proposal["contract_digest"])
            require(definition is not None, "unsupported_contract", 422)
            ref = reference(definition)
            value = parse_json(proposal["input_json"])
            definition = c.registry.input(ref, value)
            binding = next((x for x in c.config.document["bindings"] if x["contract"] == ref), None)
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
            state = "not_configured"
            matched = None
            generic = None
            snapshot = None
            if c.config.peer:
                permitted = (
                    c.config.peer["expected_service_id"] in authority["allowed_disclosure_services"]
                    and c.config.peer["expected_service_id"] in rule["disclosure_services"]
                )
                if not permitted:
                    state = "denied"
                elif (snapshot := await fresh(ref)) is None:
                    state = "unknown"
                elif not snapshot["offers"]:
                    state = "not_claimed"
                else:
                    state, matched = await self.match(
                        (offer for offer in snapshot["offers"] if offer["contract"] == ref),
                        task_id,
                        request,
                        value,
                        authority,
                        rule,
                        len(proposals),
                    )
            if (
                local == "insufficient"
                and state == "not_claimed"
                and policy["unclaimed_peer_fallback"] == "attempt"
            ):
                attempt = fallback_input(
                    definition, value, requirements, proposal["requirement_ids"]
                )
                options = []
                for target in authority["allowed_delegated_contracts"]:
                    if (
                        target in rule["delegated_contracts"]
                        and c.registry.verifiers.get(digest(target)) == "task-attempt-v1"
                    ):
                        alternative = await fresh(target)
                        if alternative:
                            options.extend(
                                x for x in alternative["offers"] if x["contract"] == target
                            )
                if options:
                    generic_state, generic = await self.match(
                        options, task_id, request, attempt, authority, rule, len(proposals)
                    )
                    if generic is None:
                        state = generic_state
            choice = decide(
                local,
                state,
                policy,
                configured=c.config.peer is not None,
                generic_available=generic is not None,
            )
            selected = matched if choice == "peer" else generic if choice == "attempt" else None
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
                if not c.config.peer
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
                "catalog_revision": snapshot["revision"] if snapshot else None,
                "offer_revision": selected["revision"] if selected else None,
                "authorization_decision_id": authority["decision_id"],
                "policy": policy,
                "selected_executor": "peer" if choice in {"peer", "attempt"} else choice,
                "contract": ref,
                "decision_reason": reason,
            }
            c.diagnostics.emit(task_id, "routing", evidence)
            if choice == "none":
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
            if choice in {"peer", "attempt"}:
                require(request["requested_limits"]["max_hops"] > 0, "authority_denied", 403)
                require(c.registry.supported(selected["contract"]), "unsupported_contract", 422)
            choices.append((proposal, ref, choice))
            inputs[proposal["step_id"]] = value
            assessments[proposal["step_id"]] = proposal
            if selected:
                offers[proposal["step_id"]] = {"offer": selected, "fallback": choice == "attempt"}
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
        self.allocate(task_id, request, private)
        return private

    def allocate(self, task_id, request, private):
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
                from .capabilities import instant

                offer = private["offers"][step["step_id"]]["offer"]
                allocation["deadline"] = instant(
                    epoch(authority["limits"]["deadline"]) - reserve["wall_time_ms"] / 1000
                )
                allocation["max_hops"] = min(
                    request["requested_limits"]["max_hops"] - 1, offer["max_hops"]
                )
                allocation["budget"] = {
                    key: min(value, offer["max_budget"][key])
                    for key, value in allocation["budget"].items()
                }
                require(epoch(allocation["deadline"]) > time.time(), "deadline_exceeded", 422)
            step["allocation"] = allocation
        check_plan(plan, c.registry, authority["limits"]["budget"], used)
        return private
