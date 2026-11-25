"""Receiver and contract scoped delegation grants."""

import hmac

from .contracts import canonical

LEAF = {"max_fanout": 0}


def task_fanout(config, rule, *, peer):
    limits = config.document["limits"]
    ceiling = min(
        rule["budget"]["delegations"],
        limits["max_task_budget"]["delegations"],
        limits["max_children"],
    )
    return min(ceiling, rule.get("onward_fanout", 0)) if peer else ceiling


def execution_terms(grant):
    return grant.get("execution", LEAF)


def verification_margin(limits):
    return max(limits["min_verification_margin_ms"], limits["integration_reserve"]["wall_time_ms"])


def margin_with_clock_uncertainty(limits):
    return verification_margin(limits) + 2000 * limits["max_clock_skew_seconds"] + 1


def configured_grants(config, rule):
    peers = {item["expected_service_id"] for item in config.peers}
    return [
        grant
        for grant in rule["delegation_grants"]
        if grant["sender_service_id"] == config.service_id and grant["receiver_service_id"] in peers
    ]


def envelope(limits, fanout, grants):
    if not fanout or not grants:
        return dict(LEAF)
    margin = verification_margin(limits)
    maximum = fanout
    for grant in grants:
        terms = execution_terms(grant)
        if terms["max_fanout"]:
            maximum = max(maximum, terms["max_fanout"])
            margin = min(margin, terms["min_verification_margin_ms"])
    return {"max_fanout": maximum, "min_verification_margin_ms": margin}


def peer_execution(config, rule, fanout, grants):
    terms = envelope(config.document["limits"], fanout, grants)
    if terms["max_fanout"] and "subtree_cap" in rule:
        terms["subtree_cap"] = rule["subtree_cap"]
    return terms


def descendant_bound(limits, fanout, grants, time_ms, maximum):
    if not fanout or not grants:
        return 0
    remaining = time_ms - verification_margin(limits)
    if remaining < 0:
        return 0
    largest_branch = max(
        1 + descendants_for_terms(execution_terms(grant), remaining, maximum) for grant in grants
    )
    return fanout * largest_branch


def descendants_for_terms(terms, time_ms, maximum):
    breadth = terms["max_fanout"]
    if not breadth:
        return 0
    depth = time_ms // terms["min_verification_margin_ms"]
    if breadth == 1:
        return depth
    total = 0
    level = 1
    for _ in range(depth):
        level *= breadth
        total += level
        if total > maximum:
            return maximum + 1
    return total


def select_recursion(config, rule, fanout, grants, time_ms, *, peer):
    limits = config.document["limits"]
    maximum = limits["max_derived_descendants"]
    cap = rule.get("subtree_cap")
    if not fanout or not grants:
        return [], None
    bound = descendant_bound(limits, fanout, grants, time_ms, maximum)
    if cap is not None and (peer or bound > maximum):
        capped = [
            grant
            for grant in grants
            if (cost := subtree_charge(execution_terms(grant), cap)) is not None and cost <= cap
        ]
        if capped or peer:
            return capped, cap

    eligible = [
        grant
        for grant in grants
        if "subtree_cap" not in execution_terms(grant)
        and descendant_bound(limits, fanout, [grant], time_ms, maximum) <= maximum
    ]
    return eligible, None


def subtree_charge(terms, parent_cap):
    if parent_cap is None:
        return None
    if not terms["max_fanout"]:
        return 1
    if "subtree_cap" in terms:
        return 1 + terms["subtree_cap"]
    return None


def execution_commitment(key, sender, receiver, offer, terms):
    message = canonical(
        [
            sender,
            receiver,
            offer["offer_id"],
            offer["revision"],
            offer["catalog_view"],
            offer["contract"],
            offer["processing"],
            terms,
        ]
    )
    return "sha256:" + hmac.digest(key, message, "sha256").hex()


def grant_key(grant):
    return (
        grant["sender_service_id"],
        grant["receiver_service_id"],
        grant["contract"]["digest"],
    )


def intersect_grants(grants, ceiling):
    limits = {grant_key(grant): grant for grant in ceiling}
    result = []
    for grant in grants:
        limit = limits.get(grant_key(grant))
        if (
            limit is None
            or grant["contract"] != limit["contract"]
            or execution_terms(grant) != execution_terms(limit)
        ):
            continue
        actions = {}
        for resource in limit["resources"]:
            actions.setdefault(resource["resource"], set()).update(resource["actions"])
        resources = []
        for resource in grant["resources"]:
            allowed = set(resource["actions"]) & actions.get(resource["resource"], set())
            if allowed:
                resources.append({"resource": resource["resource"], "actions": sorted(allowed)})
        result.append(
            {
                **grant,
                "effects": sorted(set(grant["effects"]) & set(limit["effects"])),
                "resources": resources,
                "disclosure_resources": sorted(
                    set(grant["disclosure_resources"]) & set(limit["disclosure_resources"])
                ),
            }
        )
    return result


def find_grant(grants, sender, receiver, contract):
    return next(
        (
            grant
            for grant in grants
            if grant_key(grant) == (sender, receiver, contract["digest"])
            and grant["contract"] == contract
        ),
        None,
    )
