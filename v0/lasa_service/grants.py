"""Receiver and contract scoped delegation grants."""


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
        if limit is None or grant["contract"] != limit["contract"]:
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
