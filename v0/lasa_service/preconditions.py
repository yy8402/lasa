"""Closed precondition predicates; unknown semantic premises never become facts."""

from .capabilities import require
from .contracts import validate_data
from .errors import LasaError


def check_predicates(definition, inputs, authority, additional=(), artifacts=()):
    validate_data(definition["input_schema"], inputs)
    for predicate in [*definition["preconditions"], *additional]:
        kind = predicate["kind"]
        if kind == "input_schema":
            continue
        if kind == "budget_minimum":
            require(
                authority["limits"]["budget"][predicate["resource"]] >= predicate["minimum"],
                "capacity_exhausted",
                429,
            )
        elif kind == "resource_authorized":
            require(
                any(
                    r["resource"] == predicate["resource"]
                    and set(predicate["actions"]) <= set(r["actions"])
                    for r in authority["resources"]
                ),
                "authority_denied",
                403,
            )
            workspace = predicate["resource"] == "workspace:self"
            for action in predicate["actions"]:
                effect = ("workspace." if workspace else "external.") + (
                    "read" if action == "read" else "write"
                )
                require(effect in authority["allowed_effects"], "authority_denied", 403)
        elif kind == "artifact_present":
            value = inputs.get(predicate["input_field"]) if isinstance(inputs, dict) else None
            require(
                isinstance(value, dict)
                and any(
                    a["digest"] == value.get("digest")
                    and a["artifact_id"] == value.get("artifact_id")
                    and a["media_type"] == predicate["media_type"]
                    for a in artifacts
                ),
                "precondition_failed",
                422,
            )
        elif kind == "semantic_review":
            raise LasaError("precondition_failed", 422)
        else:
            raise LasaError("precondition_failed", 422)
