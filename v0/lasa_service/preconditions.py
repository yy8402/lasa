"""Closed precondition predicates; unknown semantic premises never become facts."""

from .capabilities import require
from .contracts import canonical, parse_json, validate_data
from .errors import LasaError
from .evidence import content_digest, permitted


def input_size(inputs, *context):
    return len(canonical(inputs)) + sum(len(canonical(value)) for value in context if value)


def request_input_size(request):
    return input_size(
        request["input"],
        request.get("dependency_results"),
        request.get("delegation", {}).get("disclosed_artifacts"),
    )


def restrict(authority, effects, resources):
    allowed = {}
    for rule in resources:
        allowed.setdefault(rule["resource"], set()).update(rule["actions"])
    return {
        **authority,
        "allowed_effects": sorted(set(authority["allowed_effects"]) & set(effects)),
        "resources": [
            {
                "resource": rule["resource"],
                "actions": sorted(set(rule["actions"]) & allowed.get(rule["resource"], set())),
            }
            for rule in authority["resources"]
        ],
    }


def input_artifacts(c, task_id, inputs, authority, predicates, *, prior_artifacts=()):
    fields = {p["input_field"] for p in predicates if p["kind"] == "artifact_present"}
    if not fields:
        return []
    require(isinstance(inputs, dict), "precondition_failed", 422)
    request = c.request(task_id)
    rule = c.authorization.rule(c.principal(task_id), request["authorization_ref"])
    incoming = request.get("delegation", {}).get("disclosed_artifacts", [])
    attached = {x["manifest"]["artifact_id"]: x for x in incoming}
    require(len(attached) == len(incoming), "invalid_input")
    _, task = c.store.task(task_id)
    selected = {}
    for field in sorted(fields):
        ref = inputs.get(field)
        require(
            isinstance(ref, dict)
            and isinstance(ref.get("artifact_id"), str)
            and isinstance(ref.get("digest"), str),
            "precondition_failed",
            422,
        )
        artifact_id = ref["artifact_id"]
        attachment = attached.get(artifact_id)
        if attachment is None:
            row = c.store.db.execute(
                "SELECT a.manifest,a.content,a.released,a.task_id FROM artifacts a "
                "JOIN tasks t ON a.task_id=t.id WHERE a.id=? AND t.session_id=?",
                (artifact_id, task["session_id"]),
            ).fetchone()
            require(
                row is not None
                and (
                    row["released"] == 1
                    or (row["task_id"] == task_id and artifact_id in prior_artifacts)
                ),
                "precondition_failed",
                422,
            )
            manifest, data = parse_json(row["manifest"]), bytes(row["content"])
        else:
            manifest, data = attachment["manifest"], attachment["text"].encode()
        provenance = manifest.get("provenance")
        effect = "external.read" if provenance is not None else "workspace.read"
        resource = provenance["resource"] if provenance is not None else "workspace:self"
        require(permitted(authority, rule, effect, resource, "read"), "authority_denied", 403)
        require(
            manifest["artifact_id"] == artifact_id
            and manifest["digest"] == ref["digest"] == content_digest(data)
            and manifest["bytes"] == len(data),
            "precondition_failed",
            422,
        )
        try:
            selected[artifact_id] = {"manifest": manifest, "text": data.decode("utf-8")}
        except UnicodeDecodeError:
            raise LasaError("precondition_failed", 422) from None
    artifacts = list(selected.values())
    require(
        len(artifacts) <= 16
        and len(canonical(artifacts)) <= authority["limits"]["budget"]["input_bytes"],
        "capacity_exhausted",
        429,
    )
    return artifacts


def check_inputs(c, task_id, definition, inputs, authority, additional=(), *, prior_artifacts=()):
    artifacts = input_artifacts(
        c,
        task_id,
        inputs,
        authority,
        [*definition["preconditions"], *additional],
        prior_artifacts=prior_artifacts,
    )
    check_predicates(definition, inputs, authority, additional, [x["manifest"] for x in artifacts])
    return artifacts


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
