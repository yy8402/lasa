"""Consumer representations generated from provider-owned records."""

from urllib.parse import unquote, urlsplit

from .capabilities import require
from .contracts import canonical, digest
from .errors import LasaError

PUBLIC_TASK_FIELDS = (
    "task_id",
    "session_id",
    "service_id",
    "operation_id",
    "received_at",
    "selection",
    "request_digest",
)
PUBLIC_ARTIFACT_FIELDS = ("artifact_id", "digest", "bytes", "media_type", "source_task_id")


def public_problem(problem):
    code = {
        "peer_unavailable": "service_unavailable",
        "incompatible_protocol": "service_unavailable",
        "child_outcome_unknown": "outcome_unknown",
    }.get(problem["code"], problem["code"])
    return LasaError(
        code, problem["status"], retry=problem["retry"], effect=problem["effect_disposition"]
    ).public()


def task_view(store, document, *, control=False):
    task_id = document["task_id"]
    sequence, state = store.consumer_state(task_id, document["status"])
    view = {name: document[name] for name in PUBLIC_TASK_FIELDS}
    view.update(revision=sequence, status=state)
    if problem := document.get("problem"):
        view["problem"] = public_problem(problem)
    if not control:
        for name in ("question", "result"):
            if name in document:
                view[name] = document[name]
    else:
        view["effect_disposition"] = (
            store.effect_disposition(task_id)
            if state != "indeterminate" or store.has_resolution(task_id)
            else "unknown"
        )
    return view


def artifact_view(manifest):
    return {name: manifest[name] for name in PUBLIC_ARTIFACT_FIELDS}


def artifact_release(manifest, data):
    return {"output": artifact_view(manifest), "text": data.decode("utf-8")}


def result_view(task, definition, result):
    criterion_ids = {item["id"] for item in definition["postconditions"]}
    artifact_ids = {item["artifact_id"] for item in result["artifacts"]}
    view = {
        name: result[name]
        for name in ("contract", "request_digest", "output", "effect_disposition")
    }
    view["artifacts"] = [artifact_view(item) for item in result["artifacts"]]
    view["evidence"] = [
        {
            "criterion_id": item["criterion_id"],
            "disposition": item["disposition"],
            "summary": "Criterion verification recorded.",
            "artifact_ids": sorted(set(item["artifact_ids"]) & artifact_ids),
        }
        for item in result["evidence"]
        if item["criterion_id"] in criterion_ids
    ]
    view["receipt"] = {
        "service_id": task["service_id"],
        "task_id": task["task_id"],
        "operation_id": task["operation_id"],
        "selection": task["selection"],
        "processing": task["processing"],
        "result_digest": digest(view),
    }
    return view


def require_public_data(coordinator, task_id, value):
    local_host = urlsplit(coordinator.config.document["service"]["base_url"]).hostname
    identifiers = set()
    for peer in coordinator.config.peers:
        service_id = peer["expected_service_id"]
        identifiers.add(service_id)
        identifiers.update(peer.get("private_aliases", []))
        service_label = urlsplit(service_id).path.rstrip("/").rsplit("/", 1)[-1]
        if service_label.startswith(("lasa-", "layer")):
            identifiers.add(service_label)
        for key in ("allowed_base_url", "descriptor_url"):
            identifiers.add(peer[key])
            host = urlsplit(peer[key]).hostname
            if host and host != local_host and host not in {"localhost", "127.0.0.1", "::1"}:
                identifiers.add(host)
    for child in coordinator.store.children(task_id):
        identifiers.update(
            child[name]
            for name in ("service_id", "delegation_id", "session_id", "task_id")
            if name in child
        )
        identifiers.update(child.get("upstream_artifact_ids", []))
        if request := child.get("request"):
            identifiers.add(request["operation_id"])
    wire = value.decode() if isinstance(value, bytes) else canonical(value).decode()
    text = unquote(wire).casefold()
    require(
        not any(identifier.casefold() in text for identifier in identifiers),
        "disclosure_denied",
        403,
    )
