"""Bounded receiver-owned verification material from durable execution records.

Receipts establish operation disposition and returned bytes, never the truth of
arbitrary tool text. No live workspace reads or private model prompts are used.
"""

import hashlib

from .capabilities import require
from .contracts import canonical, digest, parse_json

MAX_BYTES = 16384
MAX_OPERATIONS = 32
MAX_ARTIFACTS = 16


def verification_material(coordinator, task_id, *, step_id=None, artifact_ids=()):
    c = coordinator
    authority = c.authority(task_id)
    rule = c.authorization.rule(c.principal(task_id), c.request(task_id)["authorization_ref"])
    material = {
        "source": "receiver_durable_store",
        "service_id": c.config.service_id,
        "task_id": task_id,
        "step_id": step_id,
        "operations": [],
        "artifacts": [],
        "truncated": False,
    }

    def permitted(effect, resource, action):
        return (
            effect in authority["allowed_effects"]
            and effect in rule["effects"]
            and all(
                any(r["resource"] == resource and action in r["actions"] for r in resources)
                for resources in [authority["resources"], rule["resources"]]
            )
        )

    def append(kind, receipt, content):
        clean = c.diagnostics.redact(content, task_id)
        value = {**receipt, "content": clean}
        if len(canonical(material)) + len(canonical(value)) + 2 > MAX_BYTES:
            value = {**receipt, "content_omitted": True}
            material["truncated"] = True
        if len(canonical(material)) + len(canonical(value)) + 2 <= MAX_BYTES:
            material[kind].append(value)
        else:
            material["truncated"] = True

    ids = list(dict.fromkeys(artifact_ids))
    require(len(ids) <= MAX_ARTIFACTS, "capacity_exhausted", 429)
    for artifact_id in ids:
        row = c.store.db.execute(
            "SELECT * FROM artifacts WHERE id=? AND task_id=?", (artifact_id, task_id)
        ).fetchone()
        require(row is not None, "verification_failed", 422)
        manifest = parse_json(row["manifest"])
        data = bytes(row["content"])
        require(
            manifest["source_task_id"] == task_id
            and manifest["bytes"] == len(data)
            and manifest["digest"] == "sha256:" + hashlib.sha256(data).hexdigest(),
            "verification_failed",
            422,
        )
        provenance = manifest.get("provenance")
        if provenance is not None:
            require(manifest["digest"] == provenance["result_digest"], "verification_failed", 422)
            if not permitted("external.read", provenance["resource"], "read"):
                continue
        elif not permitted("workspace.read", "workspace:self", "read"):
            continue
        # Exported/imported snapshots are immutable evidence, not live workspace paths.
        append(
            "artifacts",
            {"manifest": manifest, "bytes_verified": True},
            {"text": data.decode("utf-8", errors="replace")},
        )
    rows = c.store.db.execute(
        "SELECT a.*,a.rowid AS sequence,l.details FROM actions a JOIN allocations l "
        "ON a.task_id=l.task_id AND a.operation_id=l.operation_id "
        "WHERE a.task_id=? AND (? IS NULL OR json_extract(l.details,'$.step_id')=?) "
        "ORDER BY a.rowid LIMIT ?",
        (task_id, step_id, step_id, MAX_OPERATIONS + 1),
    ).fetchall()
    for row in rows[:MAX_OPERATIONS]:
        details = parse_json(row["details"])
        if not all(key in details for key in ["effect", "resource", "action"]) or not permitted(
            details["effect"], details["resource"], details["action"]
        ):
            continue
        intent = parse_json(row["intent"])
        require(digest(intent) == row["digest"], "verification_failed", 422)
        result = parse_json(row["result"]) if row["result"] is not None else None
        append(
            "operations",
            {
                "operation_id": row["operation_id"],
                "step_id": details.get("step_id"),
                "sequence": row["sequence"],
                "state": row["state"],
                "effect": row["effect"],
                "input_digest": row["digest"],
                "result_digest": digest(result),
                "succeeded": row["state"] == "finished"
                and isinstance(result, dict)
                and "value" in result,
            },
            {"request": intent, "result": result},
        )
    material["truncated"] |= len(rows) > MAX_OPERATIONS
    require(len(canonical(material)) <= MAX_BYTES, "capacity_exhausted", 429)
    return material
