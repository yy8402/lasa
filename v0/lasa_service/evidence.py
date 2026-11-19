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
MAX_READBACKS = 8
MAX_READBACK_BYTES = 8192
MAX_QUOTE_BYTES = 512


def permitted(authority, rule, effect, resource, action):
    return (
        effect in authority["allowed_effects"]
        and effect in rule["effects"]
        and all(
            any(r["resource"] == resource and action in r["actions"] for r in resources)
            for resources in [authority["resources"], rule["resources"]]
        )
    )


def may_share_readbacks(authority, rule):
    return permitted(authority, rule, "workspace.write", "workspace:self", "update") and permitted(
        authority, rule, "workspace.read", "workspace:self", "read"
    )


def child_readbacks(c, task_id, step_id):
    for child in c.store.children(task_id):
        if step_id is None or child.get("step_id") == step_id:
            yield from child.get("workspace_readbacks", ())


def content_digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def quotes_text(output, text):
    return canonical(text)[1:-1] in output


def validate_child_readbacks(result):
    receipts = result.get("workspace_readbacks", [])
    require(
        not receipts
        or (
            result["effect_disposition"] == "known"
            and len(canonical(receipts)) <= MAX_READBACK_BYTES
        ),
        "verification_failed",
        502,
    )
    output = canonical(result["output"])
    for receipt in receipts:
        require(
            receipt["write_operation_id"] != receipt["read_operation_id"],
            "verification_failed",
            502,
        )
        if "quoted_text" in receipt:
            text = receipt["quoted_text"]
            data = text.encode()
            require(
                len(data) <= MAX_QUOTE_BYTES
                and len(data) == receipt["bytes"]
                and content_digest(data) == receipt["content_digest"]
                and quotes_text(output, text),
                "verification_failed",
                502,
            )
    return receipts


def release_readbacks(c, task_id, output):
    authority = c.authority(task_id)
    rule = c.authorization.rule(c.principal(task_id), c.request(task_id)["authorization_ref"])
    if not may_share_readbacks(authority, rule):
        return []
    writes, local = {}, {}
    output = canonical(output)
    rows = c.store.db.execute(
        "SELECT operation_id,digest,intent,result FROM actions "
        "WHERE task_id=? AND state='finished' AND "
        "json_extract(intent,'$.name') IN ('workspace.write','workspace.read') "
        "ORDER BY rowid LIMIT ?",
        (task_id, MAX_OPERATIONS),
    )
    for row in rows:
        intent = parse_json(row["intent"])
        require(digest(intent) == row["digest"], "verification_failed", 422)
        value = parse_json(row["result"]).get("value")
        path = intent["arguments"]["relative_path"]
        if value is None or c.diagnostics.redact(path, task_id) != path:
            continue
        if intent["name"] == "workspace.write":
            local.pop(path, None)
            text = intent["arguments"]["text"]
            writes.pop(path, None)
            if value.get("bytes_written") == len(text.encode()):
                writes[path] = (row["operation_id"], text)
            continue
        if path not in writes or writes[path][1] != value["text"]:
            continue
        write_id, text = writes[path]
        data = text.encode()
        receipt = {
            "service_id": c.config.service_id,
            "task_id": task_id,
            "relative_path": path,
            "write_operation_id": write_id,
            "read_operation_id": row["operation_id"],
            "content_digest": content_digest(data),
            "bytes": len(data),
        }
        if len(data) <= MAX_QUOTE_BYTES and quotes_text(output, text):
            receipt["quoted_text"] = text
        local[path] = receipt
    bounded = []
    for stored in [*local.values(), *child_readbacks(c, task_id, None)]:
        receipt = dict(stored)
        text = receipt.pop("quoted_text", None)
        if c.diagnostics.redact(receipt, task_id) != receipt:
            continue
        if text is not None and (
            c.diagnostics.redact(text, task_id) == text and quotes_text(output, text)
        ):
            receipt["quoted_text"] = text
        if len(bounded) == MAX_READBACKS:
            break
        if len(canonical([*bounded, receipt])) <= MAX_READBACK_BYTES:
            bounded.append(receipt)
    return bounded


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
        "workspace_readbacks": [],
        "truncated": False,
    }

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
            and manifest["digest"] == content_digest(data),
            "verification_failed",
            422,
        )
        provenance = manifest.get("provenance")
        if provenance is not None:
            require(manifest["digest"] == provenance["result_digest"], "verification_failed", 422)
            if not permitted(authority, rule, "external.read", provenance["resource"], "read"):
                continue
        elif not permitted(authority, rule, "workspace.read", "workspace:self", "read"):
            continue
        # Exported/imported snapshots are immutable evidence, not live workspace paths.
        append(
            "artifacts",
            {"manifest": manifest, "bytes_verified": True},
            {"text": data.decode("utf-8", errors="replace")},
        )
    if may_share_readbacks(authority, rule):
        for receipt in child_readbacks(c, task_id, step_id):
            redacted = c.diagnostics.redact(receipt, task_id)
            if redacted != receipt:
                continue
            record = {
                **receipt,
                "source": "authenticated_child_result",
                "matching_artifact_ids": [
                    item["manifest"]["artifact_id"]
                    for item in material["artifacts"]
                    if item["manifest"]["digest"] == receipt["content_digest"]
                ],
            }
            if len(canonical(material)) + len(canonical(record)) + 2 <= MAX_BYTES:
                material["workspace_readbacks"].append(record)
            else:
                material["truncated"] = True
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
            authority, rule, details["effect"], details["resource"], details["action"]
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
