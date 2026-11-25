"""Bounded verification material from admitted plans and execution records.

Receipts establish provenance and returned bytes. Semantic judgments remain
the verifier's responsibility.
"""

import hashlib

from .capabilities import require
from .contracts import canonical, digest, parse_json, request_digest
from .recovery import capability_context

MAX_BYTES = 16384
MAX_OPERATIONS = 32
MAX_ARTIFACTS = 16


def permitted(authority, rule, effect, resource, action):
    return (
        effect in authority["allowed_effects"]
        and effect in rule["effects"]
        and all(
            any(r["resource"] == resource and action in r["actions"] for r in resources)
            for resources in [authority["resources"], rule["resources"]]
        )
    )


def content_digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def append_evidence(c, task_id, material, kind, receipt, content):
    value = {**receipt, "content": c.diagnostics.redact(content, task_id)}
    if len(canonical(material)) + len(canonical(value)) + 2 > MAX_BYTES:
        value = {**receipt, "content_omitted": True}
        material["truncated"] = True
    if len(canonical(material)) + len(canonical(value)) + 2 <= MAX_BYTES:
        material[kind].append(value)
    else:
        material["truncated"] = True


def approved_model_input(c, task_id, step_id, contract, inputs):
    if step_id is None:
        return inputs, None
    admitted_digest = digest(inputs)
    row = c.store.db.execute(
        "SELECT document FROM audit WHERE task_id=? AND kind='model_input_revision' "
        "AND json_extract(document,'$.step_id')=? AND json_extract(document,'$.contract_digest')=? "
        "AND json_extract(document,'$.admitted_input_digest')=? ORDER BY rowid LIMIT 1",
        (task_id, step_id, contract["digest"], admitted_digest),
    ).fetchone()
    if row is None:
        return inputs, None
    receipt = parse_json(row["document"])
    revised = capability_context(c.registry.get(contract), inputs)
    require(
        revised != inputs and digest(revised) == receipt["input_digest"], "verification_failed", 422
    )
    return revised, {
        key: receipt[key]
        for key in (
            "admitted_input_digest",
            "input_digest",
            "operation_id",
            "transfer_id",
            "model_request_digest",
        )
    }


def add_workflow_evidence(c, task_id, material, verified_steps, *, include_step_inputs):
    row, task = c.store.task(task_id)
    request = parse_json(row["request"])
    inherited = request.get("imports", [])
    if not inherited and not verified_steps and not include_step_inputs:
        return
    if verified_steps or include_step_inputs:
        admitted_plan = parse_json(row["plan"])
        require(
            digest(admitted_plan) == task["admission"]["plan_digest"], "verification_failed", 422
        )
        steps = {step["step_id"]: step for step in admitted_plan["document"]["steps"]}
    records = []
    if inherited:
        principal = parse_json(row["principal"])
        authority = parse_json(row["authority"])
        require(
            principal["id"] == authority["principal_id"]
            and authority["receiver_service_id"] == c.config.service_id
            and authority["request_digest"] == task["request_digest"] == request_digest(request),
            "verification_failed",
            422,
        )
        records.extend(
            (
                item["label"],
                item["output"],
                {
                    "source": "authenticated_consumer_request",
                    "contract": item["contract"],
                    "request_digest": task["request_digest"],
                },
            )
            for item in inherited
        )
    for key, result in verified_steps.items():
        step = steps[key]
        records.append(
            (
                key,
                result["output"],
                {
                    "source": "receiver_verified_step",
                    "service_id": c.config.service_id,
                    "task_id": task_id,
                    "contract": step["contract"],
                    "executor": step["executor"],
                    "depends_on": step["depends_on"],
                },
            )
        )
    if records and start_evidence_list(material, "dependencies"):
        for step_id, output, provenance in records:
            receipt = c.diagnostics.redact(
                {**provenance, "step_id": step_id, "output_digest": digest(output)}, task_id
            )
            append_evidence(c, task_id, material, "dependencies", receipt, output)
    if include_step_inputs and start_evidence_list(material, "step_inputs"):
        for step_id, step in steps.items():
            inputs = admitted_plan["inputs"][step_id]
            revised, provenance = approved_model_input(
                c, task_id, step_id, step["contract"], inputs
            )
            receipt = {"step_id": step_id, **(provenance or {"input_digest": digest(revised)})}
            receipt = c.diagnostics.redact(receipt, task_id)
            append_evidence(c, task_id, material, "step_inputs", receipt, revised)


def start_evidence_list(material, kind):
    if len(canonical({**material, kind: []})) > MAX_BYTES:
        material["truncated"] = True
        return False
    material[kind] = []
    return True


def verification_material(coordinator, task_id, *, step_id=None, artifact_ids=()):
    c = coordinator
    authority = c.authority(task_id)
    rule = c.current_rule(task_id)
    material = {
        "source": "receiver_durable_store",
        "service_id": c.config.service_id,
        "task_id": task_id,
        "step_id": step_id,
        "operations": [],
        "artifacts": [],
        "truncated": False,
    }

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
        append_evidence(
            c,
            task_id,
            material,
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
            authority, rule, details["effect"], details["resource"], details["action"]
        ):
            continue
        intent = parse_json(row["intent"])
        require(digest(intent) == row["digest"], "verification_failed", 422)
        result = parse_json(row["result"]) if row["result"] is not None else None
        append_evidence(
            c,
            task_id,
            material,
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
