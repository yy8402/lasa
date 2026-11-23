"""Claim binding for receipts returned by authenticated child supervisors."""

from .contracts import digest


def receipt_for(service_id, task_id, request, result, revision):
    return {
        "service_id": service_id,
        "task_id": task_id,
        "delegation_id": request["delegation"]["delegation_id"],
        "verifier_revision": revision,
        "result_digest": digest(
            {key: value for key, value in result.items() if key != "verification_receipt"}
        ),
        "dependency_digest": digest(request.get("dependency_results", {})),
    }
