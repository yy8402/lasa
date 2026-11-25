"""Registered, inline-only workflows with deterministic planning and assembly."""

from .contracts import canonical

REVIEW_CHECKLIST = "design-review-checklist-v1"
REVIEW_HANDOFF = "verified-review-handoff"
STEPS = (
    ("review", "design.review", "review-completed", []),
    ("checklist", "task.attempt", "checklist-completed", ["review"]),
)


def child_contracts():
    from .capabilities import reference
    from .config import builtin_capabilities

    return {step: reference(builtin_capabilities()[name][0]) for step, name, _, _ in STEPS}


def review_checklist_steps(inputs):
    from .capabilities import require

    checklist = inputs["checklist"]
    ids = [item["id"] for item in checklist["requirements"]]
    criteria = [item["id"] for item in inputs["review"]["criteria"]]
    require(
        REVIEW_HANDOFF not in ids
        and len(set(ids)) == len(ids)
        and len(set(criteria)) == len(criteria),
        "invalid_input",
    )
    step_inputs = {
        "review": inputs["review"],
        "checklist": {
            **checklist,
            "requirements": [
                *checklist["requirements"],
                {
                    "id": REVIEW_HANDOFF,
                    "description": "Produce a text checklist grounded in the verified design review.",
                    "acceptance": [
                        "Use the supplied review dependency and explain which verified findings support the checklist."
                    ],
                },
            ],
        },
    }
    refs = child_contracts()
    return [
        {
            "step_id": step,
            "requirement_ids": [criterion],
            "depends_on": dependencies,
            "contract_digest": refs[step]["digest"],
            "input_json": canonical(step_inputs[step]).decode(),
        }
        for step, _, criterion, dependencies in STEPS
    ]


def assemble_review_checklist(completed):
    from .capabilities import require

    require(
        not any(value["artifact_ids"] for value in completed.values()), "verification_failed", 422
    )
    review = completed["review"]["output"]
    checklist = completed["checklist"]["output"]
    require(
        all(item["disposition"] == "reviewed" for item in review["coverage"])
        and checklist["disposition"] == "fulfilled",
        "verification_failed",
        422,
    )
    return {
        "output": {"review": review, "checklist": checklist},
        "artifact_ids": [],
        "evidence": [
            {
                "criterion_id": criterion,
                "disposition": "passed",
                "summary": "Exact verified step output included in the workflow result.",
                "artifact_ids": [],
            }
            for _, _, criterion, _ in STEPS
        ],
    }
