import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from lasa_service.capabilities import (
    CapabilityRegistry,
    Publication,
    reference,
    validate_definition,
)
from lasa_service.contracts import Contracts, parse_json
from lasa_service.errors import LasaError

DESIGN = Path(__file__).resolve().parents[1] / "design/examples"


def example(name):
    return json.loads((DESIGN / (name + ".json")).read_text())


@pytest.fixture
def registry(tmp_path):
    publisher = {
        "namespace": "https://contracts.example.net/capabilities/",
        "definitions": [example("capability-review"), example("capability-attempt")],
    }
    registry = CapabilityRegistry(
        tmp_path,
        [publisher],
        [
            {
                "contract": reference(example("capability-review")),
                "verifier_id": "design-review-v1",
            },
            {
                "contract": reference(example("capability-attempt")),
                "verifier_id": "task-attempt-v1",
            },
        ],
    )
    yield registry, publisher
    registry.close()


@pytest.mark.parametrize(
    "change",
    [
        lambda x: x.update(version="^1.0"),
        lambda x: x["input_schema"].update({"$ref": "https://attacker.example/schema"}),
        lambda x: x["input_schema"].update({"$id": "https://attacker.example/"}),
        lambda x: x.update(max_effects=["external.write"]),
    ],
)
def test_reject_invalid_contract(change):
    definition = example("capability-review")
    change(definition)
    with pytest.raises((LasaError, ValueError)):
        validate_definition(definition)


@pytest.mark.parametrize("raw", ['{"a":1,"a":2}', '{"x":NaN}', '{"x":9007199254740993}'])
def test_reject_noncanonical_json(raw):
    with pytest.raises(LasaError):
        parse_json(raw)


def test_immutable_version_and_publisher_namespace(registry, tmp_path):
    existing, publisher = registry
    original = example("capability-review")
    assert existing.get(reference(original)) == original
    changed = copy.deepcopy(original)
    changed["outcome"] = "Changed semantics"
    with pytest.raises(LasaError, match="unsupported_contract"):
        CapabilityRegistry(tmp_path, [{**publisher, "definitions": [changed]}])
    with pytest.raises(LasaError):
        CapabilityRegistry(tmp_path, [{**publisher, "namespace": "https://other.example/"}])


def publication(registry):
    review = reference(example("capability-review"))
    attempt = reference(example("capability-attempt"))
    raw = example("config")
    raw["discovery_cache"]["page_size"] = 1
    config = SimpleNamespace(
        document=raw,
        revision="deployment1",
        service_id="https://identity.example/services/test",
        peers=[{"expected_service_id": "https://identity.example/services/worker"}],
    )
    budget = raw["limits"]["max_task_budget"]
    rules = {
        "alice": [
            {
                "authorization_ref": "default",
                "contracts": [review, attempt],
                "effects": ["workspace.read"],
                "resources": [{"resource": "workspace:self", "actions": ["read"]}],
                "budget": budget,
                "delegation_grants": [
                    {
                        "sender_service_id": config.service_id,
                        "receiver_service_id": config.peers[0]["expected_service_id"],
                        "contract": attempt,
                    }
                ],
            }
        ],
        "bob": [],
    }
    return Publication(
        config, registry, lambda p: rules[p["subject"]], lambda principal, offer: "available"
    ), rules


def test_caller_scoped_paging_and_private_separation(registry):
    pub, rules = publication(registry[0])
    alice = {"subject": "alice", "kind": "user"}
    first = pub.catalog(alice)
    second = pub.catalog(alice, cursor=first["next_cursor"])
    assert first["revision"] == second["revision"]
    assert len(first["offers"]) == len(second["offers"]) == 1
    assert pub.catalog({"subject": "bob", "kind": "user"})["offers"] == []
    encoded = json.dumps(first) + json.dumps(second)
    assert all(x not in encoded for x in ["executor_id", "credential_ref", "gpt-5.5", "state_root"])
    assert pub.availability(alice, first["offers"][0]["offer_id"])["state"] == "available"
    rules["alice"][0]["effects"] = []
    with pytest.raises(LasaError, match="catalog_changed"):
        pub.catalog(alice, cursor=first["next_cursor"])


def test_offer_selection_revision_withdrawal_and_retained_definition(registry):
    pub, rules = publication(registry[0])
    p = {"subject": "alice", "kind": "user"}
    offer = pub.catalog(p)["offers"][0]
    selection = {
        "contract": offer["contract"],
        "offer_id": offer["offer_id"],
        "offer_revision": offer["revision"],
        "catalog_view": offer["catalog_view"],
    }
    selected = pub.select(p, selection)
    assert selected["offer_id"] == offer["offer_id"]
    assert selected["authorization_ref"] == "default"
    assert "resources" in selected and "resources" not in offer["restrictions"]
    selection["offer_revision"] = "stale"
    with pytest.raises(LasaError, match="offer_changed"):
        pub.select(p, selection)
    rules["alice"] = []
    assert pub.catalog(p)["offers"] == []
    assert registry[0].get(offer["contract"])


def test_output_schema_and_evidence_not_sufficient_for_attempt_objective(registry):
    reg = registry[0]
    definition = example("capability-attempt")
    ref = reference(definition)
    inputs = {
        "objective": "review",
        "requirements": [
            {"id": "required-review", "description": "actual review", "acceptance": ["a review"]}
        ],
    }
    evidence = [
        {
            "criterion_id": "honest-disposition",
            "disposition": "passed",
            "summary": "honest",
            "artifact_ids": [],
        }
    ]
    assert (
        reg.check_output(
            ref,
            inputs,
            {
                "disposition": "unable",
                "reason": "unsupported",
                "unsatisfied_requirements": ["required-review"],
            },
            evidence,
        )["disposition"]
        == "unable"
    )
    with pytest.raises(LasaError, match="verification_failed"):
        reg.check_output(
            ref,
            inputs,
            {
                "disposition": "fulfilled",
                "summary": "done",
                "requirement_evidence": [{"id": "different", "evidence": "none"}],
            },
            evidence,
        )


def test_review_requires_actual_criterion_coverage(registry):
    reg = registry[0]
    definition = example("capability-review")
    with pytest.raises(LasaError, match="verification_failed"):
        reg.check_output(
            reference(definition),
            {"design": "abc", "criteria": [{"id": "required", "description": "review"}]},
            {
                "findings": [],
                "coverage": [
                    {"criterion_id": "other", "disposition": "reviewed", "evidence": "none"}
                ],
            },
            [
                {
                    "criterion_id": "criterion-coverage",
                    "disposition": "passed",
                    "summary": "ok",
                    "artifact_ids": [],
                }
            ],
        )


def test_runtime_loads_target_contracts():
    contracts = Contracts()
    assert contracts.api["openapi"] == "3.2.1"
    contracts.validate("TaskRequest", example("task-request"))


def test_unregistered_contract_cannot_inherit_verifier_by_suffix(tmp_path):
    known = example("capability-review")
    arbitrary = copy.deepcopy(known)
    arbitrary["id"] = "https://contracts.example.net/other/design.review"
    registry = CapabilityRegistry(
        tmp_path,
        [{"namespace": "https://contracts.example.net/", "definitions": [known, arbitrary]}],
        [{"contract": reference(known), "verifier_id": "design-review-v1"}],
    )
    try:
        assert registry.supported(reference(known))
        assert not registry.supported(reference(arbitrary))
        with pytest.raises(LasaError, match="unsupported_contract"):
            registry.check_output(
                reference(arbitrary),
                {"design": "x", "criteria": [{"id": "c", "description": "x"}]},
                {
                    "findings": [],
                    "coverage": [
                        {
                            "criterion_id": "c",
                            "disposition": "reviewed",
                            "evidence": "self asserted",
                        }
                    ],
                },
                [
                    {
                        "criterion_id": "criterion-coverage",
                        "disposition": "passed",
                        "summary": "self asserted",
                        "artifact_ids": [],
                    }
                ],
            )
    finally:
        registry.close()
