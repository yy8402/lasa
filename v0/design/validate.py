#!/usr/bin/env python3
"""Offline validation of proposed design artifacts; never imports LASA runtime code."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote, urlsplit

import rfc8785
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parent
BASE = "https://schemas.example.net/lasa/1.2/"
FORMAT = FormatChecker()


class ArtifactError(ValueError):
    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        super().__init__(f"{code}: {detail}")


def require(condition: bool, code: str, detail: str) -> None:
    if not condition:
        raise ArtifactError(code, detail)


def unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_key", key)
        result[key] = value
    return result


def load(path: Path):
    value = json.loads(path.read_text(), object_pairs_hook=unique_pairs)
    rfc8785.dumps(value)  # Reject data outside the canonicalization domain.
    return value


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def walk(value: object) -> Iterator[dict]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def within_url(url: str, base: str) -> bool:
    candidate, boundary = urlsplit(url), urlsplit(base)
    path = unquote(candidate.path)
    return (
        candidate.scheme == boundary.scheme == "https"
        and candidate.netloc == boundary.netloc
        and candidate.username is None
        and candidate.password is None
        and not candidate.fragment
        and not candidate.query
        and ".." not in path.split("/")
        and (path == boundary.path or path.startswith(boundary.path.rstrip("/") + "/"))
    )


def pointer(document: object, fragment: str):
    if not fragment:
        return document
    require(fragment.startswith("/"), "reference", f"Unsupported fragment {fragment}")
    value = document
    for segment in fragment[1:].split("/"):
        key = unquote(segment).replace("~1", "/").replace("~0", "~")
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


def validate() -> dict[str, int]:
    json_files = sorted(ROOT.rglob("*.json"))
    documents = {str(path.relative_to(ROOT)): load(path) for path in json_files}
    bundle = documents["contracts.schema.json"]
    config_schema = documents["config.schema.json"]
    private_schema = documents["private.schema.json"]
    api = documents["api.openapi.json"]
    source = documents["standards/source.json"]
    official_path = ROOT / "standards" / source["file"]
    require(
        hashlib.sha256(official_path.read_bytes()).hexdigest() == source["sha256"],
        "upstream_digest",
        "Pinned OpenAPI meta-schema differs from recorded upstream bytes",
    )
    official = documents["standards/" + source["file"]]
    registry = Registry().with_resources(
        (value["$id"], Resource.from_contents(value))
        for value in [bundle, config_schema, private_schema, official]
    )
    # Registry has no retrieve function: unresolved remote references fail offline.
    for schema in [bundle, config_schema, private_schema, official]:
        Draft202012Validator.check_schema(schema)
    Draft202012Validator(official, registry=registry, format_checker=FORMAT).validate(api)

    def shape(value, schema_ref: str) -> None:
        try:
            Draft202012Validator(
                {"$ref": BASE + schema_ref}, registry=registry, format_checker=FORMAT
            ).validate(value)
        except Exception as exc:
            raise ArtifactError("schema", str(exc).splitlines()[0]) from exc

    definitions = {}
    for name in sorted(key for key in documents if key.startswith("examples/capability-")):
        definition = documents[name]
        definitions[(definition["id"], definition["version"])] = definition

    def definition_for(reference: dict) -> dict:
        definition = definitions.get((reference["id"], reference["version"]))
        require(definition is not None, "unknown_contract", str(reference))
        require(digest(definition) == reference["digest"], "contract_digest", reference["id"])
        return definition

    def budget_fits(actual: dict, maximum: dict) -> None:
        require(
            all(actual[key] <= maximum[key] for key in maximum),
            "budget_exceeded",
            "Resource use/allocation exceeds its ceiling",
        )

    def plan_budget(plan: dict, maximum: dict) -> None:
        total = dict(plan["integration_reserve"])
        for step in plan["steps"]:
            for key, value in step["allocation"]["budget"].items():
                total[key] += value
        budget_fits(total, maximum)

    def semantics(value: dict, name: str) -> None:
        for node in walk(value):
            if set(node) == {"id", "version", "digest"}:
                definition_for(node)
        if name == "CapabilityDefinition":
            for key in ["input_schema", "output_schema"]:
                embedded = value[key]
                Draft202012Validator.check_schema(embedded)
                for node in walk(embedded):
                    for keyword in ["$ref", "$dynamicRef"]:
                        require(
                            keyword not in node or node[keyword].startswith("#"),
                            "remote_schema_reference",
                            f"{key}: {node.get(keyword)}",
                        )
                    require(
                        "$id" not in node,
                        "schema_identifier",
                        "Embedded schemas are fragment-local",
                    )
            if "external.write" in value["max_effects"]:
                require(
                    value["effect_safety"]["external_write_commit_evidence_required"],
                    "effect_safety",
                    "External-write contracts require commit evidence",
                )
        elif name in ["CapabilityOffer", "FulfillmentBinding", "TaskAuthorization"]:
            contract = definition_for(value["contract"])
            offered = (
                value["restrictions"]["allowed_effects"]
                if name == "CapabilityOffer"
                else value["allowed_effects"]
            )
            require(set(offered) <= set(contract["max_effects"]), "effect_ceiling", name)
        elif name == "OfferCatalog":
            ids = [offer["offer_id"] for offer in value["offers"]]
            require(len(ids) == len(set(ids)), "duplicate_offer", "Catalog offer IDs")
            for offer in value["offers"]:
                require(
                    offer["catalog_view"] == value["catalog_view"],
                    "catalog_view",
                    "Mixed authority views",
                )
                require(
                    timestamp(value["valid_until"]) <= timestamp(offer["valid_until"]),
                    "catalog_expiry",
                    "Catalog outlives offer",
                )
                semantics(offer, "CapabilityOffer")
        elif name == "ServiceDescriptor":
            for protocol in value["protocols"]:
                require(
                    set(protocol["required_features"]) <= set(protocol["features"]),
                    "protocol_features",
                    "Required features are not supported",
                )
                for link in [
                    protocol["openapi_url"],
                    value["catalog_url"],
                    value["contract_url_template"],
                ]:
                    require(within_url(link, protocol["base_url"]), "link_boundary", link)
        elif name == "Availability":
            require(
                timestamp(value["valid_until"]) > timestamp(value["checked_at"]),
                "availability_expiry",
                "Observation lifetime",
            )
        elif name == "TaskRequest":
            contract = definition_for(value["selection"]["contract"])
            Draft202012Validator(contract["input_schema"], format_checker=FORMAT).validate(
                value["input"]
            )
            require(
                len(rfc8785.dumps(value["input"]))
                <= value["requested_limits"]["budget"]["input_bytes"],
                "budget_exceeded",
                "Input bytes",
            )
            if "delegation" in value:
                envelope = value["delegation"]
                core = {key: item for key, item in value.items() if key != "delegation"}
                require(
                    digest(core) == envelope["request_digest"],
                    "request_digest",
                    "Delegated core changed",
                )
                require(
                    envelope["ancestry"][-1] == envelope["parent_service_id"]
                    and envelope["recipient_service_id"] not in envelope["ancestry"],
                    "ancestry",
                    "Parent ends ancestry and recipient is outside it",
                )
                require(
                    envelope["allocation"] == value["requested_limits"],
                    "allocation",
                    "Child request differs from reserved allocation",
                )
                require(
                    envelope["remaining_hops"] == value["requested_limits"]["max_hops"],
                    "hops",
                    "Child hop ceiling differs",
                )
        elif name == "TaskResult":
            contract = definition_for(value["contract"])
            Draft202012Validator(contract["output_schema"], format_checker=FORMAT).validate(
                value["output"]
            )
            require(
                value["effect_disposition"] != "unknown",
                "task_consistency",
                "Unknown effects cannot be a completed result",
            )
            passed = {e["criterion_id"] for e in value["evidence"] if e["disposition"] == "passed"}
            require(
                {p["id"] for p in contract["postconditions"]} <= passed,
                "postcondition_evidence",
                "Required completion evidence missing",
            )
        elif name == "Task":
            if "admission" in value:
                require(
                    value["admission"]["request_digest"] == value["request_digest"],
                    "task_consistency",
                    "Admission request mismatch",
                )
                require(
                    value["admission"]["contract"] == value["selection"]["contract"],
                    "task_consistency",
                    "Admission contract mismatch",
                )
            if "result" in value:
                result = value["result"]
                require(
                    result["request_digest"] == value["request_digest"]
                    and result["contract"] == value["selection"]["contract"],
                    "task_consistency",
                    "Result binding mismatch",
                )
                budget_fits(result["usage"], value["admission"]["effective_limits"]["budget"])
                semantics(result, "TaskResult")
        elif name == "ResponsibilityPlan":
            requirements = {item["requirement_id"]: item for item in value["requirements"]}
            steps = {step["step_id"]: step for step in value["steps"]}
            require(
                len(requirements) == len(value["requirements"])
                and len(steps) == len(value["steps"]),
                "duplicate_identity",
                "Plan IDs",
            )
            covered = set(value["integration_requirement_ids"])
            visited, active = set(), set()

            def visit(step_id):
                require(step_id in steps, "dependency", step_id)
                require(step_id not in active, "dependency_cycle", step_id)
                if step_id in visited:
                    return
                active.add(step_id)
                for dependency in steps[step_id]["depends_on"]:
                    visit(dependency)
                active.remove(step_id)
                visited.add(step_id)

            for step in steps.values():
                covered.update(step["requirement_ids"])
                visit(step["step_id"])
            require(
                covered <= set(requirements),
                "unknown_requirement",
                "Plan refers to undeclared requirements",
            )
            mandatory = {key for key, item in requirements.items() if item["mandatory"]}
            require(
                mandatory <= covered,
                "uncovered_requirement",
                "Mandatory requirement lacks an owner",
            )
        elif name == "Config":
            executors = {executor["id"] for executor in value["executors"]}
            for binding in value["bindings"]:
                require(
                    binding["executor_id"] in executors, "executor_binding", binding["executor_id"]
                )
                semantics(binding, "FulfillmentBinding")
            limits = value["limits"]
            budget_fits(limits["assessment_budget"], limits["max_task_budget"])
            budget_fits(limits["integration_reserve"], limits["max_task_budget"])
            require(
                limits["assessment_budget"]["tool_calls"]
                == limits["assessment_budget"]["delegations"]
                == 0,
                "assessment_effect",
                "Evaluation cannot dispatch tools/children",
            )
            require(
                value["authentication"]["audience"] == value["service"]["id"],
                "service_identity",
                "Receiver audience",
            )
            require(
                within_url(value["service"]["descriptor_url"], value["service"]["base_url"]),
                "link_boundary",
                "Own descriptor",
            )
            peer_ids = {value["service"]["id"]}
            for peer in value["peers"]:
                require(
                    peer["expected_service_id"] not in peer_ids, "service_identity", "Unique peer"
                )
                peer_ids.add(peer["expected_service_id"])
                require(
                    within_url(peer["descriptor_url"], peer["allowed_base_url"]),
                    "link_boundary",
                    "Peer descriptor",
                )

    # Check every authored schema reference resolves in this package, never through network.
    reference_count = 0
    for filename in [
        "contracts.schema.json",
        "config.schema.json",
        "private.schema.json",
        "api.openapi.json",
    ]:
        for node in walk(documents[filename]):
            if "$ref" not in node:
                continue
            target, _, fragment = node["$ref"].partition("#")
            target = next(
                (
                    key
                    for key, value in documents.items()
                    if isinstance(value, dict) and value.get("$id") == target
                ),
                target,
            )
            require(not target or target in documents, "reference", node["$ref"])
            pointer(documents[target or filename], fragment)
            reference_count += 1

    manifest = documents["examples/manifest.json"]
    require(
        {item["file"] for item in manifest}
        == {
            path.name for path in (ROOT / "examples").glob("*.json") if path.name != "manifest.json"
        },
        "manifest",
        "Every example must be registered exactly once",
    )
    require(
        len({item["file"] for item in manifest}) == len(manifest),
        "manifest",
        "Duplicate registration",
    )
    for item in manifest:
        example = documents["examples/" + item["file"]]
        shape(example, item["schema"])
        name = item["schema"].rsplit("/", 1)[-1] if "#" in item["schema"] else "Config"
        semantics(example, name)

    def example(name):
        return documents["examples/" + name + ".json"]

    # Cross-artifact checks with receiver and parent context.
    child = example("delegated-task-request")
    root_request = example("task-request")
    authority = example("authorization")
    require(
        authority["request_digest"] == child["delegation"]["request_digest"],
        "authority_binding",
        "Receiver authority request binding",
    )
    require(
        authority["principal_id"] == child["delegation"]["parent_service_id"],
        "authority_binding",
        "Authenticated delegator",
    )
    require(
        authority["receiver_service_id"] == child["delegation"]["recipient_service_id"],
        "authority_binding",
        "Delegation addressed to the receiver",
    )
    require(
        authority["contract"] == child["selection"]["contract"]
        and authority["limits"] == child["requested_limits"],
        "authority_binding",
        "Receiver exact contract/ceiling",
    )
    budget_fits(child["requested_limits"]["budget"], root_request["requested_limits"]["budget"])
    require(
        child["requested_limits"]["max_hops"] < root_request["requested_limits"]["max_hops"],
        "hops",
        "Strict hop attenuation",
    )
    reserve_ms = example("plan")["integration_reserve"]["wall_time_ms"]
    remaining_ms = (
        timestamp(root_request["requested_limits"]["deadline"])
        - timestamp(child["requested_limits"]["deadline"])
    ).total_seconds() * 1000
    require(remaining_ms >= reserve_ms, "integration_reserve", "Parent integration time")
    plan_budget(example("plan"), root_request["requested_limits"]["budget"])
    plan_budget(example("child-plan"), child["requested_limits"]["budget"])
    require(
        example("task-completed")["admission"]["plan_digest"] == digest(example("child-plan")),
        "plan_digest",
        "Accepted child plan",
    )
    for name in ["descriptor", "catalog", "offer", "availability"]:
        forbidden = {
            "executor_id",
            "tool_ids",
            "credential_ref",
            "workspace_root",
            "model",
            "jwks_url",
        }
        require(
            not any(forbidden & set(node) for node in walk(example(name))), "private_leak", name
        )
    require(
        example("call-event")["payload"]["input_digest"] == child["delegation"]["request_digest"],
        "event_binding",
        "Child call metadata",
    )

    # Mutation fixtures prove that negative design cases are rejected for the stated reason.
    cases = documents["validation-cases.json"]
    by_file = {item["file"]: item for item in manifest}
    for case in cases:
        value = copy.deepcopy(documents["examples/" + case["file"]])
        for mutation in case["mutations"]:
            parent = value
            for segment in mutation["path"][:-1]:
                parent = parent[segment]
            key = mutation["path"][-1]
            if mutation["op"] == "remove":
                del parent[key]
            else:
                parent[key] = mutation["value"]
        entry = by_file[case["file"]]
        try:
            shape(value, entry["schema"])
            name = entry["schema"].rsplit("/", 1)[-1] if "#" in entry["schema"] else "Config"
            semantics(value, name)
            if case.get("context") == "root_plan_budget":
                plan_budget(value, root_request["requested_limits"]["budget"])
        except ArtifactError as exc:
            require(
                exc.code == case["expected"],
                "negative_case",
                f"{case['id']}: expected {case['expected']}, got {exc.code}",
            )
        else:
            raise ArtifactError("negative_case", f"{case['id']} unexpectedly accepted")

    operations = []
    for path, item in api["paths"].items():
        for method, operation in item.items():
            operations.append(operation["operationId"])
            parameters = operation.get("parameters", [])
            for variable in re.findall(r"{([^}]+)}", path):
                require(
                    any(
                        p["name"] == variable and p["in"] == "path" and p["required"]
                        for p in parameters
                    ),
                    "openapi_parameter",
                    path,
                )
            if method == "post":
                require(
                    any(p["name"] == "Idempotency-Key" and p["required"] for p in parameters),
                    "openapi_idempotency",
                    path,
                )
                if path.endswith(("/inputs", "/cancel")):
                    require(
                        any(p["name"] == "If-Match" and p["required"] for p in parameters),
                        "openapi_precondition",
                        path,
                    )
    require(
        len(operations) == len(set(operations)), "operation_id", "Duplicate OpenAPI operation ID"
    )

    # Local Markdown links are checked; external sources are not fetched by this tool.
    markdown_links = 0
    for path in ROOT.glob("*.md"):
        for target in re.findall(r"\]\(([^)]+)\)", path.read_text()):
            if "://" in target or target.startswith("#"):
                continue
            destination = target.split("#", 1)[0]
            require((path.parent / destination).exists(), "document_link", f"{path.name}: {target}")
            markdown_links += 1
    return {
        "json_documents": len(json_files),
        "contract_definitions": len(bundle["$defs"]),
        "positive_examples": len(manifest),
        "negative_cases": len(cases),
        "resolved_authored_references": reference_count,
        "openapi_operations": len(operations),
        "local_markdown_links": markdown_links,
    }


if __name__ == "__main__":
    print(json.dumps({"status": "passed", **validate()}, indent=2))
