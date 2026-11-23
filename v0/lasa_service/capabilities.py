"""Immutable outcome definitions, caller-scoped offers, and completion checks."""

import base64
import copy
import hashlib
import hmac
import secrets
import sqlite3
import time
from datetime import UTC, datetime

from jsonschema import Draft202012Validator

from .contracts import canonical, digest, parse_json, protocol_contracts, validate_data
from .errors import LasaError
from .outcomes import SOURCE_PROFILES


def require(condition, code="precondition_failed", status=400):
    if not condition:
        raise LasaError(code, status)


def instant(seconds=None):
    return (
        datetime.fromtimestamp(time.time() if seconds is None else seconds, UTC)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def epoch(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def reference(definition):
    return {key: definition[key] for key in ("id", "version")} | {"digest": digest(definition)}


def nodes(value):
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from nodes(item)
    elif isinstance(value, list):
        for item in value:
            yield from nodes(item)


def validate_definition(definition):
    protocol_contracts().validate("CapabilityDefinition", definition)
    for key in ("input_schema", "output_schema"):
        schema = definition[key]
        Draft202012Validator.check_schema(schema)
        for node in nodes(schema):
            require("$id" not in node, "invalid_input")
            for name in ("$ref", "$dynamicRef"):
                if name in node:
                    target = node[name]
                    require(target.startswith("#/"), "invalid_input")
                    current = schema
                    try:
                        for part in target[2:].split("/"):
                            current = current[part.replace("~1", "/").replace("~0", "~")]
                    except (KeyError, TypeError):
                        raise LasaError("invalid_input") from None
    if "external.write" in definition["max_effects"]:
        require(
            definition["effect_safety"]["external_write_commit_evidence_required"], "invalid_input"
        )
    return definition


class CapabilityRegistry:
    def __init__(self, root, publishers, verifiers=()):
        self.db = sqlite3.connect(
            ":memory:" if root is None else root / "contracts.sqlite3", isolation_level=None
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS definitions(id TEXT,version TEXT,digest TEXT UNIQUE,document BLOB,PRIMARY KEY(id,version))"
        )
        self.current = {}
        self.verifiers = {digest(x["contract"]): x["verifier_id"] for x in verifiers}
        require(len(self.verifiers) == len(verifiers), "invalid_input")
        require(
            set(self.verifiers.values())
            <= {"design-review-v1", "task-attempt-v1"} | SOURCE_PROFILES,
            "unsupported_contract",
        )
        try:
            for publisher in publishers:
                for definition in publisher["definitions"]:
                    validate_definition(definition)
                    require(
                        definition["id"].startswith(publisher["namespace"]), "unsupported_contract"
                    )
                    ref = reference(definition)
                    existing = self.db.execute(
                        "SELECT digest FROM definitions WHERE id=? AND version=?",
                        (ref["id"], ref["version"]),
                    ).fetchone()
                    require(
                        existing is None or existing[0] == ref["digest"],
                        "unsupported_contract",
                        409,
                    )
                    self.db.execute(
                        "INSERT OR IGNORE INTO definitions VALUES(?,?,?,?)",
                        (ref["id"], ref["version"], ref["digest"], canonical(definition)),
                    )
                    self.current[ref["digest"]] = copy.deepcopy(definition)
        except BaseException:
            self.close()
            raise

    @classmethod
    def configured(cls, config, root=None):
        registry = cls(root, config.publishers, config.document["verifiers"])
        try:
            registry.validate_configuration(config)
        except BaseException:
            registry.close()
            raise
        return registry

    def validate_configuration(self, config):
        for ref in config.document["published_contracts"]:
            require(
                ref["digest"] in self.current and self.supported(ref), "unsupported_contract", 422
            )
            self.get(ref)
        for entry in config.document["verifiers"]:
            ref = entry["contract"]
            require(ref["digest"] in self.current, "unsupported_contract", 422)
            self.get(ref)
        operations = {
            operation["operation_id"]: operation
            for connector in config.connectors.values()
            for operation in connector["operations"]
        }
        for binding in config.document["bindings"]:
            definition = self.get(binding["contract"])
            require(
                set(binding["allowed_effects"]) <= set(definition["max_effects"]),
                "authority_denied",
                403,
            )
            for name in binding["required_operations"]:
                require(
                    all(
                        match["input_field"] in definition["input_schema"].get("properties", {})
                        for match in operations[name]["task_input_bindings"]
                    ),
                    "invalid_input",
                )
            if self.source_profile(binding["contract"]):
                require(bool(binding["required_operations"]), "invalid_input")

    def close(self):
        self.db.close()

    def get(self, ref):
        row = self.db.execute(
            "SELECT document FROM definitions WHERE digest=? AND id=? AND version=?",
            (ref["digest"], ref["id"], ref["version"]),
        ).fetchone()
        require(row is not None, "unsupported_contract", 422)
        return parse_json(row[0])

    def by_digest(self, value):
        row = self.db.execute(
            "SELECT document FROM definitions WHERE digest=?", (value,)
        ).fetchone()
        require(row is not None, "not_found", 404)
        return parse_json(row[0])

    def supported(self, ref):
        return digest(ref) in self.verifiers

    def source_profile(self, ref):
        profile = self.verifiers.get(digest(ref))
        return profile if profile in SOURCE_PROFILES else None

    def input(self, ref, value):
        require(self.supported(ref), "unsupported_contract", 422)
        definition = self.get(ref)
        validate_data(definition["input_schema"], value)
        return definition

    def check_output(self, ref, inputs, output, evidence):
        require(self.supported(ref), "unsupported_contract", 422)
        definition = self.get(ref)
        validate_data(definition["output_schema"], output, "verification_failed", 422)
        required = {item["id"] for item in definition["postconditions"]}
        passed = {
            item["criterion_id"]
            for item in evidence
            if item["disposition"] == "passed" and item["summary"].strip()
        }
        require(required <= passed, "verification_failed", 422)
        # Exact verifier references are receiver-approved; descriptors never supply code.
        profile = self.verifiers[digest(ref)]
        if profile == "task-attempt-v1":
            if output["disposition"] == "fulfilled":
                require(
                    {x["id"] for x in inputs["requirements"]}
                    <= {x["id"] for x in output["requirement_evidence"]},
                    "verification_failed",
                    422,
                )
        elif profile == "design-review-v1":
            expected = {x["id"] for x in inputs["criteria"]}
            coverage = [x["criterion_id"] for x in output["coverage"]]
            require(
                len(coverage) == len(set(coverage)) and expected == set(coverage),
                "verification_failed",
                422,
            )
        return output


def offer_terms(offer):
    """Semantic pins exclude only the renewable discovery representation lease."""
    return {key: value for key, value in offer.items() if key not in {"revision", "valid_until"}}


class Publication:
    def __init__(self, config, registry, rules, availability_state):
        self.config, self.registry, self.rules, self.availability_state = (
            config,
            registry,
            rules,
            availability_state,
        )
        self.snapshots = {}
        self.cursor_key = secrets.token_bytes(32)

    def snapshot(self, principal):
        rules = self.rules(principal)
        view = (
            "view-"
            + digest(
                {
                    "principal": principal["subject"],
                    "policy": rules,
                    "policy_revision": self.config.policy()["revision"]
                    if hasattr(self.config, "policy")
                    else None,
                    "revision": self.config.revision,
                }
            )[7:39]
        )
        previous = self.snapshots.get(principal["subject"])
        if (
            previous
            and previous["catalog_view"] == view
            and epoch(previous["valid_until"]) > time.time()
        ):
            return previous
        expires = instant(
            time.time() + max(1, self.config.document["discovery_cache"]["catalog_max_age_seconds"])
        )
        offers = []
        configured = {x["digest"] for x in self.config.document["published_contracts"]}
        peer_ids = {settings["expected_service_id"] for settings in self.config.peers}
        for rule in rules:
            delegated = [
                grant["contract"]
                for grant in rule["delegation_grants"]
                if grant["sender_service_id"] == self.config.service_id
                and grant["receiver_service_id"] in peer_ids
            ]
            for ref in rule["contracts"]:
                if (
                    ref["digest"] not in configured
                    or ref["digest"] not in self.registry.current
                    or not self.registry.supported(ref)
                ):
                    continue
                definition = self.registry.get(ref)
                can_local = any(x["contract"] == ref for x in self.config.document["bindings"])
                can_delegate = ref in delegated
                if not (can_local or can_delegate):
                    continue
                allowed = sorted(set(rule["effects"]) & set(definition["max_effects"]))
                offer_id = (
                    "offer-"
                    + digest(
                        {
                            "subject": principal["subject"],
                            "authority": rule["authorization_ref"],
                            "contract": ref,
                        }
                    )[7:39]
                )
                offer = {
                    "offer_id": offer_id,
                    "revision": "offer-"
                    + digest({"view": view, "rule": rule, "contract": ref, "expiry": expires})[
                        7:39
                    ],
                    "catalog_view": view,
                    "authorization_ref": rule["authorization_ref"],
                    "contract": ref,
                    "restrictions": {
                        "allowed_effects": allowed,
                        "resources": copy.deepcopy(rule["resources"]),
                        "additional_preconditions": copy.deepcopy(
                            rule.get("offer_preconditions", [])
                        ),
                    },
                    "max_budget": {
                        key: min(limit, self.config.document["limits"]["max_task_budget"][key])
                        for key, limit in rule["budget"].items()
                    },
                    "max_hops": min(rule["max_hops"], self.config.document["limits"]["max_hops"]),
                    "valid_until": expires,
                }
                for resource in ("model_calls", "model_tokens"):
                    minimum = self.config.document["limits"]["integration_reserve"][resource]
                    if self.config.peers:
                        minimum += self.config.document["limits"]["assessment_budget"][resource]
                    if resource == "model_calls":
                        minimum += 1
                    if minimum:
                        offer["restrictions"]["additional_preconditions"].append(
                            {
                                "kind": "budget_minimum",
                                "description": "Minimum receiver assessment, execution, and verification allocation.",
                                "resource": resource,
                                "minimum": minimum,
                            }
                        )
                offers.append(offer)
        snapshot = {
            "service_id": self.config.service_id,
            "catalog_view": view,
            "revision": "catalog-"
            + digest({"view": view, "offers": offers, "expiry": expires})[7:39],
            "valid_until": expires,
            "offers": sorted(offers, key=lambda x: x["offer_id"]),
            "next_cursor": None,
        }
        self.snapshots[principal["subject"]] = snapshot
        return snapshot

    def catalog(self, principal, *, cursor=None, contract_id=None, contract_version=None):
        require(bool(contract_id) == bool(contract_version), "invalid_input")
        value = copy.deepcopy(self.snapshot(principal))
        start = 0
        if cursor:
            try:
                raw, signature = cursor.split(".")
                require(
                    hmac.compare_digest(
                        signature,
                        hmac.new(self.cursor_key, raw.encode(), hashlib.sha256).hexdigest(),
                    ),
                    "catalog_changed",
                    409,
                )
                decoded = parse_json(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
                require(
                    decoded["revision"] == value["revision"]
                    and decoded["view"] == value["catalog_view"]
                    and decoded["filter"] == [contract_id, contract_version],
                    "catalog_changed",
                    409,
                )
                start = decoded["start"]
                require(type(start) is int and 0 <= start <= len(value["offers"]), "invalid_input")
            except (ValueError, KeyError, TypeError):
                raise LasaError("catalog_changed", 409) from None
        if contract_id:
            value["offers"] = [
                x
                for x in value["offers"]
                if x["contract"]["id"] == contract_id
                and x["contract"]["version"] == contract_version
            ]
        end = start + self.config.document["discovery_cache"]["page_size"]
        if end < len(value["offers"]):
            raw = (
                base64.urlsafe_b64encode(
                    canonical(
                        {
                            "revision": value["revision"],
                            "view": value["catalog_view"],
                            "filter": [contract_id, contract_version],
                            "start": end,
                        }
                    )
                )
                .decode()
                .rstrip("=")
            )
            value["next_cursor"] = (
                raw + "." + hmac.new(self.cursor_key, raw.encode(), hashlib.sha256).hexdigest()
            )
        value["offers"] = value["offers"][start:end]
        return value

    def offer(self, principal, offer_id):
        for offer in self.snapshot(principal)["offers"]:
            if offer["offer_id"] == offer_id:
                return copy.deepcopy(offer)
        raise LasaError("not_found", 404)

    def select(self, principal, selection):
        offer = self.offer(principal, selection["offer_id"])
        require(
            all(
                selection[key] == offer[target]
                for key, target in [
                    ("catalog_view", "catalog_view"),
                    ("offer_revision", "revision"),
                    ("contract", "contract"),
                ]
            ),
            "offer_changed",
            409,
        )
        require(epoch(offer["valid_until"]) > time.time(), "offer_changed", 409)
        return offer

    def revalidate(self, principal, pinned):
        try:
            current = self.offer(principal, pinned["offer_id"])
        except LasaError:
            raise LasaError("offer_changed", 409) from None
        require(offer_terms(current) == offer_terms(pinned), "offer_changed", 409)
        return copy.deepcopy(pinned)

    def availability(self, principal, offer_id):
        offer = self.offer(principal, offer_id)
        state = self.availability_state(principal, offer)
        checked = instant()
        value = {
            "offer_id": offer_id,
            "offer_revision": offer["revision"],
            "revision": "availability-" + digest({"state": state, "at": checked})[7:39],
            "state": state,
            "checked_at": checked,
            "valid_until": instant(
                time.time()
                + max(1, self.config.document["discovery_cache"]["availability_max_age_seconds"])
            ),
        }
        if state == "busy":
            value["retry_after_seconds"] = 1
        return value
