"""Grouped inspection configuration validation and operator output."""

import copy
import json

import pytest

from lasa_service.config import ConfigurationError
from lasa_service.errors import LasaError
from lasa_service.inspection import InspectionBindings

from .conftest import EXAMPLES, configuration, documents, example

PEER = "https://identity.example.net/services/legal-review"
INVENTORY = {"document-store": {"documents.read", "documents.search"}, "other": {"records.list"}}


def test_example_compiles_modes_and_overrides():
    settings = example("content-security-all-channels")
    embedded = (EXAMPLES.parent / "content-security.md").read_text().split("```json\n")[1]
    assert json.loads(embedded.split("```")[0]) == settings

    bindings = InspectionBindings(settings, {PEER, "https://other.example.net"}, INVENTORY)
    report = bindings.report()
    assert report["delegates"][PEER]["request"]["profile"] == "local-dlp"
    assert report["delegates"][PEER]["response"] == {
        "mode": "off",
        "origins": {"mode": "peer:" + PEER},
    }
    assert report["delegates"]["https://other.example.net"]["response"]["artifact_profile"] == (
        "local-artifacts"
    )
    assert report["connectors"]["document-store"]["response"]["mode"] == "off"
    assert report["operations"]["document-store/documents.search"]["response"]["mode"] == "off"
    assert (
        report["operations"]["document-store/documents.read"]["response"]["profile"] == "local-dlp"
    )
    assert report["operations"]["other/records.list"]["response"]["mode"] == "observe"
    assert (
        bindings.profiles["local-dlp"]["gateway_id"]
        == bindings.profiles["local-artifacts"]["gateway_id"]
    )
    assert (
        bindings.profiles["local-dlp"]["policy_revision"]
        != bindings.profiles["local-artifacts"]["policy_revision"]
    )


def test_mode_override_retains_inherited_profiles_and_reports_fallback():
    settings = example("content-security-all-channels")
    rule = settings["bindings"]["delegates"]["response"]
    rule.pop("artifact_profile")
    settings["bindings"]["delegates"]["overrides"][0]["response"] = {"mode": "observe"}
    bindings = InspectionBindings(settings, {PEER}, INVENTORY)
    result = bindings.resolve("delegation.response", "peer:" + PEER)
    assert result.profile_for(artifact=True) == result.profile_for(artifact=False) == "local-dlp"
    report = bindings.report()["delegates"][PEER]["response"]
    assert report == {
        "mode": "observe",
        "profile": "local-dlp",
        "artifact_profile": "local-dlp",
        "origins": {
            "mode": "peer:" + PEER,
            "profile": "delegates.default",
            "artifact_profile": "delegates.default",
        },
    }
    unconfigured = InspectionBindings({}, set(), {})
    assert unconfigured.report()["defaults"]["caller"]["request"]["origins"] == {
        "mode": "unconfigured"
    }


@pytest.mark.parametrize(
    "failure,expected",
    [
        ("profile-id", "Duplicate inspection profile ID"),
        ("peer", "unknown peer"),
        ("connector", "unknown connector"),
        ("operation", "outside its connector"),
        ("selector", "Duplicate inspection override selector"),
        ("profile", "unknown profile"),
        ("reenable", "requires a resolved profile"),
        ("artifact", "require a caller or delegate response"),
    ],
)
def test_resolver_rejects_invalid_configuration(failure, expected):
    settings = example("content-security-all-channels")
    groups = settings["bindings"]
    if failure == "profile-id":
        settings["inspection_profiles"][1]["id"] = settings["inspection_profiles"][0]["id"]
    elif failure == "peer":
        groups["delegates"]["overrides"][0]["service_id"] = "https://unconfigured.example.net"
    elif failure == "connector":
        groups["connectors"]["overrides"][0]["connector_id"] = "unconfigured"
    elif failure == "operation":
        groups["connectors"]["overrides"][1]["operation_id"] = "records.list"
    elif failure == "selector":
        override = copy.deepcopy(groups["connectors"]["overrides"][0])
        override["request"] = {"mode": "off"}
        groups["connectors"]["overrides"].append(override)
    elif failure == "profile":
        groups["model"]["request"]["profile"] = "unconfigured"
    elif failure == "reenable":
        groups["connectors"]["overrides"][1]["response"].pop("profile")
    elif failure == "artifact":
        groups["model"]["request"]["artifact_profile"] = "local-artifacts"
    with pytest.raises(ValueError, match=expected):
        InspectionBindings(settings, {PEER}, INVENTORY)


@pytest.mark.parametrize(
    "setting",
    [
        {"gateways": [], "bindings": []},
        {"bindings": {"model": {"request": {"profile": "missing-mode"}}}},
        {"bindings": {"model": {"request": {"mode": "off", "profile": "extra"}}}},
    ],
)
def test_manifest_rejects_flat_and_implicit_mode_rules(tmp_path, setting):
    raw = documents(tmp_path)
    raw["content_security"] = setting
    with pytest.raises(LasaError, match="invalid_input"):
        configuration(raw)


def test_configuration_checks_inventory_references(tmp_path):
    raw = documents(tmp_path)
    raw["content_security"] = {
        "bindings": {
            "delegates": {"overrides": [{"service_id": PEER, "request": {"mode": "off"}}]}
        },
    }
    with pytest.raises(ConfigurationError, match="unknown peer"):
        configuration(raw)
