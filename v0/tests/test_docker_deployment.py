import hashlib
import json
import os
import secrets
from uuid import uuid4

import pytest
from lasa_deploy import deployment, image_cache
from lasa_deploy.contracts import ConfigurationError
from lasa_deploy.managed_deployment import HostDeployment

from lasa_service.deploy_api import inspect_config
from lasa_service.inspection import (
    MANAGED_DLP_GATEWAY_ID,
    MANAGED_DLP_HOST,
    MANAGED_DLP_ORIGIN,
    MANAGED_DLP_POLICY_REVISION,
    MANAGED_DLP_URL,
)

from .conftest import example
from .http_helpers import certificate


@pytest.mark.parametrize(
    ("archive_contents", "recorded", "status", "recovery_available", "readiness"),
    [
        (b"verified", True, "verified", True, "deferred"),
        (b"verified", True, "verified", False, "blocked"),
        (b"corrupt", True, "checksum_mismatch", True, "blocked"),
        (None, True, "missing", True, "blocked"),
        (b"verified", False, "not_recorded", True, "blocked"),
    ],
)
def test_cold_plan_only_reads_candidate_and_recovery_images(
    tmp_path, monkeypatch, archive_contents, recorded, status, recovery_available, readiness
):
    platform = "linux/amd64"
    supervisor, shared, old_worker = (f"sha256:{n:064x}" for n in range(1, 4))
    pins = {"supervisor": supervisor, "launcher": shared}
    checksum = "sha256:" + hashlib.sha256(b"verified").hexdigest()
    release = {
        "release_id": "candidate",
        "platform": platform,
        "artifacts": {"images": checksum} if recorded else {},
    }
    control = tmp_path / "control"
    plan = HostDeployment(
        {
            "name": "test-site",
            "release": str(tmp_path / "release.json"),
            "control_directory": str(control),
        }
    )
    active = {
        "images": {"launcher": shared, "worker": old_worker},
        "release": {**release, "release_id": "serving", "artifacts": {"images": checksum}},
        "spec": {"release": str(tmp_path / "previous/release.json")},
    }
    archive = tmp_path / "images.tar.gz"
    recovery_archive = tmp_path / "previous/images.tar.gz"
    if archive_contents is not None:
        archive.write_bytes(archive_contents)
    if recovery_available:
        recovery_archive.parent.mkdir()
        recovery_archive.write_bytes(b"verified")
    monkeypatch.setattr(plan, "journal", lambda: {"active": active})
    monkeypatch.setattr(plan, "release_inputs", lambda active: (release, "daemon", pins))
    monkeypatch.setattr(plan, "candidate", lambda *args: pytest.fail("Started runtime preflight"))
    inspected = []

    def inspect(*args):
        assert args[:2] == ("image", "inspect")
        inspected.append(args[-1])
        if args[-1] != shared:
            raise ConfigurationError("No such image")
        return platform

    monkeypatch.setattr(image_cache, "docker", inspect)
    result = plan.run("plan")
    assert result["readiness"] == readiness
    assert result["preflight"] == "deferred"
    assert result["state"] is None and result["change"] is None
    candidate, recovery = result["image_imports"]
    assert candidate["purpose"] == "candidate" and candidate["release"] == "candidate"
    assert candidate["archive"] == str(archive) and candidate["archive_status"] == status
    assert candidate["missing_images"] == {"supervisor": supervisor}
    assert bool(candidate.get("remediation")) == (status != "verified")
    assert recovery["purpose"] == "recovery" and recovery["release"] == "serving"
    assert recovery["archive"] == str(recovery_archive)
    assert recovery["archive_status"] == ("verified" if recovery_available else "missing")
    assert recovery["missing_images"] == {"worker": old_worker}
    assert bool(recovery.get("remediation")) == (not recovery_available)
    assert inspected == [supervisor, shared, old_worker]
    assert not control.exists()


def settings(tmp_path, manifest, **local_dlp):
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(manifest))
    profiles = inspect_config({"config": str(config_file)})["inspection_profiles"]
    return deployment.DockerDeployment(
        "lasa-test", ((config_file, profiles),), local_dlp, tmp_path / ".lasa-inspection"
    )


def profile(url=MANAGED_DLP_URL):
    return {
        "id": "dlp",
        "url": url,
        "gateway_id": MANAGED_DLP_GATEWAY_ID,
        "policy_revision": MANAGED_DLP_POLICY_REVISION,
        "credential_ref": "env:DLP_TOKEN",
        "region": "local",
        "retention": "metadata-only",
    }


@pytest.mark.parametrize("mode", ["observe", "enforce"])
def test_disabled_rejects_active_bundled_profile_before_docker(tmp_path, monkeypatch, mode):
    def unexpected(*args, **kwargs):
        pytest.fail("Deployment validation must run before Docker")

    monkeypatch.setattr(deployment, "docker", unexpected)
    manifest = example("config-no-peer")
    manifest["content_security"] = {
        "inspection_profiles": [profile()],
        "bindings": {"caller": {"request": {"mode": mode, "profile": "dlp"}}},
    }
    with pytest.raises(ConfigurationError, match="requires local_dlp.enabled=true"):
        settings(tmp_path, manifest).apply()


def test_disabled_accepts_external_profiles_and_unused_bundled_profiles(tmp_path):
    manifest = example("config-no-peer")
    manifest["content_security"] = {
        "inspection_profiles": [
            profile(),
            {**profile("https://other-inspector.test/inspect"), "id": "external"},
        ],
        "bindings": {"model": {"response": {"mode": "enforce", "profile": "external"}}},
    }
    disabled = settings(tmp_path, manifest, enabled=False)
    disabled.check()
    manifest["content_security"]["bindings"]["caller"] = {
        "response": {"mode": "enforce", "profile": "external", "artifact_profile": "dlp"}
    }
    with pytest.raises(ConfigurationError, match="requires local_dlp.enabled=true"):
        settings(tmp_path, manifest).check()


def test_deployment_uses_effective_peer_override(tmp_path):
    manifest = example("config")
    peer = manifest["peers"][0]["expected_service_id"]
    manifest["peers"] = manifest["peers"][:1]
    manifest["content_security"] = {
        "inspection_profiles": [profile()],
        "bindings": {
            "delegates": {
                "request": {"mode": "enforce", "profile": "dlp"},
                "overrides": [{"service_id": peer, "request": {"mode": "off"}}],
            },
        },
    }
    settings(tmp_path, manifest, enabled=False).check()


@pytest.mark.parametrize("field", ["gateway_id", "policy_revision", "url"])
def test_enabled_rejects_inconsistent_bundled_profile(tmp_path, field):
    manifest = example("config-no-peer")
    manifest["content_security"] = {
        "inspection_profiles": [
            {
                **profile(),
                field: "https://lasa-inspection:8443/other" if field == "url" else "other",
            }
        ],
        "bindings": {"caller": {"response": {"mode": "enforce", "profile": "dlp"}}},
    }
    enabled = settings(tmp_path, manifest, enabled=True, secrets_directory=str(tmp_path))
    with pytest.raises(ConfigurationError, match="must pin"):
        enabled.validate_profiles()


def test_enabled_check_calls_dlplite_probe_with_managed_pins(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(deployment, "docker", lambda *args, **kwargs: calls.append(args))
    monkeypatch.setattr(
        deployment.DockerDeployment, "active", lambda self: ("container", "project")
    )
    enabled = settings(
        tmp_path,
        example("config-no-peer"),
        enabled=True,
        secrets_directory=str(tmp_path),
        policy_revision="pinned-v2",
    )
    enabled.check()
    assert calls == [
        (
            "exec",
            "container",
            "dlplite-probe",
            "--url",
            MANAGED_DLP_ORIGIN + "/health/ready",
            "--gateway-id",
            MANAGED_DLP_GATEWAY_ID,
            "--policy-revision",
            "pinned-v2",
            "--ca-file",
            "/run/inspection/ca.pem",
            "--token-file",
            "/run/inspection/token.txt",
            "--wait",
            "0",
        )
    ]


@pytest.mark.integration
def test_dlplite_retains_predecessor_when_staged_probe_fails(tmp_path, monkeypatch):
    image = os.environ.get("LASA_TEST_DLPLITE_IMAGE")
    if not image:
        pytest.skip("Set LASA_TEST_DLPLITE_IMAGE to run the real gateway rollout check")
    network = "lasa-dlp-test-" + uuid4().hex[:12]
    folder = tmp_path / "credentials"
    folder.mkdir()
    cert, _ = certificate(folder, dns_name=MANAGED_DLP_HOST)
    ca = folder / "ca.pem"
    ca.write_bytes(cert.read_bytes())
    token_path = folder / "token.txt"
    token_path.write_text(secrets.token_hex(32) + "\n")
    gateway = deployment.DockerDeployment(
        network,
        (),
        {"enabled": True, "inspector_image": image, "secrets_directory": str(folder)},
        tmp_path / "deployment",
    )
    deployment.docker("network", "create", "--internal", network)
    try:
        gateway.apply()
        original, _ = gateway.active()
        token_path.write_text(secrets.token_hex(32) + "\n")
        gateway.apply()
        rotated, _ = gateway.active()
        assert rotated != original
        gateway.check()

        untrusted = tmp_path / "untrusted"
        untrusted.mkdir()
        wrong_ca, _ = certificate(untrusted, dns_name=MANAGED_DLP_HOST)
        ca.write_bytes(wrong_ca.read_bytes())
        monkeypatch.setattr(deployment, "STARTUP_SECONDS", 3)
        with pytest.raises(ConfigurationError):
            gateway.apply()
        assert gateway.active()[0] == rotated
        gateway.check()
        deployment.DockerDeployment(network, (), {}, tmp_path / "other-owner").apply(
            owned_only=True
        )
        assert gateway.active()[0] == rotated
        deployment.DockerDeployment(network, (), {}, gateway.state).apply(owned_only=True)
        assert gateway.active() == (None, None)
    finally:
        deployment.DockerDeployment(network, (), {}, gateway.state).apply()
        deployment.docker("network", "rm", network)
