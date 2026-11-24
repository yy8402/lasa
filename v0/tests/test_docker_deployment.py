import json

import httpx
import pytest

from lasa_service import deployment
from lasa_service.config import ConfigurationError

from .conftest import example
from .http_helpers import certificate


def settings(tmp_path, manifest, **local_dlp):
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(manifest))
    path = tmp_path / "deployment.json"
    path.write_text(
        json.dumps(
            {
                "supervisor_network": "lasa-test",
                "supervisors": ["config.json"],
                "local_dlp": local_dlp,
            }
        )
    )
    return deployment.DockerDeployment.load(path)


def profile(url=deployment.MANAGED_URL):
    return {
        "id": "dlp",
        "url": url,
        "gateway_id": deployment.GATEWAY_ID,
        "policy_revision": deployment.POLICY_REVISION,
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


@pytest.mark.parametrize(
    ("status", "body", "error"),
    [
        (200, {"gateway_id": "local-dlp", "policy_revision": "english-dlp-v1"}, None),
        (200, {"gateway_id": "local-dlp", "policy_revision": "wrong"}, "unexpected gateway ID"),
        (401, {}, "HTTP 401"),
        (503, {}, "did not become ready"),
    ],
)
def test_probe_requires_authenticated_pinned_readiness(tmp_path, status, body, error):
    ca, _ = certificate(tmp_path)
    ca.rename(tmp_path / "ca.pem")
    (tmp_path / "token.txt").write_text("synthetic-deployment-token\n")

    def respond(request):
        assert request.url == deployment.MANAGED_ORIGIN + "/health/ready"
        assert request.headers["Authorization"] == "Bearer synthetic-deployment-token"
        return httpx.Response(status, json=body)

    options = {"directory": tmp_path, "transport": httpx.MockTransport(respond)}
    if error:
        with pytest.raises(ConfigurationError, match=error):
            deployment.probe(deployment.POLICY_REVISION, **options)
    else:
        deployment.probe(deployment.POLICY_REVISION, **options)
