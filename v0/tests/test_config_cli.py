import json
import os
import subprocess
import sys

import pytest

from lasa_service.config import Configuration
from lasa_service.errors import LasaError

from .conftest import ISSUER, JWK


def cli(tmp_path, *arguments):
    return subprocess.run(
        [sys.executable, "-m", "lasa_service.cli", "config", *map(str, arguments)],
        cwd=tmp_path,
        env={**os.environ, "LASA_MODEL_API_KEY": ""},
        text=True,
        capture_output=True,
        timeout=10,
    )


@pytest.fixture
def deployment(tmp_path):
    jwks_file = tmp_path / "jwks.json"
    jwks_file.write_text(json.dumps({"keys": [JWK]}))
    manifest_dir = tmp_path / "config"
    key_file = tmp_path / "model-key"
    args = [
        "init",
        "--output",
        manifest_dir,
        "--service-id",
        f"{ISSUER}/services/review",
        "--base-url",
        "https://lasa.example.net/prefix/",
        "--issuer",
        ISSUER,
        "--jwks-file",
        jwks_file,
        "--image",
        "sha256:" + "0" * 64,
        "--model",
        "review-model",
        "--provider-url",
        "https://models.example.net/v1",
        "--credential-ref",
        f"file:{key_file}",
        "--state-root",
        tmp_path / "state",
    ]
    return manifest_dir, key_file, args


def test_scaffold_defaults_and_secrets_are_checked_without_startup(tmp_path, deployment):
    manifest_dir, key_file, args = deployment
    path = manifest_dir / "config.json"
    result = cli(tmp_path, *args, "--operator-subject", "alice")
    assert result.returncode == 0, result.stderr
    policy = manifest_dir / "authorization.json"
    assert policy.stat().st_mode & 0o777 == 0o600
    assert path.stat().st_mode & 0o777 == 0o600
    manifest = json.loads(path.read_text())
    assert set(manifest) == {
        "config_version",
        "service",
        "authentication",
        "authorization",
        "executors",
        "runtime",
        "storage",
    }
    assert manifest["authorization"]["policy_file"] == policy.name
    assert not key_file.exists()

    result = cli(tmp_path, "check", "--config", path, "--offline")
    assert result.returncode == 2 and "missing secret" not in result.stdout
    assert "cannot read secret file" in result.stderr

    secret = "private-model-credential-fixture"
    key_file.write_text(secret)
    result = cli(tmp_path, "check", "--config", path, "--offline")
    assert result.returncode == 0, result.stderr
    assert secret not in result.stdout + result.stderr + path.read_text() + policy.read_text()
    assert not (tmp_path / "state").exists()
    cfg = Configuration.load(path)
    assert cfg.descriptor_url == "https://lasa.example.net/prefix/descriptor"
    assert cfg.executor()["model"] == "review-model"
    assert cfg.peers == [] and cfg.document["storage"]["listen_host"] == "127.0.0.1"
    assert len(cfg.document["bindings"]) == 2
    assert cfg.policy()["principals"][0]["rules"][0]["effects"] == ["workspace.read"]
    revision = cfg.document["service"]["deployment_revision"]
    key_file.write_text("rotated")
    assert cfg.secret(f"file:{key_file}") == "rotated"
    policy.write_text(
        json.dumps({"revision": "revoked", "principals": [], "trusted_delegator_service_ids": []})
    )
    assert cfg.policy()["principals"] == []
    assert Configuration.load(path).document["service"]["deployment_revision"] == revision


def test_init_preserves_existing_manifest(tmp_path, deployment):
    manifest_dir, _, args = deployment
    manifest_dir.mkdir()
    manifest = manifest_dir / "config.json"
    manifest.write_text("existing")

    result = cli(tmp_path, *args)
    assert result.returncode == 2 and "config.json already exists" in result.stderr
    assert manifest.read_text() == "existing"
    assert not (manifest_dir / "authorization.json").exists()


def test_multiple_executors_require_an_explicit_default(tmp_path, deployment):
    manifest_dir, key_file, args = deployment
    assert cli(tmp_path, *args).returncode == 0
    key_file.write_text("fixture-key")
    path = manifest_dir / "config.json"
    manifest = json.loads(path.read_text())
    manifest["executors"].append(
        {**manifest["executors"][0], "id": "other", "model": "other-model"}
    )
    with pytest.raises(LasaError, match="invalid_input"):
        Configuration.from_document(manifest, base_dir=manifest_dir)

    manifest["default_executor"] = "other"
    cfg = Configuration.from_document(manifest, base_dir=manifest_dir)
    assert cfg.executor()["model"] == "other-model"
    assert {binding["executor_id"] for binding in cfg.document["bindings"]} == {"other"}


def test_check_reports_invalid_local_jwks(tmp_path, deployment):
    manifest_dir, key_file, args = deployment
    assert cli(tmp_path, *args).returncode == 0
    key_file.write_text("fixture-key")
    (tmp_path / "jwks.json").write_text('{"keys":["invalid key material"]}')
    result = cli(tmp_path, "check", "--config", manifest_dir / "config.json", "--offline")
    assert result.returncode == 2 and "signing keys" in result.stderr
    assert "invalid key material" not in result.stdout + result.stderr
