import json
import os
import secrets
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

from lasa_service import cli as cli_module
from lasa_service.config import Configuration, ConfigurationError
from lasa_service.errors import LasaError
from lasa_service.store import STORAGE_SCHEMA_VERSION
from portal.config import Settings

from .conftest import ISSUER, JWK, delegation_grant, example, token
from .http_helpers import certificate


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
        "--launcher-socket",
        "/run/lasa/launcher.sock",
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
    result = cli(tmp_path, *args, "--consumer-subject", "alice")
    assert result.returncode == 0, result.stderr
    policy = manifest_dir / "authorization.json"
    assert policy.stat().st_mode & 0o777 == 0o600
    assert path.stat().st_mode & 0o777 == 0o600
    manifest = json.loads(path.read_text())
    assert set(manifest) == {
        "config_version",
        "service",
        "authentication",
        "executors",
        "runtime",
        "storage",
    }
    assert manifest["config_version"] == "1.0.0"
    assert manifest["storage"] == {"state_root": str(tmp_path / "state")}
    assert not key_file.exists()

    result = cli(tmp_path, "check", "--config", path, "--offline")
    assert result.returncode == 2 and "missing secret" not in result.stdout
    assert "cannot read secret file" in result.stderr

    secret = "private-model-credential-fixture"
    key_file.write_text(secret)
    path.write_text(json.dumps({**manifest, "config_version": "3.0"}))
    result = cli(tmp_path, "check", "--config", path, "--offline")
    assert result.returncode == 2
    path.write_text(json.dumps(manifest))
    result = cli(tmp_path, "check", "--config", path, "--offline")
    assert result.returncode == 0, result.stderr
    assert secret not in result.stdout + result.stderr + path.read_text() + policy.read_text()
    assert not (tmp_path / "state").exists()
    cfg = Configuration.load(path)
    assert cfg.auth_mode == "jwt"
    assert cfg.descriptor_url == "https://lasa.example.net/prefix/descriptor"
    assert cfg.executor()["model"] == "review-model"
    assert cfg.private_root == tmp_path / "state" / "private"
    assert cfg.workspace_root == tmp_path / "state" / "workspaces"
    assert cfg.document["authorization"]["policy_file"] == str(policy)
    assert cfg.peers == [] and cfg.document["storage"]["listen_host"] == "127.0.0.1"
    assert len(cfg.document["bindings"]) == 2
    assert cfg.policy()["principals"][0]["rules"][0]["effects"] == ["workspace.read"]
    revision = cfg.document["service"]["deployment_revision"]
    key_file.write_text("rotated")
    assert cfg.secret(f"file:{key_file}") == "rotated"
    policy.write_text(json.dumps({"revision": "revoked", "principals": []}))
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


@pytest.fixture
def static_deployment(tmp_path, deployment):
    folder, key, jwt_args = deployment
    args = list(jwt_args)
    for flag in ("--issuer", "--jwks-file"):
        index = args.index(flag)
        del args[index : index + 2]
    result = cli(tmp_path, *args, "--auth-mode", "static_token", "--consumer-subject", "alice")
    assert result.returncode == 0, result.stderr
    key.write_text("fixture-key")
    return folder / "config.json", folder / "authorization.json", folder / "static-tokens.json"


def test_static_config_check_and_safe_token_issuance(tmp_path, static_deployment):
    config, policy, registry = static_deployment
    assert json.loads(config.read_text())["authentication"] == {"mode": "static_token"}
    token = tmp_path / "caller-token.txt"
    issue = ("issue-token", "--config", config, "--subject", "alice")
    refused = cli(tmp_path, *issue, "--output", config.parent / "leak.txt")
    assert refused.returncode == 2 and "outside" in refused.stderr
    result = cli(tmp_path, *issue, "--output", token, "--ttl-hours", 1)
    assert result.returncode == 0, result.stderr
    assert token.stat().st_mode & 0o777 == 0o600
    secret = token.read_text().strip()
    assert secret not in result.stdout + result.stderr + config.read_text() + policy.read_text()
    assert secret not in registry.read_text()
    (record,) = json.loads(registry.read_text())["tokens"]
    assert record["subject"] == "alice" and 0 < record["expires_at"] - time.time() <= 3600
    assert cli(tmp_path, *issue, "--output", token).returncode == 2
    assert token.read_text().strip() == secret

    check = ("check", "--config", config, "--offline")
    result = cli(tmp_path, *check)
    assert result.returncode == 0, result.stderr
    registry.write_text(json.dumps({"tokens": [record, record]}))
    result = cli(tmp_path, *check)
    assert result.returncode == 2 and "static token registry" in result.stderr


@pytest.mark.parametrize("mode", ["jwt", "static_token"])
def test_config_check_validates_each_outbound_credential(tmp_path, static_deployment, mode):
    config, policy, _ = static_deployment
    manifest = json.loads(config.read_text())
    authority = json.loads(policy.read_text())
    receiver = "https://peer.example.net/lasa"
    credential = tmp_path / "peer-token.txt"
    execution_key = tmp_path / "execution-key.txt"
    execution_key.write_text(secrets.token_hex(32))
    opaque = secrets.token_urlsafe(32)
    signed = token("workload", receiver)
    peer = {
        "descriptor_url": receiver + "/v1/descriptor",
        "allowed_base_url": receiver + "/v1",
        "expected_service_id": receiver,
        "credential_ref": f"file:{credential}",
        "execution_key_ref": f"file:{execution_key}",
        "authentication": {"mode": mode},
    }
    if mode == "static_token":
        peer["authentication"]["subject"] = "workload"
    manifest["peers"] = [peer]
    authority["principals"].append(
        {
            "subject": "workload",
            "kind": "peer",
            "service_id": receiver,
            "execution_key_ref": f"file:{execution_key}",
            "rules": [],
        }
    )
    (rule,) = authority["principals"][0]["rules"]
    rule["delegation_grants"] = [
        delegation_grant(manifest["service"]["id"], receiver, rule["contracts"][0], rule)
    ]
    config.write_text(json.dumps(manifest))
    policy.write_text(json.dumps(authority))
    credential.write_text(signed if mode == "jwt" else opaque)
    result = cli(tmp_path, "check", "--config", config, "--offline")
    assert result.returncode == 0, result.stderr
    credential.write_text(opaque if mode == "jwt" else signed)
    result = cli(tmp_path, "check", "--config", config, "--offline")
    assert result.returncode == 2 and "configured authentication mode" in result.stderr


def test_default_config_path_is_shared_by_init_check_and_startup(tmp_path, deployment, monkeypatch):
    manifest_dir, key_file, args = deployment
    path = manifest_dir / "config.json"
    monkeypatch.setattr(cli_module, "DEFAULT_CONFIG_PATH", path)
    command, _, _, *flags = args
    monkeypatch.setattr(sys, "argv", ["lasa", "config", command, *map(str, flags)])
    cli_module.main()
    assert path.is_file()
    key_file.write_text("fixture-key")
    monkeypatch.setattr(sys, "argv", ["lasa", "config", "check", "--offline"])
    cli_module.main()
    monkeypatch.setattr(sys, "argv", ["lasa"])
    started = []
    monkeypatch.setattr(cli_module, "run_service", started.append)
    cli_module.main()
    assert started[0].state_root == tmp_path / "state"


@pytest.mark.parametrize("blocked", ["private", "workspaces"])
def test_check_rejects_conflicting_state_directories(tmp_path, deployment, blocked):
    manifest_dir, key_file, args = deployment
    assert cli(tmp_path, *args).returncode == 0
    key_file.write_text("fixture-key")
    path = manifest_dir / "config.json"
    root = tmp_path / "state"
    root.mkdir()
    conflict = root / blocked
    conflict.write_text("fixture")
    result = cli(tmp_path, "check", "--config", path, "--offline")
    assert result.returncode == 2 and str(conflict) in result.stderr
    conflict.unlink()
    conflict.symlink_to(manifest_dir, target_is_directory=True)
    with pytest.raises(ConfigurationError, match="direct children"):
        Configuration.load(path)


def test_preflight_rejects_incompatible_state_without_writing(tmp_path, deployment):
    manifest_dir, key_file, args = deployment
    assert cli(tmp_path, *args).returncode == 0
    key_file.write_text("fixture-key")
    private = tmp_path / "state" / "private"
    private.mkdir(parents=True)
    path = private / "tasks.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute(f"PRAGMA user_version={STORAGE_SCHEMA_VERSION - 1}")
    before = path.read_bytes()
    result = cli(tmp_path, "check", "--offline", "--config", manifest_dir / "config.json")
    assert result.returncode == 2
    assert f"{path} has schema {STORAGE_SCHEMA_VERSION - 1}" in result.stderr
    assert f"expected {STORAGE_SCHEMA_VERSION}" in result.stderr
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    ("profile", "accounts"),
    [
        ("core", None),
        ("portal-keycloak", []),
        (
            "portal-keycloak",
            [{"username": "alice", "email": "alice@example.test"}, {"email": "bob@example.test"}],
        ),
        ("portal-oidc", None),
    ],
)
def test_guided_deployment_writes_only_credentials_for_profile(
    tmp_path, profile, accounts, monkeypatch, capsys
):
    from lasa_deploy import cli as deploy_cli
    from lasa_deploy import image_cache
    from lasa_deploy.managed_deployment import HostDeployment
    from lasa_deploy.runtime import ReleaseImages

    from lasa_service.deploy_api import dispatch

    monkeypatch.setattr(
        ReleaseImages,
        "supervisor",
        lambda self, operation, *, mounts=(), **request: dispatch(operation, request),
    )
    monkeypatch.setattr(ReleaseImages, "portal", lambda self, spec: Settings.read(spec["config"]))
    cert, key = certificate(tmp_path, dns_name="lasa.example.test")
    value = "private-fixture-value"
    secret_file = tmp_path / "credential"
    secret_file.write_text(value)
    release = tmp_path / "release.json"
    pin = "sha256:" + "a" * 64
    roles = ["supervisor", "launcher", "worker", "gateway", "portal"]
    if profile == "portal-keycloak":
        roles.extend(("keycloak", "postgres"))
    images = {role: f"sha256:{index:064x}" for index, role in enumerate(roles, 1)}
    inspected = []
    monkeypatch.setattr(HostDeployment, "daemon", lambda self: "local-docker")
    monkeypatch.setattr(
        image_cache, "inspect_image", lambda image, platform: inspected.append(image)
    )
    release.write_text(
        json.dumps(
            {
                "release_id": "test-release",
                "source_revision": "a" * 40,
                "package_version": "1.0.0",
                "platform": "linux/amd64",
                "wire_schema_digest": pin,
                "store_schema": STORAGE_SCHEMA_VERSION,
                "artifacts": {
                    "service_wheel": pin,
                    "deploy_wheel": pin,
                    "sdist": pin,
                    "deploy_requirements": pin,
                },
                "images": images,
            }
        )
    )
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    output = tmp_path / ".local/share/lasa/lasa-example-test"
    config = {
        "site_url": "https://lasa.example.test",
        "model": {
            "id": "fixture",
            "base_url": "https://model.example.test/v1",
            "credential_file": secret_file.name,
        },
        "tls": {"certificate_file": cert.name, "key_file": key.name},
    }
    if profile != "core":
        config["profile"] = profile
    if accounts:
        config["keycloak"] = {"users": accounts}
    if profile == "portal-oidc":
        from lasa_deploy import install_oidc

        discovery = ISSUER + "/.well-known/openid-configuration"
        jwks = ISSUER + "/jwks"
        documents = {discovery: {"issuer": ISSUER, "jwks_uri": jwks}, jwks: {"keys": [JWK]}}
        monkeypatch.setattr(install_oidc, "fetch_document", lambda client, url: documents[url])
        audience = "https://lasa.example.test/services/lasa-example-test"
        for role in ("caller", "operator"):
            (tmp_path / f"{role}.jwt").write_text(token(subject=role, audience=audience))
        config["oidc"] = {
            "issuer": ISSUER,
            "client_id": "external-client",
            "client_secret_file": secret_file.name,
            "caller_token_file": "caller.jwt",
            "operator_token_file": "operator.jwt",
            "algorithm": "ES256",
        }
    install_config = tmp_path / "install.json"
    install_config.write_text(json.dumps(config))
    monkeypatch.setattr(
        sys, "argv", ["lasa-deploy", "install", "--prepare-only", "--config", str(install_config)]
    )
    mask = os.umask(0o077)
    try:
        deploy_cli.main()
    finally:
        os.umask(mask)
    stdout = capsys.readouterr().out
    assert value not in stdout
    selected_roles = roles if profile != "core" else roles[:4]
    assert inspected == [images[role] for role in selected_roles]
    receipt = json.loads(stdout)
    spec = json.loads((output / "deployment.json").read_text())
    assert receipt["site_url"] == "https://lasa.example.test"
    assert spec["release"] == str(release) and spec["name"] == "lasa-example-test"
    assert spec["gateway"]["certificate_file"] == str(cert.resolve())
    assert ("portal" in spec) == (profile != "core")
    assert ("keycloak" in spec) == (profile == "portal-keycloak")
    if profile == "portal-keycloak":
        assert spec["keycloak"]["origin"] == receipt["site_url"]
        realm = json.loads((output / "identity/realm/lasa-realm.json").read_text())
        assert realm["clients"][0]["redirectUris"] == [
            "https://lasa.example.test/app/auth/callback"
        ]
        assert "caller_token_file" not in spec["supervisor"]
        assert "receiver_token_file" not in spec["portal"]
        receipts = receipt["user_credentials"]
        assert len(receipts) == len(accounts)
        users = [user for user in realm["users"] if "serviceAccountClientId" not in user]
        for account, realm_user, issued in zip(accounts, users, receipts, strict=True):
            assert realm_user["email"] == issued["email"] == account["email"]
            assert (
                realm_user["username"]
                == issued["username"]
                == account.get("username", account["email"])
            )
            assert Path(issued["credentials_file"]).stat().st_mode & 0o777 == 0o600
        policy = json.loads((output / "identity/receiver/authorization.json").read_bytes())
        assert [principal["subject"] for principal in policy["principals"]] == [
            user["id"] for user in users
        ]
        credential = output / "portal/client-secret"
    elif profile == "core":
        credential = Path(receipt["caller_credentials_file"])
    else:
        credential = output / "portal/client-secret"
        policy = json.loads((output / "supervisor/authorization.json").read_bytes())
        assert [(item["subject"], item["kind"]) for item in policy["principals"]] == [
            ("caller", "user"),
            ("operator", "operator"),
        ]
    assert credential.stat().st_mode & 0o777 == 0o600
    if "portal" in spec:
        portal_settings = Settings.read(spec["portal"]["config"])
        assert receipt["portal_url"] == "https://lasa.example.test/app/"
        assert portal_settings.callback == "https://lasa.example.test/app/auth/callback"


@pytest.mark.parametrize(
    ("second", "field"),
    [
        ({"username": "ALICE", "email": "other@example.test"}, "username"),
        ({"username": "other", "email": "ALICE@example.test"}, "email"),
    ],
)
def test_keycloak_install_rejects_duplicate_accounts(tmp_path, second, field):
    from lasa_deploy.contracts import ConfigurationError as InstallError
    from lasa_deploy.guided_install import read_install_config

    for filename in ("release.json", "credential", "cert.pem", "key.pem"):
        (tmp_path / filename).touch()
    install = tmp_path / "install.json"
    install.write_text(
        json.dumps(
            {
                "profile": "portal-keycloak",
                "site_url": "https://site.example.test",
                "output": "instance",
                "model": {
                    "id": "fixture",
                    "base_url": "https://models.example.test/v1",
                    "credential_file": "credential",
                },
                "tls": {"certificate_file": "cert.pem", "key_file": "key.pem"},
                "keycloak": {
                    "users": [{"username": "alice", "email": "alice@example.test"}, second]
                },
            }
        )
    )
    with pytest.raises(InstallError, match=rf"keycloak\.users\.1\.{field}: duplicate"):
        read_install_config(install)
    assert not (tmp_path / "instance").exists()


def test_config_check_prints_resolved_inspection_without_credentials(tmp_path, deployment):
    folder, key, args = deployment
    assert cli(tmp_path, *args).returncode == 0
    key.write_text("model-key")
    gateway_key = tmp_path / "scanner-key"
    gateway_key.write_text("local-profile-credential")
    path = folder / "config.json"
    manifest = json.loads(path.read_text())
    settings = example("content-security-all-channels")
    profile = settings["inspection_profiles"][0]
    profile.pop("ca_file")
    profile["credential_ref"] = f"file:{gateway_key}"
    manifest["content_security"] = {
        "inspection_profiles": [profile],
        "bindings": {"caller": {"response": {"mode": "enforce", "profile": profile["id"]}}},
    }
    path.write_text(json.dumps(manifest))
    checked = cli(tmp_path, "check", "--config", path, "--offline")
    assert checked.returncode == 0, checked.stderr
    report = json.loads(checked.stdout.split("Effective content inspection\n")[1])
    assert report["defaults"]["model"]["request"]["mode"] == "off"
    assert report["defaults"]["caller"]["response"]["artifact_profile"] == "local-dlp"
    assert "local-profile-credential" not in checked.stdout
