"""Qualify the guided local identity install and its application rollback."""

import argparse
import gzip
import hashlib
import json
import os
import re
import secrets
import shutil
import ssl
import sys
import tempfile
import time
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit
from uuid import uuid4

import httpx

from .deployment_smoke import available_port, invoke
from .http_helpers import certificate
from .smoke_support import MODEL_KEY, docker, mount

ROOT = Path(__file__).resolve().parents[1]
SITE_HOST = "lasa-site"


class Form(HTMLParser):
    def __init__(self, fields):
        super().__init__()
        self.fields = fields
        self.action = None
        self.url = None
        self.found = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.action = attrs.get("action")
            self.found = set()
        if tag == "input":
            self.found.add(attrs.get("name"))

    def handle_endtag(self, tag):
        if tag == "form" and self.fields <= self.found:
            self.url = self.action


def submit_form(client, response, values):
    form = Form(values.keys())
    form.feed(response.text)
    assert form.url, f"Expected a Keycloak form for {sorted(values)} at {response.url.path}"
    action = urljoin(str(response.url), form.url)
    assert urlsplit(action).netloc == response.url.netloc.decode()
    assert urlsplit(action).path.startswith("/auth/realms/lasa/")
    return client.post(action, data=values)


def follow_issuer(client, response):
    for _ in range(5):
        if not response.is_redirect:
            break
        target = urljoin(str(response.url), response.headers["location"])
        if not urlsplit(target).path.startswith("/auth/realms/lasa/"):
            break
        assert urlsplit(target).netloc == response.url.netloc.decode()
        response = client.get(target)
    return response


def request_task(client, site, html):
    portal = site + "/app"
    offers = client.get(portal + "/api/offers")
    offers.raise_for_status()
    offer = offers.json()["offers"][0]
    ticket = client.get(portal + "/api/submission-ticket")
    ticket.raise_for_status()
    csrf = re.search(r'name="csrf-token" content="([^"]+)', html).group(1)
    result = client.post(
        portal + "/api/submissions",
        headers={"Origin": site, "X-CSRF-Token": csrf},
        json={
            "objective": "dlp-delegate-request-managed-keycloak",
            "checks": ["Return the deployment check."],
            "selection": {
                "offer_id": offer["offer_id"],
                "offer_revision": offer["revision"],
                "catalog_view": offer["catalog_view"],
                "contract": offer["contract"],
            },
            "ticket": ticket.json()["value"],
        },
    )
    assert result.status_code == 202, result.text
    task_url = result.json()["task_url"]
    assert task_url.startswith("/app/tasks/")
    route = portal + "/api" + task_url.removeprefix("/app")
    deadline = time.monotonic() + 90
    while True:
        task = client.get(route)
        task.raise_for_status()
        status = task.json()["status"]
        if status == "completed":
            return task.json()["task_id"]
        assert status not in {"failed", "rejected", "indeterminate"}, task.text
        assert time.monotonic() < deadline
        time.sleep(0.5)


def login(root, phase):
    for account in json.loads((root / "initial-users.json").read_bytes()):
        check_login(root, phase, Path(account["credentials_file"]))


def check_login(root, phase, credentials):
    site = (root / "site-url").read_text()
    portal = site + "/app"
    initial = json.loads(credentials.read_bytes())
    changed_password = root / f"{credentials.stem}-changed-password"
    saved_task = root / f"{credentials.stem}-task"
    password = initial["temporary_password"] if phase == "first" else changed_password.read_text()
    with httpx.Client(
        verify=ssl.create_default_context(cafile=root / "ca.pem"), trust_env=False, timeout=10
    ) as client:
        start = client.get(portal + "/auth/login")
        assert start.status_code == 303
        assert start.headers["location"].startswith(site + "/auth/realms/lasa/")
        page = client.get(start.headers["location"])
        result = follow_issuer(
            client,
            submit_form(client, page, {"username": initial["username"], "password": password}),
        )
        if phase == "first":
            updated = secrets.token_urlsafe(30)
            result = follow_issuer(
                client,
                submit_form(client, result, {"password-new": updated, "password-confirm": updated}),
            )
            changed_password.write_text(updated)
        assert result.is_redirect, result.status_code
        assert result.headers["location"].startswith(portal + "/auth/callback?")
        signed_in = client.get(result.headers["location"])
        assert signed_in.status_code == 200 and "Signed in" in signed_in.text, signed_in.text
        if phase == "first":
            page = client.get(portal + "/")
            asset = re.search(r'src="(/app/assets/[^"]+)"', page.text).group(1)
            assert client.get(site + asset).status_code == 200
            for path in (
                "/auth/admin/realms/lasa/users",
                "/auth/realms/master/.well-known/openid-configuration",
                "/health/ready",
                "/api/offers",
            ):
                assert client.get(site + path).status_code == 404
            task_id = request_task(client, site, page.text)
            saved_task.write_text(task_id)
        else:
            history = client.get(portal + "/api/tasks")
            history.raise_for_status()
            assert saved_task.read_text() in {task["task_id"] for task in history.json()["tasks"]}
    print(f"Managed Keycloak portal sign-in and task access passed ({phase}).")


def archive_release(path, release, tags):
    platform = release["platform"]
    pins = {}
    for role, tag in tags.items():
        source = docker(
            "create", "--pull", "never", "--platform", platform, release["images"][role]
        )
        try:
            pins[role] = docker("commit", "--change", f"LABEL com.lasa.smoke={tag}", source, tag)
        finally:
            docker("container", "rm", "--volumes", source)
    path.mkdir()
    tar = path / "images.tar"
    archive = path / "images.tar.gz"
    docker("image", "save", "--platform", platform, "--output", tar, *tags.values(), timeout=120)
    with tar.open("rb") as saved, gzip.open(archive, "wb", compresslevel=1) as compressed:
        shutil.copyfileobj(saved, compressed)
    tar.unlink()
    with archive.open("rb") as source:
        checksum = "sha256:" + hashlib.file_digest(source, "sha256").hexdigest()
    local_release = {
        **release,
        "images": {**release["images"], **pins},
        "artifacts": {**release["artifacts"], "images": checksum},
    }
    (path / "release.json").write_text(json.dumps(local_release))
    return local_release, archive


def run(root, release_path, lasa_deploy):
    from lasa_deploy.managed_deployment import HostDeployment

    release = json.loads(release_path.read_bytes())
    assert {"keycloak", "postgres"} <= release["images"].keys()
    name = "kc-check-" + uuid4().hex[:8]
    tags = {role: f"lasa-test-{role}:{name}" for role in release["images"]}
    upgrade_tags = {role: f"{tags[role]}-upgrade" for role in ("supervisor", "worker")}
    bundle = root / "release"
    network = f"lasa-{name}"
    site = f"https://{SITE_HOST}:{available_port()}"
    (root / "site-url").write_text(site)
    for role, hostname in (
        ("supervisor", SITE_HOST),
        ("model", "lasa-model"),
    ):
        (root / role).mkdir()
        certificate(root / role, dns_name=hostname)
    ca = root / "ca.pem"
    ca.write_bytes(
        b"".join((root / role / "certificate.pem").read_bytes() for role in ("supervisor", "model"))
    )
    (root / "model-key").write_text(MODEL_KEY)
    deploy_root = root / "deployment"
    install_config = root / "install.json"
    install_config.write_text(
        json.dumps(
            {
                "profile": "portal-keycloak",
                "output": "deployment",
                "release": "release/release.json",
                "name": name,
                "site_url": site,
                "gateway_listen_host": "127.0.0.1",
                "model": {
                    "base_url": "https://lasa-model:8443/v1",
                    "id": "fixture",
                    "credential_file": "model-key",
                    "ca_file": "ca.pem",
                },
                "tls": {
                    "certificate_file": "supervisor/certificate.pem",
                    "key_file": "supervisor/key.pem",
                    "ca_file": "ca.pem",
                },
                "ports": {role: available_port() for role in ("supervisor", "portal", "keycloak")},
                "keycloak": {
                    "users": [
                        {"username": "alice", "email": "alice@example.test"},
                        {"email": "bob@example.test"},
                    ]
                },
            }
        )
    )
    args = ["install", "--config", install_config]
    settings = deploy_root / "deployment.json"
    host = identity = None
    image = release["images"]["supervisor"]
    ids = []
    docker("network", "create", network)
    common = [
        "--network",
        network,
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--pull",
        "never",
        "--platform",
        release["platform"],
        "--workdir",
        "/verify",
        "--mount",
        mount(ROOT / "tests", "/verify/tests"),
        "--mount",
        mount(root, read_only=False),
        "--entrypoint",
        "python",
    ]

    def deploy(action, *, error=None):
        output_format = ("--json",) if action == "plan" else ()
        result = invoke(lasa_deploy, action, "--settings", settings, *output_format, error=error)
        return json.loads(result) if not error else None

    def users(action, *options):
        return json.loads(invoke(lasa_deploy, "users", action, "--settings", settings, *options))

    def identity_container():
        return docker(
            "ps",
            "-q",
            "--filter",
            f"label=com.docker.compose.project={identity.project}",
            "--filter",
            "label=com.docker.compose.service=keycloak",
        )

    try:
        cold_release, archive = archive_release(bundle, release, tags)
        docker("image", "rm", *tags.values())

        def cached(image):
            return docker("image", "inspect", "--format", "{{.Id}}", image, check=False) == image

        assert not any(cached(image) for image in cold_release["images"].values())
        held_archive = archive.with_suffix(".held")
        archive.rename(held_archive)
        archive.write_bytes(b"corrupt test archive")
        invoke(lasa_deploy, *args, error="Image archive checksum mismatch")
        assert not deploy_root.exists()
        assert not any(cached(image) for image in cold_release["images"].values())
        held_archive.replace(archive)
        for command, alias in (("model", "lasa-model"),):
            container = name + "-" + command
            ids.append(container)
            docker(
                "run",
                "-d",
                "--name",
                container,
                "--network-alias",
                alias,
                *common,
                image,
                "-m",
                "tests.keycloak_smoke",
                command,
                root,
            )
        installed = json.loads(invoke(lasa_deploy, *args))
        assert all(cached(image) for image in cold_release["images"].values())
        print("One guided install loaded every missing image from the verified bundle.")
        assert Path(installed["settings"]) == settings
        initial_users = installed["user_credentials"]
        assert [(user["username"], user["email"]) for user in initial_users] == [
            ("alice", "alice@example.test"),
            ("bob@example.test", "bob@example.test"),
        ]
        assert len({user["credentials_file"] for user in initial_users}) == 2
        for user in initial_users:
            assert Path(user["credentials_file"]).stat().st_mode & 0o777 == 0o600
        assert "temporary_password" not in json.dumps(initial_users)
        (root / "initial-users.json").write_text(json.dumps(initial_users))
        host = HostDeployment.load(settings)
        spec = host.spec
        identity = host.identity(spec)
        assert (
            "caller_token_file" not in spec["supervisor"]
            and "receiver_token_file" not in spec["portal"]
        )
        plan = deploy("plan")
        assert plan["keycloak"] == site + "/auth/realms/lasa" and not plan["change"]
        assert plan["preflight"] == "complete" and plan["image_imports"] == []
        assert plan["readiness"] == "ready"
        applied = installed["status"]
        assert applied["active"] == release["release_id"] and applied["admission"] == "open"
        assert applied["keycloak"]["ready"] and applied["portal_url"] == site + "/app/"
        edge = host.gateway(host.journal()["active"])
        gateway_id = edge.compose("ps", "-q", "gateway")
        original = identity_container()
        keys = identity.jwks.read_bytes()
        print(
            docker(
                "run",
                "--rm",
                *common,
                image,
                "-m",
                "tests.keycloak_smoke",
                "first",
                root,
                timeout=120,
            )
        )
        invited = root / "invited.json"
        users(
            "add",
            "--username",
            "charlie",
            "--email",
            "charlie@example.test",
            "--credentials-file",
            invited,
        )
        assert {"username": "charlie", "email": "charlie@example.test", "enabled": True} in users(
            "list"
        )["users"]
        reset = root / "reset.json"
        users("reset", "--username", "charlie", "--credentials-file", reset)
        assert invited.read_bytes() != reset.read_bytes()
        assert deploy("apply")["active"] == release["release_id"]
        assert identity_container() == original and identity.jwks.read_bytes() == keys

        def serving_state():
            journal = host.journal()
            current = journal["active"]
            descriptor = urlsplit(current["base_url"]).path + "/descriptor"
            assert host.mode() == "open"
            return (
                journal,
                set(host.compose(current, "ps", "-q").splitlines()),
                host.supervisor_get(current, descriptor),
            )

        def reject_unusable_archive(action, archive, pins):
            before = serving_state()
            held = archive.with_suffix(".held")
            archive.rename(held)
            try:
                for contents, error in (
                    (None, "Restore the verified image archive"),
                    (b"corrupt test archive", "Image archive checksum mismatch"),
                ):
                    if contents is not None:
                        archive.write_bytes(contents)
                    deploy(action, error=error)
                    assert serving_state() == before
                    assert not any(cached(pin) for pin in pins)
            finally:
                held.replace(archive)

        candidate_id = "managed-identity-candidate"
        upgrade = root / "upgrade"
        candidate, upgrade_archive = archive_release(
            upgrade, {**cold_release, "release_id": candidate_id}, upgrade_tags
        )
        spec["release"] = str(upgrade / "release.json")
        settings.write_text(json.dumps(spec))
        docker("image", "rm", *upgrade_tags.values())
        upgrade_pins = [candidate["images"][role] for role in upgrade_tags]
        assert not any(cached(pin) for pin in upgrade_pins)
        before = serving_state()
        preview = deploy("plan")
        assert preview["readiness"] == "deferred"
        assert preview["preflight"] == "deferred"
        assert preview["state"] is None and preview["change"] is None
        assert preview["image_imports"] == [
            {
                "purpose": "candidate",
                "release": candidate_id,
                "archive": str(upgrade_archive),
                "archive_status": "verified",
                "missing_images": {role: candidate["images"][role] for role in upgrade_tags},
            }
        ]
        assert serving_state() == before and not any(cached(pin) for pin in upgrade_pins)
        print("Read-only plan reported the exact missing upgrade images and verified archive.")
        reject_unusable_archive("apply", upgrade_archive, upgrade_pins)
        installed_upgrade = deploy("apply")
        assert (
            installed_upgrade["active"] == candidate_id and installed_upgrade["admission"] == "open"
        )
        assert all(cached(pin) for pin in upgrade_pins)
        assert (
            identity_container() == original and edge.compose("ps", "-q", "gateway") == gateway_id
        )
        print(
            "Upgrade restored the missing supervisor and worker and preserved the active release on archive errors."
        )

        worker = cold_release["images"]["worker"]
        docker("image", "rm", tags["worker"])
        assert not cached(worker)
        reject_unusable_archive("rollback", archive, [worker])
        print("Missing or corrupt rollback archive left the active release serving.")

        rolled_back = deploy("rollback")
        assert rolled_back["active"] == release["release_id"] and rolled_back["admission"] == "open"
        assert cached(worker)
        assert not docker(
            "container",
            "ls",
            "--all",
            "--quiet",
            "--filter",
            f"label=com.lasa.deployment.image-reference={host.project}",
        )
        print("Rollback automatically restored the exact missing worker image.")
        assert identity_container() == original and identity.jwks.read_bytes() == keys
        assert edge.compose("ps", "-q", "gateway") == gateway_id
        print(
            docker(
                "run",
                "--rm",
                *common,
                image,
                "-m",
                "tests.keycloak_smoke",
                "restored",
                root,
                timeout=90,
            )
        )
        print("Guided Keycloak install, user management, repeat apply, and rollback passed.")
    except BaseException:
        if host is None and settings.is_file():
            host = HostDeployment.load(settings)
            identity = host.identity(host.spec)
        if identity:
            logs = docker("logs", "--tail", "24", identity_container(), check=False)
            if logs:
                print(logs, file=sys.stderr)
        raise
    finally:
        if host:
            journal = host.journal()
            entry = journal["active"] or (journal["pending"] and journal["pending"]["target"])
            if entry:
                host.compose(entry, "down", "--remove-orphans")
                host.gateway(entry).down()
            identity_images = entry["identity_images"] if entry else release["images"]
            identity.compose(identity_images, release["platform"], "down")
            docker("volume", "rm", identity.database, check=False)
            docker("volume", "rm", host.project + "-socket", check=False)
        for container in ids:
            docker("rm", "-f", container, check=False)
        docker("image", "rm", *tags.values(), *upgrade_tags.values(), check=False)
        docker("network", "rm", network, check=False)


if __name__ == "__main__":
    os.umask(0o077)
    if sys.argv[1:2] and sys.argv[1] in {"model", "first", "restored"}:
        mode, root = sys.argv[1], Path(sys.argv[2])
        if mode == "model":
            from .container_smoke import serve_fixture

            serve_fixture(root / "model")
        else:
            login(root, mode)
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--release", required=True, type=Path)
        parser.add_argument("--lasa-deploy", required=True, type=Path)
        args = parser.parse_args()
        with tempfile.TemporaryDirectory(prefix="lasa-keycloak-install-") as temporary:
            run(Path(temporary).resolve(), args.release.resolve(), args.lasa_deploy.resolve())
