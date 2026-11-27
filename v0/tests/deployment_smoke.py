"""Exercise the installed deployment CLI, TLS ingress, portal, and rollback on Docker."""

import argparse
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit
from uuid import uuid4

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .http_helpers import certificate
from .smoke_support import ISSUER_SECRET, MODEL_KEY, PORTAL_CLIENT_ID, docker, mount

ROOT = Path(__file__).resolve().parents[1]
ISSUER = "https://lasa-idp:8443"


def dump(path, document):
    path.write_text(json.dumps(document))


def serve_issuer(root):
    from .oidc_fixture import Issuer

    key = serialization.load_pem_private_key((root / "issuer.key").read_bytes(), None)
    settings = json.loads((root / "urls.json").read_bytes())
    app = Issuer(ISSUER, settings["service_id"], key, settings["jwk"]).app
    serve(app, root / "idp")


def serve(app, tls):
    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8443,
        ssl_certfile=str(tls / "certificate.pem"),
        ssl_keyfile=str(tls / "key.pem"),
        access_log=False,
    )


def portal_request(root):
    site = json.loads((root / "urls.json").read_bytes())["site"]
    portal = site + "/app"
    with httpx.Client(
        verify=ssl.create_default_context(cafile=root / "ca.pem"),
        trust_env=False,
        follow_redirects=False,
        timeout=10,
    ) as client:
        login = client.get(portal + "/auth/login")
        authorization = urlsplit(login.headers["location"])
        assert authorization.geturl().startswith(ISSUER + "/authorize?")
        query = parse_qs(authorization.query)
        query["as_user"] = ["alice"]
        callback = client.get(authorization._replace(query=urlencode(query, doseq=True)).geturl())
        assert callback.headers["location"].startswith(portal + "/auth/callback?")
        session = client.get(callback.headers["location"])
        assert session.status_code == 200 and "Signed in" in session.text, session.status_code
        page = client.get(portal + "/")
        assert page.status_code == 200
        # The native receipt proves the portal session belongs to the same caller.
        history = client.get(portal + "/api/tasks")
        history.raise_for_status()
        assert history.json()["tasks"], history.json()
        offers = client.get(portal + "/api/offers")
        offers.raise_for_status()
        offer = offers.json()["offers"][0]
        ticket = client.get(portal + "/api/submission-ticket")
        ticket.raise_for_status()
        csrf = re.search(r'name="csrf-token" content="([^"]+)', page.text).group(1)
        started = client.post(
            portal + "/api/submissions",
            headers={"Origin": site, "X-CSRF-Token": csrf},
            json={
                "objective": "dlp-delegate-request-portal-install",
                "checks": ["Confirm the fixture deployment works."],
                "selection": {
                    "offer_id": offer["offer_id"],
                    "offer_revision": offer["revision"],
                    "catalog_view": offer["catalog_view"],
                    "contract": offer["contract"],
                },
                "ticket": ticket.json()["value"],
            },
        )
        assert started.status_code == 202, started.text
        task_path = "/api" + started.json()["task_url"].removeprefix("/app")
        deadline = time.monotonic() + 90
        while True:
            task = client.get(portal + task_path)
            task.raise_for_status()
            status = task.json()["status"]
            if status == "completed":
                break
            assert (
                status not in {"failed", "rejected", "indeterminate"}
                and time.monotonic() < deadline
            ), task.text
            time.sleep(0.5)
        print(json.dumps({"operation_id": "portal-task-" + ticket.json()["id"]}))


def available_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def credentials(release, root, name, base_url):
    from lasa_deploy.runtime import ReleaseImages

    cfg = root / "supervisor"
    cfg.mkdir()
    cert, key = certificate(cfg, dns_name=urlsplit(base_url).hostname)
    for generation in ("renewed", "untrusted"):
        (root / generation).mkdir()
        certificate(
            root / generation,
            dns_name=urlsplit(base_url).hostname,
            common_name=f"LASA {generation} fixture",
        )
    for role, host in (
        ("idp", "lasa-idp"),
        ("model", "lasa-model"),
    ):
        (root / role).mkdir()
        certificate(root / role, dns_name=host)
    ca = root / "ca.pem"
    ca.write_bytes(
        b"".join(
            path.read_bytes()
            for path in (
                cert,
                root / "renewed/certificate.pem",
                *(root / role / "certificate.pem" for role in ("idp", "model")),
            )
        )
    )
    signing_key = ec.generate_private_key(ec.SECP256R1())
    jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(signing_key.public_key()))
    jwk.update(kid="deployment-smoke-key", alg="ES256", use="sig")
    (root / "issuer.key").write_bytes(
        signing_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    jwks = cfg / "jwks.json"
    dump(jwks, {"keys": [jwk]})
    model = cfg / "model-key"
    model.write_text(MODEL_KEY)
    service_id = f"https://identity.example.test/services/{name}"
    urls = {
        "service_id": service_id,
        "jwk": jwk,
        "site": base_url.removesuffix("/lasa/v1"),
    }
    dump(root / "urls.json", urls)
    ReleaseImages(release).supervisor(
        "scaffold",
        mounts=[(cfg, True)],
        output=str(cfg),
        manifest={
            "service_id": service_id,
            "base_url": base_url,
            "authentication": {
                "mode": "jwt",
                "issuer": ISSUER,
                "jwks_file": str(jwks),
                "allowed_algorithms": ["ES256"],
            },
            "launcher_socket": "/run/lasa/launcher.sock",
            "model": "fixture",
            "provider_url": "https://lasa-model:8443/v1",
            "credential_ref": f"file:{model}",
            "state_root": str(root / "state"),
        },
        runtime={"launcher_instance": name},
        storage={
            "listen_host": "0.0.0.0",
            "tls": {"certificate_file": str(cert), "key_file": str(key)},
        },
        caller="alice",
        operator="operator",
    )
    path = cfg / "config.json"
    config = json.loads(path.read_bytes())
    config["runtime"]["startup_timeout_ms"] = 25000
    config["executors"][0]["provider_ca_file"] = str(ca)
    config["service"]["deployment_revision"] = "smoke-baseline"
    config["discovery_cache"] = {"descriptor_max_age_seconds": 1}
    dump(path, config)
    for subject in ("alice", "operator"):
        issued = int(time.time())
        token = jwt.encode(
            {
                "iss": ISSUER,
                "aud": service_id,
                "sub": subject,
                "iat": issued,
                "exp": issued + 3600,
                "jti": secrets.token_hex(12),
            },
            signing_key,
            algorithm="ES256",
            headers={"kid": jwk["kid"]},
        )
        (root / f"{subject}-token.txt").write_text(token)
    portal = root / "portal"
    portal.mkdir()
    for purpose in ("encryption-key", "journal-key", "ticket-key"):
        (portal / purpose).write_text(secrets.token_hex(32))
    (portal / "client-secret").write_text(ISSUER_SECRET)
    dump(
        portal / "config.json",
        {
            "public_origin": urls["site"],
            "base_path": "/app",
            "lasa_url": base_url,
            "lasa_service_id": service_id,
            "issuer": ISSUER,
            "client_id": PORTAL_CLIENT_ID,
            "client_secret_file": str(portal / "client-secret"),
            "state_dir": str(root / "portal-state"),
            "encryption_key_file": str(portal / "encryption-key"),
            "journal_key_file": str(portal / "journal-key"),
            "ticket_key_file": str(portal / "ticket-key"),
            "ca_file": str(ca),
        },
    )
    return config


def invoke(lasa, *args, error=None):
    result = subprocess.run(
        [str(lasa), *map(str, args)], capture_output=True, text=True, timeout=300
    )
    if error:
        assert result.returncode == 2 and error in result.stderr, result.stderr
    elif result.returncode:
        raise RuntimeError(result.stderr)
    return result.stdout


def assert_gateway_certificate(edge, expected, ca_file):
    context = ssl.create_default_context(cafile=ca_file)
    with (
        socket.create_connection(("127.0.0.1", edge.port), timeout=5) as connection,
        context.wrap_socket(connection, server_hostname=edge.origin.hostname) as tls,
    ):
        assert tls.getpeercert(binary_form=True) == ssl.PEM_cert_to_DER_cert(expected.read_text())


def run(root, release_path, lasa_deploy):
    from lasa_deploy.managed_deployment import HostDeployment

    name = "deploy-test-" + uuid4().hex[:8]
    base_url = f"https://lasa-{name}-site:{available_port()}/lasa/v1"
    release = json.loads(release_path.read_bytes())
    baseline = release["release_id"]
    image = release["images"]["supervisor"]
    config = credentials(release, root, name, base_url)
    spec = {
        "name": name,
        "network": name,
        "control_directory": str(root / "control"),
        "release": str(release_path),
        "timeout_seconds": 45,
        "gateway": {
            "listen_host": "127.0.0.1",
            "certificate_file": str(root / "supervisor/certificate.pem"),
            "key_file": str(root / "supervisor/key.pem"),
            "ca_file": str(root / "ca.pem"),
        },
        "supervisor": {
            "config": str(root / "supervisor/config.json"),
            "port": available_port(),
            "ca_file": str(root / "ca.pem"),
            "caller_token_file": str(root / "alice-token.txt"),
            "operator_token_file": str(root / "operator-token.txt"),
            "mounts": [str(root / "ca.pem")],
        },
    }
    settings = root / "deployment.json"
    dump(settings, spec)
    host = HostDeployment.load(settings)
    ids = []
    gateway_image = None
    docker("network", "create", name)
    common = [
        "--network",
        name,
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--mount",
        mount(ROOT / "tests", "/verify/tests"),
        "--mount",
        mount(root, read_only=False),
        "--workdir",
        "/verify",
        "--entrypoint",
        "python",
        "--platform",
        release["platform"],
    ]

    def deploy(action, *args, error=None):
        output_format = ("--json",) if action == "plan" else ()
        output = invoke(
            lasa_deploy, action, "--settings", settings, *output_format, *args, error=error
        )
        return json.loads(output) if not error else None

    def native(entry, route):
        return host.supervisor_get(entry, route)

    def maintain(action, *args, error=None):
        output = invoke(lasa_deploy, "gateway", action, "--settings", settings, *args, error=error)
        return json.loads(output) if not error else None

    try:
        for alias, command in (
            ("lasa-model", "model"),
            ("lasa-idp", "issuer"),
        ):
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
                "tests.deployment_smoke",
                command,
                root,
            )
        plan = deploy("plan")
        assert plan["state"] == "empty" and plan["portal"] is False
        assert not (root / "state").exists() and not (root / "control").exists()
        installed = deploy("apply")
        assert installed["active"] == baseline and installed["admission"] == "open"
        first = host.journal()["active"]
        edge = host.gateway(first)
        original_gateway = edge.compose("ps", "-q", "gateway")
        original_revision = maintain("status")["active"]
        assert original_gateway
        assert edge.request("/app/").status_code == 404
        launch = docker(
            "run",
            "--rm",
            *common,
            "--mount",
            mount(ROOT / "run_task.py", "/verify/run_task.py"),
            "--env",
            "LASA_ACCESS_TOKEN=" + (root / "alice-token.txt").read_text(),
            image,
            "/verify/run_task.py",
            "dlp-delegate-request-clean-install",
            "--base-url",
            base_url,
            "--ca-file",
            str(root / "ca.pem"),
            timeout=120,
        )
        assert '"status": "completed"' in launch, launch
        operation = next(
            line.split(": ", 1)[1]
            for line in launch.splitlines()
            if line.startswith("Task operation: ")
        )
        receipt_path = f"/lasa/v1/operations/{operation}"
        receipt = native(first, receipt_path)
        assert deploy("pause")["admission"] == "closed"
        with httpx.Client(
            verify=ssl.create_default_context(cafile=root / "ca.pem"),
            trust_env=False,
            timeout=10,
        ) as client:
            blocked = client.post(
                f"https://127.0.0.1:{spec['supervisor']['port']}/lasa/v1/sessions",
                headers={
                    "Authorization": "Bearer " + (root / "alice-token.txt").read_text(),
                    "Idempotency-Key": "paused-write",
                },
                json={"operation_id": "paused-write", "label": "Blocked by deployment pause"},
                extensions={"sni_hostname": urlsplit(base_url).hostname},
            )
            assert blocked.status_code == 503
        assert native(first, receipt_path) == receipt
        assert deploy("resume")["admission"] == "open"

        portal_options = {
            "config": str(root / "portal/config.json"),
            "port": available_port(),
            "receiver_token_file": str(root / "alice-token.txt"),
            "mounts": [str(root / "ca.pem")],
        }
        candidate_release = root / "candidate-release.json"
        dump(candidate_release, {**release, "release_id": "smoke-portal"})
        config["service"]["deployment_revision"] = "smoke-portal"
        dump(root / "supervisor/config.json", config)
        dump(settings, {**spec, "release": str(candidate_release), "portal": portal_options})
        assert deploy("plan")["portal"]
        assert deploy("apply", "--hold")["admission"] == "closed"
        assert deploy("resume")["active"] == "smoke-portal"
        upgraded = host.journal()["active"]
        assert native(upgraded, receipt_path) == receipt
        portal_result = json.loads(
            docker(
                "run",
                "--rm",
                *common,
                image,
                "-m",
                "tests.deployment_smoke",
                "login",
                root,
                timeout=120,
            )
        )
        portal_path = "/lasa/v1/operations/" + portal_result["operation_id"]
        portal_receipt = native(upgraded, portal_path)
        print("Portal HTTPS sign-in, caller history, and first task passed.")

        stable_app = host.journal()
        containers = set(host.compose(upgraded, "ps", "-q").splitlines())
        assert edge.compose("ps", "-q", "gateway") == original_gateway
        source = name + "-gateway-image"
        ids.append(source)
        docker(
            "create",
            "--name",
            source,
            "--pull",
            "never",
            "--platform",
            release["platform"],
            original_revision["image"],
        )
        gateway_image = docker("commit", "--change", f"LABEL lasa.gateway-smoke={name}", source)
        tls = root / "renewed"
        options = (
            "--image",
            gateway_image,
            "--tls-cert",
            tls / "certificate.pem",
            "--tls-key",
            tls / "key.pem",
        )
        planned = maintain("plan", *options)
        assert planned["change"] and maintain("status")["active"] == original_revision
        patched = maintain("apply", *options)
        assert patched["active"] == planned["candidate"]
        assert (
            patched["active"]["image"] == gateway_image and patched["previous"] == original_revision
        )
        assert_gateway_certificate(edge, tls / "certificate.pem", root / "ca.pem")
        unrelated = root / "untrusted"
        maintain(
            "apply",
            "--tls-cert",
            unrelated / "certificate.pem",
            "--tls-key",
            unrelated / "key.pem",
            "--ca-file",
            unrelated / "certificate.pem",
            error="previous gateway restored",
        )
        assert maintain("status") == patched
        assert_gateway_certificate(edge, tls / "certificate.pem", root / "ca.pem")
        interrupted = edge.journal()
        interrupted["pending"] = original_revision
        edge.save(interrupted)
        edge.install(original_revision, host.wait)
        assert maintain("status")["pending"] == original_revision
        assert maintain("rollback") == patched
        assert_gateway_certificate(edge, tls / "certificate.pem", root / "ca.pem")
        assert host.journal() == stable_app and host.mode() == "open"
        assert set(host.compose(upgraded, "ps", "-q").splitlines()) == containers
        active_gateway = edge.compose("ps", "-q", "gateway")
        print(
            "Standalone gateway image and certificate update, failed apply, and interrupted recovery passed."
        )

        invalid = root / "invalid-token.txt"
        invalid.write_text("invalid-synthetic-token")
        config["service"]["deployment_revision"] = "smoke-failed"
        dump(root / "supervisor/config.json", config)
        failed_release = root / "failed-release.json"
        dump(failed_release, {**release, "release_id": "smoke-failed"})
        dump(
            settings,
            {
                **spec,
                "release": str(failed_release),
                "portal": {**portal_options, "receiver_token_file": str(invalid)},
            },
        )
        deploy("apply", error="predecessor restored")
        restored = deploy("status")
        assert restored["active"] == "smoke-portal" and restored["pending"] is None
        assert restored["admission"] == "open" and native(upgraded, receipt_path) == receipt
        assert native(upgraded, portal_path) == portal_receipt

        status = deploy("rollback")
        assert status["active"] == baseline and status["previous"] == "smoke-portal"
        assert status["admission"] == "open" and native(first, receipt_path) == receipt
        assert native(first, portal_path) == portal_receipt
        assert edge.compose("ps", "-q", "gateway") == active_gateway
        assert maintain("status") == patched
        assert edge.request("/app/").status_code == 404
        assert not docker(
            "ps",
            "--all",
            "--quiet",
            "--filter",
            f"label=com.docker.compose.project={host.project}",
            "--filter",
            "label=com.docker.compose.service=portal",
        )
        assert native(first, "/lasa/v1/descriptor")["deployment_revision"] == "smoke-baseline"
        stable_app = host.journal()
        restored_gateway = maintain("rollback")
        assert restored_gateway["active"] == original_revision
        assert restored_gateway["previous"] == patched["active"]
        assert_gateway_certificate(edge, root / "supervisor/certificate.pem", root / "ca.pem")
        assert host.journal() == stable_app and host.mode() == "open"
        assert native(first, portal_path) == portal_receipt
        print("Independent gateway rollback and application state preservation passed.")

        dump(settings, spec)
        host.compose(first, "stop", "supervisor")
        private = root / "state/private"
        assert not list(private.glob("tasks.sqlite3-*"))
        assert deploy("plan")["state"] == "compatible"
        assert not list(private.glob("tasks.sqlite3-*"))
        print("Read-only preflight of stopped SQLite state passed.")
        print(
            "Clean install, first task, portal upgrade, failed apply restoration, and explicit rollback passed."
        )
    except BaseException:
        journal = host.journal()
        pending = journal["pending"]
        entry = journal["active"] or (pending and pending["target"])
        if entry:
            print(host.compose(entry, "logs", "--tail", "35"), file=sys.stderr)
        raise
    finally:
        journal = host.journal()
        pending = journal["pending"]
        entry = journal["active"] or (pending and pending["target"])
        if entry:
            host.compose(entry, "down", "--remove-orphans")
            host.gateway(entry).compose("down")
        for container in ids:
            docker("rm", "-f", container, check=False)
        if gateway_image:
            docker("image", "rm", gateway_image, check=False)
        docker("volume", "rm", host.project + "-socket", check=False)
        docker("network", "rm", name, check=False)


def model_fixture(root):
    from .container_smoke import serve_fixture

    serve_fixture(root / "model")


if __name__ == "__main__":
    fixtures = {
        "model": model_fixture,
        "issuer": serve_issuer,
        "login": portal_request,
    }
    if sys.argv[1:2] and sys.argv[1] in fixtures:
        fixtures[sys.argv[1]](Path(sys.argv[2]))
    else:
        os.umask(0o077)
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--release", required=True, type=Path)
        parser.add_argument("--lasa-deploy", required=True, type=Path)
        args = parser.parse_args()
        with tempfile.TemporaryDirectory(prefix="lasa-install-smoke-") as temp:
            root = Path(temp).resolve()
            run(root, args.release.resolve(), args.lasa_deploy.resolve())
