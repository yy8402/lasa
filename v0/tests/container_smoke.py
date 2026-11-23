"""Verify an installed LASA image using three containers and a local model fixture."""

import argparse
import json
import os
import secrets
import ssl
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import Response

from lasa_service.auth import static_token_digest

from .http_helpers import certificate
from .protocol_helpers import sse_final

ROOT = Path(__file__).resolve().parents[1]
PEERS = {"review": "design.review", "attempt": "task.attempt"}
MODEL_KEY = "local-responses-fixture"
PORT = 8443


def origin(name):
    return f"https://lasa-{name}:{PORT}"


def base(name):
    return origin(name) + "/lasa/v1"


def read(path):
    return json.loads(path.read_text())


def save(path, document):
    path.write_text(json.dumps(document, indent=2) + "\n")


def docker(*args, timeout=30, check=True):
    result = subprocess.run(
        ["docker", *map(str, args)], capture_output=True, text=True, timeout=timeout, check=False
    )
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    if args[0] == "logs" and result.returncode:
        return ""
    return (result.stdout + result.stderr if args[0] == "logs" else result.stdout).strip()


def mount(source, target=None, *, read_only=True):
    return f"type=bind,source={source},target={target or source}" + (
        ",readonly" if read_only else ""
    )


def configure(root, name, namespace, runtime):
    directory = root / name
    identity = f"https://identity.lasa.test/services/{namespace}"
    command = [
        sys.executable,
        str(ROOT / "tools/create_development_config.py"),
        "--output",
        str(directory),
        "--base-url",
        base(name),
        "--service-id",
        f"{identity}/{name}",
        "--image",
        runtime,
        "--listen-port",
        str(PORT),
    ]
    if name in PEERS:
        command += ["--trusted-parent-id", f"{identity}/parent"]
    subprocess.run(command, check=True, timeout=10)
    cert, key = certificate(directory, dns_name=f"lasa-{name}")
    config = read(directory / "config.json")
    if name == "review":
        registry = {"tokens": []}
        for subject, filename in (
            ("operator", "operator-token.txt"),
            ("peer-parent", "peer-token.txt"),
        ):
            token = secrets.token_urlsafe(32)
            (directory / filename).write_text(token + "\n")
            registry["tokens"].append(
                {
                    "subject": subject,
                    "digest": static_token_digest(config["service"]["id"], token),
                    "expires_at": int(time.time()) + 3600,
                }
            )
        save(directory / "static-tokens.json", registry)
        config["authentication"] = {"mode": "static_token"}
    config["storage"].update(
        state_root=str(root / "state" / name),
        listen_host="0.0.0.0",
        tls={"certificate_file": str(cert), "key_file": str(key)},
    )
    for executor in config["executors"]:
        executor.update(
            provider_base_url=origin("model") + "/v1", provider_ca_file=str(root / "ca.pem")
        )
    return config


def authorize(root, configs):
    parent = configs["parent"]
    policy_path = root / "parent" / "authorization.json"
    policy = read(policy_path)
    rule = policy["principals"][0]["rules"][0]
    parent["routing"]["unclaimed_peer_fallback"] = "reject"
    for name, contract_name in PEERS.items():
        receiver = configs[name]["service"]["id"]
        token_path = root / "parent" / f"{name}-token.txt"
        token_path.write_bytes((root / name / "peer-token.txt").read_bytes())
        token_path.chmod(0o600)
        parent["peers"].append(
            {
                "descriptor_url": base(name) + "/descriptor",
                "expected_service_id": receiver,
                "allowed_base_url": base(name),
                "credential_ref": "file:" + str(token_path),
                "authorization_ref": "default",
                "request_timeout_seconds": 5,
                "ca_file": str(root / "ca.pem"),
            }
        )
        if name == "review":
            parent["peers"][-1]["authentication"] = {
                "mode": "static_token",
                "subject": "peer-parent",
            }
        rule["delegation_grants"].append(
            {
                "sender_service_id": parent["service"]["id"],
                "receiver_service_id": receiver,
                "contract": next(
                    ref for ref in rule["contracts"] if ref["id"].endswith("/" + contract_name)
                ),
                "effects": rule["effects"],
                "resources": rule["resources"],
                "disclosure_resources": ["workspace:self"],
            }
        )
    save(policy_path, policy)


def payload(body):
    for item in reversed(body["input"]):
        if item.get("role") != "user":
            continue
        for part in item["content"]:
            try:
                value = json.loads(part.get("text", ""))
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict) and ("request" in value or "outcome_contract" in value):
                return value
    raise ValueError("Fixture could not find the LASA model payload")


def propose_plan(context):
    review = next(
        d
        for d, contract in context["contracts"].items()
        if contract["id"].endswith("/design.review")
    )
    request = context["request"]
    requirements = [requirement["requirement_id"] for requirement in context["requirements"]]
    review_inputs = {
        "design": "The parent delegates its review and attempt to separate authorized receivers.",
        "criteria": [{"id": "selection", "description": "Check bounded peer selection."}],
    }
    steps = [
        ("step-review", review, review_inputs, []),
        ("step-attempt", request["contract"]["digest"], request["input"], ["step-review"]),
    ]
    return {
        "steps": [
            {
                "step_id": step,
                "requirement_ids": requirements,
                "depends_on": dependencies,
                "contract_digest": contract,
                "input_json": json.dumps(inputs),
                "local_assessment": "sufficient",
                "assessment_summary": "Deterministic container fixture.",
            }
            for step, contract, inputs, dependencies in steps
        ]
    }


def execute_fixture(context):
    contract = context["outcome_contract"]
    inputs = context["input"]
    if contract["id"].endswith("/design.review"):
        output = {
            "findings": [],
            "coverage": [
                {
                    "criterion_id": item["id"],
                    "disposition": "reviewed",
                    "evidence": "The receivers are distinct.",
                }
                for item in inputs["criteria"]
            ],
        }
    else:
        if results := context.get("verified_step_results"):
            assert (
                results["step-attempt"]["output"]["summary"]
                == "The worker consumed the verified review."
            )
            summary = "The parent integrated both verified peer results."
        else:
            assert (
                context["delegated_dependencies"]["step-review"]["coverage"][0]["criterion_id"]
                == "selection"
            )
            summary = "The worker consumed the verified review."
        output = {
            "disposition": "fulfilled",
            "summary": summary,
            "requirement_evidence": [
                {"id": item["id"], "evidence": summary} for item in inputs["requirements"]
            ],
        }
    return {
        "output": output,
        "artifact_ids": [],
        "evidence": [
            {
                "criterion_id": item["id"],
                "disposition": "passed",
                "summary": "Fixture evidence.",
                "artifact_ids": [],
            }
            for item in contract["postconditions"]
        ],
    }


def serve_model(directory):
    app = FastAPI()

    @app.post("/v1/responses")
    async def respond(request: Request):
        assert request.headers["Authorization"] == "Bearer " + MODEL_KEY
        body = await request.json()
        if body.get("stream"):
            return Response(
                sse_final(json.dumps(execute_fixture(payload(body)))),
                media_type="text/event-stream",
            )
        message_format = body["text"]["format"]
        if message_format["name"] == "lasa_verification":
            developer, context, candidate = body["input"]
            assert [developer["role"], context["role"], candidate["role"]] == [
                "developer",
                "user",
                "user",
            ]
            assert (
                "The last user message is the complete candidate_output"
                in developer["content"][0]["text"]
            )
            context = json.loads(context["content"][0]["text"])
            candidate = json.loads(candidate["content"][0]["text"])
            assert "candidate_output" not in context and "output_schema" not in context["contract"]
            if context["contract"]["ref"]["id"].endswith("/design.review"):
                assert set(candidate) == {"coverage", "findings"}
            else:
                assert candidate["disposition"] == "fulfilled"
                material = context["trusted_execution_evidence"]
                assert material["dependencies"]
                if material["step_id"] is None and len(material["dependencies"]) == 2:
                    review_input, attempt_input = material["step_inputs"]
                    assert review_input["step_id"] == "step-review"
                    assert review_input["content"]["criteria"][0]["id"] == "selection"
                    assert attempt_input["step_id"] == "step-attempt"
                    assert attempt_input["content"] == context["input"]
        schema = message_format["schema"]
        answer = (
            propose_plan(payload(body))
            if "steps" in schema["properties"]
            else {"passed": True, "reason": "Deterministic verification fixture."}
        )
        return {
            "output": [
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": json.dumps(answer)}],
                }
            ],
            "usage": {"input_tokens": 10, "output_tokens": 10, "total_tokens": 20},
        }

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=PORT,
        ssl_certfile=str(directory / "certificate.pem"),
        ssl_keyfile=str(directory / "key.pem"),
        access_log=False,
    )


def verify(root):
    verify_tls = ssl.create_default_context(cafile=root / "ca.pem")
    token = (root / "parent/operator-token.txt").read_text().strip()
    with httpx.Client(
        verify=verify_tls, trust_env=False, timeout=6, headers={"Authorization": "Bearer " + token}
    ) as client:
        deadline = time.monotonic() + 45
        for name in (*PEERS, "parent"):
            receiver_token = (root / name / "operator-token.txt").read_text().strip()
            headers = {"Authorization": "Bearer " + receiver_token}
            while True:
                try:
                    if (
                        client.get(origin(name) + "/health/ready", headers=headers).status_code
                        == 200
                    ):
                        break
                except httpx.TransportError:
                    pass
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"{name} did not become ready")
                time.sleep(0.2)
        review_operator = (root / "review/operator-token.txt").read_text().strip()
        review = (
            client.get(
                base("review") + "/descriptor",
                headers={"Authorization": "Bearer " + review_operator},
            )
            .raise_for_status()
            .json()
        )
        assert review["authentication"]["mode"] == "static_token"
        assert "bounded-delegation" in review["protocols"][0]["features"]
        descriptor = client.get(base("parent") + "/descriptor").raise_for_status().json()
        protocol = descriptor["protocols"][0]["version"]
        assert protocol == "lasa/1.2", descriptor
        sibling_token = (root / "review/peer-token.txt").read_text().strip()
        assert (
            client.get(
                base("attempt") + "/descriptor",
                headers={"Authorization": "Bearer " + sibling_token},
            ).status_code
            == 401
        )
        catalog = client.get(base("parent") + "/capabilities").raise_for_status().json()
        offer = next(
            item for item in catalog["offers"] if item["contract"]["id"].endswith("/task.attempt")
        )
        session = (
            client.post(
                base("parent") + "/sessions",
                json={"operation_id": "session-container-smoke"},
                headers={"Idempotency-Key": "session-container-smoke"},
            )
            .raise_for_status()
            .json()
        )
        task = client.post(
            base("parent") + f"/sessions/{session['session_id']}/tasks",
            headers={"Idempotency-Key": "task-container-smoke"},
            json={
                "operation_id": "task-container-smoke",
                "selection": {
                    field: offer[field] for field in ("contract", "offer_id", "catalog_view")
                }
                | {"offer_revision": offer["revision"]},
                "input": {
                    "objective": "Verify two bounded peer results.",
                    "requirements": [
                        {
                            "id": "requirement-main",
                            "description": "Integrate a downstream review and attempt.",
                            "acceptance": ["Use both peer outcomes."],
                        }
                    ],
                },
                "requested_limits": {
                    "budget": offer["max_budget"],
                    "max_hops": 1,
                    "deadline": (datetime.now(UTC) + timedelta(seconds=240)).isoformat(),
                },
                "authorization_ref": offer["authorization_ref"],
                "diagnostics": "metadata",
            },
        ).raise_for_status()
        location = task.headers["Location"]
        deadline = time.monotonic() + 115
        while time.monotonic() < deadline:
            outcome = client.get(location).raise_for_status().json()
            if outcome["status"] in {
                "completed",
                "rejected",
                "failed",
                "indeterminate",
                "cancelled",
            }:
                break
            time.sleep(0.25)
        assert outcome["status"] == "completed", outcome
        result = outcome["result"]
        assert result["usage"]["delegations"] == 2
        assert result["output"]["summary"] == "The parent integrated both verified peer results."
        report = client.get(location + "/delegations").raise_for_status().json()
        children = report["children"]
        for child, name in zip(children, PEERS, strict=True):
            receiver = read(root / name / "config.json")["service"]["id"]
            assert child["service_id"] == receiver and child["state"] == "completed", child
            events = child["trace"]["events"]
            routing = next(event["payload"] for event in events if event["kind"] == "routing")
            assert routing["contract"]["id"].endswith("/" + PEERS[name]), routing
            calls = [
                event["payload"]
                for event in events
                if event["kind"] == "call" and event["payload"]["call_type"] == "model"
            ]
            executions = {
                call["operation_id"]
                for call in calls
                if call["phase"] == "started" and call.get("purpose") == "execution"
            }
            finished = {call["operation_id"] for call in calls if call["phase"] == "finished"}
            assert len(executions) == 1 and executions <= finished, child
        print(
            json.dumps(
                {
                    "protocol": protocol,
                    "task_id": outcome["task_id"],
                    "status": outcome["status"],
                    "delegations": [
                        {"service_id": child["service_id"], "task_id": child["task_id"]}
                        for child in children
                    ],
                    "wrong_audience_status": 401,
                    "model_calls": result["usage"]["model_calls"],
                },
                indent=2,
            )
        )


def run(args, root):
    namespace = "lasa-smoke-" + uuid4().hex[:10]
    image = docker("image", "inspect", "--format", "{{.Id}}", args.service_image)
    runtime = docker("image", "inspect", "--format", "{{.Id}}", args.runtime_image)
    socket_mount = mount(args.docker_socket, "/var/run/docker.sock", read_only=False)
    gid = docker(
        "run",
        "--rm",
        "--network",
        "none",
        "--mount",
        socket_mount,
        "--entrypoint",
        "stat",
        image,
        "-c",
        "%g",
        "/var/run/docker.sock",
    )
    configs = {name: configure(root, name, namespace, runtime) for name in (*PEERS, "parent")}
    model = root / "model"
    model.mkdir()
    certificate(model, dns_name="lasa-model")
    ca = root / "ca.pem"
    ca.write_bytes(
        b"".join((root / name / "certificate.pem").read_bytes() for name in (*configs, "model"))
    )
    authorize(root, configs)
    for name, config in configs.items():
        save(root / name / "config.json", config)
    containers = []
    docker("network", "create", "--internal", namespace)
    user = f"{os.getuid()}:{os.getgid()}"
    fixture = [
        "--mount",
        mount(ROOT / "tests", "/verify/tests"),
        "--workdir",
        "/verify",
        "--entrypoint",
        "python",
    ]
    try:
        containers.append(namespace + "-model")
        docker(
            "run",
            "-d",
            "--name",
            containers[-1],
            "--network",
            namespace,
            "--network-alias",
            "lasa-model",
            "--user",
            user,
            "--mount",
            mount(model),
            *fixture,
            image,
            "-m",
            "tests.container_smoke",
            "model",
            model,
        )
        for name, config in configs.items():
            state = Path(config["storage"]["state_root"])
            state.mkdir(mode=0o700, parents=True)
            containers.append(namespace + "-" + name)
            docker(
                "run",
                "-d",
                "--name",
                containers[-1],
                "--network",
                namespace,
                "--network-alias",
                "lasa-" + name,
                "--user",
                user,
                "--group-add",
                gid,
                "--mount",
                socket_mount,
                "--mount",
                mount(root / name),
                "--mount",
                mount(state, read_only=False),
                "--mount",
                mount(ca),
                "--env",
                "LASA_MODEL_API_KEY=" + MODEL_KEY,
                image,
                "--config",
                root / name / "config.json",
            )
        client = namespace + "-verify"
        containers.append(client)
        print(
            docker(
                "run",
                "--rm",
                "--name",
                client,
                "--network",
                namespace,
                "--user",
                user,
                "--mount",
                mount(root),
                *fixture,
                image,
                "-m",
                "tests.container_smoke",
                "verify",
                root,
                timeout=165,
            )
        )
        for config in configs.values():
            label = "label=com.lasa.service_id=" + config["service"]["id"]
            assert not docker("ps", "-aq", "--filter", label), "A task enclosure was left running"
            state = Path(config["storage"]["state_root"])
            assert (state / "private" / "tasks.sqlite3").is_file()
            assert any((state / "workspaces").iterdir())
    except Exception:
        for container in containers:
            logs = docker("logs", "--tail", "80", container, check=False)
            if logs:
                print(f"{container}\n{logs}", file=sys.stderr)
        raise
    finally:
        for container in reversed(containers):
            docker("stop", "-t", "5", container, check=False)
            docker("rm", "-f", container, check=False)
        for config in configs.values():
            label = "label=com.lasa.service_id=" + config["service"]["id"]
            remaining = docker("ps", "-aq", "--filter", label, check=False).splitlines()
            if remaining:
                docker("rm", "-f", *remaining)
        docker("network", "rm", namespace)


if __name__ == "__main__":
    if sys.argv[1:2] == ["model"]:
        serve_model(Path(sys.argv[2]))
    elif sys.argv[1:2] == ["verify"]:
        verify(Path(sys.argv[2]))
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--service-image", default="lasa-service:local")
        parser.add_argument("--runtime-image", default="lasa-codex:target-v1")
        parser.add_argument("--docker-socket", type=Path, default=Path("/var/run/docker.sock"))
        with tempfile.TemporaryDirectory(prefix="lasa-container-") as directory:
            run(parser.parse_args(), Path(directory).resolve())
