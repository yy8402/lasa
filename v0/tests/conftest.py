import copy
import json
import os
import shutil
import subprocess
import tempfile
import time
from contextlib import AsyncExitStack
from pathlib import Path
from uuid import uuid4

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from lasa_service.config import Configuration
from lasa_service.enclosure import Enclosure
from lasa_service.launcher import Launcher
from lasa_service.launcher_client import launcher_scope

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "design/examples"
KEY = ec.generate_private_key(ec.SECP256R1())
JWK = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(KEY.public_key())) | {
    "kid": "test-key",
    "alg": "ES256",
    "use": "sig",
}
ISSUER = "https://identity.example.net"


def example(name):
    return json.loads((EXAMPLES / (name + ".json")).read_text())


def token(subject="alice", audience="https://identity.example.net/services/layer1", **claims):
    return jwt.encode(
        {
            "iss": ISSUER,
            "sub": subject,
            "aud": audience,
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "jti": str(uuid4()),
            **claims,
        },
        KEY,
        algorithm="ES256",
        headers={"kid": "test-key"},
    )


def delegation_grant(sender, receiver, contract, rule):
    return {
        "sender_service_id": sender,
        "receiver_service_id": receiver,
        "contract": contract,
        "effects": list(rule["effects"]),
        "resources": copy.deepcopy(rule["resources"]),
        "disclosure_resources": [resource["resource"] for resource in rule["resources"]],
    }


def add_delegation_grant(raw, rule, contract):
    rule["delegation_grants"].extend(
        delegation_grant(raw["service"]["id"], peer["expected_service_id"], contract, rule)
        for peer in raw["peers"]
    )


def documents(tmp_path, layer="layer1", *, peer=False):
    tmp_path.mkdir(parents=True, exist_ok=True)
    raw = example("config")
    if not peer:
        raw["peers"] = []
    raw["service"]["id"] = "https://identity.example.net/services/" + layer
    raw["service"]["base_url"] = "https://" + layer + ".example.net/prefix/lasa/v1"
    raw["storage"]["state_root"] = str(tmp_path)
    raw["authentication"].pop("jwks_url")
    raw["authentication"]["jwks_file"] = str(tmp_path / "jwks.json")
    (tmp_path / "jwks.json").write_text(json.dumps({"keys": [JWK]}))
    (tmp_path / "contracts.json").write_text("[]")
    raw["contract_publishers"] = [
        {
            "namespace": "https://contracts.example.net/capabilities/",
            "trusted_registry_file": str(tmp_path / "contracts.json"),
        }
    ]
    raw["verifiers"] = []
    raw["limits"]["max_task_budget"].update(
        model_calls=12, model_tokens=48000, delegations=3, wall_time_ms=180000
    )
    raw["limits"]["assessment_budget"].update(model_calls=2, model_tokens=4000)
    raw["limits"]["integration_reserve"].update(model_calls=2, model_tokens=4000)
    rule = {
        "authorization_ref": "default",
        "contracts": raw["published_contracts"],
        "resources": [{"resource": "workspace:self", "actions": ["read", "create", "update"]}],
        "effects": ["workspace.read", "workspace.write"],
        "delegation_grants": [],
        "budget": raw["limits"]["max_task_budget"],
        "max_hops": 2,
        "content_diagnostics": False,
    }
    for contract in raw["published_contracts"]:
        add_delegation_grant(raw, rule, contract)
    policy = {
        "revision": "policy-1",
        "trusted_delegator_service_ids": (
            ["https://identity.example.net/services/layer1"] if layer != "layer1" else []
        ),
        "principals": [
            {"subject": "alice", "kind": "user", "rules": [copy.deepcopy(rule)]},
            {"subject": "bob", "kind": "user", "rules": []},
            {
                "subject": "peer-layer1",
                "kind": "peer",
                "service_id": "https://identity.example.net/services/layer1",
                "rules": [copy.deepcopy(rule)],
            },
        ],
    }
    (tmp_path / "authorization.json").write_text(json.dumps(policy))
    raw["authorization"]["policy_file"] = str(tmp_path / "authorization.json")
    for executor in raw["executors"]:
        executor["credential_ref"] = "env:MODEL_KEY"
    raw["discovery_cache"]["page_size"] = 1
    if peer:
        raw["peers"][0].update(
            descriptor_url="https://layer2.example.net/prefix/lasa/v1/descriptor",
            allowed_base_url="https://layer2.example.net/prefix/lasa/v1",
            authorization_ref="default",
            credential_ref="env:PEER_TOKEN",
        )
    return raw


def configuration(raw):
    return Configuration.from_document(
        raw,
        environ={
            "MODEL_KEY": "test-model-key",
            "GATEWAY_KEY": "test-gateway-key",
            **{
                peer["credential_ref"][4:]: token(
                    "peer-" + raw["service"]["id"].rsplit("/", 1)[-1], peer["expected_service_id"]
                )
                for peer in raw["peers"]
                if peer["credential_ref"].startswith("env:")
            },
        },
    )


@pytest.fixture(scope="session")
def runtime_image():
    docker = shutil.which("docker")
    if not docker:
        pytest.fail("Docker required for runtime acceptance")
    image = os.getenv("LASA_TEST_WORKER_IMAGE", "lasa-codex-worker:1.0.0")
    result = subprocess.run(
        [docker, "image", "inspect", "--format", "{{.Id}}", image],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, "Build lasa-codex-worker:1.0.0 before integration verification"
    return result.stdout.strip()


@pytest.fixture
async def worker_launcher(runtime_image):
    with tempfile.TemporaryDirectory(prefix="lasa-launch-", dir="/tmp") as directory:
        path = Path(directory) / "worker.sock"
        service_id = f"https://identity.example.net/services/launcher-test-{uuid4().hex}"
        launcher = Launcher(Enclosure(runtime_image, launcher_scope(service_id)))
        async with launcher.serve(path):
            yield launcher, path, service_id


class FakeRuntime:
    def __init__(self, handler=None):
        self.handler = handler
        self.prompts = []

    async def probe(self, coordinator):
        pass

    async def recover(self, coordinator):
        pass

    async def kill(self, task_id):
        pass

    async def run(self, context):
        self.prompts.append(copy.deepcopy(context.prompt))
        if self.handler:
            return await self.handler(context)
        inputs = context.prompt["input"]
        profile = context.definition["id"].rsplit("/", 1)[-1]
        if profile == "design.review":
            output = {
                "findings": [],
                "coverage": [
                    {
                        "criterion_id": x["id"],
                        "disposition": "reviewed",
                        "evidence": inputs["design"],
                    }
                    for x in inputs["criteria"]
                ],
            }
        else:
            output = {
                "disposition": "fulfilled",
                "summary": "Completed bounded work.",
                "requirement_evidence": [
                    {"id": x["id"], "evidence": "Verified " + x["description"]}
                    for x in inputs["requirements"]
                ],
            }
        return {
            "output": output,
            "evidence": [
                {
                    "criterion_id": p["id"],
                    "disposition": "passed",
                    "summary": "Independent test executor evidence.",
                    "artifact_ids": [],
                }
                for p in context.definition["postconditions"]
            ],
            "artifact_ids": [],
        }


@pytest.fixture
async def services(tmp_path):
    from lasa_service.api import create_app

    async with AsyncExitStack() as stack:
        count = 0

        async def make(
            *,
            raw=None,
            runtime=None,
            peer_transport=None,
            model_transport=None,
            inspection_transport=None,
            planner=None,
            verifier=None,
        ):
            nonlocal count
            count += 1
            raw = raw or documents(tmp_path / str(count))
            cfg = configuration(raw)
            app = create_app(
                cfg,
                runtime=runtime or FakeRuntime(),
                peer_transport=peer_transport,
                model_transport=model_transport,
                inspection_transport=inspection_transport,
                planner=planner or deterministic_planner,
                verifier=verifier or deterministic_verifier,
            )
            await stack.enter_async_context(app.router.lifespan_context(app))
            client = await stack.enter_async_context(
                httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app),
                    base_url=raw["service"]["base_url"],
                    headers={"Authorization": "Bearer " + token(audience=cfg.service_id)},
                )
            )
            return client, app

        yield make


async def deterministic_verifier(c, task_id, definition, inputs, output, evidence, requirements):
    return True


async def deterministic_planner(c, task_id, request, peer_catalog, requirements):
    from lasa_service.contracts import canonical

    return {
        "steps": [
            {
                "step_id": "step-main",
                "requirement_ids": [x["requirement_id"] for x in requirements],
                "depends_on": [],
                "contract_digest": request["selection"]["contract"]["digest"],
                "input_json": canonical(request["input"]).decode(),
                "local_assessment": "sufficient",
                "assessment_summary": "Deterministic controller fixture.",
            }
        ]
    }


async def new_session(client, app, operation_id=None):
    operation_id = operation_id or "session-" + uuid4().hex
    base = app.state.coordinator.config.document["service"]["base_url"]
    response = await client.post(
        base + "/sessions",
        json={"operation_id": operation_id},
        headers={"Idempotency-Key": operation_id},
    )
    assert response.status_code == 201, response.text
    return response.json()["session_id"]


async def task_request(client, app, *, profile="task.attempt", inputs=None, operation_id=None):
    from datetime import UTC, datetime, timedelta

    c = app.state.coordinator
    base = c.config.document["service"]["base_url"]
    catalog = (await client.get(base + "/capabilities")).json()
    offers = catalog["offers"]
    while catalog["next_cursor"]:
        catalog = (
            await client.get(base + "/capabilities", params={"cursor": catalog["next_cursor"]})
        ).json()
        offers += catalog["offers"]
    offer = next(x for x in offers if x["contract"]["id"].endswith("/" + profile))
    if inputs is None:
        inputs = (
            {
                "objective": "Explain a bounded service.",
                "requirements": [
                    {
                        "id": "requirement-main",
                        "description": "Explain the supplied objective.",
                        "acceptance": ["A useful bounded explanation."],
                    }
                ],
            }
            if profile == "task.attempt"
            else {
                "design": "The parent retains final responsibility.",
                "criteria": [
                    {"id": "criterion-main", "description": "Check parent responsibility."}
                ],
            }
        )
    return {
        "operation_id": operation_id or "operation-" + uuid4().hex,
        "selection": {
            "contract": offer["contract"],
            "offer_id": offer["offer_id"],
            "offer_revision": offer["revision"],
            "catalog_view": offer["catalog_view"],
        },
        "input": inputs,
        "requested_limits": {
            "budget": copy.deepcopy(c.config.document["limits"]["max_task_budget"]),
            "deadline": (datetime.now(UTC) + timedelta(seconds=120)).isoformat(),
            "max_hops": offer["max_hops"],
        },
        "authorization_ref": "default",
        "diagnostics": "metadata",
    }


async def submit(client, app, request, session_id=None):
    session_id = session_id or await new_session(client, app)
    base = app.state.coordinator.config.document["service"]["base_url"]
    return await client.post(
        base + "/sessions/" + session_id + "/tasks",
        json=request,
        headers={"Idempotency-Key": request["operation_id"]},
    )


async def settled(client, response):
    import asyncio

    assert response.status_code == 202, response.text
    for _ in range(1000):
        result = await client.get(response.headers["Location"])
        assert result.status_code == 200, result.text
        if result.json()["status"] in {
            "completed",
            "failed",
            "rejected",
            "cancelled",
            "indeterminate",
        }:
            return result.json()
        await asyncio.sleep(0.005)
    raise AssertionError("Task did not settle")
