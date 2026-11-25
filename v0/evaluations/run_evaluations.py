"""Run isolated HTTPS layers with actual Codex App Server and actual configured inference.

No deployed service is contacted or reconfigured. Credentials remain private.
"""

import argparse
import asyncio
import copy
import json
import sys
import tempfile
from contextlib import AsyncExitStack
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lasa_service.api import create_app
from lasa_service.config import Configuration
from lasa_service.enclosure import Enclosure
from lasa_service.launcher import Launcher
from lasa_service.launcher_client import launcher_scope
from tests.conftest import EXECUTION_KEY, documents, new_session, task_request, token
from tests.http_helpers import certificate, live_http

EVALUATION_ROOT = Path(__file__).resolve().parents[1]

CORPUS = json.loads(Path(__file__).with_name("assessment-corpus.json").read_text())
ROUTE_CASES = ["local_first", "delegate_first", "unclaimed_typed", "explicit_attempt", "no_peer"]
CASES = ROUTE_CASES + ["assessment_" + x["id"] for x in CORPUS]


def configure(directory, layer, case, key, launcher_socket, service_ids):
    raw = documents(directory, layer, peer=(layer == "layer1" and case != "no_peer"))
    raw["service"]["id"] = service_ids[layer]
    if raw["peers"]:
        raw["peers"][0]["expected_service_id"] = service_ids["layer2"]
    raw["runtime"]["launcher_socket"] = str(launcher_socket)
    raw["service"]["deployment_revision"] = "evaluation-" + case
    raw["discovery_cache"]["catalog_max_age_seconds"] = 300
    budget = raw["limits"]["max_task_budget"]
    budget.update(
        model_tokens=500000,
        model_calls=16,
        wall_time_ms=300000,
        tool_calls=8,
        delegations=2,
        input_bytes=128000,
        output_bytes=32000,
        artifact_bytes=128000,
    )
    raw["limits"]["assessment_budget"].update(
        model_tokens=100000, model_calls=2, wall_time_ms=60000, input_bytes=128000
    )
    raw["limits"]["integration_reserve"].update(
        model_tokens=200000, model_calls=6, wall_time_ms=90000
    )
    if layer == "layer2":
        raw["limits"]["integration_reserve"].update(
            model_tokens=50000, model_calls=2, wall_time_ms=30000
        )
    raw["routing"] = {
        "preferred_executor": "local"
        if case == "local_first" or case.startswith("assessment_")
        else "peer",
    }
    path = Path(raw["authorization"]["policy_file"])
    policy = json.loads(path.read_text())
    for principal in policy["principals"]:
        if principal["kind"] == "peer":
            principal["service_id"] = service_ids["layer1"]
        for rule in principal["rules"]:
            rule["budget"] = copy.deepcopy(budget)
            for grant in rule["delegation_grants"]:
                grant["sender_service_id"] = service_ids[layer]
                grant["receiver_service_id"] = service_ids["layer2"]
    path.write_text(json.dumps(policy))
    if case in {"unclaimed_typed", "explicit_attempt"}:
        if layer == "layer1":
            raw["bindings"] = [
                x for x in raw["bindings"] if x["contract"]["id"].endswith("/task.attempt")
            ]
        else:
            raw["published_contracts"] = [
                x for x in raw["published_contracts"] if x["id"].endswith("/task.attempt")
            ]
    env = {
        "MODEL_KEY": key,
        "LASA_EXECUTION_KEY": EXECUTION_KEY,
        "PEER_TOKEN": token("peer-layer1", service_ids["layer2"]),
    }
    return raw, env


async def events(client, url, *, credential=None):
    collected = []
    after = 0
    while True:
        headers = {"Authorization": "Bearer " + credential} if credential else None
        response = await client.get(
            url, params={"after_sequence": after, "limit": 100}, headers=headers
        )
        response.raise_for_status()
        page = response.json()
        collected += page["events"]
        if len(page["events"]) < 100:
            return collected
        after = page["next_sequence"] - 1


def outcome_matches(case, task):
    expected = case["expected_disposition"]
    if task["status"] == "rejected":
        return expected == "unable" and task["problem"]["code"] in {
            "precondition_failed",
            "unsupported_contract",
            "verification_failed",
        }
    if task["status"] != "completed":
        return False
    output = task["result"]["output"]
    if output["disposition"] != expected:
        return False
    if expected == "unable":
        return case["requirement_id"] in output["unsatisfied_requirements"]
    if case["requirement_id"] not in {item["id"] for item in output["requirement_evidence"]}:
        return False
    text = json.dumps(output).casefold()
    return all(term in text for term in case.get("required_terms", [])) and all(
        term not in text for term in case.get("excluded_terms", [])
    )


async def run_case(directory, case, key, runtime_image):
    tls = certificate(directory)
    namespace = uuid4().hex
    service_ids = {
        role: f"https://identity.example.net/services/{namespace}/{role}"
        for role in ("layer1", "layer2")
    }
    async with AsyncExitStack() as stack:
        sockets = Path(
            stack.enter_context(tempfile.TemporaryDirectory(prefix="lasa-eval-", dir="/tmp"))
        )
        for role, layer in (("child", "layer2"), ("parent", "layer1")):
            scope = launcher_scope(service_ids[layer])
            launcher = Launcher(Enclosure(runtime_image, scope))
            await stack.enter_async_context(launcher.serve(sockets / f"{role}.sock"))
        child_raw, child_env = configure(
            directory / "child", "layer2", case, key, sockets / "child.sock", service_ids
        )
        child_cfg = Configuration.from_document(child_raw, environ=child_env)
        child_app = create_app(child_cfg)
        await stack.enter_async_context(child_app.router.lifespan_context(child_app))
        child_origin = await stack.enter_async_context(live_http(child_app, tls=tls))
        prefix = "/prefix/lasa/v1"
        child_cfg.document["service"].update(base_url=child_origin + prefix)
        raw, env = configure(
            directory / "parent", "layer1", case, key, sockets / "parent.sock", service_ids
        )
        if raw["peers"]:
            raw["peers"][0].update(
                descriptor_url=child_origin + prefix + "/descriptor",
                allowed_base_url=child_origin + prefix,
                ca_file=str(tls[0]),
            )
        cfg = Configuration.from_document(raw, environ=env)
        app = create_app(cfg)
        await stack.enter_async_context(app.router.lifespan_context(app))
        origin = await stack.enter_async_context(live_http(app, tls=tls))
        cfg.document["service"].update(base_url=origin + prefix)
        client = await stack.enter_async_context(
            httpx.AsyncClient(
                base_url=origin,
                verify=__import__("ssl").create_default_context(cafile=str(tls[0])),
                trust_env=False,
                timeout=20,
                headers={"Authorization": "Bearer " + token(audience=cfg.service_id)},
            )
        )
        corpus = next((x for x in CORPUS if "assessment_" + x["id"] == case), None)
        if corpus or case == "explicit_attempt":
            scenario = corpus or CORPUS[0]
            request = await task_request(
                client,
                app,
                profile="task.attempt",
                inputs={
                    "objective": scenario["objective"],
                    "context": scenario["context"],
                    "requirements": [
                        {
                            "id": scenario["requirement_id"],
                            "description": scenario["requirement"],
                            "acceptance": [scenario["acceptance"]],
                        }
                    ],
                },
            )
        else:
            request = await task_request(
                client,
                app,
                profile="design.review",
                inputs={
                    "design": "The parent retains responsibility for final completion and verifies the result. The child performs its bounded assignment.",
                    "criteria": [
                        {
                            "id": "criterion-accountability",
                            "description": "Explain who retains responsibility and cite the design.",
                        }
                    ],
                },
            )
        from datetime import timedelta

        request["requested_limits"]["deadline"] = (
            datetime.now(UTC) + timedelta(seconds=240)
        ).isoformat()
        sid = await new_session(client, app)
        url = cfg.document["service"]["base_url"] + "/sessions/" + sid + "/tasks"
        response = await client.post(
            url, json=request, headers={"Idempotency-Key": request["operation_id"]}
        )
        response.raise_for_status()
        task_url = response.headers["Location"]
        async with asyncio.timeout(270):
            while True:
                status = await client.get(task_url)
                status.raise_for_status()
                task = status.json()
                if task["status"] in {
                    "completed",
                    "failed",
                    "rejected",
                    "cancelled",
                    "indeterminate",
                }:
                    break
                await asyncio.sleep(0.2)
        public_events = await events(client, task_url + "/events")
        operator_url = task_url.replace("/tasks/", "/operator/tasks/", 1)
        assert (await client.get(operator_url + "/events")).status_code == 403
        trace = await events(
            client, operator_url + "/events", credential=token("operator", cfg.service_id)
        )
        children = app.state.coordinator.store.children(task["task_id"])
        child_traces = []
        for child in children:
            if "task_id" not in child:
                continue
            child_client = await stack.enter_async_context(
                httpx.AsyncClient(
                    verify=__import__("ssl").create_default_context(cafile=str(tls[0])),
                    trust_env=False,
                    headers={"Authorization": "Bearer " + env["PEER_TOKEN"]},
                )
            )
            child_trace = await events(
                child_client,
                child_origin + prefix + "/operator/tasks/" + child["task_id"] + "/events",
                credential=token("operator", child_cfg.service_id),
            )
            child_task = (
                await child_client.get(child_origin + prefix + "/tasks/" + child["task_id"])
            ).json()
            child_traces.append(
                {"service_id": child["service_id"], "task": child_task, "events": child_trace}
            )
        routing = [event["payload"] for event in trace if event["kind"] == "routing"]
        selected = [event["selected_executor"] for event in routing]
        expected = {
            "local_first": ("completed", "local", "matched"),
            "delegate_first": ("completed", "peer", "matched"),
            "unclaimed_typed": ("rejected", "none", "not_claimed"),
            "explicit_attempt": ("completed", "peer", "matched"),
            "no_peer": ("completed", "local", "not_configured"),
        }.get(case)
        if corpus:
            passed = (
                not children
                and all(executor in {"none", "local"} for executor in selected)
                and (task["status"] != "completed" or selected == ["local"])
                and outcome_matches(corpus, task)
            )
        else:
            status, executor, peer_state = expected
            passed = (
                task["status"] == status
                and selected == [executor]
                and routing[0]["peer_assessment"] == peer_state
                and len(children) == int(executor == "peer")
            )
            if case == "explicit_attempt":
                passed = passed and outcome_matches(CORPUS[0], task)
            elif case == "unclaimed_typed":
                passed = passed and task["problem"]["code"] == "unsupported_contract"
            else:
                output = task.get("result", {}).get("output", {})
                passed = passed and any(
                    item["criterion_id"] == "criterion-accountability"
                    and item["disposition"] == "reviewed"
                    and "parent" in item["evidence"].casefold()
                    for item in output.get("coverage", [])
                )
            if executor == "peer":
                passed = (
                    passed
                    and len(child_traces) == 1
                    and any(
                        event["kind"] == "call" and event["payload"]["call_type"] == "model"
                        for event in child_traces[0]["events"]
                    )
                )
        assessments = [
            json.loads(row[0])
            for row in app.state.coordinator.store.db.execute(
                "SELECT document FROM audit WHERE task_id=? AND kind='plan_semantic_verdict'",
                (task["task_id"],),
            )
        ]
        result = {
            "case": case,
            "runtime_image": runtime_image,
            "passed": bool(passed),
            "expected_route": expected,
            "assessment_expectation": corpus,
            "plan_verdicts": assessments,
            "task": task,
            "consumer_events": public_events,
            "layer1_events": trace,
            "layer2": child_traces,
            "execution": "actual Codex App Server, actual gpt-5.5 API inference, real isolated HTTPS sockets; no planner/verifier/model mocks",
        }
        (directory / "evidence.json").write_text(json.dumps(result, indent=2) + "\n")
        print(
            json.dumps(
                {
                    "case": case,
                    "passed": bool(passed),
                    "status": task["status"],
                    "routing": selected,
                    "children": len(children),
                    "problem": task.get("problem", {}).get("code"),
                }
            ),
            flush=True,
        )
        return result


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", nargs="+", choices=CASES, default=CASES)
    parser.add_argument(
        "--credentials",
        type=Path,
        default=Path.home() / ".config/lasa/two-layer/credentials.local.json",
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--image", default="lasa-codex-worker:1.0.0")
    args = parser.parse_args()
    key = json.loads(await asyncio.to_thread(args.credentials.read_text))["LASA_MODEL_API_KEY"]
    output = args.output or EVALUATION_ROOT / ".evaluation-runs" / uuid4().hex
    output = output.resolve()
    output.mkdir(parents=True, mode=0o700)
    process = await asyncio.create_subprocess_exec(
        "docker",
        "image",
        "inspect",
        "--format",
        "{{.Id}}",
        args.image,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await process.communicate()
    if process.returncode:
        raise ValueError("Build the configured immutable Codex image before evaluation")
    runtime_image = stdout.decode().strip()
    results = []
    for case in args.cases:
        directory = output / case
        directory.mkdir(mode=0o700, exist_ok=True)
        try:
            results.append(await run_case(directory, case, key, runtime_image))
        except Exception as exc:
            results.append(
                {
                    "case": case,
                    "passed": False,
                    "error_type": type(exc).__name__,
                    "error_code": getattr(exc, "code", None),
                }
            )
            print(json.dumps(results[-1]), flush=True)
    summary = {
        "passed": all(x["passed"] for x in results),
        "cases": [
            {k: v for k, v in x.items() if k in {"case", "passed", "error_type"}} for x in results
        ],
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print("Evidence: " + str(output), flush=True)
    raise SystemExit(0 if summary["passed"] else 1)


if __name__ == "__main__":
    asyncio.run(main())
