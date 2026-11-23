"""Run isolated HTTPS layers with actual Codex App Server and actual configured inference.

No deployed service is contacted or reconfigured. Credentials remain private.
"""

import argparse
import asyncio
import copy
import json
import sys
from contextlib import AsyncExitStack
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lasa_service.api import create_app
from lasa_service.config import Configuration
from lasa_service.runtime import CodexRuntime
from tests.conftest import documents, new_session, task_request, token
from tests.http_helpers import certificate, live_http

EVALUATION_ROOT = Path(__file__).resolve().parents[1]

CORPUS = json.loads(Path(__file__).with_name("assessment-corpus.json").read_text())
ROUTE_CASES = ["local_first", "delegate_first", "fallback_disabled", "fallback_enabled", "no_peer"]
CASES = ROUTE_CASES + ["assessment_" + x["id"] for x in CORPUS]


def configure(directory, layer, case, key, runtime_image):
    raw = documents(directory, layer, peer=(layer == "layer1" and case != "no_peer"))
    raw["runtime"]["image"] = runtime_image
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
        "unclaimed_peer_fallback": "attempt"
        if case in {"fallback_enabled", "no_peer"}
        else "reject",
    }
    path = Path(raw["authorization"]["policy_file"])
    policy = json.loads(path.read_text())
    for principal in policy["principals"]:
        for rule in principal["rules"]:
            rule["budget"] = copy.deepcopy(budget)
    path.write_text(json.dumps(policy))
    if case.startswith("fallback"):
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
        "PEER_TOKEN": token("peer-layer1", "https://identity.example.net/services/layer2"),
    }
    return raw, env


async def events(client, url):
    collected = []
    after = 0
    while True:
        response = await client.get(url, params={"after_sequence": after, "limit": 100})
        response.raise_for_status()
        page = response.json()
        collected += page["events"]
        if len(page["events"]) < 100:
            return collected
        after = page["next_sequence"] - 1


async def run_case(directory, case, key, runtime_image):
    tls = certificate(directory)
    child_raw, child_env = configure(directory / "child", "layer2", case, key, runtime_image)
    async with AsyncExitStack() as stack:
        child_cfg = Configuration.from_document(child_raw, environ=child_env)
        child_app = create_app(child_cfg, runtime=CodexRuntime())
        await stack.enter_async_context(child_app.router.lifespan_context(child_app))
        child_origin = await stack.enter_async_context(live_http(child_app, tls=tls))
        prefix = "/prefix/lasa/v1"
        child_cfg.document["service"].update(base_url=child_origin + prefix)
        raw, env = configure(directory / "parent", "layer1", case, key, runtime_image)
        if raw["peers"]:
            raw["peers"][0].update(
                descriptor_url=child_origin + prefix + "/descriptor",
                allowed_base_url=child_origin + prefix,
                ca_file=str(tls[0]),
            )
        cfg = Configuration.from_document(raw, environ=env)
        app = create_app(cfg, runtime=CodexRuntime())
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
        request = await task_request(
            client,
            app,
            profile="design.review",
            inputs={
                "design": "The parent accepts a caller objective, sends bounded child work over authenticated HTTPS, checks returned evidence against the original criteria, and retains responsibility for final completion. The child works in its own workspace.",
                "criteria": [
                    {
                        "id": "criterion-accountability",
                        "description": "Determine whether the parent retains responsibility for final completion and support the answer from the supplied design.",
                    }
                ],
            },
        )
        if corpus:
            request = await task_request(
                client,
                app,
                profile="task.attempt",
                inputs={
                    "objective": corpus["objective"],
                    "context": corpus["context"],
                    "requirements": [
                        {
                            "id": corpus["requirement_id"],
                            "description": corpus["requirement"],
                            "acceptance": [corpus["acceptance"]],
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
        trace = await events(client, task_url + "/events")
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
                child_client, child_origin + prefix + "/tasks/" + child["task_id"] + "/events"
            )
            child_task = (
                await child_client.get(child_origin + prefix + "/tasks/" + child["task_id"])
            ).json()
            child_traces.append(
                {"service_id": child["service_id"], "task": child_task, "events": child_trace}
            )
        selected = [x["payload"]["selected_executor"] for x in trace if x["kind"] == "routing"]
        expected = (
            "local"
            if case in {"local_first", "no_peer"}
            else "none"
            if case == "fallback_disabled"
            else "peer"
        )
        expected_status = "rejected" if case == "fallback_disabled" else "completed"
        passed = (
            task["status"] == expected_status
            and selected
            and selected[0] == expected
            and bool(children) == (expected == "peer")
        )
        routing = [e["payload"] for e in trace if e["kind"] == "routing"]
        expected_peer_state = (
            "not_configured"
            if case == "no_peer"
            else "not_claimed"
            if case.startswith("fallback")
            else "matched"
        )
        if not corpus:
            passed = (
                passed and bool(routing) and routing[0]["peer_assessment"] == expected_peer_state
            )
        if expected == "peer":
            passed = passed and all(
                any(
                    e["kind"] == "call" and e["payload"]["call_type"] == "model"
                    for e in child["events"]
                )
                for child in child_traces
            )
        assessments = []
        for row in app.state.coordinator.store.db.execute(
            "SELECT document FROM audit WHERE task_id=? AND kind='planning_proposal'",
            (task["task_id"],),
        ):
            assessments += [
                {
                    k: v
                    for k, v in step.items()
                    if k
                    in {
                        "step_id",
                        "requirement_ids",
                        "local_assessment",
                        "assessment_summary",
                        "contract_digest",
                    }
                }
                for step in json.loads(row[0])["steps"]
            ]
        if corpus:
            covered = {r for step in assessments for r in step["requirement_ids"]}
            passed = (
                bool(assessments)
                and all(
                    step["local_assessment"] in corpus["expected_local_assessment"]
                    for step in assessments
                )
                and corpus["requirement_id"] in covered
                and task["status"] in corpus["expected_task_status"]
            )
        result = {
            "case": case,
            "runtime_image": runtime_image,
            "passed": bool(passed),
            "expected_status": expected_status,
            "assessment_expectation": corpus,
            "actual_model_assessments": assessments,
            "task": task,
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
