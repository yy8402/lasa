"""Exercise managed LASA services through verified HTTPS and save safe evidence.

This client never starts a service, model mock, or temporary execution runtime.
Private token files remain outside its evidence documents.
"""

import argparse
import asyncio
import copy
import json
import ssl
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import httpx

from lasa_service.config import Configuration
from lasa_service.contracts import Contracts
from lasa_service.peer import PeerClient

TARGET = Path(__file__).resolve().parents[1] / ".deploy/target"


async def run(args):
    path = args.output / (args.case + ".json")
    receipt_path = args.output / (args.case + "-receipt.json")
    if path.exists() or receipt_path.exists():
        raise FileExistsError("Choose a new case name to preserve prior observations")
    target = TARGET
    source = json.loads((target / "layer1/config.json").read_text())
    # Reuse the pinned client trust settings without configuring a service self-peer.
    source["service"]["id"] += "/verification-client"
    source["authentication"]["audience"] = source["service"]["id"]
    layer = "layer" + str(args.layer)
    receiver = json.loads((target / layer / "steady-config.json").read_text())
    token_file = (
        target / layer / ("metadata-token.txt" if args.deny_content else "operator-token.txt")
    )
    source["peer"].update(
        descriptor_url=receiver["service"]["descriptor_url"],
        expected_service_id=receiver["service"]["id"],
        allowed_base_url=receiver["service"]["base_url"],
        credential_ref="file:" + str(token_file),
    )
    cfg = Configuration.from_document(
        source, environ={"LASA_MODEL_API_KEY": "client-does-not-query-provider"}
    )
    peer = PeerClient(cfg)
    await peer.start()
    contracts = Contracts()
    try:
        catalog = await peer.discover(refresh=True)
        offer = next(
            x for x in catalog["offers"] if x["contract"]["id"].endswith("/" + args.capability)
        )
        definition = await peer.definition(offer)
        if args.input_file:
            inputs = json.loads(args.input_file.read_text())
        elif args.tool_task:
            inputs = {
                "objective": "Use the approved workspace tools to create deployment-check.txt containing exactly LASA parent retains final responsibility. Then read it back and report its exact text with evidence.",
                "requirements": [
                    {
                        "id": "verified-file",
                        "description": "Create the specified workspace file and read it back through approved tools.",
                        "acceptance": [
                            "The file is created and its exact text is reported from a subsequent read."
                        ],
                    }
                ],
            }
        else:
            inputs = {
                "design": "The parent accepts a caller objective, sends bounded child work over authenticated HTTPS, checks returned evidence against the original criteria, and retains responsibility for final completion. The child works in its own workspace.",
                "criteria": [
                    {
                        "id": "criterion-accountability",
                        "description": "Determine whether the parent retains responsibility for final completion and support the answer from the supplied design.",
                    }
                ],
            }
        contracts.validate("CapabilityDefinition", definition)
        context = ssl.create_default_context(cafile=source["peer"]["ca_file"])
        async with httpx.AsyncClient(
            verify=context,
            trust_env=False,
            follow_redirects=False,
            timeout=20,
            headers={"Authorization": "Bearer " + token_file.read_text().strip()},
        ) as client:
            base = receiver["service"]["base_url"]

            async def post(url, body):
                response = await client.post(
                    url, json=body, headers={"Idempotency-Key": body["operation_id"]}
                )
                if not args.deny_content:
                    response.raise_for_status()
                return response

            session_response = await post(
                base + "/sessions", {"operation_id": "deployment-session-" + uuid4().hex}
            )
            session_response.raise_for_status()
            session = session_response.json()
            contracts.validate("Session", session)
            body = {
                "operation_id": "deployment-task-" + uuid4().hex,
                "selection": {
                    "contract": offer["contract"],
                    "offer_id": offer["offer_id"],
                    "catalog_view": offer["catalog_view"],
                    "offer_revision": offer["revision"],
                },
                "input": inputs,
                "requested_limits": {
                    "budget": copy.deepcopy(offer["max_budget"]),
                    "deadline": (
                        datetime.now(UTC)
                        + timedelta(seconds=min(240, offer["max_budget"]["wall_time_ms"] / 1000))
                    ).isoformat(),
                    "max_hops": offer["max_hops"],
                },
                "authorization_ref": offer["authorization_ref"],
                "diagnostics": "content" if args.content or args.deny_content else "metadata",
            }
            started = time.monotonic()
            receipt = await post(base + "/sessions/" + session["session_id"] + "/tasks", body)
            if args.deny_content:
                assert receipt.status_code == 403 and receipt.json()["code"] == "disclosure_denied"
                report = {
                    "case": args.case,
                    "passed": True,
                    "http_status": 403,
                    "problem": receipt.json(),
                    "session": session,
                }
            else:
                assert receipt.status_code == 202
                url = receipt.headers["location"]
                args.output.mkdir(parents=True, exist_ok=True)
                with receipt_path.open("x") as evidence:
                    evidence.write(
                        json.dumps(
                            {
                                "task_url": url,
                                "operation_id": body["operation_id"],
                                "session_id": session["session_id"],
                            },
                            indent=2,
                        )
                        + "\n"
                    )
                async with asyncio.timeout(285):
                    while True:
                        response = await client.get(url)
                        response.raise_for_status()
                        task = response.json()
                        contracts.validate("Task", task)
                        if task["status"] in {
                            "completed",
                            "failed",
                            "rejected",
                            "cancelled",
                            "indeterminate",
                        }:
                            break
                        await asyncio.sleep(0.3)
                events = []
                after = 0
                for _ in range(50):
                    response = await client.get(
                        url + "/events", params={"after_sequence": after, "limit": 100}
                    )
                    response.raise_for_status()
                    page = response.json()
                    contracts.validate("EventPage", page)
                    events.extend(page["events"])
                    if len(page["events"]) < 100:
                        break
                    after = page["next_sequence"] - 1
                child_response = await client.get(url + "/delegations")
                child_response.raise_for_status()
                children = child_response.json()["children"]
                routes = [e["payload"] for e in events if e["kind"] == "routing"]
                selected = [r["selected_executor"] for r in routes]
                passed = task["status"] == args.expect_status and selected == [args.expect_route]
                if args.expect_route == "peer":
                    passed = (
                        passed
                        and bool(children)
                        and all(
                            "trace" in child
                            and any(
                                e["kind"] == "call" and e["payload"]["call_type"] == "model"
                                for e in child["trace"]["events"]
                            )
                            for child in children
                        )
                    )
                if args.tool_task:
                    passed = passed and any(
                        e["kind"] == "call"
                        and e["payload"]["call_type"] == "tool"
                        and e["payload"]["phase"] == "finished"
                        for e in events
                    )
                if args.content:
                    passed = passed and any("content" in e for e in events)
                else:
                    passed = passed and all("content" not in e for e in events)
                report = {
                    "case": args.case,
                    "passed": bool(passed),
                    "execution": "managed deployed services, real HTTPS, actual Codex App Server and gpt-5.5 inference",
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "descriptor": peer.descriptor,
                    "catalog_revision": catalog["revision"],
                    "session": session,
                    "task": task,
                    "events": events,
                    "children_via_parent": children,
                }
            args.output.mkdir(parents=True, exist_ok=True)
            text = json.dumps(report, indent=2) + "\n"
            secrets = [p.read_text().strip() for p in (target / "layer2").glob("*-token.txt")]
            secrets += [token_file.read_text().strip()]
            assert not any(value and value in text for value in secrets)
            with path.open("x") as evidence:
                evidence.write(text)
            print(
                json.dumps(
                    {
                        "case": args.case,
                        "passed": report["passed"],
                        "status": report.get("task", {}).get("status", report.get("http_status")),
                        "routing": [
                            e["payload"]["selected_executor"]
                            for e in report.get("events", [])
                            if e["kind"] == "routing"
                        ],
                        "children": len(report.get("children_via_parent", [])),
                        "evidence": str(path),
                    }
                ),
                flush=True,
            )
            return 0 if report["passed"] else 1
    finally:
        await peer.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--layer", type=int, choices=[1, 2], default=1)
    parser.add_argument("--case", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--capability", default="design.review")
    parser.add_argument("--expect-route", choices=["local", "peer", "none"], default="local")
    parser.add_argument("--expect-status", default="completed")
    parser.add_argument("--content", action="store_true")
    parser.add_argument("--deny-content", action="store_true")
    parser.add_argument("--tool-task", action="store_true")
    parser.add_argument(
        "--input-file", type=Path, help="JSON input for the selected exact contract"
    )
    raise SystemExit(asyncio.run(run(parser.parse_args())))


if __name__ == "__main__":
    main()
