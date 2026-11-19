#!/usr/bin/env python3
"""Create a LASA session, submit typed work, and show authorized routing evidence."""

import argparse
import json
import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import httpx


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "objective", nargs="?", default="Explain how this service handles bounded work."
    )
    parser.add_argument(
        "--base-url",
        required=True,
        help="Configured HTTPS LASA protocol base URL, including its prefix",
    )
    parser.add_argument(
        "--token-env",
        default="LASA_ACCESS_TOKEN",
        help="Environment variable containing a receiver-audience JWT",
    )
    parser.add_argument("--capability", default="task.attempt")
    parser.add_argument("--offer-id")
    parser.add_argument("--authorization-ref", default="default")
    parser.add_argument(
        "--input-json",
        type=Path,
        help="Capability-specific input JSON; default builds task.attempt input",
    )
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--diagnostics", choices=["metadata", "content"], default="metadata")
    parser.add_argument("--timeout", type=int, default=240)
    args = parser.parse_args()
    from ssl import create_default_context

    from lasa_service.config import within_url
    from lasa_service.contracts import parse_json

    base = args.base_url.rstrip("/")
    if not base.startswith("https://"):
        parser.error("--base-url must use HTTPS")
    access = os.environ.get(args.token_env)
    if not access:
        parser.error("The access-token environment variable is empty")
    verify = create_default_context(cafile=str(args.ca_file)) if args.ca_file else True
    with httpx.Client(
        verify=verify,
        trust_env=False,
        follow_redirects=False,
        timeout=20,
        headers={"Authorization": "Bearer " + access},
    ) as client:

        def get(url, **kwargs):
            if not within_url(url, base):
                raise ValueError("Discovery link escaped configured base URL")
            response = client.get(url, **kwargs)
            response.raise_for_status()
            return response.json()

        descriptor = get(base + "/descriptor")
        catalog_url = descriptor["catalog_url"]
        offers = []
        cursor = None
        for _ in range(100):
            page = get(catalog_url, params={"cursor": cursor} if cursor else {})
            offers.extend(page["offers"])
            cursor = page["next_cursor"]
            if cursor is None:
                break
        else:
            raise ValueError("Catalog paging limit exceeded")
        matches = [
            x
            for x in offers
            if (
                x["contract"]["id"] == args.capability
                or x["contract"]["id"].endswith("/" + args.capability)
            )
            and (not args.offer_id or x["offer_id"] == args.offer_id)
        ]
        if len(matches) != 1:
            parser.error(
                "Select exactly one visible capability offer using --capability and, when needed, --offer-id"
            )
        offer = matches[0]

        def post(url, body):
            response = client.post(
                url, json=body, headers={"Idempotency-Key": body["operation_id"]}
            )
            response.raise_for_status()
            return response

        session = post(
            base + "/sessions", {"operation_id": "session-" + uuid4().hex, "label": "CLI task"}
        ).json()
        inputs = (
            parse_json(args.input_json.read_bytes())
            if args.input_json
            else {
                "objective": args.objective,
                "requirements": [
                    {
                        "id": "requirement-objective",
                        "description": args.objective,
                        "acceptance": [
                            "Fulfill the stated objective with supporting evidence; report inability honestly."
                        ],
                    }
                ],
            }
        )
        seconds = min(args.timeout, offer["max_budget"]["wall_time_ms"] / 1000)
        body = {
            "operation_id": "task-" + uuid4().hex,
            "selection": {
                "contract": offer["contract"],
                "offer_id": offer["offer_id"],
                "offer_revision": offer["revision"],
                "catalog_view": offer["catalog_view"],
            },
            "input": inputs,
            "requested_limits": {
                "budget": offer["max_budget"],
                "deadline": (datetime.now(UTC) + timedelta(seconds=seconds)).isoformat(),
                "max_hops": offer["max_hops"],
            },
            "authorization_ref": args.authorization_ref,
            "diagnostics": args.diagnostics,
        }
        response = post(base + "/sessions/" + session["session_id"] + "/tasks", body)
        task_url = response.headers["Location"]
        print("Session: " + session["session_id"])
        print("Task: " + response.json()["task_id"])
        until = time.monotonic() + seconds + 10
        while time.monotonic() < until:
            task = get(task_url)
            if task["status"] in {"completed", "failed", "rejected", "cancelled", "indeterminate"}:
                break
            if task["status"] == "awaiting_input":
                print(json.dumps(task, indent=2))
                return 2
            time.sleep(0.2)
        else:
            raise TimeoutError(
                "Polling deadline exceeded; reconcile this operation before retrying work"
            )
        print(json.dumps(task, indent=2))
        after = 0
        while True:
            page = get(task_url + "/events", params={"after_sequence": after, "limit": 100})
            for event in page["events"]:
                if event["kind"] in {"routing", "call", "verification", "resolution"}:
                    print(json.dumps(event))
            if len(page["events"]) < 100:
                break
            after = page["next_sequence"] - 1
        print(json.dumps(get(task_url + "/delegations"), indent=2))
        return (
            0
            if task["status"] == "completed"
            and task["result"]["output"].get("disposition") != "unable"
            else 1
        )


if __name__ == "__main__":
    raise SystemExit(main())
