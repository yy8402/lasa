"""Restart idle managed backends and check immutable completed work over HTTPS."""

import asyncio
import hashlib
import json
import os
import sqlite3
import ssl
import subprocess
from pathlib import Path

import httpx

from lasa_service.contracts import canonical

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / ".deploy/target"
EVIDENCE = ROOT / "verification/connectors-20261119"
TERMINAL = {"completed", "failed", "rejected", "cancelled", "indeterminate"}


async def main():
    output = EVIDENCE / "restart-persistence.json"
    assert not output.exists(), "Preserve prior observations"
    with sqlite3.connect(
        "file:" + str(TARGET / "layer1/private/tasks.sqlite3") + "?mode=ro", uri=True
    ) as db:
        assert all(state in TERMINAL for (state,) in db.execute("select state from tasks"))
    remote = (
        "python3 - <<'PY'\nimport sqlite3\nfrom pathlib import Path\np=Path.home()/'Dev/CodeX/LASA/v0/.deploy/target/layer2/private/tasks.sqlite3'\nwith sqlite3.connect('file:'+str(p)+'?mode=ro',uri=True) as db:\n assert all(s in "
        + repr(TERMINAL)
        + " for s, in db.execute('select state from tasks'))\nPY"
    )
    await asyncio.to_thread(
        subprocess.run,
        ["ssh", "-o", "BatchMode=yes", "yang@192.168.0.188", remote],
        check=True,
        timeout=15,
    )
    receipt = json.loads((EVIDENCE / "documents-read-verified-receipt.json").read_text())
    task_url = receipt["task_url"]
    context = ssl.create_default_context(
        cafile=str(Path.home() / ".config/lasa/two-layer/tls/ca.pem")
    )
    async with httpx.AsyncClient(verify=context, trust_env=False, timeout=8) as client:

        def headers(layer="layer1"):
            return {
                "Authorization": "Bearer "
                + (TARGET / layer / "operator-token.txt").read_text().strip()
            }

        async def witness():
            result = {}
            for name, url in [
                ("task", task_url),
                (
                    "session",
                    task_url.rsplit("/tasks/", 1)[0] + "/sessions/" + receipt["session_id"],
                ),
                ("children", task_url + "/delegations"),
            ]:
                response = await client.get(url, headers=headers())
                response.raise_for_status()
                result[name] = hashlib.sha256(canonical(response.json())).hexdigest()
                if name == "task":
                    task = response.json()
            result["artifacts"] = {}
            for manifest in task["result"]["artifacts"]:
                response = await client.get(
                    task_url + "/artifacts/" + manifest["artifact_id"], headers=headers()
                )
                response.raise_for_status()
                sha = "sha256:" + hashlib.sha256(response.content).hexdigest()
                assert sha == manifest["digest"]
                result["artifacts"][manifest["artifact_id"]] = sha
            return result

        before = await witness()
        await asyncio.to_thread(
            subprocess.run,
            [
                "ssh",
                "-o",
                "BatchMode=yes",
                "yang@192.168.0.188",
                "systemctl --user restart lasa-layer2.service",
            ],
            check=True,
            timeout=25,
        )
        await asyncio.to_thread(
            subprocess.run,
            ["launchctl", "kickstart", "-k", "gui/" + str(os.getuid()) + "/com.lasa.layer1"],
            check=True,
            timeout=15,
        )
        async with asyncio.timeout(40):
            while True:
                try:
                    responses = [
                        await client.get(base + "/health/ready", headers=headers(layer))
                        for layer, base in [
                            ("layer1", "https://localhost:8443"),
                            ("layer2", "https://192.168.0.188"),
                        ]
                    ]
                    if all(response.status_code == 200 for response in responses):
                        break
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(1)
        after = await witness()
        assert after == before
        output.write_text(
            json.dumps(
                {
                    "passed": True,
                    "witness": receipt,
                    "before": before,
                    "after": after,
                    "both_https_ready": True,
                },
                indent=2,
            )
            + "\n"
        )
        print(
            json.dumps(
                {
                    "passed": True,
                    "preserved": [
                        "completed task",
                        "session",
                        "parent-mediated child traces",
                        "source artifact bytes",
                    ],
                    "evidence": str(output),
                }
            )
        )


if __name__ == "__main__":
    asyncio.run(main())
