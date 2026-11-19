"""Suspend/restore only the owned filesystem MCP entry point for live verification."""

import argparse
import asyncio
import json
import sqlite3
import ssl
import subprocess
import textwrap
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / ".deploy/target"
REMOTE = "/home/yang/Dev/CodeX/LASA/v0/.deploy/target"


def change(mode):
    script = textwrap.dedent("""\
        import hashlib,json,os,signal,sqlite3,subprocess
        from pathlib import Path
        import psutil
        root=Path(REMOTE)
        entry=root/'connectors/filesystem/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js'
        offline=entry.with_suffix('.js.lasa-verification-offline')
        if MODE=='down':
            with sqlite3.connect('file:'+str(root/'layer2/private/tasks.sqlite3')+'?mode=ro',uri=True) as db:
                assert all(state in {'completed','failed','rejected','cancelled','indeterminate'} for state, in db.execute('select state from tasks')), 'Active layer-2 work'
            main=int(subprocess.check_output(['systemctl','--user','show','lasa-layer2.service','--property=MainPID','--value']))
            matches=[]
            for process in psutil.process_iter(['pid','cmdline']):
                if (process.info['cmdline'] or [])[:2] == [str(root/'connectors/node-v24.22.3-linux-x64/bin/node'),str(entry)]:
                    if process.uids().real==os.getuid() and main in [p.pid for p in process.parents()]:
                        matches.append(process.pid)
            assert len(matches)==1 and entry.is_file() and not offline.exists(), 'Expected exactly one owned MCP child'
            sha=hashlib.sha256(entry.read_bytes()).hexdigest()
            entry.rename(offline)
            os.kill(matches[0],signal.SIGTERM)
            print(json.dumps({'mode':MODE,'owned_pid':matches[0],'entry_sha256':sha,'service_pid':main}))
        else:
            assert offline.is_file() and not entry.exists(), 'Expected the owned suspended entry'
            sha=hashlib.sha256(offline.read_bytes()).hexdigest()
            offline.rename(entry)
            print(json.dumps({'mode':MODE,'entry_sha256':sha,'restored':True}))
    """)
    script = "REMOTE=" + repr(REMOTE) + "\nMODE=" + repr(mode) + "\n" + script
    result = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "yang@192.168.0.188", REMOTE + "/venv/bin/python -I -"],
        input=script,
        capture_output=True,
        text=True,
        timeout=20,
        check=True,
    )
    return json.loads(result.stdout)


async def observe():
    context = ssl.create_default_context(
        cafile=str(Path.home() / ".config/lasa/two-layer/tls/ca.pem")
    )
    result = {}
    async with httpx.AsyncClient(verify=context, trust_env=False, timeout=5) as client:
        for layer in ["layer1", "layer2"]:
            config = json.loads((TARGET / layer / "config.json").read_text())
            base = config["service"]["base_url"]
            headers = {
                "Authorization": "Bearer "
                + (TARGET / layer / "operator-token.txt").read_text().strip()
            }
            ready = await client.get(
                base.rsplit("/lasa/v1", 1)[0] + "/health/ready", headers=headers
            )
            ready.raise_for_status()
            response = await client.get(base + "/capabilities", headers=headers)
            response.raise_for_status()
            catalog = response.json()
            assert catalog["next_cursor"] is None
            states = {}
            for offer in catalog["offers"]:
                response = await client.get(
                    base + "/capabilities/" + offer["offer_id"] + "/availability", headers=headers
                )
                response.raise_for_status()
                states[offer["contract"]["id"].rsplit("/", 1)[1]] = response.json()["state"]
            result[layer] = {"ready": ready.json(), "catalog": catalog, "states": states}
    return result


async def main(args):
    path = ROOT / ("verification/connectors-20261119/outage-" + args.mode + ".json")
    assert not path.exists(), "Preserve earlier outage observations"
    if args.mode == "down":
        with sqlite3.connect(
            "file:" + str(TARGET / "layer1/private/tasks.sqlite3") + "?mode=ro", uri=True
        ) as db:
            assert all(
                state in {"completed", "failed", "rejected", "cancelled", "indeterminate"}
                for (state,) in db.execute("select state from tasks")
            ), "Active layer-1 work"
    before = await observe()
    action = change(args.mode)
    try:
        async with asyncio.timeout(100):
            while True:
                after = await observe()
                states = after["layer2"]["states"]
                expected = "unavailable" if args.mode == "down" else "available"
                if states["documents.read"] == expected:
                    assert all(
                        state == "available"
                        for name, state in states.items()
                        if name != "documents.read"
                    )
                    assert len(after["layer2"]["catalog"]["offers"]) == 5
                    break
                await asyncio.sleep(1)
    except BaseException:
        if args.mode == "down":
            change("up")
        raise
    report = {"action": action, "observed_at": time.time(), "before": before, "after": after}
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "mode": args.mode,
                "layer2_states": states,
                "both_core_services_ready": True,
                "evidence": str(path),
            }
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["down", "up"])
    asyncio.run(main(parser.parse_args()))
