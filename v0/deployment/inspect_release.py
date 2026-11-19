"""Read-only installed-package, managed-runtime and HTTPS acceptance inventory."""

import asyncio
import hashlib
import json
import os
import ssl
import subprocess
import sys
import textwrap
import zipfile
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / ".deploy/target"
REMOTE = "/home/yang/Dev/CodeX/LASA/v0/.deploy/target"
EVIDENCE = ROOT / "verification/connectors-20261119"


def run(args, **kwargs):
    return subprocess.run(
        args, capture_output=True, text=True, check=True, timeout=25, **kwargs
    ).stdout


def installed(python, target, files, ssh=False):
    script = (
        "TARGET="
        + repr(str(target))
        + "\nFILES="
        + repr(files)
        + "\n"
        + textwrap.dedent("""\
        import hashlib,json,os,sqlite3,subprocess,sys,sysconfig
        from pathlib import Path
        import lasa_service
        site=Path(sysconfig.get_path('purelib'));target=Path(TARGET)
        actual={name:hashlib.sha256((site/name).read_bytes()).hexdigest() for name in FILES}
        assert actual==FILES,'Installed file mismatch'
        layer='layer2' if os.uname().sysname=='Linux' else 'layer1'
        folder=target/layer
        config=json.loads((folder/'config.json').read_text())
        assert json.loads((folder/'steady-config.json').read_text())==config
        with sqlite3.connect('file:'+str(folder/'private/tasks.sqlite3')+'?mode=ro',uri=True) as db:
            states=dict(db.execute('select state,count(*) from tasks group by state'))
        assert all(state in {'completed','failed','rejected','cancelled','indeterminate'} for state in states)
        hashes={name:hashlib.sha256((folder/name).read_bytes()).hexdigest() for name in ['config.json','authorization.json','contracts.json','connectors.json','runtime.json']}
        tokens={p.name:oct(p.stat().st_mode&0o777) for p in folder.glob('*-token.txt')}
        runtime=json.loads((folder/'runtime.json').read_text())
        containers=subprocess.check_output(['docker','ps','-aq','--filter','label=com.lasa.service_id='+config['service']['id']],text=True).split()
        assert not containers,'Owned task containers remain'
        result={'package_version':lasa_service.__version__,'module_path':lasa_service.__file__,'installed_files':actual,'configuration_hashes':hashes,'deployment_revision':config['service']['deployment_revision'],'routing':config['routing'],'has_peer':'peer' in config,'task_states':states,'token_file_modes':tokens,'owned_task_containers':containers,'runtime_image':runtime['image']}
        if layer=='layer2':
            entry=target/'connectors/filesystem/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js'
            assert entry.is_file() and not entry.with_suffix('.js.lasa-verification-offline').exists()
            result['filesystem_entry_sha256']=hashlib.sha256(entry.read_bytes()).hexdigest()
            result['filesystem_version']=json.loads((entry.parent.parent/'package.json').read_text())['version']
            result['node_version']=subprocess.check_output([str(target/'connectors/node-v24.22.3-linux-x64/bin/node'),'--version'],text=True).strip()
            result['service_active']=subprocess.check_output(['systemctl','--user','is-active','lasa-layer2.service'],text=True).strip()
            result['linger']=subprocess.check_output(['loginctl','show-user',str(os.getuid()),'--property=Linger','--value'],text=True).strip()
            pid=int(subprocess.check_output(['systemctl','--user','show','lasa-layer2.service','--property=MainPID','--value']))
            result['process_arguments']=Path('/proc/'+str(pid)+'/cmdline').read_bytes().decode().split(chr(0))[:-1]
        print(json.dumps(result))
    """)
    )
    command = (
        [python, "-I", "-"]
        if not ssh
        else ["ssh", "-o", "BatchMode=yes", "yang@192.168.0.188", python + " -I -"]
    )
    return json.loads(run(command, input=script))


async def main():
    output = EVIDENCE / sys.argv[1]
    assert not output.exists(), "Preserve previous inventories"
    wheel = ROOT / "verification/dist/lasa_service_v0-1.1.0-py3-none-any.whl"
    files = {}
    with zipfile.ZipFile(wheel) as archive:
        for name in archive.namelist():
            if name.endswith("/") or not name.startswith(("lasa_service/", "lasa_contracts/")):
                continue
            source = ROOT / name.replace("lasa_contracts/", "design/", 1)
            data = archive.read(name)
            assert source.read_bytes() == data, "Checkout differs from release: " + name
            files[name] = hashlib.sha256(data).hexdigest()
    report = {
        "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "layer1": installed(str(TARGET / "venv/bin/python"), TARGET, files),
        "layer2": installed(REMOTE + "/venv/bin/python", REMOTE, files, True),
    }
    domain = "gui/" + str(os.getuid())
    for label in ["com.lasa.layer1", "com.lasa.layer1-https", "com.lasa.tokens"]:
        status = run(["launchctl", "print", domain + "/" + label])
        assert "state = running" in status or label == "com.lasa.tokens"
    pid = run(["launchctl", "list", "com.lasa.layer1"])
    import re

    service_pid = re.search(r'"PID" = (\d+);', pid).group(1)
    report["layer1"]["process_arguments"] = run(["ps", "-p", service_pid, "-o", "command="]).strip()
    assert " -I -m lasa_service.cli " in report["layer1"]["process_arguments"]
    assert "-I" in report["layer2"]["process_arguments"]
    context = ssl.create_default_context(
        cafile=str(Path.home() / ".config/lasa/two-layer/tls/ca.pem")
    )
    async with httpx.AsyncClient(verify=context, trust_env=False, timeout=10) as client:
        for layer in ["layer1", "layer2"]:
            cfg = json.loads((TARGET / layer / "config.json").read_text())
            base = cfg["service"]["base_url"]
            headers = {
                "Authorization": "Bearer "
                + (TARGET / layer / "operator-token.txt").read_text().strip()
            }
            anonymous = await client.get(base + "/descriptor")
            assert anonymous.status_code == 401
            ready = await client.get(
                base.rsplit("/lasa/v1", 1)[0] + "/health/ready", headers=headers
            )
            ready.raise_for_status()
            catalog = await client.get(base + "/capabilities", headers=headers)
            catalog.raise_for_status()
            states = {}
            for offer in catalog.json()["offers"]:
                response = await client.get(
                    base + "/capabilities/" + offer["offer_id"] + "/availability", headers=headers
                )
                response.raise_for_status()
                states[offer["contract"]["id"].rsplit("/", 1)[1]] = response.json()["state"]
            assert len(states) == 5
            if layer == "layer2":
                assert set(states.values()) == {"available"}
            report[layer]["https"] = {
                "ready": ready.json(),
                "anonymous_status": anonymous.status_code,
                "states": states,
                "catalog": catalog.json(),
            }
    secrets = []
    for file in [
        Path.home() / ".config/lasa/two-layer/credentials.local.json",
        Path.home() / ".config/lasa/two-layer/credentials.air188.json",
    ]:
        secrets.extend(json.loads(file.read_text()).values())
    secrets.extend(
        p.read_text().strip()
        for layer in ["layer1", "layer2"]
        for p in (TARGET / layer).glob("*-token.txt")
    )
    for file in EVIDENCE.glob("*.json"):
        text = file.read_text()
        assert not any(value and value in text for value in secrets), "Credential in evidence"
    report["privacy_scan"] = "No saved model/service token values in JSON evidence"
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "evidence": str(output),
                "matched_files_per_host": len(files),
                "both_ready": True,
                "all_layer2_outcomes_available": True,
                "owned_task_containers": 0,
            }
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
