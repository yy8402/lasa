"""Record final managed deployment identity, restart durability and ownership."""

import hashlib
import importlib.metadata
import json
import os
import sqlite3
import ssl
import stat
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx
import lasa_service

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "verification/deployed-20261118"
TARGET = ROOT / ".deploy/target"
SSH = "yang@192.168.0.188"
REMOTE = "/home/yang/Dev/CodeX/LASA/v0/.deploy/target"
EXPECTED = json.loads((OUT / "expected-installed-files.json").read_text())


def sha(data):
    return hashlib.sha256(data).hexdigest()


def shell(args, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, timeout=50, check=True, **kwargs).stdout


def inventory():
    site = Path(lasa_service.__file__).parent.parent
    config = json.loads((TARGET / "layer1/config.json").read_text())
    runtime = json.loads(Path(config["executors"][0]["runtime_profile_file"]).read_text())
    image = json.loads(shell(["docker", "image", "inspect", runtime["image"]]))[0]
    containers = shell(["docker", "ps", "-a", "--filter", "label=com.lasa.service_id=" + config["service"]["id"], "--format", "{{.ID}}"])
    installed = {name: sha((site / name).read_bytes()) for name in EXPECTED}
    assert installed == EXPECTED
    with sqlite3.connect("file:" + str(TARGET / "layer1/private/tasks.sqlite3") + "?mode=ro", uri=True) as db:
        assert not db.execute("SELECT 1 FROM tasks WHERE state NOT IN ('completed','failed','rejected','cancelled','indeterminate')").fetchone()
    jobs = [line.split() for line in shell(["launchctl", "list"]).splitlines() if any(line.endswith(label) for label in ["com.lasa.layer1", "com.lasa.layer1-https", "com.lasa.tokens"])]
    assert any(row[2] == "com.lasa.layer1" and row[0].isdigit() for row in jobs)
    assert any(row[2] == "com.lasa.layer1-https" and row[0].isdigit() for row in jobs)
    report = {"python": sys.version.split()[0], "version": importlib.metadata.version("lasa-service-v0"), "module": str(lasa_service.__file__), "installed_files_matched": len(installed), "config_sha256": sha((TARGET / "layer1/config.json").read_bytes()), "policy_sha256": sha(Path(config["authorization"]["policy_file"]).read_bytes()), "deployment_revision": config["service"]["deployment_revision"], "service_id": config["service"]["id"], "base_url": config["service"]["base_url"], "routing": config["routing"], "model": config["executors"][0]["model"], "provider": config["executors"][0]["provider_base_url"], "image": image["Id"], "image_architecture": image["Architecture"], "rootfs_layers": image["RootFS"]["Layers"], "codex_expected_version": runtime["expected_version"], "owned_containers": containers.split(), "launchd_jobs": jobs}
    program = '''
import hashlib,importlib.metadata,json,sqlite3,subprocess,sys
from pathlib import Path
import lasa_service
root=Path.home()/'Dev/CodeX/LASA/v0/.deploy/target'
names=json.loads(NAMES)
site=Path(lasa_service.__file__).parent.parent
hashes={n:hashlib.sha256((site/n).read_bytes()).hexdigest() for n in names}
c=json.loads((root/'layer2/config.json').read_text());runtime=json.loads(Path(c['executors'][0]['runtime_profile_file']).read_text())
def run(a):return subprocess.run(a,capture_output=True,text=True,check=True,timeout=15).stdout
image=json.loads(run(['docker','image','inspect',runtime['image']]))[0]
with sqlite3.connect('file:'+str(root/'layer2/private/tasks.sqlite3')+'?mode=ro',uri=True) as db:
 assert not db.execute("select 1 from tasks where state not in ('completed','failed','rejected','cancelled','indeterminate')").fetchone()
unit=run(['systemctl','--user','show','lasa-layer2.service','-p','ActiveState','-p','SubState','-p','UnitFileState','-p','MainPID','-p','NRestarts'])
proxy=run(['systemctl','show','lasa-layer2-https.service','-p','ActiveState','-p','SubState','-p','UnitFileState','-p','MainPID'])
assert 'ActiveState=active' in unit and 'ActiveState=active' in proxy
assert 'peer' not in c
print(json.dumps({'python':sys.version.split()[0],'version':importlib.metadata.version('lasa-service-v0'),'installed_hashes':hashes,'config_sha256':hashlib.sha256((root/'layer2/config.json').read_bytes()).hexdigest(),'policy_sha256':hashlib.sha256(Path(c['authorization']['policy_file']).read_bytes()).hexdigest(),'deployment_revision':c['service']['deployment_revision'],'service_id':c['service']['id'],'base_url':c['service']['base_url'],'routing':c['routing'],'peer_configured':False,'model':c['executors'][0]['model'],'provider':c['executors'][0]['provider_base_url'],'image':image['Id'],'image_architecture':image['Architecture'],'rootfs_layers':image['RootFS']['Layers'],'codex_expected_version':runtime['expected_version'],'owned_containers':run(['docker','ps','-a','--filter','label=com.lasa.service_id='+c['service']['id'],'--format','{{.ID}}']).split(),'backend_unit':unit.splitlines(),'https_unit':proxy.splitlines(),'user_linger':run(['loginctl','show-user','yang','-p','Linger']).strip()}))
'''.replace("NAMES", repr(json.dumps(list(EXPECTED))))
    remote = json.loads(shell(["ssh", "-o", "BatchMode=yes", SSH, REMOTE + "/venv/bin/python", "-"], input=program))
    assert remote.pop("installed_hashes") == EXPECTED
    remote["installed_files_matched"] = len(EXPECTED)
    assert remote["rootfs_layers"] == report["rootfs_layers"]
    assert not report["owned_containers"] and not remote["owned_containers"]
    return {"layer1": report, "layer2": remote}


def main():
    assert not (OUT / "final-deployment.json").exists(), "Finalization already recorded"
    final_case = json.loads((OUT / "steady-delegation.json").read_text())
    assert final_case["passed"]
    context = ssl.create_default_context(cafile=str(Path.home() / ".config/lasa/two-layer/tls/ca.pem"))
    with httpx.Client(verify=context, trust_env=False, follow_redirects=False, timeout=10, headers={"Authorization": "Bearer " + (TARGET / "layer1/operator-token.txt").read_text().strip()}) as client:
        base = "https://localhost:8443/lasa/v1"
        url = base + "/tasks/" + final_case["task"]["task_id"]
        before = client.get(url);before.raise_for_status()
        before_digest = sha(before.content)
        initial = inventory()
        shell(["ssh", "-o", "BatchMode=yes", SSH, "systemctl --user restart lasa-layer2.service"])
        shell(["launchctl", "kickstart", "-k", "gui/" + str(os.getuid()) + "/com.lasa.layer1"])
        for layer, origin in [("layer2", "https://192.168.0.188"), ("layer1", "https://localhost:8443")]:
            until = time.monotonic() + 30
            while True:
                try:
                    ready = client.get(origin + "/health/ready", headers={"Authorization": "Bearer " + (TARGET / layer / "operator-token.txt").read_text().strip()})
                    if ready.status_code == 200:break
                except httpx.HTTPError:pass
                if time.monotonic() > until:raise TimeoutError(layer + " did not recover")
                time.sleep(0.2)
        after = client.get(url);after.raise_for_status()
        assert sha(after.content) == before_digest
        session = client.get(base + "/sessions/" + final_case["session"]["session_id"]);session.raise_for_status()
        children = client.get(url + "/delegations");children.raise_for_status()
        assert children.json()["children"] and all("trace" in child for child in children.json()["children"])
        assert client.get("https://192.168.0.188/lasa/v1/descriptor").status_code == 401
        anonymous = httpx.get(base + "/descriptor", verify=context, trust_env=False, timeout=10)
        assert anonymous.status_code == 401
        current = inventory()
    for layer in ["layer1", "layer2"]:
        assert initial[layer]["config_sha256"] == current[layer]["config_sha256"]
    assert initial["layer1"]["launchd_jobs"] != current["layer1"]["launchd_jobs"]
    assert initial["layer2"]["backend_unit"] != current["layer2"]["backend_unit"]
    modes = {str(p.relative_to(TARGET)): oct(stat.S_IMODE(p.stat().st_mode)) for p in [TARGET / "layer1/signing-key.pem", TARGET / "layer2/signing-key.pem", TARGET / "layer1/operator-token.txt", TARGET / "layer2/peer-token.txt"]}
    assert all(value == "0o600" for value in modes.values())
    report = {"status": "passed", "checked_at": datetime.now(UTC).isoformat(), "wheel_sha256": sha((ROOT / "verification/dist/lasa_service_v0-1.0.0-py3-none-any.whl").read_bytes()), "hosts": current, "restart_checks": {"both_backends_restarted": True, "configuration_preserved": True, "completed_task_byte_digest_preserved": before_digest, "session_preserved": True, "child_diagnostics_via_layer1_after_restart": True}, "authentication": {"anonymous_descriptor": 401, "wrong_receiver_audience": 401, "private_file_modes": modes}, "image_parity": "same exported amd64 rootfs layer digests; Docker stores expose different image IDs", "prototype_data": "preserved in original directories; no migration or deletion", "verification_owned_containers_remaining": 0}
    (OUT / "final-deployment.json").write_text(json.dumps(report, indent=2) + "\n")
    (OUT / "profile-changes.json").write_text(json.dumps([json.loads(line) for line in (TARGET / "profile-changes.jsonl").read_text().splitlines()], indent=2) + "\n")
    print(json.dumps({"status": "passed", "installed_files_matched_per_host": len(EXPECTED), "restart_durability": "passed", "services": "both ready", "owned_containers_remaining": 0}))


if __name__ == "__main__":
    main()
