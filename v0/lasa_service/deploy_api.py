"""The supervisor image's offline provisioning and deployment interface."""

import json
import os
import sys
from pathlib import Path

from .config import Configuration, require
from .contracts import digest, parse_json, protocol_contracts
from .errors import LasaError
from .inspection import InspectionBindings
from .provisioning import (
    check_deployment,
    configuration_error,
    initial_manifest,
    initial_policy,
    issue_static_token,
    write_scaffold,
)
from .store import STORAGE_SCHEMA_VERSION

VERSION = 1


def layout(config):
    storage = config.document["storage"]
    runtime = config.document["runtime"]
    return {
        "wire_schema_digest": digest(protocol_contracts().bundle),
        "store_schema": STORAGE_SCHEMA_VERSION,
        "service_id": config.service_id,
        "base_url": config.document["service"]["base_url"],
        "state_root": str(config.state_root),
        "listen_host": storage["listen_host"],
        "listen_port": storage["listen_port"],
        "tls": bool(storage.get("tls")),
        "launcher_instance": runtime["launcher_instance"],
        "launcher_socket": runtime["launcher_socket"],
        "authentication": config.document["authentication"],
        "policy_file": config.document["authorization"]["policy_file"],
        "inspection_profiles": inspection_profiles(config.inspection),
    }


def inspection_profiles(inspection):
    return [
        {key: profile[key] for key in ("id", "url", "gateway_id", "policy_revision")}
        for profile in inspection.active_profiles()
    ]


def scaffold(request):
    output = Path(request["output"])
    manifest = initial_manifest(**request["manifest"])
    manifest["runtime"].update(request["runtime"])
    manifest["storage"].update(request["storage"])
    if provider_ca := request.get("provider_ca"):
        manifest["executors"][0]["provider_ca_file"] = provider_ca
    callers = request.get("additional_callers", [])
    if caller := request.get("caller"):
        callers = [caller, *callers]
    policy = initial_policy(callers, request.get("operator"), "task.attempt")
    separate_policy = request.get("policy_file")
    if separate_policy:
        manifest["authorization"] = {"policy_file": separate_policy}
    protocol_contracts().validate("Config", manifest)
    write_scaffold(output, manifest, None if separate_policy else policy)
    if separate_policy:
        with Path(separate_policy).open("x") as file:
            json.dump(policy, file)
            file.write("\n")
    if tokens := request.get("tokens"):
        config = Configuration.load(output / "config.json", environ={})
        for subject, file in tokens.items():
            issue_static_token(config, output, subject, Path(file), 720)
    return {"caller_count": len(callers)}


def policy_update(request):
    current = request["policy"]
    callers = [request["caller"]] if request.get("caller") else []
    added = initial_policy(callers, request.get("operator"), "task.attempt")
    present = {principal["subject"] for principal in current["principals"]}
    current["principals"] += [
        principal for principal in added["principals"] if principal["subject"] not in present
    ]
    current["revision"] = digest(current["principals"])
    return {"policy": protocol_contracts().validate("AuthorizationPolicy", current)}


def inspect_config(request):
    manifest = protocol_contracts().validate(
        "Config", parse_json(Path(request["config"]).read_bytes())
    )
    return {"inspection_profiles": inspection_profiles(InspectionBindings.from_manifest(manifest))}


def dispatch(operation, request):
    if operation == "scaffold":
        return scaffold(request)
    if operation == "policy":
        return policy_update(request)
    if operation == "inspection":
        return inspect_config(request)
    require(operation in {"layout", "preflight"}, "Unknown supervisor deployment operation")
    config = Configuration.load(request["config"], environ={})
    result = layout(config)
    if operation == "preflight":
        result["state"] = check_deployment(
            config,
            offline=True,
            issuer_bootstrap=request.get("issuer_bootstrap", False),
            readonly_state=True,
        )
    return result


def main():
    os.umask(0o077)
    try:
        request = parse_json(sys.stdin.buffer.read())
        require(
            isinstance(request, dict) and request.get("version") == VERSION,
            "Unsupported deployment interface",
        )
        result = dispatch(sys.argv[1], request)
        print(json.dumps({"version": VERSION, **result}))
    except (OSError, ValueError, TypeError, LookupError, LasaError) as exc:
        print(f"Supervisor deployment check: {configuration_error(exc)}.", file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
