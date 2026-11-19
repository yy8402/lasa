#!/usr/bin/env python3
"""Create an isolated administrator-controlled LASA configuration and development JWTs."""

import argparse
import json
import os
import time
from importlib.resources import files
from pathlib import Path
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--base-url", required=True, help="HTTPS protocol URL served by your TLS proxy"
    )
    parser.add_argument("--service-id", required=True)
    parser.add_argument("--image", required=True, help="Immutable sha256 Docker image ID")
    parser.add_argument("--listen-port", type=int, default=8787)
    parser.add_argument("--model-key-env", default="LASA_MODEL_API_KEY")
    parser.add_argument("--peer-descriptor")
    parser.add_argument("--peer-service-id")
    parser.add_argument(
        "--peer-credential-ref", help="env:NAME or file:/absolute/private/token.txt"
    )
    parser.add_argument("--peer-ca-file")
    parser.add_argument("--trusted-parent-id")
    parser.add_argument("--trusted-parent-subject", default="peer-parent")
    args = parser.parse_args()
    os.umask(0o077)
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if any(root.iterdir()):
        parser.error("Choose an empty output directory")
    peer = any([args.peer_descriptor, args.peer_service_id, args.peer_credential_ref])
    if peer and not all([args.peer_descriptor, args.peer_service_id, args.peer_credential_ref]):
        parser.error("Configure all three peer arguments together")
    examples = files("lasa_contracts").joinpath("examples")
    config = json.loads(examples.joinpath("config.json").read_text())

    def save(name, value):
        path = root / name
        with path.open("x") as out:
            json.dump(value, out, indent=2)
            out.write("\n")
        path.chmod(0o600)
        return str(path)

    contracts = [
        json.loads(examples.joinpath("capability-" + name + ".json").read_text())
        for name in ["review", "attempt"]
    ]
    config["service"].update(
        id=args.service_id,
        base_url=args.base_url.rstrip("/"),
        descriptor_url=args.base_url.rstrip("/") + "/descriptor",
        workspace_root=str(root / "workspaces"),
        deployment_revision="development-" + uuid4().hex,
    )
    config["storage"] = {
        "data_root": str(root / "private"),
        "listen_host": "127.0.0.1",
        "listen_port": args.listen_port,
    }
    key = ec.generate_private_key(ec.SECP256R1())
    public = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key())) | {
        "kid": "development-key",
        "use": "sig",
        "alg": "ES256",
    }
    issuer = args.service_id.rstrip("/") + "/development-issuer"
    config["authentication"] = {
        "issuer": issuer,
        "audience": args.service_id,
        "jwks_file": save("jwks.json", {"keys": [public]}),
        "allowed_algorithms": ["ES256"],
    }
    keypath = root / "signing-key.pem"
    keypath.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    keypath.chmod(0o600)

    def issue(subject, path):
        value = jwt.encode(
            {
                "iss": issuer,
                "sub": subject,
                "aud": args.service_id,
                "iat": int(time.time()),
                "exp": int(time.time()) + 86400,
                "jti": uuid4().hex,
            },
            key,
            algorithm="ES256",
            headers={"kid": "development-key"},
        )
        destination = root / path
        destination.write_text(value + "\n")
        destination.chmod(0o600)

    issue("operator", "operator-token.txt")
    budget = config["limits"]["max_task_budget"]
    budget.update(model_tokens=500000, model_calls=16, wall_time_ms=300000, input_bytes=128000)
    config["limits"]["assessment_budget"].update(
        model_tokens=100000, model_calls=2, wall_time_ms=60000
    )
    config["limits"]["integration_reserve"].update(
        model_tokens=200000 if peer else 50000,
        model_calls=6 if peer else 2,
        wall_time_ms=90000 if peer else 30000,
    )
    rule = {
        "authorization_ref": "default",
        "contracts": config["published_contracts"],
        "resources": [{"resource": "workspace:self", "actions": ["read", "create", "update"]}],
        "effects": ["workspace.read", "workspace.write"],
        "disclosure_services": [args.peer_service_id] if peer else [],
        "delegated_contracts": config["published_contracts"] if peer else [],
        "budget": budget,
        "max_hops": config["limits"]["max_hops"],
        "content_diagnostics": False,
    }
    principals = [{"subject": "operator", "kind": "user", "rules": [rule]}]
    if args.trusted_parent_id:
        principals.append(
            {
                "subject": args.trusted_parent_subject,
                "kind": "peer",
                "service_id": args.trusted_parent_id,
                "rules": [rule],
            }
        )
        issue(args.trusted_parent_subject, "peer-token.txt")
    config["authorization"] = {
        "resolver_id": "receiver-policy",
        "policy_file": save(
            "authorization.json", {"revision": "policy-1", "principals": principals}
        ),
        "trusted_delegator_service_ids": [args.trusted_parent_id] if args.trusted_parent_id else [],
    }
    config["contract_publishers"][0]["trusted_registry_file"] = save("contracts.json", contracts)
    runtime = save(
        "runtime.json",
        {
            "image": args.image,
            "executable": "/usr/local/bin/codex",
            "expected_version": "0.169.0-alpha.11.1",
            "startup_timeout_ms": 10000,
        },
    )
    tools = save("connectors.json", {"connectors": []})
    for executor in config["executors"]:
        executor.update(
            runtime_profile_file=runtime,
            connector_policy_file=tools,
            credential_ref="env:" + args.model_key_env,
        )
    if peer:
        config["peer"] = {
            "descriptor_url": args.peer_descriptor,
            "expected_service_id": args.peer_service_id,
            "allowed_base_url": args.peer_descriptor.rsplit("/", 1)[0],
            "credential_ref": args.peer_credential_ref,
            "authorization_ref": "default",
            "request_timeout_seconds": 15,
        }
        if args.peer_ca_file:
            config["peer"]["ca_file"] = str(Path(args.peer_ca_file).resolve())
    else:
        config.pop("peer", None)
    from lasa_service.contracts import Contracts

    Contracts().validate("Config", config)
    save("config.json", config)
    print("Configuration: " + str(root / "config.json"))
    print(
        "Development token files are private and expire after 24 hours; use a configured issuer for normal operation."
    )


if __name__ == "__main__":
    main()
