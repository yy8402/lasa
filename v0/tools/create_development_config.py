#!/usr/bin/env python3
"""Create an isolated administrator-controlled LASA configuration and development JWTs."""

import argparse
import json
import os
import time
from pathlib import Path
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from lasa_service.capabilities import reference
from lasa_service.config import builtin_capabilities, packaged_defaults
from lasa_service.provisioning import initial_manifest, write_scaffold


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--base-url", required=True, help="HTTPS protocol URL served by your TLS proxy"
    )
    parser.add_argument("--service-id", required=True)
    parser.add_argument("--launcher-socket", type=Path, required=True)
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
    parser.add_argument("--execution-key-ref", default="env:LASA_EXECUTION_KEY")
    args = parser.parse_args()
    os.umask(0o077)
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if any(root.iterdir()):
        parser.error("Choose an empty output directory")
    peer = any([args.peer_descriptor, args.peer_service_id, args.peer_credential_ref])
    if peer and not all([args.peer_descriptor, args.peer_service_id, args.peer_credential_ref]):
        parser.error("Configure all three peer arguments together")
    key = ec.generate_private_key(ec.SECP256R1())
    public = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key())) | {
        "kid": "development-key",
        "use": "sig",
        "alg": "ES256",
    }
    issuer = args.service_id.rstrip("/") + "/development-issuer"
    (root / "jwks.json").write_text(json.dumps({"keys": [public]}) + "\n")
    config = initial_manifest(
        service_id=args.service_id,
        base_url=args.base_url,
        authentication={
            "issuer": issuer,
            "jwks_file": "jwks.json",
            "allowed_algorithms": ["ES256"],
        },
        launcher_socket=args.launcher_socket,
        model="gpt-5.5",
        provider_url="https://api.openai.com/v1/",
        credential_ref="env:" + args.model_key_env,
        state_root=root / "state",
    )
    config["storage"]["listen_port"] = args.listen_port
    config["routing"] = {"preferred_executor": "peer"}
    config["peers"] = []
    defaults = packaged_defaults()
    config["limits"] = {
        name: dict(defaults["limits"][name])
        for name in ("max_task_budget", "assessment_budget", "integration_reserve")
    }
    contracts = [
        reference(builtin_capabilities()[name][0]) for name in defaults["published_contracts"]
    ]
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

    issue("consumer", "consumer-token.txt")
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
        "contracts": contracts,
        "resources": [{"resource": "workspace:self", "actions": ["read", "create", "update"]}],
        "effects": ["workspace.read", "workspace.write"],
        "delegation_grants": [],
        "budget": budget,
        "content_diagnostics": False,
    }
    if peer:
        rule["delegation_grants"] = [
            {
                "sender_service_id": config["service"]["id"],
                "receiver_service_id": args.peer_service_id,
                "contract": contract,
                "effects": rule["effects"],
                "resources": rule["resources"],
                "disclosure_resources": [resource["resource"] for resource in rule["resources"]],
            }
            for contract in contracts
        ]
    principals = [
        {"subject": "consumer", "kind": "user", "rules": [rule]},
        {"subject": "operator", "kind": "operator", "rules": []},
    ]
    if args.trusted_parent_id:
        principals.append(
            {
                "subject": args.trusted_parent_subject,
                "kind": "peer",
                "service_id": args.trusted_parent_id,
                "execution_key_ref": args.execution_key_ref,
                "rules": [rule],
            }
        )
        issue(args.trusted_parent_subject, "peer-token.txt")
    authorization = {
        "revision": "policy-1",
        "principals": principals,
    }
    if peer:
        settings = {
            "descriptor_url": args.peer_descriptor,
            "expected_service_id": args.peer_service_id,
            "allowed_base_url": args.peer_descriptor.rsplit("/", 1)[0],
            "credential_ref": args.peer_credential_ref,
            "execution_key_ref": args.execution_key_ref,
            "request_timeout_seconds": 15,
        }
        if args.peer_ca_file:
            settings["ca_file"] = str(Path(args.peer_ca_file).resolve())
        config["peers"] = [settings]
    write_scaffold(root, config, authorization)
    print("Configuration: " + str(root / "config.json"))
    print(
        "Development token files are private and expire after 24 hours; use a configured issuer for normal operation."
    )


if __name__ == "__main__":
    main()
