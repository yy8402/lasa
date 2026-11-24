"""Start the service or manage its deployment configuration."""

import argparse
import os
import sys
from pathlib import Path

import uvicorn
from jsonschema import ValidationError

from .api import create_app
from .config import Configuration, ConfigurationError
from .errors import LasaError
from .provisioning import (
    check_deployment,
    initial_manifest,
    initial_policy,
    issue_static_token,
    write_scaffold,
)

DEFAULT_CONFIG_PATH = Path("/etc/lasa/config.json")


def add_init_options(parser):
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_CONFIG_PATH.parent,
        help=f"Configuration directory (default: {DEFAULT_CONFIG_PATH.parent})",
    )
    parser.add_argument("--service-id", required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--auth-mode", choices=["jwt", "static_token"], default="jwt")
    parser.add_argument("--issuer")
    jwks = parser.add_mutually_exclusive_group()
    jwks.add_argument("--jwks-url")
    jwks.add_argument("--jwks-file", type=Path)
    parser.add_argument("--jwt-algorithm", action="append", choices=["ES256", "EdDSA", "RS256"])
    parser.add_argument(
        "--launcher-socket",
        type=Path,
        required=True,
        help="Private Unix socket for the worker launcher",
    )
    parser.add_argument("--model", required=True)
    parser.add_argument("--provider-url", required=True)
    parser.add_argument("--credential-ref", default="env:LASA_MODEL_API_KEY")
    parser.add_argument(
        "--operator-subject", help="Grant this user subject read-only design review"
    )
    parser.add_argument(
        "--state-root", type=Path, help="Parent of private and workspace directories"
    )


def initialize(args):
    if args.auth_mode == "jwt":
        if args.issuer is None or (args.jwks_url is None and args.jwks_file is None):
            raise ConfigurationError("JWT initialization requires --issuer and one JWKS source")
        jwks = (
            {"jwks_file": str(args.jwks_file.absolute())}
            if args.jwks_file is not None
            else {"jwks_url": args.jwks_url}
        )
        authentication = {
            "mode": "jwt",
            "issuer": args.issuer,
            "allowed_algorithms": args.jwt_algorithm or ["ES256"],
            **jwks,
        }
    else:
        if any((args.issuer, args.jwks_url, args.jwks_file, args.jwt_algorithm)):
            raise ConfigurationError("JWT issuer and signing-key options require --auth-mode jwt")
        authentication = {"mode": "static_token"}
    manifest = initial_manifest(
        service_id=args.service_id,
        base_url=args.base_url,
        authentication=authentication,
        launcher_socket=args.launcher_socket,
        model=args.model,
        provider_url=args.provider_url,
        credential_ref=args.credential_ref,
        state_root=args.state_root,
    )
    write_scaffold(args.output, manifest, initial_policy(args.operator_subject))
    print(f"Created LASA configuration in {args.output}.")


def configuration_error(exc):
    if isinstance(exc, ConfigurationError):
        return str(exc)
    if isinstance(exc.__cause__, ValidationError):
        error = exc.__cause__
        path = ".".join(map(str, error.absolute_path)) or "document"
        if error.validator == "required":
            missing = ", ".join(key for key in error.validator_value if key not in error.instance)
            return f"Missing required settings in {path}: {missing}"
        return f"Schema validation failed at {path} ({error.validator})"
    if isinstance(exc, LasaError):
        return f"Invalid configuration ({exc.code})"
    if isinstance(exc, OSError) and exc.filename:
        return f"Cannot access {exc.filename}"
    return "Invalid configuration data"


def run_service(config):
    app = create_app(config)
    settings = config.document["storage"]
    tls = settings.get("tls", {})
    uvicorn.run(
        app,
        host=settings["listen_host"],
        port=settings["listen_port"],
        ssl_certfile=tls.get("certificate_file"),
        ssl_keyfile=tls.get("key_file"),
        access_log=False,
        proxy_headers=False,
    )


def add_config_path(parser):
    parser.add_argument(
        "--config",
        type=Path,
        default=argparse.SUPPRESS,
        help=f"Path to the LASA manifest (default: {DEFAULT_CONFIG_PATH})",
    )


def main():
    parser = argparse.ArgumentParser(description="LASA service using Codex App Server")
    add_config_path(parser)
    commands = parser.add_subparsers(dest="command")
    config_command = commands.add_parser("config", help="Scaffold or check service configuration")
    config_commands = config_command.add_subparsers(dest="action", required=True)
    add_init_options(
        config_commands.add_parser("init", help="Create a manifest and receiver policy")
    )
    check = config_commands.add_parser("check", help="Validate a deployment without starting LASA")
    add_config_path(check)
    check.add_argument(
        "--offline", action="store_true", help="Skip remote JWKS and launcher checks"
    )
    issue = config_commands.add_parser("issue-token", help="Issue a standalone caller token")
    add_config_path(issue)
    issue.add_argument("--subject", required=True)
    issue.add_argument("--output", type=Path, required=True, help="New caller-owned token file")
    issue.add_argument("--ttl-hours", type=int, default=720)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.command == "config" and args.action == "init":
            initialize(args)
            return
        config_path = getattr(args, "config", DEFAULT_CONFIG_PATH)
        config = Configuration.load(config_path)
        if args.command == "config" and args.action == "issue-token":
            issue_static_token(
                config, config_path.parent, args.subject, args.output, args.ttl_hours
            )
            print(f"Issued a static token for {args.subject} in {args.output}.")
        elif args.command == "config":
            check_deployment(config, offline=args.offline)
            mode = " (offline)" if args.offline else ""
            print(
                f"Configuration valid{mode}. Deployment revision {config.document['service']['deployment_revision']}."
            )
            print(f"Verifier revision {config.verifier_revision}.")
        else:
            run_service(config)
    except (OSError, ValueError, LasaError) as exc:
        print(f"LASA configuration: {configuration_error(exc)}.", file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
