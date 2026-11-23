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
from .provisioning import check_deployment, initial_manifest, initial_policy, write_scaffold


def add_init_options(parser):
    parser.add_argument("--output", type=Path, required=True, help="Configuration directory")
    parser.add_argument("--service-id", required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--issuer", required=True)
    jwks = parser.add_mutually_exclusive_group(required=True)
    jwks.add_argument("--jwks-url")
    jwks.add_argument("--jwks-file", type=Path)
    parser.add_argument("--jwt-algorithm", action="append", choices=["ES256", "EdDSA", "RS256"])
    parser.add_argument("--image", required=True, help="Local immutable Docker worker image ID")
    parser.add_argument("--model", required=True)
    parser.add_argument("--provider-url", required=True)
    parser.add_argument("--credential-ref", default="env:LASA_MODEL_API_KEY")
    parser.add_argument(
        "--operator-subject", help="Grant this issuer subject read-only design review"
    )
    parser.add_argument(
        "--state-root", type=Path, help="Parent of private and workspace directories"
    )


def initialize(args):
    jwks = (
        {"jwks_file": str(args.jwks_file.absolute())}
        if args.jwks_file is not None
        else {"jwks_url": args.jwks_url}
    )
    manifest = initial_manifest(
        service_id=args.service_id,
        base_url=args.base_url,
        issuer=args.issuer,
        jwks=jwks,
        algorithms=args.jwt_algorithm or ["ES256"],
        image=args.image,
        model=args.model,
        provider_url=args.provider_url,
        credential_ref=args.credential_ref,
    )
    if args.state_root is not None:
        root = args.state_root.absolute()
        manifest["service"]["workspace_root"] = str(root / "workspaces")
        manifest["storage"] = {"data_root": str(root / "private")}
    write_scaffold(args.output, manifest, initial_policy(args.operator_subject))
    print(f"Created {args.output / 'config.json'} and {args.output / 'authorization.json'}.")


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


def main():
    parser = argparse.ArgumentParser(description="LASA service using Codex App Server")
    parser.add_argument("--config", type=Path, help="Path to the LASA config.json used at startup")
    commands = parser.add_subparsers(dest="command")
    config_command = commands.add_parser("config", help="Scaffold or check service configuration")
    config_commands = config_command.add_subparsers(dest="action", required=True)
    add_init_options(
        config_commands.add_parser("init", help="Create a manifest and receiver policy")
    )
    check = config_commands.add_parser("check", help="Validate a deployment without starting LASA")
    check.add_argument("--config", type=Path, required=True)
    check.add_argument("--offline", action="store_true", help="Skip remote JWKS and Docker checks")
    args = parser.parse_args()
    if args.command is None and args.config is None:
        parser.error("provide --config or a configuration command")
    os.umask(0o077)
    try:
        if args.command == "config" and args.action == "init":
            initialize(args)
            return
        config = Configuration.load(args.config)
        if args.command == "config":
            check_deployment(config, offline=args.offline)
            mode = " (offline)" if args.offline else ""
            print(
                f"Configuration valid{mode}. Deployment revision {config.document['service']['deployment_revision']}."
            )
        else:
            run_service(config)
    except (OSError, ValueError, LasaError) as exc:
        print(f"LASA configuration: {configuration_error(exc)}.", file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
