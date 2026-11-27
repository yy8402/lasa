"""Operate LASA from its deployment host."""

import argparse
import json
import os
import shlex
import sys
from pathlib import Path

from .contracts import ConfigurationError
from .deployment import DockerDeployment, read_json
from .guided_install import initialize as initialize_deployment
from .managed_deployment import HostDeployment


def guided_install(args):
    receipt = initialize_deployment(args.config)
    if not args.prepare_only:
        settings = Path(receipt["settings"])
        try:
            receipt["status"] = HostDeployment.load(settings).run("apply")
        except (OSError, ValueError, KeyboardInterrupt):
            command = shlex.join(["lasa-deploy", "apply", "--settings", str(settings)])
            print(f"Settings saved. To resume, run {command}", file=sys.stderr)
            for user in receipt.get("user_credentials", ()):
                print(
                    f"Temporary credentials for {user['username']} are at {user['credentials_file']}",
                    file=sys.stderr,
                )
            raise
    return receipt


def print_plan(result, settings):
    readiness = result["readiness"]
    print(f"{readiness.title()}  {result['deployment']} ({result['release']})")
    if result["preflight"] == "deferred":
        print("Candidate preflight needs the missing images.")
    elif result["change"]:
        print("Candidate preflight passed.")
    else:
        print("Candidate preflight passed. The active revision matches this plan.")
    for item in result["image_imports"]:
        status = item["archive_status"].replace("_", " ")
        print(f"\n{item['purpose'].title()} archive for {item['release']} ({status})")
        print(f"  {item['archive']}")
        for role, pin in item["missing_images"].items():
            print(f"  {role}  {pin}")
        if remediation := item.get("remediation"):
            print(f"  {remediation}")
    if readiness == "blocked":
        print("\nFix the archive issues and run plan again.")
    elif result["change"] is not False:
        command = shlex.join(["lasa-deploy", "apply", "--settings", str(settings)])
        print(f"\nRun {command} to continue.")


def main():
    parser = argparse.ArgumentParser(description="Install and operate a host-local LASA deployment")
    deploy_actions = parser.add_subparsers(dest="action", required=True)
    install = deploy_actions.add_parser("install", help="Create and apply a deployment from JSON")
    install.add_argument("--config", type=Path, required=True, help="Path to install.json")
    install.add_argument(
        "--prepare-only", action="store_true", help="Write settings for review before applying"
    )
    gateway = deploy_actions.add_parser("gateway", help="Maintain the site's HTTPS gateway")
    gateway_actions = gateway.add_subparsers(dest="gateway_action", required=True)
    for action in ("plan", "apply", "status", "rollback"):
        gateway_action = gateway_actions.add_parser(action)
        gateway_action.add_argument("--settings", type=Path, required=True)
        if action in {"plan", "apply"}:
            gateway_action.add_argument("--image", help="Locally loaded Caddy image digest")
            gateway_action.add_argument("--tls-cert", type=Path, help="New site certificate PEM")
            gateway_action.add_argument("--tls-key", type=Path, help="New site private key PEM")
            gateway_action.add_argument(
                "--ca-file", type=Path, help="CA bundle for site HTTPS checks"
            )
    users = deploy_actions.add_parser("users", help="Manage users for local Keycloak")
    user_actions = users.add_subparsers(dest="user_action", required=True)
    for action in ("list", "add", "reset"):
        user_action = user_actions.add_parser(action)
        user_action.add_argument("--settings", required=True, type=Path)
        if action == "add":
            user_action.add_argument("--email", required=True)
            user_action.add_argument("--username", help="Defaults to the full email address")
        elif action == "reset":
            user_action.add_argument("--username", required=True)
        if action != "list":
            user_action.add_argument("--credentials-file", required=True, type=Path)
    for action, help_text in (
        ("plan", "Validate a release and show the proposed changes"),
        ("apply", "Install a release and verify readiness before opening admission"),
        ("status", "Show the active release and any interrupted rollout"),
        ("rollback", "Restore the previous release without rewinding task state"),
        ("pause", "Drain work and close admission"),
        ("resume", "Verify the current release and open admission"),
    ):
        subcommand = deploy_actions.add_parser(action, help=help_text)
        subcommand.add_argument(
            "--settings", type=Path, required=True, help="Path to the deployment JSON file"
        )
        if action in {"apply", "rollback"}:
            subcommand.add_argument("--hold", action="store_true", help="Leave admission closed")
        if action == "plan":
            subcommand.add_argument("--json", action="store_true", help="Print the full JSON plan")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.action == "install":
            print(json.dumps(guided_install(args), indent=2))
            return
        settings = read_json(args.settings)
        if args.action == "gateway":
            deployment = HostDeployment.load(args.settings, settings)
            result = deployment.gateway_action(
                args.gateway_action,
                image=getattr(args, "image", None),
                certificate=getattr(args, "tls_cert", None),
                key=getattr(args, "tls_key", None),
                ca=getattr(args, "ca_file", None),
            )
        elif args.action == "users":
            deployment = HostDeployment.load(args.settings, settings)
            result = deployment.users(
                args.user_action,
                email=getattr(args, "email", None),
                username=getattr(args, "username", None),
                credentials=getattr(args, "credentials_file", None),
            )
        elif "supervisor_network" in settings:
            deployment = DockerDeployment.load(args.settings)
            result = deployment.run(args.action)
        else:
            deployment = HostDeployment.load(args.settings, settings)
            result = deployment.run(args.action, hold=getattr(args, "hold", False))
            if args.action == "plan" and not args.json:
                print_plan(result, args.settings)
                return
        print(json.dumps(result, indent=2))
        return
    except (OSError, ValueError) as exc:
        message = (
            str(exc)
            if isinstance(exc, ConfigurationError)
            else "Invalid or inaccessible deployment data"
        )
        print(f"LASA deployment: {message}.", file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
