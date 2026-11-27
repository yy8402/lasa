"""Build the verified LASA Python distributions and matching Docker images."""

import argparse
import gzip
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(*args, capture=False, timeout=300):
    return subprocess.run(
        args,
        cwd=ROOT,
        timeout=timeout,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
    ).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--source-revision")
    parser.add_argument(
        "--worker-image", help="Reuse a local worker with matching entrypoint and Codex version"
    )
    parser.add_argument(
        "--export-images", action="store_true", help="Include a docker load archive"
    )
    parser.add_argument("--platform", default="linux/amd64", choices=("linux/amd64", "linux/arm64"))
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", args.release_id):
        parser.error("Use a lowercase alphanumeric/hyphen release ID")
    revision = args.source_revision or run("git", "rev-parse", "HEAD", capture=True).strip()
    if not re.fullmatch(r"[a-f0-9]{40,64}", revision):
        parser.error("Supply a full source revision")
    destination = args.output.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        parser.error("Use an empty output directory")

    with tempfile.TemporaryDirectory(prefix="lasa-release-") as directory:
        scratch = Path(directory)
        image_input = scratch / "release"
        image_input.mkdir()
        # uv builds the wheel from the source archive, isolating it from checkout build caches.
        run("uv", "build", "--package", "lasa-service", "--out-dir", str(destination))
        host_dist = scratch / "host-dist"
        run("uv", "build", "--package", "lasa-deploy", "--out-dir", str(host_dist))
        (host_wheel,) = host_dist.glob("lasa_deploy-*.whl")
        shutil.move(host_wheel, destination / host_wheel.name)
        (wheel,) = destination.glob("lasa_service-*.whl")
        (deploy_wheel,) = destination.glob("lasa_deploy-*.whl")
        (sdist,) = destination.glob("lasa_service-*.tar.gz")
        for options, name in (
            ([], "requirements.txt"),
            (["--group", "portal"], "requirements-portal.txt"),
        ):
            run(
                "uv",
                "export",
                "--locked",
                "--no-dev",
                "--no-emit-project",
                "--no-header",
                *options,
                "--output-file",
                str(image_input / name),
                capture=True,
            )
        wheel_copy = image_input / wheel.name
        wheel_copy.write_bytes(wheel.read_bytes())
        venv = scratch / "venv"
        run("uv", "venv", "--python", "3.12", str(venv))
        python = str(venv / "bin/python")
        run(
            "uv",
            "pip",
            "sync",
            "--python",
            python,
            "--require-hashes",
            str(image_input / "requirements.txt"),
        )
        run("uv", "pip", "install", "--python", python, "--no-deps", str(wheel))
        verified = json.loads(
            run(
                python,
                "-I",
                str(ROOT / "deployment/check_release.py"),
                "--wheel",
                str(wheel),
                "--deploy-wheel",
                str(deploy_wheel),
                "--sdist",
                str(sdist),
                capture=True,
            )
        )
        info = json.loads(
            run(
                python,
                "-I",
                "-c",
                """
import json
from lasa_service.contracts import digest, protocol_contracts
from lasa_service.store import STORAGE_SCHEMA_VERSION
print(json.dumps({
    "wire_schema_digest": digest(protocol_contracts().bundle),
    "store_schema": STORAGE_SCHEMA_VERSION,
}))
""",
                capture=True,
            )
        )
        deploy_requirements = destination / "requirements-deploy.txt"
        run(
            "uv",
            "export",
            "--locked",
            "--package",
            "lasa-deploy",
            "--no-dev",
            "--no-emit-project",
            "--no-header",
            "--output-file",
            str(deploy_requirements),
            capture=True,
        )
        host_venv = scratch / "host-venv"
        run("uv", "venv", "--python", "3.12", str(host_venv))
        host_python = str(host_venv / "bin/python")
        run(
            "uv",
            "pip",
            "sync",
            "--python",
            host_python,
            "--require-hashes",
            str(deploy_requirements),
        )
        run("uv", "pip", "install", "--python", host_python, "--no-deps", str(deploy_wheel))
        run(str(host_venv / "bin/lasa-deploy"), "install", "--help", capture=True)
        pins = json.loads(
            run(
                host_python,
                "-I",
                "-c",
                """
import json
from importlib.util import find_spec
from lasa_deploy.site_gateway import GATEWAY_IMAGE
from lasa_deploy.keycloak import KEYCLOAK_IMAGES
assert find_spec("lasa_service") is None
assert find_spec("portal") is None
print(json.dumps({"gateway": GATEWAY_IMAGE, "identity": KEYCLOAK_IMAGES}))
""",
                capture=True,
            )
        )
        upstream_images = {"gateway": pins["gateway"], **pins["identity"]}
        images = {}
        tags = []
        for role in ("worker", "launcher", "supervisor", "portal"):
            repository = "lasa-codex-worker" if role == "worker" else f"lasa-{role}"
            tag = f"{repository}:{args.release_id}"
            tags.append(tag)
            options = (
                []
                if role == "worker"
                else [
                    "-f",
                    "Dockerfile.service",
                    "--target",
                    role,
                    "--build-context",
                    f"release={image_input}",
                ]
            )
            if role == "worker" and args.worker_image:
                worker = run(
                    "docker",
                    "image",
                    "inspect",
                    "--format",
                    "{{.Id}}",
                    args.worker_image,
                    capture=True,
                ).strip()
                platform = run(
                    "docker",
                    "image",
                    "inspect",
                    "--format",
                    "{{.Os}}/{{.Architecture}}",
                    worker,
                    capture=True,
                ).strip()
                probe = [
                    "docker",
                    "run",
                    "--rm",
                    "--pull",
                    "never",
                    "--platform",
                    args.platform,
                    "--network",
                    "none",
                ]
                version = json.loads((ROOT / "lasa_service/config_defaults.json").read_bytes())[
                    "worker"
                ]["expected_version"]
                observed = run(
                    *probe, worker, "probe", "/usr/local/bin/codex", capture=True
                ).strip()
                entrypoint = run(
                    *probe,
                    "--entrypoint",
                    "sha256sum",
                    worker,
                    "/opt/lasa/container_entry.py",
                    capture=True,
                ).split()[0]
                expected = hashlib.sha256(
                    (ROOT / "lasa_service/container_entry.py").read_bytes()
                ).hexdigest()
                if (
                    platform != args.platform
                    or observed != f"codex-cli {version}"
                    or entrypoint != expected
                ):
                    parser.error(
                        "The supplied worker does not match the release platform, Codex pin, and entry script"
                    )
                run("docker", "tag", worker, tag)
            else:
                run(
                    "docker",
                    "build",
                    "--platform",
                    args.platform,
                    "--tag",
                    tag,
                    *options,
                    ".",
                    timeout=480,
                )
            images[role] = run(
                "docker", "image", "inspect", "--format", "{{.Id}}", tag, capture=True
            ).strip()
        for role, reference in upstream_images.items():
            inspect = (
                "docker",
                "image",
                "inspect",
                "--platform",
                args.platform,
                "--format",
                "{{.Id}} {{.Os}}/{{.Architecture}}",
                reference,
            )
            try:
                found = run(*inspect, capture=True).strip().split()
            except subprocess.CalledProcessError:
                found = []
            if len(found) != 2 or found[1] != args.platform:
                run("docker", "pull", "--platform", args.platform, reference, timeout=480)
                found = run(*inspect, capture=True).strip().split()
            if len(found) != 2 or found[1] != args.platform:
                parser.error(f"{role} is unavailable for {args.platform}")
            image = run(
                "docker", "image", "inspect", "--format", "{{.Id}}", reference, capture=True
            ).strip()
            tag = f"lasa-{role}:{args.release_id}"
            run("docker", "tag", image, tag)
            tags.append(tag)
            images[role] = image
        manifest = {
            "release_id": args.release_id,
            "source_revision": revision,
            "package_version": verified["version"],
            "platform": args.platform,
            **info,
            "artifacts": {
                "service_wheel": "sha256:" + verified["service_wheel_sha256"],
                "deploy_wheel": "sha256:" + verified["deploy_wheel_sha256"],
                "sdist": "sha256:" + verified["source_archive_sha256"],
                "deploy_requirements": "sha256:"
                + hashlib.sha256(deploy_requirements.read_bytes()).hexdigest(),
            },
            "images": images,
        }
        if args.export_images:
            image_tar = scratch / "images.tar"
            run(
                "docker",
                "image",
                "save",
                "--platform",
                args.platform,
                "--output",
                str(image_tar),
                *tags,
                timeout=480,
            )
            # Selecting a platform flattens upstream multi-platform indexes.
            # Pin the IDs a deployment receives from the archive.
            run("docker", "image", "load", "--input", str(image_tar), timeout=480)
            for role, tag in zip(images, tags, strict=True):
                images[role] = run(
                    "docker", "image", "inspect", "--format", "{{.Id}}", tag, capture=True
                ).strip()
            image_archive = destination / "images.tar.gz"
            with (
                image_tar.open("rb") as source,
                gzip.open(image_archive, "wb", compresslevel=3) as out,
            ):
                shutil.copyfileobj(source, out)
            with image_archive.open("rb") as source:
                manifest["artifacts"]["images"] = (
                    "sha256:" + hashlib.file_digest(source, "sha256").hexdigest()
                )
        (destination / "release.json").write_text(json.dumps(manifest, indent=2) + "\n")
        print(destination / "release.json")


if __name__ == "__main__":
    try:
        main()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        sys.exit(f"Release build failed: {exc}")
