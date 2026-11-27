"""Verify a clean install and rollback using the release artifacts in a new environment."""

import argparse
import hashlib
import json
import subprocess
import tarfile
import tempfile
from pathlib import Path


def verify(path, expected):
    with path.open("rb") as file:
        actual = "sha256:" + hashlib.file_digest(file, "sha256").hexdigest()
    if actual != expected:
        raise ValueError(f"Release checksum mismatch for {path.name}")


def run(*args, cwd=None):
    subprocess.run([str(arg) for arg in args], cwd=cwd, check=True, timeout=540)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--release", required=True, type=Path, help="Directory containing release.json"
    )
    args = parser.parse_args()
    root = args.release.resolve()
    release = root / "release.json"
    manifest = json.loads(release.read_bytes())
    (wheel,) = root.glob("lasa_service-*.whl")
    (deploy_wheel,) = root.glob("lasa_deploy-*.whl")
    (archive,) = root.glob("lasa_service-*.tar.gz")
    verify(wheel, manifest["artifacts"]["service_wheel"])
    verify(deploy_wheel, manifest["artifacts"]["deploy_wheel"])
    verify(archive, manifest["artifacts"]["sdist"])
    requirements = root / "requirements-deploy.txt"
    verify(requirements, manifest["artifacts"]["deploy_requirements"])
    if image_checksum := manifest["artifacts"].get("images"):
        verify(root / "images.tar.gz", image_checksum)
    with tempfile.TemporaryDirectory(prefix="lasa-clean-install-") as directory:
        work = Path(directory).resolve()
        with tarfile.open(archive, "r:gz") as source:
            fixtures = [
                member
                for member in source.getmembers()
                if Path(member.name).parts[1:2] in {("tests",), ("run_task.py",)}
            ]
            source.extractall(work, members=fixtures, filter="data")
        (project,) = work.iterdir()
        venv = work / "venv"
        python = venv / "bin/python"
        run("uv", "venv", "--python", "3.12", venv)
        run("uv", "pip", "sync", "--python", python, "--require-hashes", requirements)
        run("uv", "pip", "install", "--python", python, "--no-deps", deploy_wheel)
        run("uv", "pip", "check", "--python", python)
        run(
            python,
            "-c",
            "import importlib.util, shutil; "
            "assert importlib.util.find_spec('lasa_service') is None; "
            "assert importlib.util.find_spec('portal') is None; "
            "assert shutil.which('lasa') is None",
            cwd=project,
        )
        # Make the base fixture images available. The cold install test uses distinct image IDs.
        run(
            python,
            "-c",
            "import json, sys; from pathlib import Path; "
            "from lasa_deploy.image_cache import ensure_release_images; "
            "path = Path(sys.argv[1]); release = json.loads(path.read_bytes()); "
            "ensure_release_images(path, release, release['images'])",
            release,
            cwd=project,
        )
        for role in ("supervisor", "launcher", "portal"):
            run(
                "docker",
                "run",
                "--rm",
                "--pull",
                "never",
                "--network",
                "none",
                "--platform",
                manifest["platform"],
                "--entrypoint",
                "python",
                manifest["images"][role],
                "-I",
                "-c",
                "import importlib.util, shutil; "
                "assert importlib.util.find_spec('lasa_deploy') is None; "
                "assert shutil.which('lasa-deploy') is None",
            )
        run(
            python,
            "-m",
            "tests.deployment_smoke",
            "--release",
            release,
            "--lasa-deploy",
            venv / "bin/lasa-deploy",
            cwd=project,
        )
        run(
            python,
            "-m",
            "tests.keycloak_smoke",
            "--release",
            release,
            "--lasa-deploy",
            venv / "bin/lasa-deploy",
            cwd=project,
        )


if __name__ == "__main__":
    main()
