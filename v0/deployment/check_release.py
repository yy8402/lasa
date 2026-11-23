"""Verify a release wheel, source archive, and isolated installation."""

import argparse
import asyncio
import hashlib
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from email import policy
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
PRIVATE_DIRS = {".git", ".deploy", ".venv", "verification", "__pycache__"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def archive_path(name):
    path = PurePosixPath(name)
    if (
        path.is_absolute()
        or ".." in path.parts
        or PRIVATE_DIRS.intersection(path.parts)
        or path.name.endswith((".pem", ".key", "-token.txt"))
        or path.name.startswith(("credentials", ".env"))
    ):
        raise ValueError(f"Invalid release archive path: {name}")
    return path.parts


def match_metadata(data, project):
    metadata = BytesParser(policy=policy.default).parsebytes(data)
    if (metadata["Name"], metadata["Version"]) != (project["name"], project["version"]):
        raise ValueError("Distribution metadata does not match pyproject.toml")


def wheel_sources(root, setuptools):
    sources = {}
    for package in setuptools["packages"]:
        prefix = Path(*package.split("."))
        directory = root / setuptools["package-dir"].get(package, str(prefix))
        for pattern in ["*.py", *setuptools.get("package-data", {}).get(package, ())]:
            for path in directory.glob(pattern):
                if path.is_file():
                    sources[(prefix / path.relative_to(directory)).as_posix()] = path
    return sources


def check_wheel(wheel, root=ROOT):
    settings = tomllib.loads((root / "pyproject.toml").read_text())
    project = settings["project"]
    sources = wheel_sources(root, settings["tool"]["setuptools"])
    with zipfile.ZipFile(wheel) as archive:
        for member in archive.infolist():
            archive_path(member.filename)
        names = [member.filename for member in archive.infolist() if not member.is_dir()]
        metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata) != 1 or len(set(names)) != len(names):
            raise ValueError("Wheel must contain one metadata set and unique file paths")
        match_metadata(archive.read(metadata[0]), project)
        info = metadata[0].removesuffix("METADATA")
        payload = set(names) - {name for name in names if name.startswith(info)}
        if payload != sources.keys():
            raise ValueError(f"Unexpected wheel contents: {sorted(payload ^ sources.keys())}")
        fingerprints = {}
        for name, source in sources.items():
            data = archive.read(name)
            if data != source.read_bytes():
                raise ValueError(f"Wheel file differs from checkout: {name}")
            fingerprints[name] = sha(data)
    return project, fingerprints


def source_files(root):
    files = set()
    for line in (root / "MANIFEST.in").read_text().splitlines():
        fields = line.split()
        if not fields or fields[0].startswith("#"):
            continue
        command, *patterns = fields
        if command == "include":
            for pattern in patterns:
                files.update(path for path in root.glob(pattern) if path.is_file())
        elif command == "recursive-include":
            directory, *patterns = patterns
            for pattern in patterns:
                files.update(path for path in (root / directory).rglob(pattern) if path.is_file())
        else:
            raise ValueError(f"Unsupported MANIFEST.in directive: {command}")
    return files


def check_sdist(sdist, project, root=ROOT):
    settings = tomllib.loads((root / "pyproject.toml").read_text())
    checkout_data = settings["tool"]["setuptools"]
    expected = source_files(root) | set(wheel_sources(root, checkout_data).values())
    checked, seen, prefixes = set(), set(), set()
    with tarfile.open(sdist, "r:gz") as archive:
        for member in archive:
            parts = archive_path(member.name)
            if not parts:
                raise ValueError("Source archive has an empty path")
            prefixes.add(parts[0])
            if member.isdir():
                continue
            path = "/".join(parts[1:])
            if len(parts) < 2 or not member.isfile() or path in seen:
                raise ValueError(f"Invalid source archive member: {member.name}")
            seen.add(path)
            with archive.extractfile(member) as data:
                content = data.read()
            if path == "PKG-INFO":
                match_metadata(content, project)
            elif path != "setup.cfg" and not parts[1].endswith(".egg-info"):
                source = root / path
                if not source.is_file() or source.read_bytes() != content:
                    raise ValueError(f"Source archive file differs from checkout: {path}")
                checked.add(source)
    if len(prefixes) != 1 or "PKG-INFO" not in seen or expected - checked:
        missing = sorted(path.relative_to(root).as_posix() for path in expected - checked)
        raise ValueError(f"Source archive is incomplete: {missing}")
    return len(checked)


def check_installed_files(project, fingerprints):
    import hashlib
    from importlib.metadata import distribution

    installed = distribution(project["name"])
    if installed.version != project["version"]:
        raise ValueError("Installed package version differs from the release")
    site = installed.locate_file("")
    roots = {name.split("/", 1)[0] for name in fingerprints}
    paths = {
        path.relative_to(site).as_posix(): path
        for root in roots
        for path in (site / root).rglob("*")
        if path.is_file() and "__pycache__" not in path.relative_to(site).parts
    }
    if paths.keys() != fingerprints.keys():
        raise ValueError(
            f"Unexpected installed files: {sorted(paths.keys() ^ fingerprints.keys())}"
        )
    actual = {}
    for name, path in paths.items():
        actual[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual[name] != fingerprints[name]:
            raise ValueError(f"Installed file differs from the wheel: {name}")
    return actual


def check_installation(project, fingerprints):
    from importlib.resources import files

    from lasa_service import PROTOCOL_VERSION, __version__
    from lasa_service.contracts import Contracts, digest

    check_installed_files(project, fingerprints)
    cli = subprocess.run(
        [sys.executable, "-I", "-m", "lasa_service.cli", "--help"],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    if "--config" not in cli.stdout:
        raise ValueError("Installed service CLI does not expose configuration")
    contracts = Contracts()
    examples = files("lasa_contracts").joinpath("examples")
    descriptor = json.loads(examples.joinpath("descriptor.json").read_bytes())
    release = project["version"]
    if (
        __version__ != release
        or contracts.api["info"]["version"] != release
        or contracts.config["properties"]["config_version"]["const"] != release
        or descriptor["descriptor_version"] != release
        or PROTOCOL_VERSION != f"lasa/{release}"
        or descriptor["protocols"][0]["version"] != PROTOCOL_VERSION
        or descriptor["protocols"][0]["wire_schema_digest"] != digest(contracts.bundle)
    ):
        raise ValueError("Packaged LASA versions or wire schema digest differ from the release")
    manifest = json.loads(examples.joinpath("manifest.json").read_bytes())
    for example in manifest:
        schema = example["schema"]
        name = "Config" if schema == "config.schema.json" else schema.rsplit("/", 1)[-1]
        contracts.validate(name, json.loads(examples.joinpath(example["file"]).read_bytes()))
    return len(manifest)


def check_provisioning():
    from lasa_service.auth import Authentication
    from lasa_service.config import Configuration

    with tempfile.TemporaryDirectory(prefix="lasa-package-") as directory:
        subprocess.run(
            [
                sys.executable,
                "-I",
                str(ROOT / "tools/create_development_config.py"),
                "--output",
                directory,
                "--base-url",
                "https://localhost:8443/lasa/v1",
                "--service-id",
                "https://identity.example.net/services/package-smoke",
                "--image",
                "sha256:" + "0" * 64,
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        folder = Path(directory)
        config = Configuration.load(
            folder / "config.json", environ={"LASA_MODEL_API_KEY": "package-smoke-only"}
        )
        token = (folder / "operator-token.txt").read_text().strip()

        async def authenticate():
            auth = Authentication(config)
            await auth.start()
            if auth.authenticate("Bearer " + token)["subject"] != "operator":
                raise ValueError("Installed package did not authenticate the expected operator")

        asyncio.run(authenticate())

        cli = [sys.executable, "-I", "-m", "lasa_service.cli", "config"]
        smoke_env = {**os.environ, "LASA_MODEL_API_KEY": "package-smoke-only"}
        common = [
            "--service-id",
            config.service_id,
            "--base-url",
            config.document["service"]["base_url"],
            "--image",
            "sha256:" + "0" * 64,
            "--model",
            "release-check",
            "--provider-url",
            "https://model.example.net/v1",
            "--state-root",
            str(folder / "state"),
            "--operator-subject",
            "operator",
        ]

        def config_command(*args):
            subprocess.run(
                [*cli, *args],
                env=smoke_env,
                check=True,
                capture_output=True,
                timeout=10,
            )

        official = folder / "official"
        config_command(
            "init",
            "--output",
            str(official),
            *common,
            "--issuer",
            config.document["authentication"]["issuer"],
            "--jwks-file",
            str(folder / "jwks.json"),
        )
        config_command("check", "--config", str(official / "config.json"), "--offline")
        static = folder / "static"
        static_config = str(static / "config.json")
        caller_token = folder / "caller-token.txt"
        config_command("init", "--output", str(static), *common, "--auth-mode", "static_token")
        config_command(
            "issue-token",
            "--config",
            static_config,
            "--subject",
            "operator",
            "--output",
            str(caller_token),
        )
        config_command("check", "--config", static_config, "--offline")
        config = Configuration.load(static_config, environ=smoke_env)
        token = caller_token.read_text().strip()
        asyncio.run(authenticate())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--sdist", required=True, type=Path)
    args = parser.parse_args()
    if not sys.flags.isolated or sys.prefix == sys.base_prefix:
        parser.error("Run with -I using the clean virtual environment that installed the wheel")
    project, fingerprints = check_wheel(args.wheel)
    source_count = check_sdist(args.sdist, project)
    examples = check_installation(project, fingerprints)
    check_provisioning()
    print(
        json.dumps(
            {
                "status": "passed",
                "version": project["version"],
                "wheel_sha256": sha(args.wheel.read_bytes()),
                "source_archive_sha256": sha(args.sdist.read_bytes()),
                "installed_files_matched": len(fingerprints),
                "source_files_matched": source_count,
                "packaged_examples_validated": examples,
                "development_config_and_signed_jwt": "passed",
                "installed_config_commands": "passed",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
