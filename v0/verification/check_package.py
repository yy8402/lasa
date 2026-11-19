"""Verify the final installed distribution against this checkout, without credentials in output."""

import asyncio
import hashlib
import importlib.metadata
import json
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from importlib.resources import files
from pathlib import Path

import lasa_service
from lasa_service.auth import Authentication
from lasa_service.config import Configuration
from lasa_service.contracts import Contracts

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "verification"
WHEEL = OUT / "dist/lasa_service_v0-1.0.0-py3-none-any.whl"
SOURCE = OUT / "dist/lasa_service_v0-1.0.0.tar.gz"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    module = Path(lasa_service.__file__).resolve()
    assert module.is_relative_to(OUT / "package-env") and "site-packages" in str(module)
    assert importlib.metadata.version("lasa-service-v0") == "1.0.0"
    contracts = Contracts()
    assert contracts.api["openapi"] == "3.2.1"
    resource = files("lasa_contracts")
    examples = resource.joinpath("examples")
    manifest = json.loads(examples.joinpath("manifest.json").read_text())
    for example in manifest:
        name = "Config" if example["schema"] == "config.schema.json" else example["schema"].rsplit("/", 1)[-1]
        contracts.validate(name, json.loads(examples.joinpath(example["file"]).read_text()))

    cli = subprocess.run(
        [str(OUT / "package-env/bin/lasa"), "--help"],
        capture_output=True, text=True, timeout=10, check=True,
    )
    assert "--config" in cli.stdout
    provisioned = Path(tempfile.mkdtemp(prefix="package-provision-", dir=OUT))
    subprocess.run(
        [sys.executable, "-I", str(ROOT / "tools/create_development_config.py"),
         "--output", str(provisioned), "--base-url", "https://localhost:8443/lasa/v1",
         "--service-id", "https://identity.example.net/services/package-smoke",
         "--image", json.loads((OUT / "image.json").read_text())["image"]],
        capture_output=True, text=True, timeout=10, check=True,
    )
    config = Configuration.load(provisioned / "config.json", environ={"LASA_MODEL_API_KEY": "package-smoke-only"})

    async def authenticate():
        authentication = Authentication(config)
        await authentication.start()
        token = (provisioned / "operator-token.txt").read_text().strip()
        assert authentication.authenticate("Bearer " + token)["subject"] == "operator"

    asyncio.run(authenticate())
    hashes = {}
    with zipfile.ZipFile(WHEEL) as archive:
        for name in archive.namelist():
            if name.startswith("lasa_service/"):
                source_path = ROOT / name
            elif name.startswith("lasa_contracts/"):
                source_path = ROOT / "design" / name.removeprefix("lasa_contracts/")
            else:
                continue
            assert source_path.read_bytes() == archive.read(name), name
            hashes[str(source_path.relative_to(ROOT))] = sha(source_path.read_bytes())
        for directory in ("lasa_service", "design"):
            for source_path in (ROOT / directory).rglob("*"):
                if source_path.is_file() and source_path.suffix in {".py", ".json", ".md"}:
                    assert str(source_path.relative_to(ROOT)) in hashes, source_path.name
        archive_names = archive.namelist()
    with tarfile.open(SOURCE) as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            name = member.name.split("/", 1)[1]
            archive_names.append(name)
            source_path = ROOT / name
            if source_path.is_file() and ".egg-info/" not in name:
                assert source_path.read_bytes() == archive.extractfile(member).read(), name
        assert any(name.endswith("tests/test_time_limits.py") for name in archive_names)
    for name in archive_names:
        assert not any(part in {".deploy", ".venv", "verification", "__pycache__"} for part in Path(name).parts)
        assert not name.endswith((".pem", "operator-token.txt", "peer-token.txt", "credentials.local.json"))
    (OUT / "source-hashes.json").write_text(json.dumps(hashes, indent=2, sort_keys=True) + "\n")
    report = {
        "status": "passed", "python": sys.version.split()[0], "installed_module": str(module),
        "version": "1.0.0", "packaged_examples_validated": len(manifest),
        "source_matched_packaged_files": len(hashes),
        "source_matched_code_and_schema_files": sum(Path(name).suffix in {".py", ".json"} for name in hashes),
        "installed_cli_help": "passed", "development_config_and_signed_jwt": "passed",
        "archive_hygiene": "passed", "source_distribution_matches_checkout": "passed",
        "wheel_sha256": sha(WHEEL.read_bytes()), "source_archive_sha256": sha(SOURCE.read_bytes()),
        "commands": ["uv build --project v0 --out-dir v0/verification/dist",
                     "uv pip install --python v0/verification/package-env/bin/python --reinstall --no-deps v0/verification/dist/lasa_service_v0-1.0.0-py3-none-any.whl",
                     "v0/verification/package-env/bin/python -I v0/verification/check_package.py"],
    }
    (OUT / "package-check.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
