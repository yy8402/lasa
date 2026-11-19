"""Refresh only source-archive evidence after final report edits."""

import hashlib
import json
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "verification"
archive_path = OUT / "dist/lasa_service_v0-1.0.0.tar.gz"
wheel = OUT / "dist/lasa_service_v0-1.0.0-py3-none-any.whl"
report = json.loads((OUT / "package-check.json").read_text())
assert hashlib.sha256(wheel.read_bytes()).hexdigest() == report["wheel_sha256"]
matched = 0
with tarfile.open(archive_path) as archive:
    names = []
    for member in archive.getmembers():
        if not member.isfile():
            continue
        name = member.name.split("/", 1)[1]
        names.append(name)
        assert not any(p in {"verification", ".deploy", ".venv", "__pycache__"} for p in Path(name).parts)
        assert not name.endswith((".pem", "operator-token.txt", "credentials.local.json"))
        source = ROOT / name
        if source.is_file() and ".egg-info/" not in name:
            assert source.read_bytes() == archive.extractfile(member).read(), name
            matched += 1
    for name in ["deployment/DEPLOYMENT.md", "deployment/issue_tokens.py", "deployment/set_profile.py", "deployment/verify_deployed.py", "lasa_service/evidence.py", "tests/test_verification_evidence.py"]:
        assert name in names
report.update(source_archive_sha256=hashlib.sha256(archive_path.read_bytes()).hexdigest(), source_distribution_matches_checkout="passed", source_distribution_files_matched=matched)
report["commands"] += ["uv build --sdist --project v0 --out-dir v0/verification/dist", "v0/verification/package-env/bin/python -I v0/verification/check_source_archive.py"]
(OUT / "package-check.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps({"source_archive": "passed", "source_files_matched": matched, "installed_wheel_evidence": "unchanged and retained", "wheel_sha256": report["wheel_sha256"]}))
