"""Load private credentials and replace this process with the LASA CLI."""

import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--credentials", type=Path, required=True)
    args = parser.parse_args()
    metadata = args.credentials.stat()
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        parser.exit(2, "Credentials must be owned by this user and readable only by this user.\n")
    credentials = json.loads(args.credentials.read_bytes())
    if not isinstance(credentials, dict) or not all(
        re.fullmatch(r"[A-Z][A-Z0-9_]*", key) and isinstance(value, str) and value
        for key, value in credentials.items()
    ):
        parser.exit(2, "Invalid credentials document.\n")
    os.environ.update(credentials)
    os.execv(
        sys.executable,
        [sys.executable, "-I", "-m", "lasa_service.cli", "--config", str(args.config)],
    )


if __name__ == "__main__":
    main()
