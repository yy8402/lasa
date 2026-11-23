"""Refresh receiver-audience JWT files on the LASA administrator host.

The private issuance configuration and signing keys remain on the administrator
Mac. Receivers need only their configured public JWKS and authorization policy.
"""

import argparse
import json
import os
import tempfile
import time
from pathlib import Path
from uuid import uuid4

import jwt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    settings = json.loads(args.config.read_text())
    lifetime = settings["lifetime_seconds"]
    if not 3600 <= lifetime <= 86400:
        parser.error("Token lifetime must be between one and 24 hours")
    for receiver in settings["receivers"]:
        key = Path(receiver["signing_key_file"]).read_bytes()
        for identity in receiver["tokens"]:
            now = int(time.time())
            token = jwt.encode(
                {
                    "iss": receiver["issuer"],
                    "aud": receiver["audience"],
                    "sub": identity["subject"],
                    "iat": now,
                    "exp": now + lifetime,
                    "jti": uuid4().hex,
                },
                key,
                algorithm="ES256",
                headers={"kid": "development-key"},
            )
            destination = Path(identity["output_file"])
            fd, temporary = tempfile.mkstemp(prefix=".jwt-", dir=destination.parent)
            try:
                with os.fdopen(fd, "w") as output:
                    output.write(token + "\n")
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temporary, destination)
            finally:
                Path(temporary).unlink(missing_ok=True)
    print("Receiver-scoped token files refreshed.")


if __name__ == "__main__":
    main()
