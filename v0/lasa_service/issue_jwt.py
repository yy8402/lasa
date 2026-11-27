"""Refresh receiver-audience JWT files on the LASA administrator host.

The private issuance configuration and signing keys remain on the administrator
Mac. Receivers need only their configured public JWKS and authorization policy.
"""

import argparse
import json
import os
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import jwt


def prepare(settings):
    lifetime = settings["lifetime_seconds"]
    if type(lifetime) is not int or not 3600 <= lifetime <= 86400:
        raise ValueError("Token lifetime must be between one and 24 hours")
    now = int(time.time())
    expiry = now + lifetime
    outputs = {}
    receivers = {}
    for receiver in settings["receivers"]:
        audience = receiver["audience"]
        kid = receiver["key_id"]
        public_keys = json.loads(Path(receiver["jwks_file"]).read_bytes())["keys"]
        candidates = [key for key in public_keys if key["kid"] == kid]
        if not kid or len(candidates) != 1 or candidates[0].get("alg", "ES256") != "ES256":
            raise ValueError(f"Receiver {audience} does not publish the configured ES256 key ID")
        public_key = jwt.PyJWK.from_dict(candidates[0], algorithm="ES256")
        key = Path(receiver["signing_key_file"]).read_bytes()
        for identity in receiver["tokens"]:
            token = jwt.encode(
                {
                    "iss": receiver["issuer"],
                    "aud": audience,
                    "sub": identity["subject"],
                    "iat": now,
                    "exp": expiry,
                    "jti": uuid4().hex,
                },
                key,
                algorithm="ES256",
                headers={"kid": kid},
            )
            jwt.decode(
                token,
                public_key.key,
                algorithms=["ES256"],
                audience=audience,
                issuer=receiver["issuer"],
            )
            destination = Path(identity["output_file"]).resolve()
            if destination in outputs or not destination.parent.is_dir():
                raise ValueError(f"Invalid or repeated output file {destination}")
            outputs[destination] = token
        receivers[audience] = datetime.fromtimestamp(expiry, UTC).isoformat()
    return outputs, receivers


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        outputs, receivers = prepare(json.loads(args.config.read_text()))
        for destination, token in outputs.items():
            fd, temporary = tempfile.mkstemp(prefix=".jwt-", dir=destination.parent)
            try:
                with os.fdopen(fd, "w") as output:
                    output.write(token + "\n")
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temporary, destination)
            finally:
                Path(temporary).unlink(missing_ok=True)
    except (KeyError, TypeError, ValueError, OSError, jwt.PyJWTError) as exc:
        parser.exit(2, f"Token issuance failed: {exc}\n")
    print(json.dumps({"expires_by_receiver": receivers}, indent=2))


if __name__ == "__main__":
    main()
