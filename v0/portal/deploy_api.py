"""Read-only validation of portal configuration in its release image."""

import json
import sys
from pathlib import Path

from .config import Settings


def main():
    try:
        request = json.load(sys.stdin)
        if request["version"] != 1:
            raise ValueError("Unsupported deployment interface")
        settings = Settings.read(request["config"])
        settings.keys()
        settings.tls_context()
        if not Path(settings.client_secret_file).read_text().strip():
            raise ValueError("Portal client secret is empty")
        print(
            json.dumps(
                {
                    "version": 1,
                    "lasa_url": settings.lasa_url,
                    "lasa_service_id": settings.lasa_service_id,
                    "issuer": settings.issuer,
                    "state_dir": settings.state_dir,
                    "public_origin": settings.public_origin,
                    "base_path": settings.base_path,
                }
            )
        )
    except (OSError, ValueError, TypeError, KeyError):
        print(
            "Portal deployment check failed. Check its configuration, files, and TLS trust.",
            file=sys.stderr,
        )
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
