"""Run the single-instance service with administrator configuration."""

import argparse
import os
from pathlib import Path

import uvicorn

from .api import create_app
from .config import Configuration
from .errors import LasaError


def main():
    parser = argparse.ArgumentParser(description="LASA Service v0 using Codex App Server")
    parser.add_argument("--config", type=Path, required=True, help="Administrator service.json")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        config = Configuration.load(args.config.resolve())
    except (OSError, ValueError, LasaError) as exc:
        parser.exit(2, f"Configuration could not be loaded ({type(exc).__name__}).\n")
    app = create_app(config)
    settings = config.document["storage"]
    tls = settings.get("tls", {})
    uvicorn.run(
        app,
        host=settings["listen_host"],
        port=settings["listen_port"],
        ssl_certfile=tls.get("certificate_file"),
        ssl_keyfile=tls.get("key_file"),
        access_log=False,
        proxy_headers=False,
    )


if __name__ == "__main__":
    main()
