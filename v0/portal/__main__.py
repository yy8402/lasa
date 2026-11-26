"""Run the optional portal behind an HTTPS ingress."""

import argparse
import logging
import os

import uvicorn

from .app import create_app
from .config import Settings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", default=8080, type=int)
    args = parser.parse_args()
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    # The HTTP clients log full upstream URLs at INFO.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    uvicorn.run(
        create_app(Settings.read(args.config)),
        host=args.listen,
        port=args.port,
        access_log=False,
        proxy_headers=False,
    )


if __name__ == "__main__":
    main()
