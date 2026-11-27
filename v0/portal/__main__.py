"""Run the optional portal behind an HTTPS ingress."""

import argparse
import asyncio
import logging
import os
import sys

import httpx
import uvicorn

from .app import create_app
from .client import IdentityProvider, Native
from .config import PortalError, Settings


async def qualify(settings, token):
    async with httpx.AsyncClient(
        verify=settings.tls_context(), trust_env=False, timeout=settings.timeout_seconds
    ) as http:
        await IdentityProvider(settings, http).metadata()
        native = Native(settings, http)
        await native.qualify(token)
        if not await native.offers(token):
            raise ValueError("The qualification user has no eligible portal offer")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", default=8080, type=int)
    parser.add_argument(
        "--qualify", action="store_true", help="Check issuer and receiver using a token on stdin"
    )
    args = parser.parse_args()
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    # The HTTP clients log full upstream URLs at INFO.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    settings = Settings.read(args.config)
    if args.qualify:
        token = sys.stdin.read(65537).strip()
        if not token or len(token) > 65536:
            parser.error("Supply the qualification user's access token on stdin")
        try:
            asyncio.run(qualify(settings, token))
        except PortalError as exc:
            parser.exit(2, f"Portal qualification failed: {exc.code}\n")
        except (OSError, ValueError) as exc:
            parser.exit(2, f"Portal qualification failed: {exc}\n")
        print("Portal issuer and receiver qualification passed.")
        return
    uvicorn.run(
        create_app(settings),
        host=args.listen,
        port=args.port,
        access_log=False,
        proxy_headers=False,
    )


if __name__ == "__main__":
    main()
