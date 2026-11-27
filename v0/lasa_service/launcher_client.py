"""Supervisor client for the private local worker launcher."""

import asyncio
import hashlib
import json
import re
import time
from contextlib import suppress

from .errors import LasaError

MAX_START_SECONDS = 60
FRAME_LIMIT = 2 * 1024 * 1024
INSTANCE_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
DEFAULT_INSTANCE = "default"


def launcher_scope(service_id, instance=DEFAULT_INSTANCE):
    return hashlib.sha256(f"{service_id}\0{instance}".encode()).hexdigest()


async def send_frame(writer, frame):
    writer.write(json.dumps(frame, separators=(",", ":")).encode() + b"\n")
    await writer.drain()


async def close_stream(writer):
    writer.close()
    with suppress(OSError):
        await writer.wait_closed()


class LauncherClient:
    def __init__(self, path, service_id, instance=DEFAULT_INSTANCE):
        self.path = path
        self.scope = launcher_scope(service_id, instance)

    async def request(self, operation, **fields):
        writer = None
        try:
            reader, writer = await asyncio.open_unix_connection(self.path, limit=FRAME_LIMIT)
            await send_frame(writer, {"operation": operation, "scope": self.scope, **fields})
            response = json.loads(await reader.readline())
            if response != {"ok": True}:
                raise LasaError("internal_error", 503)
            return reader, writer
        except BaseException as exc:
            if writer is not None:
                await close_stream(writer)
            if isinstance(exc, (OSError, ValueError)):
                raise LasaError("internal_error", 503) from exc
            raise

    async def check(self):
        _, writer = await self.request("check")
        await close_stream(writer)

    async def probe(self, model):
        _, writer = await self.request("probe", model=model)
        await close_stream(writer)

    async def launch(self, attempt_id, model, startup_seconds):
        return await self.request(
            "launch", attempt_id=attempt_id, model=model, expires_at=time.time() + startup_seconds
        )

    async def stop(self, attempt_id):
        _, writer = await self.request("stop", attempt_id=attempt_id)
        await close_stream(writer)
