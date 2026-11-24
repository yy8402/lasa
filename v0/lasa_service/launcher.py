"""Own the Docker daemon connection on behalf of one LASA supervisor."""

import argparse
import asyncio
import fcntl
import json
import logging
import os
import re
import stat
import time
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from uuid import uuid4
from weakref import WeakValueDictionary

from .config import packaged_defaults
from .enclosure import ATTEMPT_ID, Enclosure
from .errors import LasaError
from .launcher_client import MAX_START_SECONDS, close_stream, launcher_scope, send_frame

LOG = logging.getLogger(__name__)


async def relay(reader, writer):
    while chunk := await reader.read(65536):
        writer.write(chunk)
        await writer.drain()


class Launcher:
    def __init__(self, enclosure):
        self.enclosure = enclosure
        self.claimed = {}
        self.attached = set()
        self.locks = WeakValueDictionary()

    def lock(self, attempt_id):
        return self.locks.setdefault(attempt_id, asyncio.Lock())

    async def stop(self, attempt_id):
        async with self.lock(attempt_id):
            # Fence a launch request delayed behind this stop. Closed requests expire on the wire.
            self.claimed[attempt_id] = time.time() + MAX_START_SECONDS
            await self.enclosure.remove(attempt_id)

    async def sweep(self):
        now = time.time()
        self.claimed = {key: expiry for key, expiry in self.claimed.items() if expiry > now}
        for attempt_id in await self.enclosure.inventory():
            async with self.lock(attempt_id):
                if attempt_id not in self.attached:
                    await self.enclosure.remove(attempt_id)

    async def collect(self):
        while True:
            await asyncio.sleep(10)
            try:
                await self.sweep()
            except (LasaError, OSError, TimeoutError):
                LOG.warning("Worker cleanup could not confirm Docker state")

    async def probe(self, model):
        attempt_id = "attempt-" + uuid4().hex
        self.attached.add(attempt_id)
        try:
            container = await self.enclosure.create(attempt_id, model, "config-check")
            await self.enclosure.run("start", "--attach", container)
        finally:
            self.attached.discard(attempt_id)
            await self.enclosure.remove(attempt_id)

    async def launch(self, reader, writer, attempt_id, model, expires_at):
        async with self.lock(attempt_id):
            now = time.time()
            if (
                type(expires_at) not in {int, float}
                or not now < expires_at <= now + MAX_START_SECONDS
                or attempt_id in self.claimed
                or attempt_id in self.attached
            ):
                raise ValueError("Invalid or previously submitted worker attempt")
            self.claimed[attempt_id] = expires_at
            self.attached.add(attempt_id)
            try:
                container_id = await self.enclosure.create(attempt_id, model, "serve")
                if time.time() >= expires_at:
                    raise TimeoutError
                process = await self.enclosure.start(container_id)
            except BaseException:
                self.attached.discard(attempt_id)
                raise
        relays = []
        try:
            await send_frame(writer, {"ok": True})
            relays = [
                asyncio.create_task(relay(reader, process.stdin)),
                asyncio.create_task(relay(process.stdout, writer)),
            ]
            await asyncio.wait(relays, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for job in relays:
                job.cancel()
            await asyncio.gather(*relays, return_exceptions=True)
            process.stdin.close()
            self.attached.discard(attempt_id)
            # Only this launcher owns the Docker attachment. A successful remove also
            # stops it, while the sweep covers clients that disconnect without stopping.
            if process.returncode is None:
                with suppress(ProcessLookupError):
                    process.kill()
            await process.wait()

    async def handle(self, reader, writer):
        try:
            async with asyncio.timeout(5):
                request = json.loads(await reader.readline())
            if not isinstance(request, dict):
                raise ValueError("Expected a launcher request")
            if request.pop("scope") != self.enclosure.scope:
                raise ValueError("Launcher scope mismatch")
            operation = request.pop("operation")
            fields = {
                "check": set(),
                "probe": {"model"},
                "launch": {"attempt_id", "model", "expires_at"},
                "stop": {"attempt_id"},
            }
            if operation not in fields or request.keys() != fields[operation]:
                raise ValueError("Invalid launcher request")
            if "attempt_id" in request and (
                not isinstance(request["attempt_id"], str)
                or not ATTEMPT_ID.fullmatch(request["attempt_id"])
            ):
                raise ValueError("Invalid worker attempt")
            if "model" in request and (
                not isinstance(request["model"], str) or not 0 < len(request["model"]) <= 256
            ):
                raise ValueError("Invalid model")
            if operation == "launch":
                await self.launch(reader, writer, **request)
                return
            if operation == "stop":
                await self.stop(**request)
            elif operation == "probe":
                await self.probe(**request)
            else:
                await self.enclosure.inventory()
            await send_frame(writer, {"ok": True})
        except (KeyError, TypeError, ValueError, LasaError, OSError, TimeoutError):
            with suppress(OSError):
                await send_frame(writer, {"ok": False})
        finally:
            await close_stream(writer)

    @asynccontextmanager
    async def serve(self, path):
        # The mount containing this socket is private to the launcher and its supervisor.
        with path.with_suffix(".lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            await self.enclosure.verify_image(packaged_defaults()["worker"]["expected_version"])
            await self.sweep()
            with suppress(FileNotFoundError):
                if not stat.S_ISSOCK(path.lstat().st_mode):
                    raise ValueError("Launcher path must be a Unix socket")
                path.unlink()
            server = await asyncio.start_unix_server(self.handle, path, start_serving=False)
            try:
                path.chmod(0o600)
                async with server:
                    await server.start_serving()
                    cleanup = asyncio.create_task(self.collect())
                    try:
                        yield
                    finally:
                        cleanup.cancel()
                        await asyncio.gather(cleanup, return_exceptions=True)
            finally:
                path.unlink(missing_ok=True)


async def run(enclosure, path):
    async with Launcher(enclosure).serve(path):
        await asyncio.Event().wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="Immutable local Docker image ID")
    parser.add_argument(
        "--scope", required=True, help="Unique, stable service identity on this daemon"
    )
    parser.add_argument("--socket", required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.image) or not args.socket.is_absolute():
        parser.error("An immutable image ID and absolute Unix socket path are required")
    os.umask(0o077)
    scope = launcher_scope(args.scope)
    asyncio.run(run(Enclosure(args.image, scope), args.socket))


if __name__ == "__main__":
    main()
