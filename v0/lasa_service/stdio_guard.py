"""Bound JSON-RPC frames and terminate only the owned stdio server group."""

import argparse
import asyncio
import os
import signal
import sys


class Sink(asyncio.Protocol):
    def __init__(self):
        self.writable = asyncio.Event()
        self.writable.set()
        self.error = None

    def connection_made(self, transport):
        self.transport = transport

    def pause_writing(self):
        self.writable.clear()

    def resume_writing(self):
        self.writable.set()

    def connection_lost(self, exc):
        self.error = exc or BrokenPipeError()
        self.writable.set()

    async def send(self, data):
        if self.error:
            raise self.error
        self.transport.write(data)
        await self.writable.wait()
        if self.error:
            raise self.error


async def serve(maximum, command):
    loop = asyncio.get_running_loop()
    stopped = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stopped.set)
    reader = asyncio.StreamReader(limit=maximum + 1)
    input_transport, _ = await loop.connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(reader), sys.stdin.buffer
    )
    sink = Sink()
    output_transport, _ = await loop.connect_write_pipe(lambda: sink, sys.stdout.buffer)
    child = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        limit=maximum + 1,
        start_new_session=True,
    )

    async def incoming():
        while line := await reader.readline():
            if len(line) > maximum:
                raise ValueError("Frame exceeds approved bound")
            child.stdin.write(line)
            await child.stdin.drain()

    async def outgoing():
        while line := await child.stdout.readline():
            if len(line) > maximum:
                raise ValueError("Frame exceeds approved bound")
            await sink.send(line)

    async def errors():
        used = 0
        while data := await child.stderr.read(4096):
            if used < maximum:
                sys.stderr.buffer.write(data[: maximum - used])
                sys.stderr.buffer.flush()
                used += len(data)

    tasks = [
        asyncio.create_task(operation())
        for operation in [incoming, outgoing, errors, child.wait, stopped.wait]
    ]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:
            task.cancel()
        if child.returncode is None:
            try:
                os.killpg(child.pid, signal.SIGTERM)
                async with asyncio.timeout(2):
                    await child.wait()
            except TimeoutError:
                os.killpg(child.pid, signal.SIGKILL)
                await child.wait()
            except ProcessLookupError:
                pass
        await asyncio.gather(*tasks, return_exceptions=True)
        input_transport.close()
        output_transport.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-bytes", type=int, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command or not 1024 <= args.max_bytes <= 1048576:
        parser.error("Invalid bounded stdio invocation")
    asyncio.run(serve(args.max_bytes, command))


if __name__ == "__main__":
    main()
