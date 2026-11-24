"""Networkless container carrier: App Server RPC and gateway frames share stdio."""

import asyncio
import base64
import json
import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

MAX_BODY = 1048576


async def serve(executable):
    queues = {}
    write_lock = asyncio.Lock()

    async def send(value):
        async with write_lock:
            sys.stdout.write(json.dumps(value, separators=(",", ":")) + "\n")
            sys.stdout.flush()

    async def http(reader, writer):
        request_id = str(uuid4())
        queue = asyncio.Queue()
        queues[request_id] = queue
        try:
            header = await reader.readuntil(b"\r\n\r\n")
            lines = header.decode("latin-1").split("\r\n")
            method, path, _ = lines[0].split(" ", 2)
            headers = dict(line.split(":", 1) for line in lines[1:] if ":" in line)
            headers = {name.lower(): value.strip() for name, value in headers.items()}
            length = int(headers.get("content-length", "0"))
            if length < 0 or length > MAX_BODY or "transfer-encoding" in headers:
                raise ValueError("unsupported request framing")
            body = await reader.readexactly(length)
            await send(
                {
                    "lasa_gateway": "request",
                    "id": request_id,
                    "method": method,
                    "path": path,
                    "body": base64.b64encode(body).decode(),
                }
            )
            while True:
                frame = await queue.get()
                if frame["lasa_gateway"] == "response":
                    content_type = frame.get("content_type", "application/json")
                    writer.write(
                        (
                            f"HTTP/1.1 {frame['status']} Response\r\nContent-Type: {content_type}\r\n"
                            "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                        ).encode()
                    )
                elif frame["lasa_gateway"] == "chunk":
                    data = base64.b64decode(frame["data"], validate=True)
                    if data:
                        writer.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
                else:
                    writer.write(b"0\r\n\r\n")
                    break
                await writer.drain()
            await writer.drain()
        except (OSError, ValueError, asyncio.IncompleteReadError):
            pass
        finally:
            queues.pop(request_id, None)
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(http, "127.0.0.1", 39231, limit=65536)
    process = await asyncio.create_subprocess_exec(
        executable,
        "app-server",
        "--listen",
        "stdio://",
        "--strict-config",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        limit=2 * MAX_BODY,
    )
    host = asyncio.StreamReader(limit=2 * MAX_BODY)
    protocol = asyncio.StreamReaderProtocol(host)
    await asyncio.get_running_loop().connect_read_pipe(lambda: protocol, sys.stdin.buffer)

    async def input_frames():
        while line := await host.readline():
            value = json.loads(line)
            if "lasa_gateway" in value:
                queue = queues.get(value["id"])
                if queue is not None:
                    queue.put_nowait(value)
            else:
                process.stdin.write(line)
                await process.stdin.drain()
        process.stdin.close()
        if process.returncode is None:
            process.terminate()

    async def output_frames():
        while line := await process.stdout.readline():
            await send(json.loads(line))

    incoming = asyncio.create_task(input_frames())
    outgoing = asyncio.create_task(output_frames())
    try:
        return await process.wait()
    finally:
        incoming.cancel()
        await asyncio.gather(incoming, outgoing, return_exceptions=True)
        server.close()
        await server.wait_closed()


def main():
    role = sys.argv[1]
    executable = sys.argv[2] if len(sys.argv) > 2 else "/usr/local/bin/codex"
    if role == "probe":
        return subprocess.call([executable, "--version"])
    if role in {"config-check", "serve"}:
        (Path(os.environ["CODEX_HOME"]) / "config.toml").write_text(
            os.environ.pop("LASA_CODEX_CONFIG"), encoding="utf-8"
        )
        os.environ["LASA_LOCAL_MODEL_KEY"] = "local"
    if role == "config-check":
        return subprocess.call(
            [executable, "app-server", "--strict-config", "--print-startup-config"]
        )
    if role != "serve":
        raise ValueError("Unknown container role")
    return asyncio.run(serve(executable))


if __name__ == "__main__":
    sys.exit(main())
