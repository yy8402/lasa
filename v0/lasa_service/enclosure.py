"""Docker operations available only to the host-local launcher."""

import asyncio
import os
import re
import shutil

import tomli_w

from .errors import LasaError
from .worker_config import worker_configuration

ATTEMPT_ID = re.compile(r"attempt-[0-9a-f]{32}")
CONTAINER_ID = re.compile(r"[0-9a-f]{64}")
WORKER_EXECUTABLE = "/usr/local/bin/codex"


class Enclosure:
    def __init__(self, image, scope):
        self.docker = shutil.which("docker")
        self.image = image
        self.scope = scope

    async def run(self, *arguments, check=True):
        if self.docker is None:
            raise LasaError("internal_error", 503)
        process = await asyncio.create_subprocess_exec(
            self.docker,
            *arguments,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            async with asyncio.timeout(20):
                stdout, stderr = await process.communicate()
        except BaseException:
            if process.returncode is None:
                process.kill()
            await process.wait()
            raise
        if check and process.returncode:
            raise LasaError("internal_error", 503)
        return process.returncode, stdout, stderr

    def isolation(self):
        return [
            "--pull",
            "never",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "64",
            "--memory",
            "768m",
            "--cpus",
            "1",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
        ]

    async def verify_image(self, expected_version):
        _, value, _ = await self.run("image", "inspect", "--format", "{{.Id}}", self.image)
        if value.decode().strip() != self.image:
            raise LasaError("internal_error", 503)
        _, stdout, _ = await self.run(
            "run", "--rm", *self.isolation(), self.image, "probe", WORKER_EXECUTABLE
        )
        if stdout.decode().strip() != "codex-cli " + expected_version:
            raise LasaError("internal_error", 503)

    async def create(self, attempt_id, model, role):
        _, stdout, _ = await self.run(
            "create",
            "--rm",
            "--init",
            "--interactive",
            *self.isolation(),
            "--name",
            "lasa-" + attempt_id,
            "--label",
            "com.lasa.launcher=" + self.scope,
            "--label",
            "com.lasa.attempt=" + attempt_id,
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777",
            "--tmpfs",
            "/workspace:rw,nosuid,nodev,noexec,size=64m,mode=1777",
            "--tmpfs",
            "/home/lasa:rw,nosuid,nodev,noexec,size=64m,mode=1777",
            "--workdir",
            "/workspace",
            "--env",
            "LASA_CODEX_CONFIG=" + tomli_w.dumps(worker_configuration(model)),
            self.image,
            role,
            WORKER_EXECUTABLE,
        )
        container_id = stdout.decode().strip()
        if not CONTAINER_ID.fullmatch(container_id):
            raise LasaError("internal_error", 503)
        return container_id

    async def start(self, container_id):
        return await asyncio.create_subprocess_exec(
            self.docker,
            "start",
            "--attach",
            "--interactive",
            container_id,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )

    async def inventory(self, attempt_id=None):
        filters = ["--filter", "label=com.lasa.launcher=" + self.scope]
        if attempt_id is not None:
            filters += ["--filter", "label=com.lasa.attempt=" + attempt_id]
        _, stdout, _ = await self.run(
            "ps",
            "--all",
            "--no-trunc",
            *filters,
            "--format",
            '{{.ID}} {{.Label "com.lasa.attempt"}}',
        )
        containers = {}
        for line in stdout.decode().splitlines():
            container_id, _, attempt = line.partition(" ")
            if (
                not CONTAINER_ID.fullmatch(container_id)
                or not ATTEMPT_ID.fullmatch(attempt)
                or (attempt_id is not None and attempt != attempt_id)
                or attempt in containers
            ):
                raise LasaError("internal_error", 503)
            containers[attempt] = container_id
        return containers

    async def remove(self, attempt_id):
        container_id = (await self.inventory(attempt_id)).get(attempt_id)
        if container_id is not None:
            await self.run("rm", "--force", container_id, check=False)
            if await self.inventory(attempt_id):
                raise LasaError("internal_error", 503)
