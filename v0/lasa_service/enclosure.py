"""A networkless, unprivileged Docker boundary for each agent task."""

import asyncio
import json
import os
import shutil
import stat

from .errors import LasaError


class Enclosure:
    def __init__(self):
        self.docker = shutil.which("docker")
        self.last_error = ""

    async def run(self, *arguments, check=True, limit_seconds=20):
        if self.docker is None:
            raise LasaError("internal_error", 503)
        process = await asyncio.create_subprocess_exec(
            self.docker,
            *map(str, arguments),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            async with asyncio.timeout(limit_seconds):
                stdout, stderr = await process.communicate()
        except BaseException:
            process.kill()
            await process.wait()
            raise
        if check and process.returncode:
            self.last_error = stderr.decode(errors="replace")[:8192]
            raise LasaError("internal_error", 503)
        return process.returncode, stdout, stderr

    async def verify_image(self, image, executable, expected_version):
        _, value, _ = await self.run("image", "inspect", "--format", "{{.Id}}", image)
        if value.decode().strip() != image:
            raise LasaError("internal_error", 503)
        _, stdout, _ = await self.run(
            "run",
            "--rm",
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
            image,
            "probe",
            executable,
        )
        if stdout.decode().strip() != "codex-cli " + expected_version:
            raise LasaError("internal_error", 503)

    async def create(
        self,
        *,
        image,
        executable,
        task_id,
        service_id,
        workspace,
        home,
        protected,
        token,
        lifetime,
        role="serve",
        workspace_readonly=False,
    ):
        for reserved in (".codex", ".agents"):
            path = workspace / reserved
            try:
                path.mkdir(mode=0o700)
            except FileExistsError:
                if path.is_symlink() or not path.is_dir():
                    raise LasaError("precondition_failed", 422) from None
        fd = os.open(workspace / "AGENTS.md", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise LasaError("precondition_failed", 422)
        finally:
            os.close(fd)
        name = "lasa-" + task_id
        args = [
            "create",
            "--rm",
            "--pull",
            "never",
            "--init",
            "--interactive",
            "--name",
            name,
            "--label",
            "com.lasa.task_id=" + task_id,
            "--label",
            "com.lasa.service_id=" + service_id,
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
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=67108864,mode=1777",
            "--workdir",
            "/workspace",
        ]
        for source, target, readonly in (
            (workspace, "/workspace", workspace_readonly),
            (home, "/home/lasa", False),
            (home / "config.toml", "/home/lasa/config.toml", True),
            (protected / "empty", "/workspace/.codex", True),
            (protected / "empty", "/workspace/.agents", True),
            (protected / "empty-file", "/workspace/AGENTS.md", True),
        ):
            args += [
                "--mount",
                f"type=bind,source={source},target={target}" + (",readonly" if readonly else ""),
            ]
        for key, value in {
            "LASA_GATEWAY_TOKEN": token,
            "LASA_GATEWAY_TIMEOUT": str(lifetime),
        }.items():
            args += ["--env", f"{key}={value}"]
        _, stdout, _ = await self.run(*args, image, role, executable)
        container_id = stdout.decode().strip()
        if len(container_id) != 64 or any(c not in "0123456789abcdef" for c in container_id):
            raise LasaError("internal_error", 503)
        return container_id

    async def inspect(self, container_id):
        status, stdout, _ = await self.run(
            "inspect", "--format", "{{json .Config.Labels}}", container_id, check=False
        )
        if status:
            # Distinguish an absent container from an unreachable daemon before releasing ownership.
            await self.run("info", "--format", "{{.ServerVersion}}")
            return None
        return json.loads(stdout)

    async def remove(self, container_id, task_id, service_id):
        labels = await self.inspect(container_id)
        if labels is None:
            return
        if (
            labels.get("com.lasa.task_id") != task_id
            or labels.get("com.lasa.service_id") != service_id
        ):
            raise LasaError("internal_error", 503)
        await self.run("rm", "--force", container_id)
