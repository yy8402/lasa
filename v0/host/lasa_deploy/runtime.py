"""Call the pinned release images with isolated, purpose-specific mounts."""

import csv
import io
import json
import os
from pathlib import Path

from .contracts import IMAGE_API_VERSION, parse_json, require
from .deployment import docker


def mount_argument(path, writable):
    fields = ["type=bind", f"src={path}", f"dst={path}"]
    if not writable:
        fields.append("readonly")
    buffer = io.StringIO()
    csv.writer(buffer).writerow(fields)
    return buffer.getvalue().rstrip("\r\n")


def config_mounts(settings):
    return [
        (Path(settings["config"]).parent, False),
        *((p, False) for p in settings.get("mounts", [])),
    ]


def state_mounts(root):
    path = Path(root)
    require(path.is_absolute(), "The image must report an absolute state path")
    for directory in (path / "private", path / "workspaces"):
        while not directory.exists() and not directory.is_symlink():
            directory = directory.parent
        require(
            directory.is_dir() and os.access(directory, os.W_OK | os.X_OK),
            f"State directory is unavailable at {root}",
        )
    return [(path, False)] if path.exists() else []


class ReleaseImages:
    def __init__(self, release):
        self.platform = release["platform"]
        self.images = release["images"]

    def invoke(self, role, module, args, mounts, request):
        command = [
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
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--platform",
            self.platform,
            "--entrypoint",
            "python",
            "-i",
        ]
        for path, writable in mounts:
            command.extend(("--mount", mount_argument(path, writable)))
        result = parse_json(
            docker(
                *command,
                self.images[role],
                "-I",
                "-m",
                module,
                *args,
                input_text=json.dumps({"version": IMAGE_API_VERSION, **request}),
                timeout=60,
            )
        )
        require(
            isinstance(result, dict) and result.pop("version", None) == IMAGE_API_VERSION,
            f"{role} image returned an unsupported deployment response",
        )
        return result

    def supervisor(self, operation, *, mounts=(), **request):
        return self.invoke("supervisor", "lasa_service.deploy_api", (operation,), mounts, request)

    def portal(self, settings):
        return self.invoke(
            "portal",
            "portal.deploy_api",
            (),
            config_mounts(settings),
            {"config": settings["config"]},
        )
