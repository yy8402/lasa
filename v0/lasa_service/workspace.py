"""Descriptor-relative filesystem access; never follow caller-controlled links."""

import os
import stat
from pathlib import Path, PurePosixPath
from uuid import uuid4

from .errors import LasaError

RESERVED = frozenset({".codex", ".agents", ".lasa", ".git", "agents.md"})


class Workspace:
    def __init__(self, root: Path, max_bytes: int):
        self.root = root
        self.max_bytes = max_bytes

    def _parts(self, path, *, directory=False):
        if not isinstance(path, str) or "\\" in path or any(ord(c) < 32 for c in path):
            raise LasaError("verification_failed")
        if directory and path in ("", "."):
            return []
        parts = path.split("/")
        if PurePosixPath(path).is_absolute() or any(
            p in ("", ".", "..") or p.casefold() in RESERVED for p in parts
        ):
            raise LasaError("verification_failed")
        return parts

    def _directory(self, parts, *, create=False):
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in parts:
                if create:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=fd)
                    except FileExistsError:
                        pass
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            return fd
        except BaseException:
            os.close(fd)
            raise

    def read(self, relative_path):
        parts = self._parts(relative_path)
        parent = self._directory(parts[:-1])
        try:
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            with os.fdopen(fd, "rb") as source:
                if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                    raise LasaError("verification_failed")
                content = source.read(self.max_bytes + 1)
            if len(content) > self.max_bytes:
                raise LasaError("capacity_exhausted")
            return content.decode("utf-8")
        finally:
            os.close(parent)

    def write(self, relative_path, text):
        data = text.encode("utf-8")
        if len(data) > self.max_bytes:
            raise LasaError("capacity_exhausted", 413)
        parts = self._parts(relative_path)
        parent = self._directory(parts[:-1], create=True)
        temporary = f".lasa-write-{uuid4()}"
        try:
            try:
                existing = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISREG(existing.st_mode):
                    raise LasaError("verification_failed")
            except FileNotFoundError:
                pass
            fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent,
            )
            with os.fdopen(fd, "wb") as target:
                target.write(data)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, parts[-1], src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
            return {"bytes_written": len(data)}
        finally:
            try:
                os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError:
                pass
            os.close(parent)

    def list(self, relative_path="."):
        fd = self._directory(self._parts(relative_path, directory=True))
        try:
            entries = []
            for name in sorted(os.listdir(fd)):
                if name.casefold() in RESERVED:
                    continue
                metadata = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode):
                    entries.append(
                        {
                            "name": name,
                            "kind": "directory" if stat.S_ISDIR(metadata.st_mode) else "file",
                        }
                    )
                if len(entries) > 1000:
                    raise LasaError("capacity_exhausted")
            return {"entries": entries}
        finally:
            os.close(fd)
