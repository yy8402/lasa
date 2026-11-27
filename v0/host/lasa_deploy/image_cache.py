"""Load verified release images and hold image pins during a rollout."""

import hashlib
import logging
import sys
from contextlib import contextmanager
from pathlib import Path

from .contracts import ConfigurationError, require
from .deployment import docker

LOG = logging.getLogger(__name__)
REFERENCE_LABEL = "com.lasa.deployment.image-reference"
ARCHIVE_REMEDIATION = {
    "missing": "Copy images.tar.gz from the original release bundle to the listed archive path.",
    "unreadable": "Make the archive readable by the user running lasa-deploy.",
    "checksum_mismatch": "Replace the archive with the original images.tar.gz for this release.",
    "not_recorded": "Restore the listed image pins from their original source.",
}


def archive_matches(archive, expected):
    return "sha256:" + hashlib.file_digest(archive, "sha256").hexdigest() == expected


def load_archive(release_path, release, missing):
    path = Path(release_path).with_name("images.tar.gz")
    detail = f"Release {release['release_id']} is missing local images ({', '.join(missing)})"
    expected = release["artifacts"].get("images")
    require(expected, f"{detail}. Restore the pinned images from their original source.")
    try:
        with path.open("rb") as archive:
            require(
                archive_matches(archive, expected),
                f"{detail}. Image archive checksum mismatch at {path}.",
            )
            archive.seek(0)
            print(
                f"Loading Docker images for {release['release_id']} from the verified archive.",
                file=sys.stderr,
            )
            try:
                docker("image", "load", input_file=archive, timeout=480)
            except ConfigurationError as exc:
                raise ConfigurationError(f"{detail}. Could not load {path}: {exc}") from None
    except OSError:
        raise ConfigurationError(
            f"{detail}. Restore the verified image archive at {path}."
        ) from None


def planned_import(release_path, release, missing, purpose):
    path = Path(release_path).with_name("images.tar.gz")
    expected = release["artifacts"].get("images")
    status = "not_recorded"
    if expected:
        try:
            with path.open("rb") as archive:
                status = "verified" if archive_matches(archive, expected) else "checksum_mismatch"
        except FileNotFoundError:
            status = "missing"
        except OSError:
            status = "unreadable"
    report = {
        "purpose": purpose,
        "release": release["release_id"],
        "archive": str(path),
        "archive_status": status,
        "missing_images": missing,
    }
    if status != "verified":
        report["remediation"] = ARCHIVE_REMEDIATION[status]
    return report


def image_missing(error):
    detail = str(error).lower()
    return "no such image" in detail or "not found" in detail


def inspect_image(image, platform):
    actual = docker(
        "image", "inspect", "--platform", platform, "--format", "{{.Os}}/{{.Architecture}}", image
    )
    require(actual == platform, f"Image {image} platform is {actual}, expected {platform}")


def missing_images(images, platform):
    missing = {}
    for role, image in images.items():
        try:
            inspect_image(image, platform)
        except ConfigurationError as exc:
            if not image_missing(exc):
                raise
            missing[role] = image
    return missing


def ensure_release_images(release_path, release, roles):
    platform = release["platform"]
    missing = missing_images({role: release["images"][role] for role in roles}, platform)
    if missing:
        load_archive(release_path, release, missing)
        for role, image in missing.items():
            try:
                inspect_image(image, platform)
            except ConfigurationError as exc:
                raise ConfigurationError(
                    f"Verified archive did not provide the pinned {role} image {image}: {exc}"
                ) from None


def create_reference(image, label, platform):
    return docker(
        "container",
        "create",
        "--pull",
        "never",
        "--network",
        "none",
        "--label",
        label,
        *(() if platform is None else ("--platform", platform)),
        "--entrypoint",
        "/lasa-image-reference",
        image,
    )


def pin_image(role, image, label, platform):
    try:
        return create_reference(image, label, platform)
    except ConfigurationError as exc:
        raise ConfigurationError(f"Cannot use pinned {role} image {image}: {exc}") from None


def entry_images(entry):
    return {**entry["images"], **entry.get("identity_images", {})}


@contextmanager
def rollout_images(project, *entries):
    label = f"{REFERENCE_LABEL}={project}"
    # The deployment lock makes references left by a stopped process safe to collect.
    containers = docker("container", "ls", "--all", "--quiet", "--filter", f"label={label}").split()
    held = set()
    try:
        for entry in filter(None, entries):
            platform = entry["release"]["platform"]
            images = entry_images(entry)
            missing = {}
            for role, image in images.items():
                if image in held:
                    continue
                try:
                    containers.append(create_reference(image, label, platform))
                except ConfigurationError as exc:
                    if not image_missing(exc):
                        raise
                    missing[role] = image
                else:
                    held.add(image)
            if missing:
                load_archive(entry["spec"]["release"], entry["release"], missing)
                for role, image in missing.items():
                    containers.append(pin_image(role, image, label, platform))
                    held.add(image)
            if entry["spec"].get("local_dlp", {}).get("enabled"):
                for role in ("inspector_image", "presidio_image"):
                    image = entry["spec"]["local_dlp"][role]
                    if image not in held:
                        containers.append(pin_image(role, image, label, None))
                        held.add(image)
        yield
    finally:
        if containers:
            try:
                docker("container", "rm", "--volumes", *containers)
            except ConfigurationError as exc:
                LOG.warning("Could not remove temporary deployment image references: %s", exc)
