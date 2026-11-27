"""Host deployment data and the versioned interface to release images."""

import hashlib
import json
import re
from functools import cache
from importlib.resources import files
from urllib.parse import urlsplit

import rfc8785
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

IMAGE_API_VERSION = 1
INSTANCE_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")


class ConfigurationError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ConfigurationError(message)


def https_origin(value):
    parsed = urlsplit(value)
    require(
        parsed.scheme == "https"
        and parsed.hostname
        and parsed.username is None
        and parsed.password is None
        and not (parsed.path or parsed.query or parsed.fragment),
        "Expected a canonical HTTPS origin",
    )
    return parsed


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key")
        result[key] = value
    return result


def parse_json(data):
    try:
        result = json.loads(data, object_pairs_hook=unique_pairs)
        canonical(result)
        return result
    except (ValueError, RecursionError, rfc8785.CanonicalizationError):
        raise ConfigurationError("Invalid deployment JSON") from None


def canonical(value):
    return rfc8785.dumps(value)


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


@cache
def validator(name):
    schema = json.loads(files("lasa_deploy").joinpath("deployment.schema.json").read_bytes())
    return Draft202012Validator(
        {**schema, "$ref": "#/$defs/" + name}, format_checker=FormatChecker()
    )


def validate(name, value):
    try:
        validator(name).validate(value)
    except ValidationError as exc:
        path = ".".join(map(str, exc.absolute_path)) or name
        raise ConfigurationError(
            f"Invalid deployment settings at {path} ({exc.validator})"
        ) from None
    return value
