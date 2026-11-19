"""Canonical JSON and the single target protocol schema bundle."""

import hashlib
import json
from functools import cache
from importlib.resources import files

import rfc8785
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry, Resource

from .errors import LasaError


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _nonfinite(_):
    raise ValueError("nonfinite JSON number")


def parse_json(value):
    try:
        result = json.loads(value, object_pairs_hook=_pairs, parse_constant=_nonfinite)
        rfc8785.dumps(result)
        return result
    except (ValueError, RecursionError, rfc8785.CanonicalizationError) as exc:
        raise LasaError("invalid_input") from exc


def canonical(value):
    return rfc8785.dumps(value)


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def request_digest(request):
    return digest({key: value for key, value in request.items() if key != "delegation"})


def validate_data(schema, value, code="invalid_input", status=400):
    try:
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)
    except (ValidationError, TypeError, ValueError) as exc:
        raise LasaError(code, status) from exc
    return value


class Contracts:
    def __init__(self):
        root = files("lasa_contracts")
        self.api = parse_json(root.joinpath("api.openapi.json").read_bytes())
        self.config = parse_json(root.joinpath("config.schema.json").read_bytes())
        self.bundle = parse_json(root.joinpath("contracts.schema.json").read_bytes())
        self.private = parse_json(root.joinpath("private.schema.json").read_bytes())
        self.schemas = self.bundle["$defs"]
        self.registry = Registry().with_resources(
            (s["$id"], Resource.from_contents(s)) for s in (self.bundle, self.config, self.private)
        )

    def validate(self, name, value, code="invalid_input", status=400):
        target = (
            self.config["$id"]
            if name == "Config"
            else (self.private if name in self.private["$defs"] else self.bundle)["$id"]
            + "#/$defs/"
            + name
        )
        try:
            Draft202012Validator(
                {"$ref": target}, registry=self.registry, format_checker=FormatChecker()
            ).validate(value)
        except (ValidationError, TypeError, ValueError) as exc:
            raise LasaError(code, status) from exc
        return value

    def expanded(self, name):
        def expand(value):
            if isinstance(value, dict):
                if "$ref" in value:
                    return expand(self.schemas[value["$ref"].rsplit("/", 1)[1]])
                return {key: expand(item) for key, item in value.items()}
            if isinstance(value, list):
                return [expand(item) for item in value]
            return value

        return expand(self.schemas[name])


@cache
def protocol_contracts():
    return Contracts()
