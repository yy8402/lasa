"""Local-only JSON Schema validation for approved connector contracts."""

from jsonschema import Draft7Validator, Draft202012Validator
from referencing import Registry

from .capabilities import require
from .errors import LasaError


def check_schema(schema):
    validator = (
        Draft7Validator
        if schema.get("$schema") == "http://json-schema.org/draft-07/schema#"
        else Draft202012Validator
    )
    require(
        schema.get("$schema")
        in {
            None,
            "http://json-schema.org/draft-07/schema#",
            "https://json-schema.org/draft/2020-12/schema",
        },
        "invalid_input",
    )
    validator.check_schema(schema)

    def walk(value):
        if isinstance(value, dict):
            require("$id" not in value, "invalid_input")
            for key in ("$ref", "$dynamicRef"):
                if key in value:
                    require(value[key].startswith("#/"), "invalid_input")
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(schema)


def validate(schema, value, code="verification_failed", status=422):
    # No retriever is installed: even a malformed local reference cannot fetch a URL.
    validator = (
        Draft7Validator
        if schema.get("$schema") == "http://json-schema.org/draft-07/schema#"
        else Draft202012Validator
    )
    try:
        validator(schema, registry=Registry()).validate(value)
    except Exception:
        raise LasaError(code, status) from None
    return value
