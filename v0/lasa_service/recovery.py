"""Trusted declarations for deterministic omission of optional context."""

from copy import deepcopy

from .contracts import canonical, validate_data
from .errors import LasaError

OPTIONAL_CONTEXT = "x-lasa-optional-context"


def optional_context(schema, protected=()):
    properties = schema.get("properties", {})
    fields = {
        key
        for key, value in properties.items()
        if isinstance(value, dict) and OPTIONAL_CONTEXT in value
    }
    if fields & (set(schema.get("required", ())) | set(protected)) or any(
        properties[key][OPTIONAL_CONTEXT] is not True for key in fields
    ):
        raise ValueError("Optional context must be an unbound, non-required property marked true")
    return fields


def omit_fields(value, fields):
    if not isinstance(value, dict):
        return value
    omitted = fields & value.keys()
    if not omitted:
        return value
    return {key: item for key, item in value.items() if key not in omitted}


def capability_context(definition, value):
    schema = definition["input_schema"]
    revised = omit_fields(value, optional_context(schema))
    if revised is not value:
        try:
            return validate_data(schema, revised)
        except LasaError:
            pass
    return value


def revise_model_context(body, original, revised):
    if revised == original:
        return None
    before = canonical(original).decode()
    after = canonical(revised).decode()

    def matching_parts(value):
        for message in value.get("input", []):
            if not isinstance(message, dict) or message.get("role") != "user":
                continue
            parts = message.get("content")
            if isinstance(parts, list):
                for part in parts:
                    if (
                        isinstance(part, dict)
                        and part.get("type") == "input_text"
                        and part.get("text") == before
                    ):
                        yield part

    if not any(matching_parts(body)):
        return None

    def revise(value):
        candidate = deepcopy(value)
        for part in matching_parts(candidate):
            part["text"] = after
        return candidate

    return revise
