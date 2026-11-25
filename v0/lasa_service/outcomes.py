"""Server-owned exact outcomes from approved, digest-verified source results."""

import hashlib
from dataclasses import dataclass

from .contracts import digest, parse_json
from .errors import LasaError

SOURCE_PROFILES = frozenset({"documents-read-v1", "documents-search-v1", "repository-inspect-v1"})
TEXT_BYTES = 8192


@dataclass(frozen=True)
class SourceOutcome:
    output: dict
    document_read: dict | None = None


def supported(condition):
    if not condition:
        raise LasaError("verification_failed", 422)


def source_resource(profile, value):
    if profile == "documents-read-v1":
        return "documents:lasa"
    if profile == "repository-inspect-v1" and isinstance(value, dict) and "result" in value:
        return "documentation:python-sdk"
    return "repository:python-sdk"


def assemble_source_outcome(profile, contract, inputs, material):
    input_digest = digest(inputs)
    facts = []
    for artifact in material["artifacts"]:
        manifest = artifact["manifest"]
        provenance = manifest.get("provenance", {})
        if (
            provenance.get("kind") != "operation-result"
            or provenance.get("contract") != contract
            or provenance.get("input_digest") != input_digest
            or not artifact["bytes_verified"]
            or "content" not in artifact
        ):
            continue
        value = parse_json(artifact["content"]["text"])
        supported(digest(value) == provenance["result_digest"] == manifest["digest"])
        facts.append((manifest, value))
    facts.sort(
        key=lambda item: (item[0]["provenance"]["service_id"], item[0]["provenance"]["sequence"])
    )

    def latest(resource, predicate):
        for manifest, value in reversed(facts):
            if manifest["provenance"]["resource"] == resource and predicate(value):
                return manifest, value
        raise LasaError("verification_failed", 422)

    if profile == "documents-read-v1":
        manifest, value = latest(
            "documents:lasa",
            lambda value: isinstance(value, dict) and isinstance(value.get("text"), str),
        )
        text = value["text"]
        data = text.encode("utf-8")
        supported(len(data) <= TEXT_BYTES)
        output = {
            "document_id": inputs["document_id"],
            "content": text,
            "content_digest": "sha256:" + hashlib.sha256(data).hexdigest(),
            "source_uri": "lasa-docs://" + inputs["document_id"],
        }
        provenance = manifest["provenance"]
        return SourceOutcome(
            output,
            document_read={
                "document_id": output["document_id"],
                "source_uri": output["source_uri"],
                "document_content_utf8_sha256": output["content_digest"],
                "operation_result_artifact": {
                    "artifact_id": manifest["artifact_id"],
                    "operation_id": provenance["operation_id"],
                    "service_id": provenance["service_id"],
                    "canonical_json_sha256": manifest["digest"],
                },
            },
        )
    if profile == "documents-search-v1":
        _, entries = latest("repository:python-sdk", lambda value: isinstance(value, list))
        supported(
            all(
                isinstance(item, dict)
                and isinstance(item.get("name"), str)
                and isinstance(item.get("type"), str)
                and "html_url" in item
                for item in entries
            )
        )
        matches = [
            {"document_id": item["name"], "source_uri": item["html_url"]}
            for item in entries
            if item["type"] == "file"
            and item["name"].lower().endswith(".md")
            and inputs["query"].casefold() in item["name"].casefold()
        ]
        supported(
            all(
                isinstance(item["source_uri"], str)
                and item["source_uri"].startswith(
                    "https://github.com/modelcontextprotocol/python-sdk/"
                )
                for item in matches
            )
        )
        matches.sort(key=lambda item: item["document_id"])
        return SourceOutcome(
            {"matches": matches[: inputs["limit"]], "truncated": len(matches) > inputs["limit"]}
        )
    supported(profile == "repository-inspect-v1")
    _, metadata = latest(
        "repository:python-sdk", lambda value: isinstance(value, dict) and "full_name" in value
    )
    _, documentation = latest(
        "documentation:python-sdk",
        lambda value: isinstance(value, dict) and isinstance(value.get("result"), str),
    )
    index = documentation["result"]
    supported(
        metadata["full_name"] == inputs["repository"] and len(index.encode("utf-8")) <= TEXT_BYTES
    )
    supported(metadata.get("html_url") == "https://github.com/" + inputs["repository"])
    supported(
        isinstance(metadata.get("default_branch"), str)
        and "description" in metadata
        and isinstance(metadata["description"], (str, type(None)))
    )
    return SourceOutcome(
        {
            "repository": metadata["full_name"],
            "description": metadata["description"],
            "default_branch": metadata["default_branch"],
            "documentation_index": index,
            "sources": [metadata["html_url"], "https://deepwiki.com/" + inputs["repository"]],
        }
    )
