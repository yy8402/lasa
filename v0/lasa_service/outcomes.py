"""Server-owned exact outcomes from approved, digest-verified source results."""

import hashlib

from .contracts import digest, parse_json
from .errors import LasaError

SOURCE_PROFILES = frozenset({"documents-read-v1", "documents-search-v1", "repository-inspect-v1"})
TEXT_BYTES = 8192


def supported(condition):
    if not condition:
        raise LasaError("verification_failed", 422)


def source_output(profile, contract, inputs, material):
    facts = []
    for artifact in material["artifacts"]:
        manifest = artifact["manifest"]
        provenance = manifest.get("provenance", {})
        if (
            provenance.get("kind") != "operation-result"
            or provenance.get("contract") != contract
            or provenance.get("input_digest") != digest(inputs)
            or not artifact["bytes_verified"]
            or "content" not in artifact
        ):
            continue
        value = parse_json(artifact["content"]["text"])
        supported(digest(value) == provenance["result_digest"] == manifest["digest"])
        facts.append((provenance, value))
    facts.sort(key=lambda item: (item[0]["service_id"], item[0]["sequence"]))

    def latest(resource, predicate):
        candidates = [
            value
            for provenance, value in facts
            if provenance["resource"] == resource and predicate(value)
        ]
        supported(bool(candidates))
        return candidates[-1]

    if profile == "documents-read-v1":
        value = latest(
            "documents:lasa",
            lambda value: isinstance(value, dict) and isinstance(value.get("text"), str),
        )
        text = value["text"]
        supported(len(text.encode("utf-8")) <= TEXT_BYTES)
        return {
            "document_id": inputs["document_id"],
            "content": text,
            "content_digest": "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "source_uri": "lasa-docs://" + inputs["document_id"],
        }
    if profile == "documents-search-v1":
        entries = latest("repository:python-sdk", lambda value: isinstance(value, list))
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
        return {"matches": matches[: inputs["limit"]], "truncated": len(matches) > inputs["limit"]}
    supported(profile == "repository-inspect-v1")
    metadata = latest(
        "repository:python-sdk", lambda value: isinstance(value, dict) and "full_name" in value
    )
    index = latest(
        "documentation:python-sdk",
        lambda value: isinstance(value, dict) and isinstance(value.get("result"), str),
    )["result"]
    supported(
        metadata["full_name"] == inputs["repository"] and len(index.encode("utf-8")) <= TEXT_BYTES
    )
    supported(metadata.get("html_url") == "https://github.com/" + inputs["repository"])
    supported(
        isinstance(metadata.get("default_branch"), str)
        and "description" in metadata
        and isinstance(metadata["description"], (str, type(None)))
    )
    return {
        "repository": metadata["full_name"],
        "description": metadata["description"],
        "default_branch": metadata["default_branch"],
        "documentation_index": index,
        "sources": [metadata["html_url"], "https://deepwiki.com/" + inputs["repository"]],
    }
