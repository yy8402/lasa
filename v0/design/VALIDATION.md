# Artifact validation evidence

The offline command `v0/.venv/bin/python v0/design/validate.py` passed on 2026-11-25. It covered 37 JSON documents, 32 contract definitions, 29 positive examples, 31 negative cases, 168 resolved authored references, 19 OpenAPI operations, and 54 local Markdown links. The official OpenAPI 3.2 meta-schema is pinned with provenance and SHA-256 under `standards/source.json`.

This validates the packaged wire artifacts for the current runtime. The target processing-boundary and recursive-fulfillment requirements have separate [qualification criteria](acceptance.md#6-target-processing-boundaries-and-recursive-fulfillment). Existing runtime, model, package, and deployment evidence is recorded in [the verification matrix](../VERIFICATION.md).
