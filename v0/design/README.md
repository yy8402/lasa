# LASA capabilities, discovery, and routing: proposed architecture

Status: **implemented target contracts**. Updated 2026-11-18. Runtime evidence is in [the acceptance matrix](../VERIFICATION.md).

This package specifies the architecture implemented by the Python runtime. It derives its design from requirements and current standards. Isolated implementation evidence and separately authorized deployed-service verification are distinguished in [the deployment report](../deployment/DEPLOYMENT.md).

The central decision is to make a capability an immutable, versioned **outcome contract**. Keep that contract separate from how a service fulfills it, what a caller may request, present availability, and permission to execute one task. A parent delegates bounded steps and remains responsible for the original request.

Read in this order:

1. [Requirements, boundaries, and decisions](architecture.md)
2. [Capability contracts and ownership](capabilities.md)
3. [Discovery, identity, HTTP API, and caching](discovery.md)
4. [Planning, routing, admission, execution, and evidence](execution.md)
5. [Implementation acceptance checklist](acceptance.md)
6. [Standards and sources](sources.md)

Machine-readable artifacts (also packaged for the runtime):

- [Public and internal contracts](contracts.schema.json), [private configuration](config.schema.json), [private policy/runtime/tools schemas](private.schema.json), and [OpenAPI 3.2.1](api.openapi.json).
- [Examples](examples/manifest.json), including five capability definitions, caller-visible discovery, local configuration, a task and delegation, admission, results, and diagnostics.
- [Design validator](validate.py) and [validation evidence](VALIDATION.md).

Protocol target: `lasa/1.1`. This is a LASA design version, not a claim of conformance to an external LASA specification. JSON examples use reserved example domains and contain no usable credentials. Normative MUST/SHALL statements are LASA requirements; standards references are identified separately. Shapes and behavioral invariants both apply. A discrepancy is a design defect to resolve, not implementation discretion.

This design task has three finite acceptance milestones:

- [x] Settle capability, discovery, authorization, and routing ownership and alternatives.
- [x] Supply explicit schemas, API, configuration, examples, and implementation acceptance criteria.
- [x] Validate the design artifacts offline and record the limits of that evidence.

Run validation from the checkout:

```sh
v0/.venv/bin/python v0/design/validate.py
```

This validates design documents and fixtures. It neither tests nor modifies service execution.
