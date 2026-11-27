# LASA Service

Python implementation of the outcome-contract architecture in [design](design/README.md), using Codex App Server as its local execution harness.

A service owns workspace-bound sessions, receiver authorization, asynchronous admission, deterministic routing, bounded delegation, durable operation identity, verification, and released results. A model proposes a plan; it cannot grant permissions or dispatch work directly.

Start with [running instructions](RUNNING.md). Use [run_task.py](run_task.py) to create a session, submit a task, and inspect caller-visible progress. The [acceptance matrix](VERIFICATION.md) records tests and actual-model evaluations separately from deployed-service verification.

The normative protocol lives in [design/api.openapi.json](design/api.openapi.json), [design/contracts.schema.json](design/contracts.schema.json), [design/config.schema.json](design/config.schema.json), and [design/private.schema.json](design/private.schema.json). These same files are packaged as `lasa_contracts`; there is one runtime contract source.

Useful entry points:

- [Capability ownership and semantics](design/capabilities.md)
- [Discovery, identity, and HTTP](design/discovery.md)
- [Optional caller portal](portal/README.md)
- [Admission, routing, execution, and diagnostics](design/execution.md)
- [Implementation acceptance requirements](design/acceptance.md)
- [Private development configuration generator](tools/create_development_config.py)
- [Bounded actual-model evaluations](evaluations/run_evaluations.py)

The [installation guide](deployment/DEPLOYMENT.md) covers a new site and its optional components.
The [operations runbook](deployment/OPERATIONS.md) covers updates, upgrades, and recovery.
