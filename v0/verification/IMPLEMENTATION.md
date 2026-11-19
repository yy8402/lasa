# Target implementation acceptance

Work directly in the current checkout. No Git metadata is available; initial-files.json records the initial authored files. Deployment data and credentials are outside the edited components.

Finite milestones, verified in order:

- [x] 1. Immutable contracts, caller-scoped publication, availability separation and outcome verification.
- [x] 2. Configured discovery, authenticated identity, negotiation, conditional/private caching and stable paging.
- [x] 3. Receiver-owned authorization, durable evaluation/admission, verified plans and bounded reservations.
- [x] 4. Deterministic routing, exact fallback, bounded delegation and parent verification.
- [x] 5. Durable operations, failure/reconciliation, diagnostics and bounded real-model evaluations.

Evidence records distinguish mocked/deterministic tests, actual Codex transport, actual model inference, and deployed services. Existing deployments are not automatically upgraded by changing checkout code.

Milestone 1: `v0/.venv/bin/python -m pytest -q v0/tests/test_publication.py` — 13 passed.

Design corrections made concrete for implementation: private policy/runtime/tools files now have closed schemas; receiver keys may be loaded from a configured local JWKS file or a configured HTTPS URL, never a token-supplied URL. The design bundle itself is the packaged runtime contract source; the superseded contracts directory is removed.

Milestone 1 correction: exact approved verifier references, fail-closed registration, suffix regression — publication suite 14 passed.
Milestone 2: `v0/.venv/bin/python -m pytest -q v0/tests/test_discovery.py` — 9 passed, including real TLS sockets with a configured CA and rejection without that CA. JWT claims/algorithm/key URL rejection, prefixed routes, ETags, policy-scoped pages and peer wire negotiation are covered.

Milestone 3: admission suite 15 passing cases (13 passed on the candidate plus the 2 corrected integration-fixture cases). Covers receipt/acceptance, forged authority, limits, revocation, unknown preconditions, independent semantic refusal, session isolation, revision/idempotent clarification, plan coverage/DAG, terminal ledger closure, binding resources, and zero-tool/zero-artifact step allocations. Full affected suite will run once on the final integrated candidate.

Milestone 4: routing/HTTP integration suite 42 cases passed. Includes exact preference/fallback table, no-peer settings ignored, domain work absent from local bindings, actual parent/child HTTP records, inability, corrupt child/artifact rejection, envelope checks, offer preconditions, and claimed-but-unsuitable peer states. Runtime fixtures are deterministic; real Codex/model evaluation is milestone 5. The existing design table already explicitly allows unknown local plus proven matched peer; no conflicting table change is needed.

Milestone 5 closed with durable failure/reconciliation tests, actual process-death recovery, actual stdio MCP, real Codex transport, HTTPS CLI, and bounded actual-model observations. A semantic no-peer rejection is retained and documented; the short-verdict observability correction has focused passing regression evidence. The final requirement matrix and exact commands/results are in ../VERIFICATION.md.

Hard elapsed-time acceptance was reopened for the confirmed narrower-wall-time versus later-deadline defect, then closed after the central monotonic task/assessment/step/operation expiry correction. Stalled runtime/model/tool regressions and affected native integration checks passed (94 cases in 25.35s). Strengthened cleanup-across-expiry and gateway header/stream regressions passed (3 cases in 2.55s). Cleanup remains separately bounded and unknown disposition stays indeterminate. No unrelated actual-model evaluation was repeated.

Separately authorized deployment exposed a real evidence-delivery gap: independent verification lacked the receiver's recorded write/read facts. It was corrected with bounded task/step receipts, digest-verified artifact bytes, current authority, redaction through final verification, and trusted-facts cache identity. Affected groups passed 83, 10, and 14 checks; the changed real HTTPS tool task completed without weakening verification. Rotating workload file credentials passed 12 discovery/routing checks. Both actual deployed services now run the corrected package; exact identity, package/image/configuration hashes, restart durability, retained failure, and final steady-state outcomes are in ../deployment/DEPLOYMENT.md and deployed-20261118/final-deployment.json.
