# Runtime acceptance criteria

These requirements govern the implementation. Results and requirement-to-code mappings are in [the acceptance matrix](../VERIFICATION.md). The implementation replaces superseded prototype components. Changes and tests remain under `v0`.

## 1. Contracts and publication

- Enforce exact immutable capability identities, canonical digests, trusted publisher namespace, and offline embedded-schema validation. Reject remote `$ref`, duplicate JSON keys, invalid versions, and changed content for an existing version.
- Publish caller-scoped offers derived from approved bindings/delegation policy. Prove no model, tool names, provider credentials, or private workspace paths leak.
- Keep availability, offer lifetime, and authority separate. Withdrawn/expired offers cannot admit new tasks; accepted records preserve their pinned versions.
- Enforce contract effect ceilings and postconditions; a generic attempt's `unable` cannot satisfy a mandatory requested outcome.

## 2. Discovery and identity

- Support configured descriptor URLs, prefixed deployments, and multiple APIs on an origin. Optional registered `api-catalog` bootstrap passes RFC 9727/9264 fixtures. Do not implement the old custom well-known path in the target.
- Verify TLS, expected service ID, issuer/audience/subject/algorithm/expiry, and configured link boundary. Reject identity changes, redirects outside the configured boundary, arbitrary JWKS/schema fetches, and incompatible protocol/features.
- Exercise ETag/304, policy-scoped private caches, stable revision paging, expiry, view changes, and `409` rediscovery. A failed/incomplete lookup must not become `not_claimed`.

## 3. Authority and admission

- Bind authorization decisions to exact request digest, principal, receiver, permitted effects/resources/disclosures, delegated contracts, expiry, and budgets. Deny forged reference/parent JSON. Prove a permitted delegated contract need not have a local binding.
- Show `202 evaluating` is distinct from `accepted`. Evaluation uses only approved bounded assessment resources; no effectful action/child dispatch precedes verified admission.
- Verify declared requirement coverage, DAG, schemas, available inputs, preconditions, ledger reservations, and integration reserve. Keep semantic uncertainty explicit.
- Reject untrusted delegation envelopes, loops, expanded authority, exhausted hops, oversubscribed aggregate budgets, and excessive data. No hidden queue.

## 4. Routing and delegation

- Test every row of the routing table with deterministic facts and separately test model assessment quality using a fixed evaluation corpus. Policy tests do not prove model judgment quality.
- When both executors match, `local` selects local and `peer` selects peer. A no-peer service ignores both settings, including `attempt`.
- Local insufficiency plus fresh `not_claimed`: `reject` reports inability; `attempt` uses only an advertised/authorized generic attempt. Distinguish peer unknown, denied, busy, stale catalog, and transport failure; none triggers this fallback.
- Delegate typed bounded steps, verify child admission and result, and retain parent integration responsibility. Reject schema-valid but insufficient evidence, altered artifacts, mismatched request/contract, and unauthorized output.
- Demonstrate that child `unable`, refusal, or unavailable capacity leaves the original requirement unsatisfied. No silent success or replay of an uncertain effect.

## 5. Durable operations and evidence

- Inject lost responses before/after receipt, admission, effect commit, and result release. Idempotent retries preserve operation identity; changed content conflicts. Crash/restart does not replay work.
- Exercise cancellation, deadline, child timeout, reconciliation, late output quarantine, immutable terminal records, and appended resolutions. Prove `indeterminate` is used when effect disposition is unknown.
- External-write bindings must demonstrate commit receipt/reconciliation and no double execution after uncertainty; otherwise publish only contracts whose effects they can control.
- Verify metadata shows actual layer-1 model/tool calls and layer-2 delegation separately, with contract revisions, input digest, decision reason, reservations versus actual usage, and verification outcome.
- Content diagnostics require independent permission and omit secrets/hidden reasoning/private prompts. Truncating payloads preserves operation evidence. Cross-session/caller access is denied.

Runtime acceptance requires deterministic controller tests, HTTP/authorization contract tests, failure-injection integration tests, and bounded end-to-end model evaluations. The [artifact validator](validate.py) supplies design consistency evidence; runtime tests and actual-model evaluations supply the separate implementation evidence.
