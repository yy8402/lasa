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
- Reject client-supplied policy selectors and delegation envelopes. For the deployed profile, enforce pure/read-only inbound service scopes, one hop per branch, private aggregate reservations, and byte limits.

## 4. Routing and delegation

- Test every row of the routing table with deterministic facts and separately test model assessment quality using a fixed evaluation corpus. Policy tests do not prove model judgment quality.
- When both executors match, `local` selects local and `peer` selects peer. A no-peer service ignores both settings, including `attempt`.
- Preserve the requested contract through routing. Verify that a missing offer never converts a typed outcome into a generic attempt. Admit a generic attempt only through its explicit contract.
- Delegate typed bounded steps, verify child admission and result, and retain parent integration responsibility. Reject schema-valid but insufficient evidence, altered artifacts, mismatched request/contract, and unauthorized output.
- Demonstrate that child `unable`, refusal, or unavailable capacity leaves the original requirement unsatisfied. No silent success or replay of an uncertain effect.

## 5. Durable operations and evidence

- Inject lost responses before/after receipt, admission, effect commit, and result release. Idempotent retries preserve operation identity; changed content conflicts. Crash/restart does not replay work.
- Exercise cancellation, deadline, child timeout, reconciliation, late output quarantine, immutable terminal records, and appended resolutions. Prove `indeterminate` is used when effect disposition is unknown.
- External-write bindings must demonstrate commit receipt/reconciliation and no double execution after uncertainty; otherwise publish only contracts whose effects they can control.
- Verify private operator metadata distinguishes local model/tool calls from direct child tasks, with contract revisions, input digest, decision reason, reservations versus actual usage, and verification outcome.
- Content diagnostics require independent permission and omit secrets/hidden reasoning/private prompts. Truncating payloads preserves operation evidence. Cross-session/caller access is denied.

Runtime acceptance requires deterministic controller tests, HTTP/authorization contract tests, failure-injection integration tests, and bounded end-to-end model evaluations. The [artifact validator](validate.py) supplies design consistency evidence; runtime tests and actual-model evaluations supply the separate implementation evidence.

## 6. Target processing boundaries and recursive fulfillment

- Publish and retrieve both processing offer modes. Prove account restrictions, exact historical offer binding in receipts, fully in-domain success, and failure before any task-bearing egress when an external fallback is healthy. Observe actual traffic and storage paths, including ingress, DLP, model verification, tools, logs, artifact/cache reuse, and recovery after restart or revocation.
- Qualify the same controller at zero, one, two, and at least three downstream edges. Under a domain-only offer, prove that in-domain composition succeeds and an in-domain child with an out-of-domain dependency is ineligible. Prove leaf-by-default behavior, rejection of incompatible recursive offer terms before dispatch, and enforcement of restrictions through derived inputs and branch joins.
- Verify the derived descendant bound at zero and one fan-out and with concurrent siblings. Exercise a bound below and equal to the operator's maximum with only direct-child reservations. Above the maximum, exercise both narrowing the eligible routes and enforcing a private subtree cap. Block recursive dispatch when neither fits. In the capped path, prove a child continues to honor the inherited cap even when its own derived bound is small enough for default mode. Inject a cap commitment mismatch and exhaust the cap with concurrent siblings.
- Prove each downstream deadline preserves the configured minimum time for verification and release after clock uncertainty and timestamp rounding. Exercise too little time to dispatch, expired work, authorized re-entry, and restart or fallback without deadline reset. Verify the lifetime fan-out ceiling under concurrent dispatch, rejection, cancellation, uncertainty, restart, and policy changes. A retry reuses the original operation and charge. A new direct operation needs a new charge.
- Lose a submission acknowledgement at an intermediate node. Reconcile against the same receiver, retaining the direct-child reservation and any capped allocation. Exercise cancellation with an unconfirmed child disposition and a late result. Compare caller-visible discovery, status, errors, receipts, and artifact releases across routes. Inject private provider identifiers into child output, evidence, artifact bytes and metadata to verify the release checks. Prove consumer credentials cannot read operator traces.
