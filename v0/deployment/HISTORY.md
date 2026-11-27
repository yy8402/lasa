# Managed deployment history

The Mac parent and both air188 backends use the `lasa-service` package and the `lasa-supervisor` and `lasa-codex-worker` images. The `1.0.0` release uses wire protocol `lasa/1.0.0`, the `1.0.0` service manifest and descriptor formats, and OpenAPI `info.version` set to `1.0.0`.

| Service | HTTPS API | Container | Authentication |
| --- | --- | --- | --- |
| Mac parent | `https://localhost:8443/lasa/v1` | `lasa-parent` | JWT |
| air188 primary | `https://192.168.0.188/lasa/v1` | `lasa-primary` | JWT |
| air188 review | `https://192.168.0.188/review/lasa/v1` | `lasa-review` | Static token with workload identity pin |

## Historical 1.0.0 deployment verification

On November 23, 2026, the Mac parent and both air188 backends passed `lasa config check` at deployment revision `docker-1.0.0-unified-43e45cad4420`. All three authenticated HTTPS endpoints advertised wire protocol `lasa/1.0.0`, descriptor format `1.0.0`, and OpenAPI `info.version` `1.0.0`. The Mac JWT renewal job also passed with the updated package.

The clean-slate cutover archived 16 previous Mac tasks, 13 air188 primary tasks, and 14 air188 review tasks. Each host keeps the verified archives and retired settings under `~/.local/state/lasa/archives/pre-1.0.0-20261123/`. The format alignment uses fresh SQLite stores at schema revision `1` and keeps the earlier verification stores under `~/.local/state/lasa/archives/pre-unified-1.0.0-20261123/`.

Live task `task-b37a936281b54a498dd5aaf6a510305e` finished with disposition `fulfilled`. Air188 review ran `design.review` with a pinned static-token workload identity, and air188 primary ran the dependent `task.attempt` using JWT. The primary verifier received the review output, and the Mac verified the original inputs from both steps. Both child traces remained readable after the predecessor containers were retired.

Air188 primary also completed `documents.read` in task `task-204474f7c39243e1a51b587f02053170`. The returned `README.md` digest matched the approved file. Run receipts and diagnostics are in the Mac's private `~/.local/state/lasa/releases/1.0.0/unified-formats/` directory.

## Historical typed workflow rollout and live benchmark

The benchmark used revision `docker-1.0.0-typed-982347ae1b54` across all three supervisors with their existing service identities, task stores, and workspaces. The Mac publishes `design.review-checklist` to the operator under `review-checklist`. The authorization rule pins the static-token review peer for `design.review` and the JWT primary peer for `task.attempt`, with a separate verifier revision pin for each grant. Both receivers use `gpt-6-luna` with low reasoning effort for outcome verification and `gpt-5.5` for execution. The Mac keeps its own verifier for independent checks when policy calls for them.

The typed benchmark used the cutover and rollback design from the earlier open-ended task. Elapsed time is measured from receipt to completion on the Mac. The first attempt reached both peers and failed verification because the checklist added conditions beyond the review evidence. The three timed runs specified readiness, rollback, and retirement as explicit review criteria and asked the checklist to preserve exactly those gates.

| Parent task | Elapsed | Model calls |
| --- | ---: | ---: |
| `task-ff7d8d424eb2445d95682079f7fee623` | 52.5 s | 4 |
| `task-b44087e4386e4c42a2ac6170ac0f362d` | 47.6 s | 4 |
| `task-c20b697350694366a5a1ec080d36c253` | 43.9 s | 4 |

Each air188 backend made one execution call and one verification call. The Mac accepted both exact, policy-pinned receipts, confirmed the review output matched primary's dependency, and assembled the result without asking a model. Earlier comparable open-ended tasks took 149–162 seconds and ten model calls. The Mac keeps benchmark inputs, traces, the initial rejection, and rollout evidence under `~/.local/state/lasa/releases/1.0.0/typed-workflows/`.

## Verified consumer API rollout

On November 25, 2026, the Mac parent and both air188 receivers moved to `consumer-api-20261125-6121eeb73c44` using the same immutable supervisor, launcher, and worker image IDs. The three predecessor stores were idle at cutover. The candidate used separate schema-3 stores and retained the verified predecessor images, configuration, stores, and container records for rollback.

The authenticated HTTPS canary and deployed workflow verified review on air188 review using its static-token workload relationship, followed by the dependent checklist on air188 primary using JWT. The Mac independently verified both results. Private records bind the exact review handoff to a fresh disclosure decision for the selected receiver. Air188 primary returned the approved document with a matching source digest. The consumer transcript passed the closed schema and identifier checks, and the consumer credential was denied on the operator endpoints. [Air188 isolation](air188.md)

## Verified processing-boundary and recursive-fulfillment rollout

The qualified November 25, 2026 candidate is `processing-recursive-20261125-37be3fc1cca5`. Mac and air188 reported matching immutable image IDs. The final worker was reused from the earlier test-source snapshot because all its build inputs were identical.

| Image | Immutable ID |
| --- | --- |
| Supervisor | `sha256:c5fb362e1e8cc1b99430347c436e762323c45931712bbd3f729c0ffe9bcf2cc9` |
| Launcher | `sha256:76a89fb758f70c5f34c760b200a6de9a9c84938df45b932c298699a22214cdf1` |
| Codex worker | `sha256:d1f54d26b7053daa0797e0c100c81bb153870560e5ffa5750a88368bd97f74b3` |

The authenticated canary verified the Mac workflow with the air188 static-token and JWT relationships, exact handoff and release decisions, and the approved document digest. The first production attempt completed the workflow, then the `documents.read` verification encountered an inference transport failure before the connector ran. The rollout restored and reverified all three predecessor HTTPS services. The isolated candidate subsequently completed the same approved read, and fresh retry stores were staged with the same immutable images. The preserved first-attempt log, diagnostic and rollback evidence are `managed-cutover-attempt-1.log`, `primary-production-read-diagnostic.private.json`, and `rollback/` under the Mac release evidence root.

The retry deployed the candidate to the Mac parent and both air188 receivers. All three stores were idle at the cutover gate. The deployed Mac workflow and air188 `documents.read` passed over authenticated HTTPS. Private evidence binds the verified review to a fresh disclosure decision for the exact checklist request and confirms the approved document digest. Consumer discovery, progress, receipts, results, and artifact retrieval preserved the caller boundary. The consumer credential was denied operator traces. `postflight-running.json` confirms the running supervisor and launcher IDs and immutable worker pin on each role. The predecessor containers and state remain available with verified retry snapshots in `rollback-retry/` on the Mac and under `~/.local/state/lasa/releases/1.0.0/processing-recursive-20261125-37be3fc1cca5/evidence/rollback-retry/` on air188.

The production profile publishes `approved_processing` offers and uses the two air188 receivers as leaves. Its model endpoint is outside the service's administrative domain, so `provider_domain_only` offers are unpublished. Independent TLS fixtures qualify domain-only composition and deeper recursion with synthetic data. [Qualification and private evidence locations](../VERIFICATION.md#processing-boundaries-and-recursive-fulfillment-qualification) · [Air188 isolation](air188.md)
