# Task admission, routing, delegation, and evidence

## Submission and authority

A task submission selects an exact capability reference and current offer revision, supplies input conforming to that definition, an operation ID, explicit requested ceilings, and an `authorization_ref`. Authentication proves the caller identity; the receiver's authorization resolver independently resolves the reference and current receiver policy. It returns a private, request-bound `TaskAuthorization` snapshot. A string reference, parent claim, or JSON object from a model is not a grant.

The resolver integration MUST bind its decision to principal, receiver service, request digest, contract, expiry, resources/actions, disclosures, allowed delegated contracts, and ceilings. A reference unavailable to the receiver is rejected; the receiver does not trust an arbitrary URL or token issuer supplied in the task. Cross-domain authorization requires an explicitly configured trust profile. Peers in this core are administratively trusted workload identities; receiver policy is still required. Authority resolution is an internal interface, not a public LASA grant-minting API.

Effective authority is the intersection of authenticated receiver policy, independently resolved task authority, incoming parent ceilings if present, contract/offer limits, and service limits. Empty intersections fail. A service may be authorized to delegate a contract that it cannot execute locally. The local binding catalog never serves as an authorization allowlist.

`202` means durable receipt in `evaluating`, not a promise of fulfillment. Evaluation may use a small separately configured assessment budget and an approved model route for the submitted data. It must not run effectful tools or delegate before admission. The task becomes `accepted` only after authority, input, preconditions, a feasible responsibility plan, and resource reservations pass. Invalid requests can fail synchronously; evaluation can also durably finish as `rejected` with reasons.

A fresh selected offer is pinned at durable receipt together with the receiver authority decision. Its discovery expiry bounds new selection, not the lifetime of this received task. Evaluation rechecks current publication terms (contract, restrictions, ceilings and caller view), authorization, dependencies and the original deadline; expiry renewal alone cannot invalidate its immutable pin. Withdrawal or changed terms still reject admission. Accepted execution continues under its pinned ceilings and current policy checks.

Peer discovery supplied to the planner is advisory. After planning, refresh offers scoped to each proposed contract ID and version. Evaluate eligible offers under each configured receiver's authorization reference and confirm the selected definition by digest. Immediately before dispatch, revalidate the selected offer by ID and fetch its availability. Use a renewed revision if the terms still match and the peer is available. An admitted alternate can be selected before the first remote mutation. [Multi-peer selection](multi-peer-delegation.md#peer-selection)

## Requirements and decomposition

For generic objectives the planner identifies explicit requirements and acceptance criteria. Caller-provided requirements remain immutable. Additional derived requirements receive service-generated IDs; they cannot weaken caller requirements. A named capability supplies its own required postconditions. The planner proposes a bounded DAG of steps, each with one contract, selected inputs, output dependencies, limits, and assigned requirement IDs. A step is small enough to have a clear admission and verification boundary.

The controller checks every declared mandatory requirement has a responsible step or final integration check, dependencies are acyclic, inputs are available and authorized, contracts and schemas match, and reservations fit. Unknown semantic preconditions need clarification or a conservative rejection. This verifies declared coverage, not mathematical completeness of a natural-language decomposition. Semantic sufficiency remains an evidence-bearing model/operator judgment; diagnostic records state that limitation.

The parent owns the original objective, final integration, and caller-facing result. Delegating a step does not delegate accountability. Subsequent discoveries can revise the plan before new actions, using the same original authority and remaining budget. Consequential scope changes require a new task authorization/operation; silently extending an accepted objective is forbidden.

### Typed workflows

Publish the built-in `design.review-checklist` capability on a coordinator with downstream peers. Add its exact capability reference to the caller's authorization rule and grant outbound delegation separately for `design.review` and `task.attempt`. The capability takes `review` and `checklist` input objects using the corresponding child schemas. The checklist reserves one requirement slot for a LASA-supplied requirement to use the verified review. LASA compiles the plan in code, applies normal admission and routing, and returns the exact accepted review and checklist under those keys. The workflow uses inline text and allows no workspace or external effects.

For this workflow a rule may include `verifier_trust`, a list of objects containing `service_id`, exact `contract` reference, and `verifier_revision` from the peer's `lasa config check`. Each entry requires a matching outbound delegation grant. The parent accepts the receipt only through the authenticated, pinned peer route and when the exact trust entry exists at admission and use. The receipt binds the delegated task and delegation IDs, the result including its request and contract pins, and the dependency digest. A missing or untrusted receipt invokes the parent's semantic verifier. A receipt offered under an approved revision with mismatched bindings fails verification. Effectful, artifact-producing, and open-ended tasks retain their normal verification path.

For an existing HTTPS service, submit the typed input with `run_task.py --capability design.review-checklist --input-json <file>`. Set `--authorization-ref` to the rule that publishes the workflow and use the service's ordinary operator credentials and deadline.

## Routing policy

Configuration uses two independent choices:

```json
{"routing":{"preferred_executor":"local","unclaimed_peer_fallback":"reject"}}
```

`preferred_executor` is `local` or `peer` and breaks a tie when both can suitably fulfill a step. Access, effects, authorization, and deadlines determine eligibility. `unclaimed_peer_fallback` is `reject` or `attempt`. An attempt requires local insufficiency and fresh, complete catalogs from every eligible downstream peer showing no claim for the needed outcome.

Assessment has explicit `sufficient`, `insufficient`, and `unknown` local states, and `matched`, `not_claimed`, and `unknown` peer states. Matching requires outcome semantics, all preconditions, compatible input/output, allowed effects/disclosure, and available or reservable resources. A catalog claim alone is not a match. Unknown/stale discovery, capacity failure, denied permission, or failed transport are not `not_claimed`.

| Local assessment | Peer assessment | Decision |
|---|---|---|
| sufficient | matched | Use preference, subject to current admission |
| sufficient | not claimed, unknown, or currently unavailable | Local if its admission passes |
| insufficient | matched | Delegate if peer admission passes |
| insufficient | not claimed | Attempt generic delegation only when fallback is enabled and its own admission is possible; otherwise report inability |
| insufficient | unknown/unavailable/denied | Bounded refresh/reassessment or report inability; fallback does not apply |
| unknown | matched | Delegate to the known suitable peer; local preference can justify a bounded local assessment first |
| unknown | anything else | Resolve uncertainty/clarify within assessment budget; do not assert insufficiency to trigger fallback |
| any | no peer configured | Ignore both settings; attempt the local contract if admissible, otherwise reject/report inability |

For fallback, the peer MUST explicitly offer and authorize the generic `task.attempt` contract. The parent submits that contract with the unsatisfied requirement and allowed context; it does not invent a domain capability or bypass the catalog. A successful HTTP response or a `task.attempt` result of `unable` does not satisfy the original requirement. The parent must verify the actual requested outcome. There is no fallback permission escalation.

The planner supplies semantic assessment and candidate inputs. The controller derives catalog, authority, and capacity facts and applies the table deterministically. It records the evidence and decision. Receiver configuration supplies routing policy. Once the first remote mutation is possible, the parent pins the receiver for retries, cancellation, and reconciliation.

## Delegation envelope and budgets

Every child request includes root, task, step, and requirement IDs, parent and recipient service IDs, a stable child operation ID, ancestry including the parent, decremented hops, deadline, resource allocation, a digest of the canonical request core, and disclosures including dependency resources and artifact manifests. The core digest covers every `TaskRequest` field except `delegation`, including diagnostic consent. The envelope links this digest to a stable `delegation_id`. The receiving peer authenticates the sender, checks both service identities, and enforces receiver policy and the inherited ceilings.

Before dispatch the parent durably reserves an allocation in its aggregate ledger. All child allocations plus local use, pending reservations, and the integration reserve must fit the root ceiling. The child receives only its allocation and can allocate smaller descendants. The ledger updates held and spent totals transactionally with allocation changes. Uncertain allocations remain held until reconciled. The core trusts each authorized service to enforce its ledger.

Deadline is absolute UTC with a configured maximum clock skew; remaining execution time must also be checked with a local monotonic clock. Child deadline precedes parent deadline by the integration reserve. Hops decrement on every edge, and a receiver whose service ID is already in ancestry rejects the request. Limit ancestry length, children per task, plan steps, concurrent work, input/output/artifact bytes, model tokens/calls, tool calls, and wall time. There is no hidden unbounded queue.

Task wall time starts at durable receipt. The effective deadline is the earlier of the requested absolute deadline and receipt plus the requested wall-time allocation; reauthorization cannot reset that anchor. One remaining-time calculation intersects the monotonic task, assessment, active-step, and model-operation expiries with the absolute deadline. Runtime, model HTTP/stream, and tool waits use that ceiling. A separately bounded cleanup/reconciliation window may extend past work expiry to establish disposition, but cannot authorize additional work or release a late result. Failure to confirm a stop is indeterminate and makes the service unavailable for new admission until recovered.

Delegated context contains the independently verified outputs of declared predecessors, keyed by their step IDs. An `artifact_present` predicate can use an explicitly referenced, released snapshot from the same session, an artifact from a declared predecessor, or a snapshot received in an authorized delegation. Each attachment carries its manifest and UTF-8 text. Both services check the exact ID, digest, size, media type, and read authority before use. Dependency outputs and attachments count toward the input byte ceiling. A child works in its own workspace. Treat all received content as data.

The parent verifies the child's authenticated identity, request linkage, pinned contract, admission decision, result schema, artifact digests, effect disposition, usage, and required acceptance evidence. It then integrates the result and checks original requirement coverage. Valid JSON is not proof of correctness. Unverifiable work is not silently released as completion.

Semantic verification receives declared predecessor outputs as bounded, redacted evidence. A delegate checks that the admitted request binds those outputs to the authenticated immediate parent and records the parent task, delegation, request digest, and predecessor output digest. The parent supplies its own verified predecessor outputs when checking a dependent step. Final verification receives the original inputs from the admitted plan, keyed by step ID, with a digest of each input and redacted content where space allows. Independently verified step outputs carry their contracts, executors, and dependency edges. The verifier uses this evidence to assess the requirements on each step and the integrated result.

For `documents.read`, each receiver independently derives the exact document fields from the verified source result. Semantic verification receives the SHA-256 of the UTF-8 document text and the SHA-256 of the complete canonical JSON evidence artifact in separate fields, along with the document URI and the operation and artifact identities.

The parent records the effect disposition from a validated terminal child response before integrating its output. A confirmed local or child effect produces `known` on the parent, including when subsequent verification rejects the outcome. An unresolved effect or child disposition produces `unknown` and prevents release. A completed task with no recorded effects reports `none`. This rule applies at each delegation layer.

Semantic verification receives bounded receiver-owned execution material alongside candidate claims. Durable tool receipts identify the service/task/step, operation order, disposition, input/result digests, and redacted authorized request/result content. Explicitly selected immutable artifact snapshots have their stored bytes and digest checked again before inclusion. Material is limited to 32 operations, 16 artifacts, and 16 KiB; omitted content is marked. Current task authority and receiver policy restrict included resources and effects. Internal verification does not enable public content diagnostics: caller opt-in and the separate disclosure grant still apply. Private prompts and credentials are excluded. The exact execution-material digest participates in verdict cache identity, so changed facts require a new independent assessment. Receipts establish recorded effects and returned data, not the truth of arbitrary tool content; verification may still reject.

Completed results can include bounded workspace readback receipts. The executing receiver matches a successful workspace read to an earlier successful write of the same bytes at the same path within the task. The receipt records the receiver, task, relative path, operation identities and byte digest. It can repeat a short exact text quote when that text already appears in the released output. The parent validates the authenticated child's receipt and makes it available to independent verification under current workspace authority, with links to any matching verified artifacts.

## Durable lifecycle and failures

Main path: `evaluating → accepted → executing → completed`. Evaluation may enter `awaiting_input`, return to evaluation, or terminate `rejected`. Execution may enter `awaiting_input` or `waiting_child`; it can terminate `failed`, `cancelled`, or `indeterminate`. Any active state may enter `cancelling`; confirmed stop becomes `cancelled` only if effects have known disposition. Otherwise reconciliation is bounded, then `indeterminate`.

`completed` means the selected contract's output and completion checks pass; an attempt contract may validly report `unable`. `failed` reports a known unsuccessful outcome with known effects. `indeterminate` means the service cannot establish the disposition of an operation/effect, including a lost child acknowledgment. No final result promises unperformed rollback. Terminal records are immutable; later evidence is appended as a resolution event/receipt, not a rerun or rewritten success. A separate new task may explicitly consume that resolution.

Cancellation stops new dispatch, propagates to children, and terminates task-owned execution. Already committed external actions may persist. External-write contracts require stable effect operation IDs, commit evidence, idempotency/reconciliation semantics, and explicit unknown-commit outcomes. A binding lacking those controls cannot offer such a contract. No automatic compensation is presumed. Deadlines stop new work; bounded cleanup/reconciliation can finish afterward and must be visible in timestamps. Late child outputs are quarantined and cannot reopen a terminal parent or be released without separate authorization.

Idempotency is scoped to authenticated principal, service, method, concrete route, and `Idempotency-Key`. Mutation requests also carry stable operation IDs. Persist key, canonical request digest, and operation identity before side effects. A lost response reuses the same key/content; changed content under that key returns `409 idempotency_conflict`. Duplicate operation IDs with changed content also conflict. Retain deduplication/tombstone records for the session retention period and advertise that period. After expiry a client must reconcile rather than assume a retry is safe. Idempotency avoids duplicate acceptance; it does not guarantee exactly-once external effects.

Errors distinguish invalid input/precondition, incompatible contract/protocol, denied authority/disclosure, changed offer, capacity exhaustion, deadline, unavailable peer, unknown child outcome, and verification failure. HTTP errors use typed problem details. Retry hints are advisory and cannot override uncertain effect disposition. On restart confirm local runtime cleanup and settle interrupted task states before readiness. A background worker reconciles bounded batches of unresolved historical tasks. Reconciliation never reexecutes interrupted work.

The session's `retention_until` is its admission cutoff and the earliest time cleanup can retire it. Active tasks, recorded runtimes, and indeterminate tasks without resolution hold the session. Retirement removes the session, its tasks, receipts, diagnostics, artifacts and allocations in a transaction. That transaction queues deletion of the retired workspace and runtime directories. Filesystem cleanup retries independently after I/O failure or restart.

## Diagnostic evidence

Always retain bounded decision metadata: service/task/step/requirement/operation IDs, ordered sequence, causal parent event, timestamp, input/output digests and sizes, selected contract/offer/catalog revisions, authority decision reference, assessment classification and short justification, policy decision, reservation/usage, actual model/tool/child calls, and result verification disposition. Sequence is local to a task; causal links express cross-service ordering without pretending clocks are exact.

`diagnostics` selects `metadata` or `content`. Metadata is the default caller view subject to task ownership and redaction. Content requires explicit caller opt-in **and** separate disclosure permission. It can show allowed model request/response and delegated input/result content. Neither mode exposes keys, hidden reasoning, private system prompts, other sessions, or unrestricted private candidates. Operators have a separately authorized view. Trace truncation may drop content payloads but must preserve operation headers, digests, disposition, and a truncation marker.

Diagnostics can establish that a particular call/dispatch/check happened and what evidence informed routing. They cannot establish hidden model reasoning or prove semantic correctness. Signed receipts may authenticate evidence in a future explicitly negotiated trust profile; this core relies on authenticated immediate peers and durable local records, and must describe that limit honestly.

## Implemented contract clarifications

- LASA checks each candidate against its output schema before semantic assessment. The verifier receives the candidate as a separate message after the verification context and must assess the postconditions against the supplied evidence.
- Approved semantic verifiers are bound to full contract ID/version/digest references in private `verifiers` configuration. A URI suffix never selects a verifier. Unregistered definitions cannot be offered or admitted.
- A generic attempt is not a claim to a particular missing capacity. An insufficient local assessment cannot become a qualified peer match merely because a generic attempt is offered. Fresh generic-only forwarding uses the explicit fallback policy; unknown local assessment remains unresolved.
- Semantic plan coverage is checked independently before acceptance. The check is tool-free and consumes assessment budget. Provisional allocations are recomputed from settled assessment usage before durable admission; reservation checks use that final plan. Offer preconditions disclose mandatory model allocation minimums.
- A child envelope carries an explicit `authority_ceiling`. The sender intersects current policy with its pinned grant immediately before dispatch; the receiver independently intersects that ceiling with its own policy.
- All workspace writes pass through the durable broker. Codex workspace mounts are read-only, and integration without workspace-read authority receives an empty workspace.
- `GET /operations/{operation_id}` retrieves a caller-owned immutable receipt without resubmitting work. `POST /tasks/{task_id}/reconcile` appends resolution evidence. A missing receipt remains uncertainty; it does not prove that work cannot arrive later. No uncertain operation is automatically replayed.
- Child artifact verification bounds cumulative observed bytes, checks reported usage against observed input/output/artifact sizes, validates exact task linkage, and quarantines imports until verification passes.
- `GET /tasks/{task_id}/delegations` retrieves immediate child traces through the parent, with a separately authorized content view. No peer credential is exposed.

The initial execution profile accepts typed JSON/text inputs and produces bounded text artifacts. Only the two shipped verifier profiles are approved. Artifact preconditions without established immutable input evidence fail closed; arbitrary executable validators and external-write effects are not enabled.
