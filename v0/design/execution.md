# Task admission, routing, delegation, and evidence

## Submission and authority

A task selects a published offer revision and exact capability, provides typed input with its acceptance criteria, and supplies a durable operation ID. It may provide supported task limits. The receiving provider resolves a private `TaskAuthorization` snapshot from the locally authenticated principal and current rules for the selected offer.

The resolver integration MUST bind its decision to principal, receiver service, request digest, contract, expiry, resources/actions, disclosures, allowed delegated contracts, and ceilings. A reference unavailable to the receiver is rejected; the receiver does not trust an arbitrary URL or token issuer supplied in the task. Cross-domain authorization requires an explicitly configured trust profile. Peers in this core are administratively trusted workload identities; receiver policy is still required. Authority resolution is an internal interface, not a public LASA grant-minting API.

Effective authority is the intersection of authenticated receiver policy, the selected offer, the exact contract, supported task limits, and service limits. Empty intersections fail. A service may be authorized to delegate a contract that it cannot execute locally. The local binding catalog never serves as an authorization allowlist.

`202` means durable receipt in `evaluating`, not a promise of fulfillment. Evaluation may use a small separately configured assessment budget and an approved model route for the submitted data. It must not run effectful tools or delegate before admission. The task becomes `accepted` only after authority, input, preconditions, a feasible responsibility plan, and resource reservations pass. Invalid requests can fail synchronously; evaluation can also durably finish as `rejected` with reasons.

A fresh selected offer is pinned at durable receipt together with the receiver authority decision. Its discovery expiry bounds new selection, not the lifetime of this received task. Evaluation rechecks current publication terms (contract, restrictions, ceilings and caller view), authorization, dependencies and the original deadline; expiry renewal alone cannot invalidate its immutable pin. Withdrawal or changed terms still reject admission. Accepted execution continues under its pinned ceilings and current policy checks.

For the target domain guarantee, derive the effective scope before intake inspection and pin it at durable receipt. Revalidate the pinned scope against current revocations before each task-data transfer, including fallback and recovery. See [target boundary enforcement](multi-peer-delegation.md#target-boundary-enforcement).

Supply the planner with authorized contract definitions. Keep offers, peer identities, capacity, and placement policy in the controller. Look up the exact contract under each eligible receiver's authority view after validating the proposed plan. Revalidate the selected offer and capacity before dispatch. A lease renewal can update the offer revision when the terms still match. An admitted alternate can be selected before the first remote mutation. [Multi-peer selection](multi-peer-delegation.md#selection-and-recovery)

## Requirements and decomposition

The controller compiles direct exact-contract calls from their unchanged input and registered workflows from their declared composition. Open objectives can use advisory model decomposition. Assign each mandatory requirement to exactly one step. A supporting step supplies evidence to an owning step through declared dependencies. The controller rejects missing and duplicate ownership, unused steps, and cycles before scoped peer lookup. Validate concrete inputs, the available evidence, and budgets before accepting responsibility. Integration checks the assembled outcome and its evidence.

The parent owns the original objective, final integration, and caller-facing result. Delegating a step does not delegate accountability. Subsequent discoveries can revise the plan before new actions, using the same original authority and remaining budget. Consequential scope changes require a new task authorization/operation; silently extending an accepted objective is forbidden.

### Typed workflows

Publish the built-in `design.review-checklist` capability on a coordinator with downstream peers. Add its exact capability reference to the caller's authorization rule and grant outbound delegation separately for `design.review` and `task.attempt`. The capability takes `review` and `checklist` input objects using the corresponding child schemas. The checklist reserves one requirement slot for a LASA-supplied requirement to use the verified review. LASA compiles the plan in code, applies normal admission and routing, and returns the exact accepted review and checklist under those keys. The workflow uses inline text and allows no workspace or external effects.

LASA validates the provider-issued receipt against the selected receiver and original operation, and verifies each returned outcome independently. The first result becomes an input to the second step only after verification and a fresh disclosure decision for the second receiver.

For an existing HTTPS service, submit the typed input with `run_task.py --capability design.review-checklist --input-json <file>`. Use a consumer credential that receives the workflow offer and select its offer ID when needed.

## Routing policy

Configuration uses two independent choices:

```json
{"routing":{"preferred_executor":"local"}}
```

The controller determines local eligibility from the approved binding, current authority, resource availability, and input preconditions. It determines peer eligibility from an exact contract match, authority, disclosure, current availability, and budget. `preferred_executor` is `local` or `peer` and breaks a tie. A named outcome has no implicit substitution. A caller can explicitly select an authorized `task.attempt`. Its `unable` disposition is an attempt result. A required supporting outcome still needs evidence of fulfillment.

## Provider-local reservations and budgets

LASA submits a standard consumer task to the selected receiver. The request includes the receiver's offer, stable operation ID, typed input, and any approved imports or attachments. Both sides retain their own request digest. The receiver caps pure or read-only execution with its own offer and current policy.

LASA privately reserves each child allocation and keeps the sum of local use, pending work, and integration reserve within the task ceiling. The remote consumer limit contains supported execution dimensions. It carries no LASA topology, ledger, or onwards grants. An uncertain operation holds its reservation. LASA settles a dispatched operation against the original receiver at most once and charges the reserved allocation on terminal confirmation.

Child deadlines precede the parent deadline by the integration reserve. Each receiver checks absolute UTC time and uses monotonic expiry for work. Cap children, plan steps, active tasks, input/output/artifact bytes, model tokens and calls, tool calls, and wall time.

The controller bounds recursion through an inherited absolute deadline, a guaranteed verification and release margin on every edge, and a durable lifetime ceiling on the task's direct child operations. The operator accepts the derived worst-case descendant bound or requires tighter routing or a private subtree cap. A capped branch also reserves each child's full descendant allowance. See [inherited deadlines and lifetime fan-out](multi-peer-delegation.md#inherited-deadlines-and-lifetime-fan-out) and [when to apply a subtree cap](multi-peer-delegation.md#derive-the-bound-before-applying-a-subtree-cap).

Task wall time starts at durable receipt. The effective deadline is the earlier of the requested absolute deadline and receipt plus the requested wall-time allocation; reauthorization cannot reset that anchor. One remaining-time calculation intersects the monotonic task, assessment, active-step, and model-operation expiries with the absolute deadline. Runtime, model HTTP/stream, and tool waits use that ceiling. A separately bounded cleanup/reconciliation window may extend past work expiry to establish disposition, but cannot authorize additional work or release a late result. Failure to confirm a stop is indeterminate and makes the service unavailable for new admission until recovered.

Typed imports identify a dependency with a consumer-local label, exact contract, output, and output digest. The receiving provider binds these data to its authenticated consumer and admitted request. LASA retains producer and resource attribution in its private records. A precondition may authorize an artifact snapshot from the same session or an approved attachment containing its public manifest and UTF-8 text. Both receivers validate the ID, digest, size, type and policy before use. Transfers count against the input byte ceiling.

The parent verifies the provider's authenticated identity, request and operation linkage, receipt, exact contract, typed result, artifact bytes and metadata, effect disposition, and acceptance evidence. It then integrates the result and checks original requirement coverage. Valid JSON is not proof of correctness. Unverifiable work is not silently released as completion.

Semantic verification receives declared predecessor outputs as bounded, redacted evidence. The receiving provider checks the exact admitted request and records its local request and import digests. The parent supplies its own verified predecessor outputs when checking a dependent step. Final verification receives the original inputs from the admitted plan, keyed by step ID, with a digest of each input and redacted content where space allows. Independently verified step outputs carry their contracts, executors, and dependency edges. The verifier uses this evidence to assess the requirements on each step and the integrated result.

For `documents.read`, each receiver independently derives the exact document fields from the verified source result. Semantic verification receives the SHA-256 of the UTF-8 document text and the SHA-256 of the complete canonical JSON evidence artifact in separate fields, along with the document URI and the operation and artifact identities.

The parent records the effect disposition from a validated terminal child response before integrating its output. A confirmed local write produces `known`, including when subsequent verification rejects the outcome. The cross-domain profile requires a completed downstream result to report `none`. An unresolved effect or child disposition produces `unknown` and prevents release. A completed task with no recorded effects reports `none`. An ambiguous child remains attached to its original receiver for reconciliation.

Semantic verification receives bounded receiver-owned execution material alongside candidate claims. Durable tool receipts identify the service/task/step, operation order, disposition, input/result digests, and redacted authorized request/result content. Explicitly selected immutable artifact snapshots have their stored bytes and digest checked again before inclusion. Material is limited to 32 operations, 16 artifacts, and 16 KiB; omitted content is marked. Current task authority and receiver policy restrict included resources and effects. Operator trace content is provisioned in private policy and accessed through a separate operator principal. Private prompts and credentials are excluded. The exact execution-material digest participates in verdict cache identity, so changed facts require a new independent assessment. Receipts establish recorded effects and returned data, not the truth of arbitrary tool content; verification may still reject.

Completed results can include bounded workspace readback receipts. The executing receiver matches a successful workspace read to an earlier successful write of the same bytes at the same path within the task. The receipt records the receiver, task, relative path, operation identities and byte digest. It can repeat a short exact text quote when that text already appears in the released output. The parent validates the authenticated child's receipt and makes it available to independent verification under current workspace authority, with links to any matching verified artifacts.

## Durable lifecycle and failures

Main path: `evaluating → accepted → executing → completed`. Evaluation may enter `awaiting_input`, return to evaluation, or terminate `rejected`. Execution may enter `awaiting_input` or `waiting_child`; it can terminate `failed`, `cancelled`, or `indeterminate`. Any active state may enter `cancelling`; confirmed stop becomes `cancelled` only if effects have known disposition. Otherwise reconciliation is bounded, then `indeterminate`.

`completed` means the selected contract's output and completion checks pass; an attempt contract may validly report `unable`. `failed` reports a known unsuccessful outcome with known effects. `indeterminate` means the service cannot establish the disposition of an operation/effect, including a lost child acknowledgment. No final result promises unperformed rollback. Terminal records are immutable; later evidence is appended as a resolution event/receipt, not a rerun or rewritten success. A separate new task may explicitly consume that resolution.

Cancellation stops new dispatch, propagates to children, and terminates task-owned execution. Already committed external actions may persist. External-write contracts require stable effect operation IDs, commit evidence, idempotency/reconciliation semantics, and explicit unknown-commit outcomes. A binding lacking those controls cannot offer such a contract. No automatic compensation is presumed. Deadlines stop new work; bounded cleanup/reconciliation can finish afterward and must be visible in timestamps. Late child outputs are quarantined and cannot reopen a terminal parent or be released without separate authorization.

Idempotency is scoped to authenticated principal, service, method, concrete route, and `Idempotency-Key`. Mutation requests also carry stable operation IDs. Persist key, canonical request digest, and operation identity before side effects. A lost response reuses the same key/content; changed content under that key returns `409 idempotency_conflict`. Duplicate operation IDs with changed content also conflict. Retain deduplication/tombstone records for the session retention period and advertise that period. After expiry a client must reconcile rather than assume a retry is safe. Idempotency avoids duplicate acceptance; it does not guarantee exactly-once external effects.

Errors distinguish invalid input/precondition, incompatible contract/protocol, denied authority/disclosure, changed offer, capacity exhaustion, deadline, unavailable peer, unknown child outcome, and verification failure. HTTP errors use typed problem details. Retry hints are advisory and cannot override uncertain effect disposition. Before launch, persist the local execution attempt ID. The host-local launcher owns Docker access and creates one disposable worker for the attempt. On restart, use the recorded attempt ID to confirm cleanup through the launcher and settle interrupted task states before readiness. A Docker query failure leaves stop disposition unknown. A background worker reconciles bounded batches of unresolved historical tasks. Reconciliation never reexecutes interrupted work.

The session's `retention_until` is its admission cutoff and the earliest time cleanup can retire it. Active tasks, recorded runtimes, and indeterminate tasks without resolution hold the session. Retirement removes the session, its tasks, receipts, diagnostics, artifacts and allocations in a transaction. That transaction queues deletion of the retired workspace. Filesystem cleanup retries independently after I/O failure or restart.

## Diagnostic evidence

Always retain bounded decision metadata: service/task/step/requirement/operation IDs, ordered sequence, causal parent event, timestamp, input/output digests and sizes, selected contract/offer/catalog revisions, authority decision reference, assessment classification and short justification, policy decision, reservation/usage, actual model/tool/child calls, and result verification disposition. Sequence is local to a task; causal links express cross-service ordering without pretending clocks are exact.

The consumer reads LASA-scoped progress and criterion dispositions. An independently provisioned operator credential can read provider-local traces. Private policy controls whether the bounded trace captures content. Truncated trace entries retain operation headers, digests, and disposition.

Diagnostics can establish that a particular call/dispatch/check happened and what evidence informed routing. They cannot establish hidden model reasoning or prove semantic correctness. Signed receipts may authenticate evidence in a future explicitly negotiated trust profile; this core relies on authenticated immediate peers and durable local records, and must describe that limit honestly.

## Implemented contract clarifications

- LASA checks each candidate against its output schema before semantic assessment. The verifier receives the candidate separately and returns a verdict for each required criterion. A supported verdict references evidence from the receiver's evidence catalog. Exact-input reuse requires a verified step result covering the same contract and criteria.
- Approved semantic verifiers are bound to full contract ID/version/digest references in private `verifiers` configuration. A URI suffix never selects a verifier. Unregistered definitions cannot be offered or admitted.
- Semantic plan coverage is checked independently before acceptance. The check is tool-free and consumes assessment budget. Provisional allocations are recomputed from settled assessment usage before durable admission; reservation checks use that final plan. Offer preconditions disclose mandatory model allocation minimums.
- The sender rechecks current outbound grants and inspection before dispatch. The receiver authenticates the sender and applies its own admission policy to the selected offer.
- All session workspace reads and writes pass through the durable broker. The Codex container starts with empty scratch space and receives no host mounts.
- `GET /operations/{operation_id}` retrieves a caller-owned immutable receipt without resubmitting work. `POST /tasks/{task_id}/reconcile` appends resolution evidence. A missing receipt remains uncertainty; it does not prove that work cannot arrive later. No uncertain operation is automatically replayed.
- Child artifact verification bounds cumulative observed bytes, validates exact task linkage and receipt, and quarantines imports until verification passes.
- `GET /operator/tasks/{task_id}/events` and `/operator/tasks/{task_id}/delegations` require a separately provisioned operator principal. They describe work from this provider’s own store.

The initial execution profile accepts typed JSON/text inputs and produces bounded text artifacts. Capability verification uses receiver-approved profiles. Artifact preconditions without established immutable input evidence fail closed; arbitrary executable validators and external-write effects are not enabled.
