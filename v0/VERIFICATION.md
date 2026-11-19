# Target implementation acceptance and evidence

The connector release is covered by [the 2026-11-19 report](deployment/CONNECTORS.md) and its [bounded acceptance record](verification/connectors-20261119/ACCEPTANCE.md). The earlier candidate evidence below remains attached to its recorded inputs.

Original implementation verified on 2026-11-18. Implementation and tests are under `v0`; work used the existing checkout. The checkout has no Git metadata. `verification/initial-files.json` records the initial authored files. Superseded prototype source contracts, example interfaces, routing/delegation implementations, and tests were replaced rather than retained as compatibility paths.

The target uses Codex App Server, immutable outcome contracts, receiver-owned authorization, explicit admission, deterministic routing, bounded delegation, parent verification, durable operation identities, and owner-authorized diagnostics.

## Candidate checks

| Check | Command and observed result |
|---|---|
| Whole affected suite | `v0/.venv/bin/python -m pytest -q v0/tests` — **109 passed in 37.46s** |
| Semantic verdict observability and unchanged-obligation caching | `v0/.venv/bin/python -m pytest -q v0/tests/test_admission.py::test_independent_verification_can_reject_schema_valid_claim v0/tests/test_durability.py::test_changed_requirements_cannot_reuse_semantic_verdict v0/tests/test_codex.py` — **3 passed in 6.17s** after recording short verdict reasons |
| Execution-scoped tool identity and actual Codex carrier | `v0/.venv/bin/python -m pytest -q v0/tests/test_gateway.py v0/tests/test_codex.py` — **8 passed in 7.80s**, including the added operation-namespace regression |
| Parent-mediated child diagnostic API | `v0/.venv/bin/python -m pytest -q v0/tests/test_routing.py::test_two_service_http_preferences_and_diagnostics` — **2 passed** with the additional child-trace assertions |
| Managed workload credential refresh | `v0/.venv/bin/python -m pytest -q v0/tests/test_workload_credentials.py v0/tests/test_discovery.py v0/tests/test_routing.py::test_two_service_http_preferences_and_diagnostics` — **12 passed in 2.35s**; discovery/task requests reread rotated private token files. Authenticated artifact retrieval is covered by the later boundary suite. |
| Durable evidence delivered to independent verification | `v0/.venv/bin/python -m pytest -q v0/tests/test_verification_evidence.py v0/tests/test_admission.py v0/tests/test_durability.py v0/tests/test_boundaries.py v0/tests/test_routing.py v0/tests/test_codex.py v0/tests/test_connectors.py v0/tests/test_workload_credentials.py` — **83 passed in 23.08s**; genuine receipts/artifact bytes reach verification, unsupported claims and explicit negative verdicts remain rejected, changed trusted facts invalidate caching |
| Artifact provenance boundaries and time ceilings after evidence delivery changes | `v0/.venv/bin/python -m pytest -q v0/tests/test_verification_evidence.py::test_artifact_material_rejects_other_task_or_corrupt_snapshot v0/tests/test_time_limits.py` — **10 passed in 6.22s** |
| Final evidence redaction lifetime and native carrier | `v0/.venv/bin/python -m pytest -q v0/tests/test_verification_evidence.py v0/tests/test_gateway.py v0/tests/test_codex.py` — **14 passed in 8.83s**; task-scoped ephemeral secrets remain available for redaction through final verification, then are cleared |
| Hard elapsed-time ceilings and affected runtime checks | `v0/.venv/bin/python -m pytest -q v0/tests/test_time_limits.py v0/tests/test_admission.py v0/tests/test_routing.py v0/tests/test_durability.py v0/tests/test_gateway.py v0/tests/test_codex.py v0/tests/test_connectors.py v0/tests/test_boundaries.py v0/tests/test_enclosure.py v0/tests/test_task_client.py` — **94 passed in 25.35s** |
| Model operation stalls and cleanup crossing the task expiry | `v0/.venv/bin/python -m pytest -q 'v0/tests/test_time_limits.py::test_stalled_runtime_stops_at_allocation[cleanup]' v0/tests/test_time_limits.py::test_stalled_gateway_model_obeys_operation_expiry` — **3 passed in 2.55s**, after strengthening the cleanup fixture and adding both gateway wait phases |
| Lint | `v0/.venv/bin/python -m ruff check v0/lasa_service v0/tests v0/evaluations v0/run_task.py v0/tools v0/design/validate.py v0/deployment --output-format concise` — clean |
| Contracts and fixtures | `v0/.venv/bin/python v0/design/validate.py` — **32 JSON documents, 44 contract definitions, 24 positive examples, 32 negative cases, 145 resolved authored references, 20 OpenAPI operations** |
| Pinned execution image | `docker build --pull=false --build-arg CODEX_VERSION=0.169.0-alpha.11.1 -t lasa-codex:target-v1 v0` — built; immutable ID and version in [image.json](verification/image.json) |
| Distribution and installed-wheel checks | Exact commands and machine results are in [package-check.json](verification/package-check.json); artifacts are under `verification/dist` |

The last whole-suite run and subsequent focused checks are distinct evidence. Unchanged passing checks were retained; the new diagnostic and operation-identity checks were run after their relevant edits. No assertion is made that mocked execution alone verifies Codex or model behavior.

The final elapsed-time correction anchors effective task deadlines at receipt and intersects absolute deadlines with monotonic task, assessment, active-step, and model-operation expiries. Model requests and streamed responses, tool waits, and runtime execution are interrupted at the tightest ceiling. Cleanup uses a separate bounded confirmation window; an unconfirmed stop or pending effect yields `indeterminate`, never completion. The nine elapsed-time cases use controlled stalled runtime/HTTP/connector fixtures. Actual Codex carrier, MCP, routing, cancellation, and durability checks passed in the affected run. Existing actual-model observations below remain evidence of those recorded runs; they were not rerun after this timer correction.

## Requirement-to-code acceptance matrix

Requirement IDs follow the bullets in [the runtime acceptance checklist](design/acceptance.md). All rows are implemented within the declared execution profile; limitations below remain explicit.

| Requirement | Implementation ownership | Passing test/evaluation evidence |
|---|---|---|
| 1.1 Immutable identities, canonical digests, publisher trust, offline schemas | [contracts.py](lasa_service/contracts.py), [capabilities.py](lasa_service/capabilities.py) | `test_publication`: invalid definitions, duplicate/noncanonical JSON, immutable version/publisher namespace, exact digest and remote-reference rejection; artifact negative fixtures |
| 1.2 Caller-scoped publication from approved fulfillment | `Publication`, `CapabilityRegistry`, [config.py](lasa_service/config.py) | Caller-scoped paging/private separation; exact verifier binding and suffix regression; delegated capability without a parent local binding |
| 1.3 Offers, availability, authority, withdrawal and pinned history | `Publication`, [auth.py](lasa_service/auth.py), [store.py](lasa_service/store.py) | Offer revision/withdrawal/history test; policy-view changes; availability HTTP tests; exact admission records |
| 1.4 Effects and postconditions; inability is not fulfillment | Registry output checks, `Planner.verify`, delegation result verification | Schema-valid claim rejected independently; required criterion coverage; fallback `unable` fails the required review; actual fallback evaluation |
| 2.1 Configured prefixed discovery and registered bootstrap | [discovery.py](lasa_service/discovery.py), [peer.py](lasa_service/peer.py) | Prefixed HTTP discovery, catalog GET/HEAD/profile/link checks, no old well-known route; real two-layer HTTPS evaluations |
| 2.2 TLS, identity, token validation, links and negotiation | `Authentication`, `Configuration`, `PeerClient` | Real TLS socket accepts configured CA and rejects untrusted CA; JWT issuer/audience/subject/expiry/algorithm/key-URL cases; identity mismatch and link-boundary checks |
| 2.3 Private caches, ETags, coherent paging and unknown discovery | `Discovery.response`, `Publication.catalog`, `PeerClient.discover` | 304/private-view tests; revision-pinned cursors; policy-change 409; unreachable peer remains unknown and cannot trigger fallback |
| 3.1 Receiver authority bound to exact request and resources | `Authorization.resolve`, `Coordinator.permits`, dispatch ceilings | Forged/expanded request rejection; changed policy revocation; narrow binding versus broad caller; dispatch attenuation and independent receiving policy; capability absent from local binding |
| 3.2 Durable receipt differs from acceptance; bounded evaluation | [coordinator.py](lasa_service/coordinator.py), `ModelService`, `Store` | `evaluating` response before execution; no work on rejected authority; post-receipt/admission faults; stalled assessment interrupted at its own ceiling; actual planning and independent plan check before child execution |
| 3.3 Plan coverage/DAG, preconditions and reservations | [planning.py](lasa_service/planning.py), [preconditions.py](lasa_service/preconditions.py), `RoutingController.allocate` | Cycle/coverage/aggregate tests; unknown preconditions; zero step-tool/artifact quotas; last assessment usage accounted before child admission; semantic plan gate and frozen assessment corpus |
| 3.4 Trusted bounded envelopes, ancestry, hops, disclosure and data | `Authorization.resolve`, [delegation.py](lasa_service/delegation.py), ledger | Sender/loop/digest/hop tests; altered allocation and budget fixtures; current-policy ceiling test; bounded child HTTP requests and aggregate reservations |
| 4.1 Routing table and separate model-assessment quality | [routing.py](lasa_service/routing.py), `Planner` | Deterministic table tests plus three frozen actual-model assessment cases; actual proposed assessments and declared requirement coverage saved separately from controller facts |
| 4.2 Both preferences and no-peer settings ignored | `decide`, `RoutingController` | Both preference tests; 12 no-peer combinations; real local-first, delegate-first and no-peer observations |
| 4.3 Exact fallback conjunction, explicit generic contract | Router qualification and delegation input conversion | Enabled/disabled fresh-unclaimed cases; unknown/busy/denied/precondition cases never become unclaimed fallback; actual generic-attempt fallback evidence |
| 4.4 Parent owns bounded child work and final integration | `DelegationController.execute`, `Planner.verify`, release | Task/request/contract linkage, corrupt bytes, underreported/cumulative artifact budget, quarantined imports, missing evidence tests; actual parent and child model calls |
| 4.5 Refusal/inability/capacity is not silent completion | Delegation failure handling, controller terminal states | Fallback unable test; unsuitable claims use admissible local execution; failed/uncertain children do not cause blind replay |
| 5.1 Durable identities through lost responses and crashes | `Store.operations`, action ledger, operation receipt API | Duplicate key and operation-ID tests; changed-content conflict; failures before/after receipt/admission/release; lost child acknowledgment; actual process death after a committed write |
| 5.2 Cancellation, deadlines, reconciliation and immutable terminals | Controller lifecycle, central monotonic expiry, child reconciliation, artifact quarantine | [test_time_limits.py](tests/test_time_limits.py): stalled runtime, assessment/execution model, gateway headers/stream, and connector; 1-second task versus later deadline; 200-ms step; unknown effect; bounded unconfirmed cleanup across task expiry. Revision-guarded cancel, lost-child reconciliation, append-only write resolution, no replay after actual process death; late/unverified imports remain unreleased |
| 5.3 External effects controlled by approved bindings | Configuration and broker effect gates | External-write bindings rejected. Supported workspace writes have durable intent, stable operation identity and reconciliation; uncontrolled external writes are not published |
| 5.4 Useful local/child operation evidence and accounting | [diagnostics.py](lasa_service/diagnostics.py), events and delegation-report APIs | Actual layer-1/layer-2 call metadata, reservation versus usage records, parent-mediated child traces, actual native Codex carrier, actual stdio MCP connector, real HTTPS CLI subprocess |
| 5.5 Content permission, redaction, truncation and isolation | Diagnostics producer and owner-scoped API | Content denied without independent grant; secret redaction and truncation retain headers/digests; owner isolation; current policy removes content; short semantic rejection reasons now persisted |

## Actual model evaluations

All accepted observations use actual `gpt-5.5` inference at the configured OpenAI Responses endpoint. Both layers use actual Codex App Server containers, independent sessions/workspaces, receiver policies, and real isolated HTTPS sockets. No model/planner/verifier mocks were used for these evaluations. Private model credentials were reused without printing them.

[accepted-model-evidence.json](verification/accepted-model-evidence.json) pins each raw evidence file by SHA-256. Raw files preserve task state, routing decisions, model-call metadata, actual model assessments, and child traces. Historical failed implementation trials remain on disk.

| Scenario | Observed disposition | Layer-1 model calls | Layer-2 model calls |
|---|---|---:|---:|
| local-first, both suitable | completed locally | 4 | 0 |
| delegate-first, both suitable | completed through layer 2 | 4 | 2 |
| local insufficient + peer unclaimed, fallback disabled | rejected without child work | 1 | 0 |
| local insufficient + peer unclaimed, fallback enabled | completed through advertised generic attempt and parent verification | 5 | 2 |
| no peer, preference/fallback settings present | completed locally in the instrumented observation | 2 | 0 |
| supplied-context assessment corpus | sufficient; completed | 4 | 0 |
| required network access missing | insufficient; rejected | 1 | 0 |
| required evidence unsupplied | conservative uncertainty/insufficiency; rejected | 1 | 0 |

Exact bounded commands and results:

```text
v0/.venv/bin/python v0/evaluations/run_evaluations.py --output v0/verification/final-model-evaluations
  6/8 passed; the two peer execution cases exposed pre-admission allocation accounting.

v0/.venv/bin/python v0/evaluations/run_evaluations.py --cases delegate_first fallback_enabled --output v0/verification/peer-evaluations-v2
  2/2 passed after settled assessment usage was included in final allocations.

v0/.venv/bin/python v0/evaluations/run_evaluations.py --cases local_first fallback_disabled no_peer assessment_supplied_context_supported assessment_required_network_access_missing assessment_required_evidence_unsupplied --output v0/verification/final-remaining-evaluations
  5/6 passed; no_peer routed locally but was rejected by semantic verification.

v0/.venv/bin/python v0/evaluations/run_evaluations.py --cases no_peer --output v0/verification/no-peer-verdict-observation
  1/1 passed in one bounded observation after short-verdict diagnostic recording was added.
```

The no-peer rejection in `final-remaining-evaluations` is **retained as a counterexample**, not erased by the later completion. Its output passed structural/coverage checks; the independent semantic verifier returned false. The earlier metadata view did not retain the short reason. The observability correction now records verdict reasons, and its focused regression proves rejection remains enforced. Verification rules and prompts were not weakened. The later passing observation does not establish that the earlier rejection was erroneous or eliminate model-quality uncertainty.

The frozen assessment corpus has three task-specific cases. It demonstrates conservative behavior for these inputs, not general planning or verification correctness. Repeated actual-model runs may yield guarded failures.

## Packaging and process ownership

The [release validation procedure](deployment/DEPLOYMENT.md#release-upgrades-and-rollback) checks both archives against the checkout, verifies a clean installation, and can confirm that both managed hosts run the wheel. The [original package-check report](verification/package-check.json) records the historical 1.0.0 observations and hashes.

[cleanup.json](verification/cleanup.json) records the final task-owned process/container check. The pinned image is retained as a reusable artifact. Test services/listeners, MCP fixtures, Codex clients, and task containers are closed.

## Deployment status and limits

The initial implementation evidence above used isolated services. A separately authorized deployment now provisions the managed local/air188 services; actual HTTPS observations, final service/configuration revisions, operational commands, and retained failures are recorded in [the deployment report](deployment/DEPLOYMENT.md). Prototype stores/workspaces and saved model credentials are preserved. Target stores and receiver-scoped JWT trust use separate directories.

The current execution profile approves five verifier profiles: design review, generic attempt, LASA document read, repository document-name search, and repository inspection. Read-only application JSON GET and both supported MCP transports remain private fulfillment mechanisms. External-write bindings are rejected. Immediate peers are administratively trusted; this core does not claim adversarial federation, cryptographic global-budget enforcement, or formal semantic truth. Model correctness remains probabilistic, including the retained semantic rejection above. Artifact/schema tests alone do not establish any of those stronger assurances.
