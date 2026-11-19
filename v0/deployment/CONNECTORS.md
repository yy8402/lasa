# Managed application and MCP integration release

Release 1.1.0 uses protocol `lasa/1.1`. Both layers use Codex App Server with gpt-5.5 at `https://api.openai.com/v1/`. Deployment acceptance is complete. Both managed services are running in their intended steady profile. The finite checklist and retained observations are in [ACCEPTANCE.md](../verification/connectors-20261119/ACCEPTANCE.md).

## Public outcomes and private fulfillment

| Approved outcome | Layer 2 fulfillment | Scope |
|---|---|---|
| `documents.read` | `@modelcontextprotocol/server-filesystem@2.4.0`, stdio MCP, isolated Node 24.22.3 | Exact full reads of three copied LASA documents; selected task document must match the approved path |
| `documents.search` | GitHub HTTPS JSON GET application interface | Case-insensitive substring search of top-level Markdown filenames in `modelcontextprotocol/python-sdk`; not full-text search |
| `repository.inspect` | GitHub repository metadata plus DeepWiki Streamable HTTP MCP | The same public repository, exact metadata and documentation index |

The existing `design.review` and `task.attempt` outcomes remain available. Layer 1 has no external connector bindings. It publishes the approved delegated outcomes and discovers layer 2 through its configured authenticated HTTPS descriptor. Public catalogs expose outcome contracts, restrictions, limits and availability; they do not expose private endpoints, launch commands, credentials or raw tool schemas. Installing an App/MCP never publishes a capability or grants task authority by itself.

Private `ConnectorPolicy.connectors` is the only integration registry. A binding's `required_operations` defines its dependencies and external-operation allowlist. Effective calls intersect the binding, selected task inputs, caller authority, current receiver policy, remaining budget and deadline. The public sources need no external credentials; configured private credentials use explicit administrator-owned file/environment references with refresh behavior.

Successful source calls produce durable receipts and immutable server-issued operation-result artifacts. Exact content, UTF-8 hashes, source identifiers, search results and repository fields are assembled and corroborated by the server. The independent semantic verifier receives those checks and the bounded source facts; it can still reject release. The parent checks child linkage and imported artifact bytes before its own verification. A child saying complete is insufficient.

Core readiness is separate from optional dependency readiness. An outage retains the capability claim and changes its availability. Busy, unavailable, unauthorized and unknown never become unclaimed. `unclaimed_peer_fallback=attempt` applies only to a fresh missing claim together with local insufficiency. The intended steady routing is peer preferred on layer 1 and no peer on layer 2.

## Operation

Canonical APIs remain `https://localhost:8443/lasa/v1` and `https://192.168.0.188/lasa/v1`. SSH is used for administration only. Runtime calls use receiver-scoped JWTs and verified HTTPS; the existing hourly six-hour token renewal remains managed on the Mac.

From the repository root, retrieve a LASA document through layer 1 with diagnostic content:

```sh
LASA_ACCESS_TOKEN="$(cat v0/.deploy/target/layer1/operator-token.txt)" \
v0/.venv/bin/python v0/run_task.py \
  --base-url https://localhost:8443/lasa/v1 \
  --ca-file "$HOME/.config/lasa/two-layer/tls/ca.pem" \
  --capability documents.read \
  --input-json v0/verification/connectors-20261119/documents-read-input.json \
  --diagnostics content
```

Use `architecture.md` or `capabilities.md` for the other approved LASA documents. For the public integrations, select `documents.search` with `{"collection":"python-sdk-root","query":"read","limit":5}`, or `repository.inspect` with `{"repository":"modelcontextprotocol/python-sdk"}`. Content diagnostics require separate receiver permission; metadata diagnostics remain available without that content permission.

`prepare_connectors.py` staged the initial connector policies and approved document corpus. Use the [managed release tool](DEPLOYMENT.md#release-upgrades-and-rollback) to update both installed backends. `run_service.py` imports the installed package in isolated Python mode. `verify_deployed.py` creates a session, submits a typed task, and records actual model/tool/child traces. Use a distinct case name for each observation.

## Acceptance evidence

| Milestone | Observed outcome | Evidence |
|---|---|---|
| Closed contracts and private dependencies | Five approved outcome/verifier profiles; three private connector kinds; explicit scopes and required operations | [Design](../design/connectors.md), packaged schemas/examples |
| Controller, transports and evidence | Initial complete suite: 160 passed (43.37s). Live-driven corrections: 119 affected checks passed (26.39s), then 37 remaining affected runtime checks passed (17.49s). Nine unchanged transport cases retain their valid earlier passing evidence. Scoped lint and offline contract validation pass | [Full suite](../verification/connectors-20261119/pytest-full.log), [corrections](../verification/connectors-20261119/pytest-live-corrections.log), [runtime checks](../verification/connectors-20261119/pytest-live-runtime.log) |
| Actual filesystem MCP | Document task completed through layer 1 -> layer 2; one source tool operation; exact document bytes and server-computed hash verified | [Document observation](../verification/connectors-20261119/documents-read-verified.json) |
| Actual application API | GitHub filename search completed through layer 2; returned README.md with its source URI | [Search observation](../verification/connectors-20261119/documents-search-verified.json) |
| Actual Streamable HTTP MCP | Repository inspection completed through layer 2 using both GitHub metadata and the exact DeepWiki documentation index | [Inspection observation](../verification/connectors-20261119/repository-inspect-verified.json) |
| Claimed dependency outage | All five claims retained; only document read became unavailable; both core services remained ready. Layer 1 observed local insufficient + peer unavailable, selected none, and created zero children with fallback enabled | [Outage state](../verification/connectors-20261119/outage-down.json), [routing rejection](../verification/connectors-20261119/claimed-source-outage.json) |
| Isolation and recovery | Unrelated review completed locally on layer 2 during the outage. Original filesystem entry restored with matching hash, all offers available, new delegated document task completed | [Unrelated work](../verification/connectors-20261119/unrelated-during-outage.json), [restoration](../verification/connectors-20261119/outage-up.json), [recovered task](../verification/connectors-20261119/source-recovered.json) |
| Diagnostics and credentials | Content request without permission rejected HTTP 403 before inference; four receiver-scoped token files rotated, six-hour lifetime, 0600, hourly renewal retained; no saved model/service token values in JSON evidence | [Permission check](../verification/connectors-20261119/content-permission-denied.json), [token renewal](../verification/connectors-20261119/token-renewal.json), final inventory |
| Restart, source facts and ownership | Both backends restarted; completed task/session/parent-mediated child traces/artifact bytes unchanged. Independent client rechecked all three source outputs against downloaded artifacts. No owned task containers remain | [Persistence](../verification/connectors-20261119/restart-persistence.json), [source bytes](../verification/connectors-20261119/source-byte-checks.json) |
| Installed package parity | 76 runtime/contract files match checkout and wheel on each host; isolated Python imports installed packages; both HTTPS services ready, layer 2 all five outcomes available, intended routing restored | [Final inventory](../verification/connectors-20261119/final-inventory.json) |

Final wheel SHA-256: `45e5f26c1b1ac59d015e5df2befa5446eed8b87e110c1bf0c1952389a84a12fd`. Both service revisions are `connectors-20261119-45e5f26c1b1a-steady`. The pinned Codex carrier/root filesystem, private CA, workspace stores and signing keys were retained. Layer 2 runs the isolated Node 24.22.3 runtime and filesystem server 2.4.0. Final per-host configuration/policy/runtime hashes and task dispositions are recorded in the inventory.

Layer 1's three delegation-only offers report availability `unknown` until a task evaluates the peer path; availability reads do not recursively query neighboring services. Their claims remain visible. Layer 2 currently reports all five outcomes `available`.

Finished operations from actual traces:

| Scenario | L1 model queries | L2 model queries | L2 source operations | Result |
|---|---:|---:|---:|---|
| LASA document read | 4 | 4 | 1 | completed |
| Repository document-name search | 4 | 6 | 1 | completed |
| Repository inspection | 4 | 6 | 2 | completed |
| Claimed filesystem source unavailable | 1 | 0 | 0 | rejected, no child |
| Unrelated review during outage | 0 | 2 | 0 | completed on layer 2 |

Counts come from finished diagnostic operations, not aggregate parent usage or estimates. See the [scenario matrix](../verification/connectors-20261119/scenario-matrix.json). A new document task also completed after restoration and token renewal (72.049s).

## Retained observations and limits

The initial document observation selected the peer, then rejected admission when the original 30-second catalog lease expired during planning. A separate attempt with a validated 300-second catalog lifetime retrieved the real document, then the independent verifier rejected insufficiently explained hash/source corroboration. Both are retained; neither was relabeled successful. The initial 45-second outage-observation window was shorter than the configured 60-second idle discovery interval; its automatic restoration and the subsequent bounded observation are also recorded. A helper initially queried the wrong session URL and failed before any restart; the corrected persistence check then passed. Deterministic regressions now distinguish discovery leases from received task pins, reject changed or withdrawn terms, and bound peer offer refresh. Source verification explicitly identifies server-performed corroboration while preserving negative semantic vetoes.

The supported profile excludes application/MCP writes, GUI automation, arbitrary URLs, automatic connector installation, interactive OAuth onboarding, legacy SSE transport and adversarial federation. Response sizes, queues, discovery, retries, cancellation and evidence packets are bounded. Public services can change schemas, rate-limit or become unavailable; these conditions fail closed or affect the dependent offer rather than silently substituting a source. A successful live run demonstrates the recorded scenario, not universal model correctness.
