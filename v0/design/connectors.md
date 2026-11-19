# Private connectors and approved outcome fulfillment

Status: design settled before runtime changes, 2026-11-19. The finite acceptance record is `verification/connectors-20261119/ACCEPTANCE.md`.

## Release identity

This release is package 1.1.0 and protocol `lasa/1.1`, with schema identifiers under `/lasa/1.1/`. Both layers move together; there is no old-protocol alias or private-config compatibility parser. Existing immutable capability definitions and their versions remain unchanged. The HTTP major path stays `/lasa/v1`. The internal broker transport and pinned Codex carrier are unchanged.

## Ownership and supported profile

One private `ConnectorPolicy.connectors` registry replaces the duplicated application/MCP arrays. Its closed variants are `mcp-stdio`, `mcp-http` (Streamable HTTP over verified HTTPS), and `json-get` (an application HTTPS JSON GET interface). Desktop GUI automation, arbitrary application CLI RPC, application writes, external-write MCP operations, legacy HTTP+SSE transport, arbitrary URL forwarding, and interactive OAuth onboarding are outside this v0 profile. Optional HTTP bearer credentials are provisioned by the administrator through explicit environment/file references; no automatic issuer discovery or token passthrough is performed.

Connector IDs, endpoints, launch commands, secret references, upstream tool IDs, and schemas remain private. A connector is not a capability. Installing one or listing its tools creates neither publication nor authority. Approved public outcome definitions, exact verifier references, caller contract permission, and private bindings are required independently. The existing capability and task APIs remain the peer interface.

`FulfillmentBinding` belongs in the private schema. `required_operations` is an explicit list of registered operation IDs for the binding's executor. This list is both the dependency set and the external-operation allowlist; optional operations are not supported by this profile. Each dependency's resource and effect must fit the binding ceiling. A task intersects that ceiling with current receiver policy, the pinned task grant, parent ceilings, and its remaining allocation before every call. Core workspace tools retain their existing explicit resource/effect checks. A generic attempt binding with no required operations does not acquire every installed connector.

Private `task_input_bindings` tie a tool argument to the selected task input by exact value or POSIX basename comparison. For document reads, the approved path must also select the requested document ID; an arbitrary different allowed document cannot be relabeled as the requested one. Provenance pins the selected contract/input and receiver-local operation sequence as well as result/schema digests.

## Protocol and lifecycle

MCP initialization and complete paged `tools/list` discovery are bounded. Input schemas and the presence/value of upstream output schemas are pinned by the administrator. A changed/missing tool invalidates that operation, while other valid operations on the same connection remain usable. Discovery is refreshed periodically; no discovered code, tool, or permission is installed automatically. Schema references are local-only and validators do not fetch remote schemas.

MCP results support either schema-validated `structuredContent` or an explicitly selected text normalization (`{"text": ...}` from text content blocks). `isError` is an operation failure. Images, audio, embedded resources and automatic resource-link fetching are unsupported in this profile. If an upstream output schema is present, structured results are validated against it before normalization. Normalized results also conform to the private operation's output schema. `argument_constraints` restrict approved arguments independently of the discovered input schema.

Application JSON GET operations use fixed administrator-configured HTTPS URLs within one approved base boundary. Arguments become query parameters only; callers cannot choose origins or paths. Response JSON is checked against a pinned response schema, then an explicit top-level field projection minimizes object/array-of-object data before normalized-output validation. Redirects are disabled. TLS validation uses normal trust or an explicitly configured CA. Authorization/cookie headers cannot be embedded as literal header values.

Every connector has one lifecycle owner, a bounded queue, bounded startup/discovery/call/close waits, and a configured recovery interval. Queued and active calls share the caller's monotonic expiry, capped by the connector timeout. Cancellation removes queued work or cancels the active request. Connection failure settles waiting callers without silently replaying operations. Background recovery reestablishes a connection and validates schemas; it does not replay task work. HTTP credentials are resolved on each request. Changed stdio credential values cause a controlled reconnect between operations. Limits bound response bytes, discovery pages/tools, and queued work. Rate-limit responses are represented as busy and respect bounded retry hints.

## Publication, availability, and routing

Service readiness reflects the core service/runtime, not every optional dependency. Per-offer availability intersects service capacity with the selected local binding's dependency states and the caller's current resource/effect permission. Public states are `available`, `busy`, `unavailable`, `unauthorized`, and `unknown`; private reason details never expose endpoints or tool IDs. Delegation-only offers report unknown until task evaluation establishes a feasible peer path. Availability inspection itself does not recursively call neighboring availability endpoints.

An outage leaves the approved offer present. A missing or changed schema is unavailable; an upstream credential refusal or caller resource denial is unauthorized; an unobserved dependency is unknown. These states never become a missing claim. The router preserves the existing exact fallback conjunction: local insufficient plus a fresh complete peer catalog that does not claim the outcome, plus an authorized generic attempt offer. Claimed-but-unavailable/denied/unknown dependencies cannot activate unclaimed fallback.

## Evidence and concrete approved outcomes

Successful external operations have durable request/result receipts bound to the task, step, operation, resource, and exact operation schema. Before a dependent result can complete, each required operation must have successful supporting evidence. Server-generated immutable operation-result artifacts carry normalized, redacted result bytes and provenance (issuing service/task, selected-input digest, operation identity, resource, and result/schema digests). Caller-authored workspace exports cannot claim this provenance. These artifacts use the existing byte budget, authorized artifact API and parent import verification; no public raw-tool proxy is introduced.

Independent verification receives bounded authorized receipts and checked artifact bytes. Its cache identity includes the trusted material digest. New approved profiles deterministically corroborate source facts before semantic assessment; unsupported claims, missing source results, changed bytes, and negative semantic verdicts remain failures. Parent verification checks the authenticated child linkage and artifact provenance without receiving connector credentials. Task diagnostics retain separate metadata/content permission and redaction controls.

Exact source fields are server assembled from those recorded results. The private Codex completion form for these three profiles only confirms that the retrieval workflow is ready for verification; the model does not invent hashes or reproduce large source bodies. Missing required operations or source artifacts fail assembly. The trusted verifier packet also identifies successful server source corroboration, including UTF-8 hashing and contract-derived logical source identifiers; these checks establish the exact fields already matched against recorded facts. An independent semantic verdict still gates release, and a negative verdict is never replaced by assembly. Text hashes are computed over UTF-8 bytes; the repository documentation index is copied from the recorded normalized upstream result.

Three outcome definitions are approved for actual read-only integration verification:

| Contract | Meaning | Intended fulfillment |
|---|---|---|
| `documents.read@1.0.0` | Return the exact content/digest of an approved LASA document | Maintained filesystem MCP server over stdio, restricted to the deployed LASA documentation collection |
| `documents.search@1.0.0` | Find matching top-level document filenames in an approved public repository; this is filename metadata search | GitHub repository-contents application JSON API |
| `repository.inspect@1.0.0` | Return repository metadata and its documentation index from the approved sources | GitHub application JSON API plus DeepWiki MCP over Streamable HTTP |

The real deployed document collection contains LASA project documents, not fixture responses. Public integration targets are the `modelcontextprotocol/python-sdk` repository and its DeepWiki index. Test fixtures remain separate controller/protocol evidence. Both LASA layers continue using gpt-5.5 and their existing authenticated HTTPS boundary.

Sources: [MCP tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools), [MCP transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports), [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization), [DeepWiki MCP](https://docs.devin.ai/work-with-devin/deepwiki-mcp), [GitHub repository API](https://docs.github.com/en/rest/repos/repos).
