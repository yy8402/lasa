# Discovery and API contract

## Bootstrap decision

Configure a peer's canonical descriptor URL, expected service identity, permitted origin/path prefix, and authentication reference. Example: `https://layer2.example.net/lasa/v1/descriptor`. A configured URL supports reverse-proxy prefixes and multiple services on one origin; it needs no root-level discovery.

For clients that know only an origin, optionally publish `GET /.well-known/api-catalog`. RFC 9727 already defines this location and a Linkset JSON representation. Each link context anchors a particular API instance; `service-desc` points to OpenAPI and `service-meta` to the LASA descriptor. Use `Content-Type: application/linkset+json; profile="https://www.rfc-editor.org/info/rfc9727"`. [RFC 9727](https://www.rfc-editor.org/rfc/rfc9727.html), [RFC 9264](https://www.rfc-editor.org/rfc/rfc9264.html)

`/.well-known/lasa-service` is **not the target path**. A custom suffix would require a specification and registration, consume an origin-wide bootstrap name, and still need instance and version selection. RFC 8615 requires registration; the IANA registry checked on 2026-11-18 has `api-catalog` and `agent-card.json`, not `lasa-service`. The existing registered catalog solves the bootstrap requirement. Reconsider a dedicated suffix only if interoperating LASA implementations establish a requirement the API catalog cannot meet. [RFC 8615](https://www.rfc-editor.org/rfc/rfc8615.html), [IANA registry](https://www.iana.org/assignments/well-known-uris)

The bootstrap document contains only approved links and public labels. It may be authenticated for private deployments. It is not the authority to trust a discovered service. Do not reuse caller tokens across origins, follow unapproved redirects, or accept a peer-supplied new trust root.

## Authenticated descriptor and contract selection

1. Authenticate transport using normal HTTPS validation and a configured trust store. Resolve credentials privately; never place them in a descriptor or URL.
2. Fetch the configured descriptor. Verify `service_id` against the configured expected identity and bind that identity to the configured origin/path. Service identity is stable across restarts; `deployment_revision` describes a deployment, not a new identity.
3. Select a mutually supported exact LASA protocol version and required features. The descriptor format has its own `descriptor_version`. Unknown mandatory features, unsupported protocol majors, or changed service identity fail negotiation. A newer minor is usable only after explicit support is declared; no optimistic parsing.
4. Fetch the versioned OpenAPI document and caller-scoped offer catalog using this protocol. Resolve needed definitions from the advertised contract endpoint and verify their digests and trusted publisher namespace. Request schemas are part of these pinned definitions, not inferred from a skill description.
5. Match semantic requirements and preconditions, check availability, then submit an exact contract and offer revision. Admission makes the final decision using current authority and capacity.

The descriptor's `protocols` describe communication features; the capability catalog describes outcomes. Descriptor/catalog responses do not expose private model configuration or local tool bindings. Authentication metadata names a pretrusted issuer and intended resource audience; it is not permission to fetch arbitrary issuer/JWKS URLs. JWT access tokens require issuer, audience, subject, lifetime, and algorithm validation using preconfigured trust, as applicable to the chosen issuer profile. Revocation/expiry checks are receiver-owned. [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html), [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html)

## Resources

Paths below are relative to the selected protocol base URL; they are not well-known paths. [OpenAPI](api.openapi.json) specifies methods, authentication, request/response schemas, and errors.

| Resource | Purpose |
|---|---|
| `GET /descriptor` | Authenticated identity, protocol choices, links, revision |
| `GET /openapi.json` | Selected protocol's transport contract |
| `GET /capabilities` | Paged caller-visible offers; optional exact contract ID/version filter |
| `GET /capabilities/{offer_id}` | Current offer in the same authority view |
| `GET /capabilities/{offer_id}/availability` | Capacity observation; never an admission promise |
| `GET /contracts/{digest}` | Immutable capability definition visible to this caller |
| `POST /sessions`, `GET /sessions/{session_id}` | Create/access a workspace-bound session |
| `POST /sessions/{session_id}/tasks` | Durable submission for evaluation; not yet execution acceptance |
| `GET /tasks/{task_id}` | State, acceptance/rejection, released result or safe failure |
| `POST /tasks/{task_id}/inputs` | Answer a pending clarification using its question ID and revision |
| `POST /tasks/{task_id}/cancel` | Request cancellation and return current task state |
| `GET /tasks/{task_id}/events` | Authorized metadata diagnostics, paged by sequence |
| `GET /tasks/{task_id}/artifacts/{artifact_id}` | Authorized released bytes with digest and bounded content type |

Sessions carry opaque server-issued IDs; workspace paths are private. One active task per session avoids ambiguous concurrent writes. The same task API serves callers and peers; only authenticated trusted peer principals may include a delegation envelope. A child uses its own session/workspace. Sessions are not shared filesystems.

## Revisions and caching

Keep these revisions distinct: immutable definition digest; descriptor/deployment revision; caller catalog view and revision; per-offer revision; availability revision; task revision. A task records exact references and the authority decision that admitted it. A changed contract requires explicit reselection. `409 offer_changed` or `catalog_changed` triggers bounded rediscovery and reevaluation, never silent substitution. Offer withdrawal prevents new admission; it does not erase historical execution evidence.

Discovery uses `ETag`, `If-None-Match`, and `304`. Use strong ETags for task `If-Match` on clarification and cancellation. Missing required preconditions return `428`; stale ones return `412`. Caller-sensitive resources use `Cache-Control: private, max-age=N, must-revalidate` with `Vary: Authorization, Accept`; local caches must also key by service identity, principal, authority context, protocol, and representation. Do not share authenticated caches. A stable revision returns stable content: timestamps and expiry are not regenerated on each GET. Renewing expiry creates a new representation/ETag. [HTTP semantics](https://www.rfc-editor.org/rfc/rfc9110.html), [HTTP caching](https://www.rfc-editor.org/rfc/rfc9111.html)

Private contract definitions can have longer private caching because their digest is immutable. Availability has a separate short TTL and `valid_until`; expired or unreachable means `unknown`, never `not_claimed`. Accepted authority is rechecked despite cached metadata. Tasks, events, and artifact responses default to `no-store` because they contain work data. Artifact retrieval still verifies the advertised digest.

All learned URLs must remain inside the configured allowed origin/prefix except explicitly preconfigured contract-publisher endpoints. The initial profile requires same-origin service resources, preventing discovery from becoming SSRF or credential forwarding. No network fetching occurs during JSON Schema validation.

## Configuration

[Config schema](config.schema.json) and [example](examples/config.json) separate service identity/API, private execution bindings, authorization integration, bounded resources, and optional peer configuration. Absence of `peer` means local execution only; routing preference and unclaimed fallback are ignored. There is no automatic peer search.

The configured model is an implementation detail behind an executor binding. Provider URLs and secret references are private configuration, never capability claims. Config changes produce an explicit deployment revision and invalidate affected offers/authority decisions; active tasks retain immutable input and contract records, while revoked permission stops new actions. This package introduces no aliases for previous prototype setting names.

## Implemented HTTP/configuration details

The optional API catalog supports both GET Linkset JSON and HEAD with an `api-catalog` Link header. The negotiated wire bundle is available at `/contracts.schema.json`; each protocol entry pins `wire_schema_digest`. Operation receipts, bounded reconciliation, and parent-mediated child diagnostics use the resources specified in OpenAPI.

Private authorization, runtime, and MCP tool files have closed schemas in `private.schema.json`. Authentication uses a configured local public JWKS file or a configured HTTPS JWKS URL. Storage paths are absolute. The optional `peer` block replaces the prototype's separate neighbor configuration format. Development provisioning and normal issuer configuration are described in the running instructions.
