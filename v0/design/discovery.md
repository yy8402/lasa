# Discovery and API contract

## Bootstrap decision

Configure a peer's canonical descriptor URL, expected service identity, permitted origin/path prefix, and authentication reference. Example: `https://layer2.example.net/lasa/v1/descriptor`. A configured URL supports reverse-proxy prefixes and multiple services on one origin; it needs no root-level discovery.

For clients that know only an origin, optionally publish `GET /.well-known/api-catalog`. RFC 9727 already defines this location and a Linkset JSON representation. Each link context anchors a particular API instance; `service-desc` points to OpenAPI and `service-meta` to the LASA descriptor. Use `Content-Type: application/linkset+json; profile="https://www.rfc-editor.org/info/rfc9727"`. [RFC 9727](https://www.rfc-editor.org/rfc/rfc9727.html), [RFC 9264](https://www.rfc-editor.org/rfc/rfc9264.html)

`/.well-known/lasa-service` is **not the target path**. A custom suffix would require a specification and registration, consume an origin-wide bootstrap name, and still need instance and version selection. RFC 8615 requires registration; the IANA registry checked on 2026-11-18 has `api-catalog` and `agent-card.json`, not `lasa-service`. The existing registered catalog solves the bootstrap requirement. Reconsider a dedicated suffix only if interoperating LASA implementations establish a requirement the API catalog cannot meet. [RFC 8615](https://www.rfc-editor.org/rfc/rfc8615.html), [IANA registry](https://www.iana.org/assignments/well-known-uris)

The bootstrap document contains only approved links and public labels. It may be authenticated for private deployments. It is not the authority to trust a discovered service. Do not reuse caller tokens across origins, follow unapproved redirects, or accept a peer-supplied new trust root.

## Authenticated descriptor and contract selection

1. Authenticate transport using normal HTTPS validation and a configured trust store. Resolve credentials privately; never place them in a descriptor or URL.
2. Fetch the configured descriptor. Verify `service_id` against the configured expected identity and bind that identity to the configured origin/path. Service identity is stable across restarts; `deployment_revision` describes a deployment, not a new identity.
3. Select the exact LASA protocol version and required features. The `1.0.0` descriptor advertises `lasa/1.0.0`. Unknown mandatory features, an unsupported protocol version, or a changed service identity fail negotiation.
4. Fetch the versioned OpenAPI document and caller-scoped offer catalog using this protocol. Peers match the advertised wire schema digest and required HTTP operations. OpenAPI's `info.version` identifies the implementation release. Fetch definitions as needed from the advertised contract endpoint and verify their digests and trusted publisher namespace.
5. Match semantic requirements and preconditions against offers in the caller's configured authorization view. Refresh the selected offer and its availability by offer ID before submission. Submit the exact contract and offer revision from that catalog view. Admission independently checks current authority and capacity.

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
| `GET /tasks/{task_id}/events` | Provider task progress, paged by sequence |
| `GET /tasks/{task_id}/artifacts/{artifact_id}` | Authorized released bytes with digest and bounded content type |

Sessions carry opaque server-issued IDs; workspace paths are private. One active task per session avoids ambiguous concurrent writes. Every consumer uses the same task API and each authenticated principal owns its receiving provider’s session. Setup and administration use private configuration and a separate operator credential.

## Revisions and caching

Keep these revisions distinct: immutable definition digest; descriptor/deployment revision; caller catalog view and revision; per-offer revision; availability revision; task revision. A task records exact references and the authority decision that admitted it. A changed contract requires explicit reselection. `409 offer_changed` or `catalog_changed` triggers bounded rediscovery and reevaluation, never silent substitution. Offer withdrawal prevents new admission; it does not erase historical execution evidence.

Discovery uses `ETag`, `If-None-Match`, and `304`. Use strong ETags for task `If-Match` on clarification and cancellation. Missing required preconditions return `428`; stale ones return `412`. Caller-sensitive resources use `Cache-Control: private, max-age=N, must-revalidate` with `Vary: Authorization, Accept`; local caches must also key by service identity, principal, authority context, protocol, and representation. Do not share authenticated caches. A stable revision returns stable content: timestamps and expiry are not regenerated on each GET. Renewing expiry creates a new representation/ETag. [HTTP semantics](https://www.rfc-editor.org/rfc/rfc9110.html), [HTTP caching](https://www.rfc-editor.org/rfc/rfc9111.html)

Private contract definitions can have longer private caching because their digest is immutable. Availability has a separate short TTL and `valid_until`; expired or unreachable means `unknown`, never `not_claimed`. Accepted authority is rechecked despite cached metadata. Tasks, events, and artifact responses default to `no-store` because they contain work data. Artifact retrieval still verifies the advertised digest.

All learned URLs must remain inside the configured allowed origin/prefix except explicitly preconfigured contract-publisher endpoints. The initial profile requires same-origin service resources, preventing discovery from becoming SSRF or credential forwarding. No network fetching occurs during JSON Schema validation.

## Configuration

A service has one [deployment manifest](config.schema.json). It declares identity, authentication trust, execution, and ordered downstream peers. The package supplies local defaults, built-in definitions, and verifier mappings. The [compact example](examples/config-no-peer.json) uses only required deployment settings. The [advanced example](examples/config.json) shows explicit routing, limits, and bindings.

The configured model and provider credentials are private execution settings. The descriptor URL follows the base URL and the receiver audience equals the stable service ID. Deployments record an effective configuration revision. Active tasks retain immutable input and contract records. Current receiver policy controls new authorization decisions after revocation.

## Implemented HTTP/configuration details

The optional API catalog supports both GET Linkset JSON and HEAD with an `api-catalog` Link header. The negotiated wire bundle is available at `/contracts.schema.json`; each protocol entry pins `wire_schema_digest`. Operation receipts, bounded reconciliation, and parent-mediated child diagnostics use the resources specified in OpenAPI.

The separate receiver authorization policy and inline connector definitions have closed schemas in `private.schema.json`. JWT authentication uses a configured local public JWKS file or a configured HTTPS JWKS URL. Services can also opt into opaque bearer tokens backed by a private digest registry. Their descriptors advertise `static_token`. Both credential modes use the same receiver policy and can support delegation. Each outgoing peer entry selects and pins its receiver authentication mode. Storage paths are absolute. Development provisioning and issuer configuration are described in the running instructions.
