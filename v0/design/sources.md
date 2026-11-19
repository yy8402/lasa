# Primary sources and scope of use

Reviewed 2026-11-18. LASA decisions in this package are proposals derived from requirements; these standards are references, not claims that an existing prototype conforms to them. No existing project document was treated as architectural authority.

| Source | Used for |
|---|---|
| [RFC 8615: Well-Known URIs](https://www.rfc-editor.org/rfc/rfc8615.html) and [IANA registry](https://www.iana.org/assignments/well-known-uris) | Registration and origin-scoped bootstrap; registry checked for current names |
| [RFC 9727: API Catalog](https://www.rfc-editor.org/rfc/rfc9727.html) | Registered API discovery, media type/profile, API metadata links |
| [RFC 9264: Linkset](https://www.rfc-editor.org/rfc/rfc9264.html) | JSON link contexts and relations |
| [OpenAPI 3.2.1](https://spec.openapis.org/oas/v3.2.1.html) | Current published HTTP API description format; 2026-09-10 publication |
| [Official OAS 3.2 schema, 2026-11-12](https://spec.openapis.org/oas/3.2/schema/2026-11-12) | Pinned offline structural validation; see provenance in `standards/source.json` |
| [JSON Schema 2020-12](https://json-schema.org/draft/2020-12/) | Payload/schema contracts; no runtime network resolution |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html) and [RFC 9111](https://www.rfc-editor.org/rfc/rfc9111.html) | HTTP conditional requests and cache semantics |
| [RFC 9457: Problem Details](https://www.rfc-editor.org/rfc/rfc9457.html) | Error envelope; LASA error codes are its own extension |
| [RFC 9530: Digest Fields](https://www.rfc-editor.org/rfc/rfc9530.html) | HTTP artifact Content-Digest header |
| [RFC 8785: JSON Canonicalization](https://www.rfc-editor.org/rfc/rfc8785.html) | Definition/request digests |
| [RFC 9700: OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html) and [RFC 8725: JWT BCP](https://www.rfc-editor.org/rfc/rfc8725.html) | Trusted issuer/audience and token validation design |
| [A2A specification](https://a2a-protocol.org/latest/specification/) and [discovery](https://a2a-protocol.org/latest/topics/agent-discovery/) | Evaluated agent interoperability alternative; no A2A conformance claim |
| [MCP tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) | Distinction between private tool schemas and public outcome contracts |

The vendored OpenAPI schema retains the upstream document and its license metadata. The validator checks its recorded SHA-256 before using it. All other LASA artifacts are authored here; no remote document is fetched by validation.
