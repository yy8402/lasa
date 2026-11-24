# LASA content inspection proposal

The operator selects which content streams LASA inspects and how each verdict affects the transfer. The `content_security` configuration registers inspection profiles and groups request and response bindings by boundary. [Current operator configuration](../CONFIGURATION.md#content-security)

LASA checks task authority, protects credentials, validates schemas and limits, governs disclosure and release, and records transfer metadata in every inspection mode. The endpoint's disclosure policy decides whether both the intended destination and the scanner may receive their respective representations. Binding a profile to a stream authorizes its gateway for the minimized projection only within that policy. Keep any required classification, residency, retention, and forwarding rules in the endpoint's disclosure policy. Derived content carries its source restrictions across transfers. Hold a disclosure when a required policy decision is unavailable. [Gateway architecture](../../doc/13-agent-endpoint-design-specification.md#10-enforcement-gateways) · [Release architecture](../../doc/07-artifacts-and-information-release.md)

## Grouped bindings

A stream is a semantic request or response at a LASA boundary. The runtime selects the projection and enforces the decision before the content is persisted, consumed, or released at the relevant point.

| Section | Request | Response |
| --- | --- | --- |
| `caller` | Task input, dependency data, submitted artifacts, and clarification answers | Final results and artifacts, clarification prompts, and authorized diagnostic content |
| `model` | Normalized requests for planning, verification, execution, and compaction | Bounded, validated JSON or assembled streaming output before the worker or planner consumes it |
| `delegates` | Child request, predecessor outputs, and attached artifact data before dispatch | Authenticated child results, returned artifacts, and authorized diagnostic content before use or forwarding |
| `connectors` | Validated arguments before dispatch to an app or MCP operation | Schema-validated, normalized results before use or storage as source evidence |

An optional `artifact_profile` on a caller or delegate response rule selects the inspection profile for the artifact projection. Otherwise artifacts use the response rule's `profile`. Both use the response rule's effective mode. LASA defines projections for each supported content type. The ordinary settings require no field selection or per-contract allowlist. [Delegation lifecycle](execution.md#delegation-envelope-and-budgets) · [Connector schema and lifecycle](connectors.md#protocol-and-lifecycle)

## Explicit modes and inheritance

Every configured `request` or `response` rule includes a `mode`, including rules in overrides. Applicable rules operate as follows.

| Mode | Behavior |
| --- | --- |
| `enforce` | A valid permit satisfies the configured inspection check. A denial, timeout, unavailable gateway, malformed response, or verdict that fails binding validation holds the transfer. |
| `observe` | Record the verdict or failure. The transfer can proceed subject to the other applicable controls. Approve and audit the scanner disclosure before sending the projection. |
| `off` | Skip configurable inspection for this direction, including artifact inspection. The rule consists of `"mode": "off"`. |

Resolve each direction independently.

1. Start with the section's `request` or `response`. An omitted direction starts at `off`.
2. For delegates, apply the override for the authenticated peer's `service_id`. For connectors, apply the connector override by `connector_id`, then the operation override by `connector_id` and `operation_id`. LASA gets these identities from its own peer and connector inventory.
3. An omitted direction in an override inherits the current rule. A present direction sets its mode explicitly. An active override inherits unspecified profile fields from the current active rule. An `off` rule clears both profile fields. A more specific rule that re-enables inspection after `off` supplies a `profile`.
4. Apply the single resolved rule to the transfer. Select one registered inspection profile for the payload. Resolve `artifact_profile` and its fallback after applying the overrides.

`lasa config check` rejects unknown profiles, peers, connectors or operations, duplicate profile IDs or selectors, invalid fields, and active rules without a resolved `profile`. An operation must belong to its named connector. Override precedence is independent of array order. Show the effective mode, profile, artifact profile where applicable, and the default or override that supplied each setting. Display explicitly disabled and unconfigured streams as `off`, with their respective origin.

## Inspection profiles and gateways

Register each profile under `inspection_profiles`. Its unique `id` is the name used by bindings. Its `gateway_id` is the identity LASA expects in the gateway's verdict, and `policy_revision` pins the inspection policy for that profile. Several profiles can share a gateway identity. Each supplies the fixed HTTPS `url` and dedicated `credential_ref` for its inspection endpoint. A private CA can be supplied with `ca_file`. Processing region and retention declarations inform the endpoint's disclosure policy.

Local gateways can run as a sidecar or on a private network. Local and remote gateways use the same authenticated, verdict-only HTTPS contract. LASA's basic safeguards run in the supervisor, so a deployment can start with local checks and add inspection profiles when needed. [Gateway placement and non-bypassability](../../doc/13-agent-endpoint-design-specification.md#103-placement-and-non-bypassability)

## Complete JSON example

This is a complete `content_security` object. The example assumes the service already configures the peer `legal-review`, the connector `document-store`, and its `documents.read` operation. The two local profiles share the `lasa-local-inspection` gateway identity and select different inspection endpoints and policy revisions. Set deployment-specific URLs, trust roots, credentials, and data-handling declarations before enabling the example.

```json
{
  "inspection_profiles": [
    {
      "id": "local-dlp",
      "gateway_id": "lasa-local-inspection",
      "url": "https://inspection.lasa.internal.example.net/v1/dlp",
      "credential_ref": "file:/run/secrets/lasa/local-dlp-key",
      "ca_file": "/etc/lasa/inspection-ca.pem",
      "policy_revision": "dlp-v1",
      "region": "eu",
      "retention": "none"
    },
    {
      "id": "local-artifacts",
      "gateway_id": "lasa-local-inspection",
      "url": "https://inspection.lasa.internal.example.net/v1/artifacts",
      "credential_ref": "file:/run/secrets/lasa/local-artifact-key",
      "ca_file": "/etc/lasa/inspection-ca.pem",
      "policy_revision": "artifacts-v1",
      "region": "eu",
      "retention": "none"
    },
    {
      "id": "managed-safety",
      "gateway_id": "managed-content-safety",
      "url": "https://safety.example.net/v1/inspect",
      "credential_ref": "env:LASA_SAFETY_KEY",
      "policy_revision": "safety-v1",
      "region": "eu",
      "retention": "none"
    }
  ],
  "bindings": {
    "caller": {
      "request": { "mode": "enforce", "profile": "managed-safety" },
      "response": {
        "mode": "enforce",
        "profile": "local-dlp",
        "artifact_profile": "local-artifacts"
      }
    },
    "model": {
      "request": { "mode": "enforce", "profile": "local-dlp" },
      "response": { "mode": "observe", "profile": "managed-safety" }
    },
    "delegates": {
      "request": { "mode": "enforce", "profile": "local-dlp" },
      "response": {
        "mode": "enforce",
        "profile": "local-dlp",
        "artifact_profile": "local-artifacts"
      },
      "overrides": [
        {
          "service_id": "https://identity.example.net/services/legal-review",
          "response": { "mode": "off" }
        }
      ]
    },
    "connectors": {
      "request": { "mode": "enforce", "profile": "local-dlp" },
      "response": { "mode": "observe", "profile": "managed-safety" },
      "overrides": [
        {
          "connector_id": "document-store",
          "response": { "mode": "off" }
        },
        {
          "connector_id": "document-store",
          "operation_id": "documents.read",
          "response": { "mode": "enforce", "profile": "local-dlp" }
        }
      ]
    }
  }
}
```

Requests to `legal-review` inherit required local DLP. The explicit response `off` clears inspection of both its results and its artifacts. Other peers inherit required response inspection and the `local-artifacts` profile for artifacts. Requests to `document-store` inherit local DLP. Its responses skip configurable inspection except for `documents.read`, which explicitly re-enables required local DLP. Other connectors inherit response observation through `managed-safety`.

## Inspection contract and evidence

Use one bounded HTTPS request with closed, versioned request and response schemas. Authenticate the configured endpoint and verify TLS. Apply adapter-wide request and response size limits and cap the inspection timeout by the remaining operation deadline. Disable redirects and ambient proxy settings. Bind the exact, minimized projection to a fresh inspection ID and digest. Private prompts, transport credentials, hidden reasoning, and opaque provider state stay within their designated boundaries.

| Message | Required fields |
| --- | --- |
| Inspection request | `version`, `inspection_id`, `binding_revision`, `policy_revision`, `gateway_policy_revision`, `channel`, `purpose`, `media_type`, `inspection_digest`, and `content` |
| Inspection response | `version`, `inspection_id`, `gateway_id`, `gateway_policy_revision`, `inspection_digest`, `verdict`, and bounded `reason_codes` |

Use the resolved profile's `policy_revision` as the request's `gateway_policy_revision`. Accept `permit`, `hard_deny`, and `indeterminate`. Validate the returned `gateway_id` and `gateway_policy_revision` against the profile and bind the verdict to the inspection ID and digest. LASA derives `binding_revision` from the resolved rule after inheritance and overrides. The request's `policy_revision` identifies the LASA disclosure policy used for the decision.

Keep the full representation's digest private and link it to the projection digest in the decision record. Recheck applicable revocations on subsequent transfers or reads. A future transformation produces a new candidate that needs its own digest, source lineage, verification, and release decision. [Governance updates and revocation](../../doc/13-agent-endpoint-design-specification.md#84-governance-update-and-revocation) · [Candidate release semantics](../../doc/13-agent-endpoint-design-specification.md#19-candidate-artifacts-and-release)

Record the effective mode and its origin, logical stream and purpose, service and operation IDs, selected profile ID and gateway identity, policy revisions, digests, verdict, reason code, and timestamp. Limit routine content audit records to metadata. Record the approval for a scanner disclosure before sending its projection. Persist release evidence with visibility changes. Record the actual transfer outcome separately from permission to send. Preserve confirmed effects and usage when a result is withheld, and preserve the original receiver and operation identity during reconciliation. [Durable operations and diagnostics](execution.md#diagnostic-evidence)

## Implementation and acceptance

Replace the flat inspection binding list and remove the duplicated route, executor, and per-binding class fields from the inspection configuration. Resolve the grouped configuration once and reuse it at the existing model, intake, delegation, connector, and release enforcement points. The optional `content_disclosure` section in the receiver's authorization policy owns source and destination class rules. Use the same resolver for enforcement and `lasa config check`.

| Area | Acceptance cases |
| --- | --- |
| Configuration | Parse the complete example. Verify all three explicit modes, absent section directions, omitted overrides, peer matching, connector and operation precedence, and artifact fallback. Prove `off` clears both profile references and re-enabling requires a newly resolved profile. Reject invalid references, duplicate profile IDs, and duplicate selectors. |
| Gateway behavior | Exercise local and remote HTTPS fixtures with the same verdict schema. Verify that two profiles sharing a gateway identity can pin different policy revisions and that a verdict for the wrong revision fails validation. In `enforce`, denial, timeout, invalid verdict, and unavailable mandatory audit storage hold the transfer. In `observe`, record the outcome and preserve independent disclosure decisions. In `off`, send zero inspection requests. |
| Model and release | Apply policy to planning, verification, worker execution, and compaction. Validate complete bounded JSON or SSE responses before exposing content to a worker, including content split across frames. Count observed model usage when withholding a response. Bind final result and artifact permits to the exact representation before publication and protect later reads and replays. |
| Caller and delegation | Withheld caller input stays out of evaluation. Withheld child requests never dispatch. Withheld returned results stay private while confirmed effects, usage, and authenticated control metadata remain available. Check clarification and diagnostic content before exposure. |
| Connectors and evidence | Withheld arguments never reach the tool and withheld results stay out of worker input and source evidence. Approved operations preserve provenance, schema checks, and accounting. Audit records preserve permit and outcome metadata without carrying raw payloads. |

Use the existing HTTP, transport, and durability fixtures with deterministic inspection endpoints. Validate the updated private schema and operator examples as part of implementation. [Runtime verification](../VERIFICATION.md)
