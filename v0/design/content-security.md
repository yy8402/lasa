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

Use one bounded HTTPS request per inspection attempt with closed, versioned request and response schemas. Authenticate the configured endpoint and verify TLS. Apply adapter-wide request and response size limits and cap the inspection timeout by the remaining operation deadline. Disable redirects and ambient proxy settings. Bind the exact, minimized projection to a fresh inspection ID and digest. Private prompts, transport credentials, hidden reasoning, and opaque provider state stay within their designated boundaries.

| Message | Required fields |
| --- | --- |
| Inspection request | `version`, `inspection_id`, `binding_revision`, `policy_revision`, `gateway_policy_revision`, `channel`, `purpose`, `media_type`, `inspection_digest`, and `content` |
| Inspection response | `version`, `inspection_id`, `gateway_id`, `gateway_policy_revision`, `inspection_digest`, `verdict`, and bounded `reason_codes` |

Use the resolved profile's `policy_revision` as the request's `gateway_policy_revision`. Accept `permit`, `hard_deny`, and `indeterminate`. Validate the returned `gateway_id` and `gateway_policy_revision` against the profile and bind the verdict to the inspection ID and digest. LASA derives `binding_revision` from the resolved rule after inheritance and overrides. The request's `policy_revision` identifies the LASA disclosure policy used for the decision.

Keep the full representation's digest private and link it to the projection digest in the decision record. Recheck applicable revocations on subsequent transfers or reads. Each transformation produces a new candidate with its own digest, source lineage, verification, and release decision. [Governance updates and revocation](../../doc/13-agent-endpoint-design-specification.md#84-governance-update-and-revocation) · [Candidate release semantics](../../doc/13-agent-endpoint-design-specification.md#19-candidate-artifacts-and-release)

Record the effective mode and its origin, logical stream and purpose, service and operation IDs, selected profile ID and gateway identity, policy revisions, digests, verdict, reason code, and timestamp. Limit routine content audit records to metadata. Record the approval for a scanner disclosure before sending its projection. Persist release evidence with visibility changes. Record the actual transfer outcome separately from permission to send. Preserve confirmed effects and usage when a result is withheld, and preserve the original receiver and operation identity during reconciliation. [Durable operations and diagnostics](execution.md#diagnostic-evidence)

Bind each result and artifact release to its exact bytes, audience, disclosure policy, and mandatory `caller.response` profile. Resolve the artifact profile independently from the result profile. Request and other response bindings govern their own transfers. Changes to their settings leave existing release approvals valid. An applicable disclosure or mandatory release profile change holds subsequent reads and replays. When upgrading a legacy store, start the new supervisor with the existing inspection configuration first. It scopes each grant whose legacy revision still matches that configuration before reporting readiness.

## Shared recovery

The supervisor owns recovery for every binding. It uses the inspection verdict, the transfer's dispatch state, and the remaining budget to decide whether to retry inspection, revise an undispatched request, request corrected input, reconcile a dispatched operation, or hold the transfer. Inspection bindings select mode and profile. The capability or connector operation declares which adjustments preserve its contract. The gateway supplies the verdict.

### Service limits

The proposed `limits.content_recovery` manifest settings apply across all bindings on the service. Each limit counts extra actions after the initial inspection. Omitted settings take the defaults below. The first implementation accepts integers from zero through each default. Zero disables the corresponding automatic action. A task-level limit of zero disables both.

| Setting | Default | Scope |
| --- | --- | --- |
| `max_inspection_retries_per_transfer` | 1 | Extra scanner calls for transient failures, shared by the original candidate and any revision of the same transfer |
| `max_candidate_revisions_per_transfer` | 1 | Automatic local revisions after a policy denial, available before outbound dispatch when the operation declares an eligible adjustment |
| `max_actions_per_task` | 4 | Combined scanner retries and candidate revisions across the task, including parallel branches and release |

With both per-transfer defaults, a transfer can make up to three scanner calls. The original deadline and the remaining task budget bound all attempts. Reserve each recovery action durably before starting it so concurrent branches and restarts consume the same limits. Before a task exists, account for intake recovery under the authenticated submission's operation identity. Carry any intake charges into the task when LASA creates it.

### Recovery decisions

1. **Retry a transient inspection failure in `enforce`.** Inspect the same projection through the same authorized profile with a fresh inspection ID. Retry a timeout, transient transport failure, or explicitly retryable gateway outage while both budgets allow it. A malformed verdict, profile or digest mismatch, configuration error, or unavailable mandatory audit storage holds the transfer immediately. An exhausted transient failure reports `content_gateway_unavailable`. In `observe`, record the verdict or failure from the initial inspection. In `off`, skip gateway inspection. LASA applies its independent disclosure controls in all modes.
2. **Revise an eligible outbound candidate after a denial.** Start with deterministic omission of context explicitly declared optional for that operation. Apply the adjustment inside the supervisor. Keep the same task, step, destination, and authorized effect. Carry forward source restrictions and preserve required inputs, resource identities, and effect-bearing arguments. Validate the new candidate against the schema, authority, required inputs, and current policy. Dispatch only the exact candidate with its own permit. If recovery is unavailable or the revised candidate is denied, report `disclosure_denied` and use a supported correction checkpoint where appropriate. Independent steps may continue within the authorized plan.
3. **Preserve dispatched operations.** Once dispatched, retain the request digest, receiver, operation ID, and idempotency key. A withheld response keeps its original usage, receipts, and confirmed effects. Reconcile any uncertain dispatch against that receiver before considering another execution. A future capability may authorize a locally produced derivative of a withheld response. Verify its provenance and contract compliance and inspect the derivative before use. [Idempotency and reconciliation](execution.md#durable-lifecycle-and-failures)

Use a stable transfer ID across attempts. Link the original and revised candidate digests, inspection IDs, applied adjustment, budget consumption, and final transfer outcome in metadata-only audit records. Return safe problem details and a decision reference where recorded. Keep matched text and detector internals in their existing authorized boundaries.

Capability publishers mark eligible top-level input properties with `"x-lasa-optional-context": true` in the trusted definition's `input_schema`. A marked property must be optional and outside required artifact preconditions. Model recovery revises only matching supervisor-built user context. Connector operators list eligible arguments in `optional_context_arguments` on the private operation, alongside the pinned upstream schema. Revalidation also checks conditional requirements and task input constraints.

When a revised model request for a plan step is confirmed delivered, record the model operation and transfer IDs, the accepted request digest, and the admitted and revised step input digests. Verification reconstructs the revised input from the admitted plan and checks its digest against this receipt before presenting it as step evidence. The admitted plan and its digest retain the original input. A candidate that was withheld or whose delivery is uncertain provides no such receipt.

### Behavior by binding

| Binding | Behavior when content is held |
| --- | --- |
| `caller.request` | Reject blocked task input before evaluation and ask for corrected content. A blocked clarification answer leaves the task at its existing checkpoint. |
| `caller.response` | Hold a blocked clarification prompt and return a safe problem. Publish the final result and required artifacts together after each clears its applicable check, including `artifact_profile` when selected. Return authorized diagnostic metadata with withheld content omitted. |
| `model.request` | Rebuild a request from approved task data and omit only declared optional context. Apply this rule to planning, verification, execution, and compaction. |
| `model.response` | Withhold the full response, including buffered streaming output, from the worker or planner. Settle observed model usage. |
| `delegates.request` | Omit explicitly optional child context or attachments when the child contract permits it. Preserve required predecessor evidence and the authorized peer. |
| `delegates.response` | Withhold child result or artifact content from downstream work and preserve the child receipt, confirmed effects, and usage. Return authorized trace metadata when trace content is withheld. |
| `connectors.request` | Apply the operation's declared adjustment to optional arguments. Preserve the selected resource, operation, required arguments, and caller-authorized scope. |
| `connectors.response` | Withhold the result from the worker and source evidence. Settle the original connector call and preserve its receipt. |

### JSON settings

Set `content_recovery` in the supervisor manifest's top-level `limits` object alongside the existing task budgets. The grouped `content_security` settings above select which inspections use it.

```json
{
  "limits": {
    "content_recovery": {
      "max_inspection_retries_per_transfer": 1,
      "max_candidate_revisions_per_transfer": 1,
      "max_actions_per_task": 4
    }
  }
}
```

## Implementation and acceptance

Replace the flat inspection binding list and remove the duplicated route, executor, and per-binding class fields from the inspection configuration. Resolve the grouped configuration once and reuse it at the existing model, intake, delegation, connector, and release enforcement points. The optional `content_disclosure` section in the receiver's authorization policy owns source and destination class rules. Use the same resolver for enforcement and `lasa config check`.

| Area | Acceptance cases |
| --- | --- |
| Configuration | Parse the complete example. Verify all three explicit modes, absent section directions, omitted overrides, peer matching, connector and operation precedence, and artifact fallback. Prove `off` clears both profile references and re-enabling requires a newly resolved profile. Reject invalid references, duplicate profile IDs, and duplicate selectors. |
| Gateway behavior | Exercise local and remote HTTPS fixtures with the same verdict schema. Verify that two profiles sharing a gateway identity can pin different policy revisions and that a verdict for the wrong revision fails validation. In `enforce`, denial, timeout, invalid verdict, and unavailable mandatory audit storage hold the transfer. In `observe`, record the outcome and preserve independent disclosure decisions. In `off`, send zero inspection requests. |
| Model and release | Apply policy to planning, verification, worker execution, and compaction. Validate complete bounded JSON or SSE responses before exposing content to a worker, including content split across frames. Count observed model usage when withholding a response. Bind final result and artifact permits to the exact representation before publication and protect later reads and replays. Preserve valid legacy grants and verify that connector binding changes leave reads and replays available. Exercise independent artifact policy revocation. |
| Caller and delegation | Withheld caller input stays out of evaluation. Withheld child requests never dispatch. Withheld returned results stay private while confirmed effects, usage, and authenticated control metadata remain available. Check clarification and diagnostic content before exposure. |
| Connectors and evidence | Withheld arguments never reach the tool and withheld results stay out of worker input and source evidence. Approved operations preserve provenance, schema checks, and accounting. Audit records preserve permit and outcome metadata without carrying raw payloads. |
| Shared recovery | Validate defaults, zero limits, and invalid counts. Recover a transient failure over the same projection and dispatch only after a valid permit. Revise eligible model, delegate, and connector requests and verify that the original bytes never dispatch. Exercise exhaustion, parallel budget reservations, crash and replay, missing required inputs, denied responses, and ambiguous dispatch. Verify that `observe` findings produce audit evidence without triggering revision. |

Use the existing HTTP, transport, and durability fixtures with deterministic inspection endpoints. Validate the updated private schema and operator examples as part of implementation. [Runtime verification](../VERIFICATION.md)
