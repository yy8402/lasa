# OpenAI-compatible user interface

Status: proposed.

Expose an opt-in Responses API on the user-facing supervisor. An OpenAI SDK can submit text and supported documents with a LASA bearer credential and receive a verified text answer. The supervisor creates a native LASA task for every new response. Use the native API for peer requests, full task control, typed results, evidence, and artifact downloads.

Ship the Responses profile first. It supports foreground requests and the submit, retrieve, and cancel flow for background work. Support inline UTF-8 documents in the first release. Add separately uploaded files when the first client needs upload-by-ID. Qualify a specific client before offering streaming or Chat Completions. [Responses create](https://developers.openai.com/api/reference/resources/responses/methods/create) · [Background mode](https://developers.openai.com/api/docs/guides/background)

## Placement and configuration

Mount a small route group beside the native routes in the supervisor. With native base URL `https://lasa.example.net/review`, the SDK base URL is `https://lasa.example.net/review/openai/v1`. Derive the prefix and absolute links from service configuration. Both route groups call shared submission, cancellation, inspection, and release logic, using their own request and response schemas. Advertise the Responses profile separately from native peer discovery. [Architecture](architecture.md) · [Native routes](discovery.md#resources)

| Setting | Design |
| --- | --- |
| Enablement | The `openai_interface` manifest section is absent by default. Enabled deployments mount the route group behind authenticated HTTPS. |
| Caller access | The existing authentication configuration verifies the bearer token. A receiver policy opt-in grants access to specific aliases to a principal of kind `user`. Every submission also requires the ordinary capability grant. Peer and operator principals cannot use these routes. |
| Alias binding | Each configured public alias, such as `lasa-assistant`, binds one immutable capability ID, version, digest, and exact processing terms. Resolve the current caller-visible offer and pin its ID, revision, and catalog view on submission. Refuse ambiguous or ineligible selections. Changing the contract or processing terms requires a new alias. |
| Execution | The initial assistant offer is local-only and pure. Native policy and routing enforce these restrictions, including verification and recovery. Introduce read-only tools or downstream fulfillment only through an explicitly authorized offer with its own acceptance evidence. |
| Resource limits | Configure request bytes, decoded file bytes and count, foreground wait, authenticated request rates, in-flight response count, and file storage quotas where enabled. The effective task budget remains constrained by the offer, principal, service ceilings, and processing terms. |

Use `lasa config check` to validate route separation, alias uniqueness, exact contract and processing terms, and compatible limits. Report enabled features and aliases without credentials or provider details. Model discovery applies current user policy and offer visibility, independently of temporary capacity. An authentication failure returns `401`, an authenticated principal barred from the interface gets `403`, and an absent or unauthorized alias gets `404`. [Receiver policy](../CONFIGURATION.md#incoming-authentication-and-authorization) · [Processing guarantees](multi-peer-delegation.md)

Start the canary with a 128 KiB HTTP body limit, at most four documents per request, 16 KiB per decoded document and 32 KiB combined, two active tasks per caller on this interface, and a 25-second foreground wait. These are proposed canary values. Use a lower value wherever the ingress, contract, native task budget, or processing policy is stricter. Set per-route request rates and the retention period when provisioning the canary.

## HTTP contract

Paths below are relative to the SDK base URL. The compatibility OpenAPI document and conformance fixtures are versioned with the supervisor release and identified separately from the native LASA protocol.

| Method and path | Semantics |
| --- | --- |
| `GET /models` | Return `{"object":"list","data":[...]}` with visible aliases. Each model record has `id`, `object: "model"`, a stable Unix `created` timestamp, and `owned_by: "lasa"`. |
| `GET /models/{model}` | Return one visible alias record. |
| `POST /responses` | Validate, translate, and durably submit one native task. Return a Response object with HTTP `200` when the response resource can be returned. |
| `GET /responses/{response_id}` | Return the current Response object for the owning principal, including terminal failures. Apply current read and release checks. |
| `POST /responses/{response_id}/cancel` | Request cancellation of a background response. Return its current state. Repeat calls return the current state and share the same cancellation operation. A foreground response returns `400 not_background_response`. |

For `POST /responses`, accept the following closed set of fields. Reject unsupported fields or values with `400`, an `error.param` identifying the field, and a stable `error.code`. Validate nested content as strictly as top-level parameters. [Responses create](https://developers.openai.com/api/reference/resources/responses/methods/create) · [Models API](https://developers.openai.com/api/reference/resources/models/methods/list)

| Field | Accepted values |
| --- | --- |
| `model` | Required, exact visible alias. |
| `input` | Required, nonblank string or a nonempty array of messages. Accept `user`, `assistant`, `system`, and `developer` roles, an optional `type: "message"`, and string content or an array of `input_text` parts. Only user messages can include `input_file` parts. Require at least one user message with a nonblank instruction or question. |
| `instructions` | Optional string. Treat it and all message roles as caller-supplied guidance. The role labels preserve conversational meaning within the task. |
| `background`, `stream`, `store` | `background` defaults to `false`. Accept omitted or `false` for `stream`, and omitted or `true` for `store`. Advertise retained response resources and the configured retention period. |
| `tools`, `tool_choice`, `parallel_tool_calls`, `text` | Accept omission or the supported defaults `[]`, `"none"`, `false`, and `{"format":{"type":"text"}}` respectively. |

Clients supply conversation history explicitly. Each submission has its own workspace-bound session. The allowlist excludes `previous_response_id`, `conversation`, function and tool items, provider sampling controls, and `max_output_tokens`. The operator sets the whole-task budget. Publish the supported routes and fields for each release so callers can check features such as streaming, structured output, or webhooks before enabling them. [Responses create](https://developers.openai.com/api/reference/resources/responses/methods/create)

### Background request example

Send the following JSON to `POST /responses` with the user's LASA bearer credential and a stable `Idempotency-Key`.

```json
{
  "model": "lasa-assistant",
  "background": true,
  "input": [
    {
      "role": "user",
      "content": [
        {"type": "input_text", "text": "Who is responsible for verification?"},
        {
          "type": "input_file",
          "filename": "design.txt",
          "file_data": "data:text/plain;base64,VGhlIHBhcmVudCB2ZXJpZmllcyB0aGUgcmVzdWx0Lgo="
        }
      ]
    }
  ]
}
```

Save the returned `id`. Poll `GET /responses/{id}` while the state is `queued` or `in_progress`. On completion, read the assistant message. On terminal failure, read the Response's `error`.

### Native capability and request translation

Define and qualify a dedicated `assistant.respond` outcome contract for the initial alias. Its input contains optional `instructions`, ordered `messages`, and optional `documents`. Message parts preserve text and document positions. Document references point to input-local IDs. Each document contains a display name, canonical media type, SHA-256 digest of the decoded bytes, and exact UTF-8 text. The capability supplies its own bounded completion criteria. Its output includes `disposition` of `answered` or `unable` and a released `answer` string. Qualify that a completed answer addresses the supplied request and that a valid `unable` answer states the limitation explicitly. Reuse LASA verification and release. Each later alias must have an explicit mapping for both its contract input and its released output. [Capability design](capabilities.md) · [Native request example](examples/task-request.json)

Translate request fields deterministically. Treat caller instructions, assistant history, filenames, and file content as data under the receiver policy. Bind the exact offer, processing terms, native operation identity, and effective deadline. Pass the canonical task input through normal caller intake inspection, input accounting, admission, execution, verification, and release. Profile-specific behavior such as interaction and response projection comes from supervisor-owned submission options. Public JSON cannot set execution authority, provider model, tool configuration, workspace path, or delegation terms. [Native admission](execution.md#submission-and-authority) · [Content inspection](content-security.md)

## Response lifecycle

Each Response has a stable opaque `resp_…` ID. The supervisor projects the native consumer task state. In foreground mode, wait up to the configured HTTP wait limit for a terminal state. If the wait expires, return HTTP `504` with `x-lasa-response-id`. The admitted task continues under its original deadline and the client can retrieve it. A disconnected client also leaves the admitted task running. Clients that need an ID immediately or explicit compatibility cancellation use `background: true`. The native task link can also be used for native task control. Keep the foreground wait below the ingress timeout. [OpenAI background and cancellation behavior](https://developers.openai.com/api/docs/guides/background)

| Native consumer state | Response status and content |
| --- | --- |
| `evaluating`, `accepted` | `queued`, empty `output`. |
| `executing`, `cancelling` | `in_progress`, empty `output`. Continue polling until confirmed disposition. |
| `completed` with releasable result | `completed`, one final assistant message with one `output_text` part. An approved `unable` result uses its explicit explanation as the answer. |
| `cancelled` | `cancelled`, empty `output`. |
| `rejected`, `failed`, `indeterminate` | `failed`, empty `output`, and a sanitized `error`. For `indeterminate`, say that LASA could not confirm the outcome. Discourage resubmission for that outcome. |

The compatibility task runs without a clarification turn. Persist that choice at submission and enforce it at both planning and runtime. Where appropriate, release a verified `unable` answer. A required clarification without a valid outcome ends the task with a safe input-required failure and guidance to submit a new request with more detail. [Native lifecycle](execution.md#durable-lifecycle-and-failures)

Use a stable response shape validated against a pinned OpenAI SDK reference and checked-in examples. Include `id`, `object: "response"`, `created_at`, `model`, `status`, `background`, `error`, `incomplete_details`, `output`, `tools: []`, `tool_choice: "none"`, and `parallel_tool_calls: false`. Set `incomplete_details` and `usage` to `null`. Use `instructions: null` to avoid reflecting submitted instructions. The output message has a stable `msg_…` ID, `type: "message"`, `role: "assistant"`, `status: "completed"`, and `content: [{"type":"output_text","text":"…","annotations":[]}]`. The SDK can derive `output_text` from the message. Native budgets and utilization remain available for operator accounting. [OpenAI Response type](https://github.com/openai/openai-python/blob/main/src/openai/types/responses/response.py)

Check current ownership, authorization, and release scope on every read or replay, including the original foreground response and cancellation responses. Use the already pinned task for reads when an alias is withdrawn from new submissions. Return a safe `403` when the current owner has lost authorization to read the result. Use `404` for a foreign or expired response ID. Link the native task with a same-origin `Link` header using `rel="related"`. Following the link requires the LASA credential. The native result supplies evidence, receipts, and artifact IDs for download. Keep draft text, raw model frames, tools, private peer topology, and operator traces inside the supervisor boundary. [Consumer result projection](../lasa_service/consumer.py) · [Release read checks](../lasa_service/coordinator.py)

### HTTP errors and task failures

Request errors use `{"error":{"message":"…","type":"…","param":null,"code":"…"}}`. Include a per-HTTP-attempt `x-request-id` and `Cache-Control: no-store`. Keep code and message inputs allowlisted and safe for clients. Return HTTP `200` with `status: "failed"` for a recorded terminal task failure, so polling and SDK retry logic can distinguish it from a failed HTTP exchange. Preserve effect uncertainty in the native task record. [OpenAI API errors](https://developers.openai.com/api/docs/guides/error-codes) · [OpenAI ResponseError type](https://github.com/openai/openai-python/blob/main/src/openai/types/responses/response_error.py)

| Condition | HTTP or Response mapping |
| --- | --- |
| Malformed input, unsupported parameter, or unsupported file form | HTTP `400 invalid_request_error` with a field path. |
| Invalid credentials, forbidden action, unknown resource | HTTP `401`, `403`, or `404` as applicable. |
| Conflicting idempotency key or admission offer change | HTTP `409` with distinct conflict codes. A changed offer requires re-evaluation against the configured binding. |
| Oversized input or temporary request, capacity, or storage limit | HTTP `413` for size and `429` for exhausted quota or capacity. Supply `Retry-After` when a retry time is known. |
| Supervisor or required inspection dependency unavailable before submission | HTTP `503` when temporary. A policy denial is a separate `403`. |
| Foreground wait expired after durable submission | HTTP `504 response_timeout` with `x-lasa-response-id` and the native task link. |
| Recorded task failure | `error.code: "invalid_prompt"` for unusable input or required clarification, `"rate_limit_exceeded"` for a recorded rate limit, and `"server_error"` for operational, verification, or indeterminate failures. Map only cases with those meanings. Include a safe LASA disposition code in `x-lasa-task-code` for callers using raw HTTP. |

## Durable identity, retries, and retention

Store a small response record in the supervisor's durable store. It holds owner, ID, task link, alias, foreground/background mode, and timestamps. The native store owns task state, input, output, receipts, and cancellation. Store a durable request reservation scoped to owner, route, and `Idempotency-Key` for each keyed create. Derive stable native session, submit, and cancel operation keys server-side from the reservation or response identity. Store a digest of the strictly validated canonical client request. Reuse the original operation for the same key and request. A changed request with the same key returns `409 idempotency_conflict`.

Clients can omit `Idempotency-Key`. Each independently received unkeyed create is a new request. Recommend a stable caller-generated key on every retryable create and configure the SDK retry policy where the client cannot supply one. Never deduplicate across requests by prompt text. An identical business request can intentionally be submitted twice. [Native idempotency](execution.md#durable-lifecycle-and-failures) · [OpenAI Python SDK retries](https://github.com/openai/openai-python#retries)

Persist the reservation before allocating a new session. Associate the session idempotently with that reservation. Commit the response-to-task link, native task, and native submit receipt in one transaction. Use the native submit preflight and transactional recheck around asynchronous inspection. Concurrent keyed submissions share one bounded intake attempt. A concurrent retry can wait for that attempt within its intake budget or receive `409 request_in_progress` with `Retry-After`. Store a digest and an expiring claim for pre-commit intake. A matching client retry can recover an interrupted claim under the original deadline and pins. Release expired claims and collect unused sessions through the native lifecycle. After native receipt, use normal startup reconciliation and resume observation of the same task. A lost create acknowledgment after commit leaves a recoverable response ID. Use the shared native cancellation operation and settle races against the current task revision, including a terminal result that wins the race. [Coordinator submission and cancellation](../lasa_service/coordinator.py)

Retain the response mapping and keyed replay record for the owning native session's documented retention period. Collection follows session teardown and preserves the native treatment of active or unreconciled work. Keep replay uniqueness while the task exists. After the retention window, retrieving the old ID returns `404`. Document the retry window and require clients that lost an acknowledgment to resolve the old operation before initiating another after that window. HTTP disconnect, response cancellation, response expiry, and file deletion are distinct operations. [Session retention](execution.md#durable-lifecycle-and-failures)

## File inputs and released artifacts

### Inline documents

Accept `input_file` with a display `filename` and inline Base64 `file_data`. The initial allowlist is UTF-8 `.txt` and `.md`, with matching `text/plain` or `text/markdown` and optional UTF-8 charset. Check filename length, reject path syntax and control characters, enforce strict Base64 and UTF-8 decoding, and reject mismatched or unsupported media types. If the data is bare Base64, infer the media type from the allowlisted extension. Cap both encoded request size and decoded bytes before allocating significant memory. Include the decoded text and its digest in the canonical task input and account for its final serialized size against the native task budget. [OpenAI file inputs](https://developers.openai.com/api/docs/guides/file-inputs)

Document inputs have their own input-local identity. LASA's existing artifact manifests carry a source task ID and describe output a task produced. Use the dedicated capability's `documents` field for user-supplied files and reuse native caller request inspection on that input. Apply the selected processing terms to inspection, execution, verification, and any future delegation. Use separate ingress and parser qualifications before accepting PDFs, Office files, or images. Reject `file_url` in this profile. [Artifact schema](contracts.schema.json) · [LASA processing boundary](multi-peer-delegation.md)

### Upload by file ID

Enable Files routes as a separate feature when an identified client uses upload-by-ID. The scoped profile accepts multipart `POST /files` with `purpose=user_data`, returns a standard File object, and supports owner-scoped `GET /files/{file_id}`, `GET /files/{file_id}/content`, and `DELETE /files/{file_id}`. A Responses `input_file` part can carry that `file_id` in place of inline data. Use opaque `file-…` IDs and stable filename, byte count, timestamps, purpose, and expiry. Apply the same type and size policy as inline documents. [OpenAI Files API](https://developers.openai.com/api/reference/resources/files/methods/create)

Store bounded immutable upload bytes and metadata in the supervisor's private store, owned by the authenticated principal. Publish the file ID only after complete validation and a durable commit. Check current access, expiry, digest, and processing eligibility when resolving a file ID. Read a consistent snapshot, then recheck that the same file is accessible at native task commit. Persist its text and digest in the native task input before returning the response. Deletion or expiry blocks future task use. An admitted task keeps its inspected snapshot until native retention ends. Keyed uploads reuse the same file ID while it is valid and return `404` for a deleted or expired file during the advertised replay window. Apply per-owner file count, stored-byte, and upload-rate limits, plus a global storage ceiling.

An upload arrives before the client selects a model alias. Qualify the upload store, parser and any upload-time inspection within one explicitly provisioned processing boundary. Enable Files only for principals and aliases that permit that staging boundary. On each use, apply the selected offer's current processing terms and the normal task intake check before any task-bearing transfer. Give uploads a finite operator-set TTL and advertise it to clients.

### Downloads

Clients can use the related native task's manifest to fetch released artifacts at `GET /tasks/{task_id}/artifacts/{artifact_id}` with their LASA credential. The route returns authorized, integrity-checked bytes. A client that needs first-class OpenAI-style generated file citations would require a mapping to released artifacts with the same ownership and release checks. [Native artifact endpoint](api.openapi.json) · [OpenAI container file downloads](https://developers.openai.com/api/docs/guides/tools-code-interpreter#work-with-files)

## Operations and later compatibility

- Use separate ingress rate limits for create, retrieve, cancel, and upload. Bound active responses per caller and use the native supervisor's global capacity. Bound body read time and size before parsing, waits after submit, and cleanup time after cancellation. Disable shared caches and body logging at both the proxy and app. If browser access is required, allowlist exact origins and the headers that the chosen client needs.
- Record metadata-only counters and latency for intake, admission, completion, verification failure, policy denial, idempotent replay, cancel, and file storage. Correlate the HTTP request ID with the native task ID in authorized logs. Exclude bearer tokens, raw idempotency keys, prompt text, filenames, file bytes, provider frames, and released answer text from routine logs.
- Disabling new work during rollout leaves retrieval and cancellation available while active tasks drain. Gate new starts at ingress or with a defined supervisor drain mode. After draining, the operator can unmount the route group. Establish client-visible limits and retention before enablement and verify them over the deployed HTTPS prefix.
- Add Responses streaming only for a qualified client. Specify and test standard SSE event order, stable item identifiers, sequence numbers, bounded wait and buffering, error events, and disconnect and resume behavior. Stream status and final text from the public task view after release. Streaming of draft model tokens would change LASA's release guarantee.
- If the target requires Chat Completions, define its message, finish-reason, error, timeout, and streaming contract against the same native task semantics. Carry conversation text explicitly. Add server-side chaining separately if needed, with current authorization on all retained context and preserved input lineage.

## Implementation and acceptance

| Milestone | Evidence required before completion |
| --- | --- |
| Wire contract | Pin a Responses reference and SDK versions. Validate request and response fixtures. Exercise `base_url`, bearer auth, model listing, foreground, background, cancellation, and expected error types with the first client. Use the official Python SDK as a baseline and qualify another SDK only if it is in scope. |
| Native integration | Demonstrate one native task for each new response, the exact alias offer and processing terms, native deadline and quotas, correct status and result mapping, and explicit behavior for clarification and unable outcomes. Run the native protocol, admission, privacy, and verification checks affected by shared changes. |
| Authority and release | Exercise two different users plus peer and operator tokens. Verify isolation across aliases, response and file IDs, same-origin native links, and artifact access. Revoke access after admission and after completion. Inject withheld content, document instructions, invalid inputs, and inspection failure, and check the resulting outbound traffic and public errors. |
| Reliability | Lose the create acknowledgment before and after the commit, race equivalent keyed requests, change content under the same key, and retry after restart. Race completion with cancellation. Test foreground timeout, disconnect, native indeterminate reconciliation, storage quotas, cleanup, and expiry. |
| Files | Exercise empty, malformed, oversized, and valid UTF-8 inputs, media-type mismatch, input accounting, and artifact release. Before enabling upload-by-ID, test interrupted upload, duplicate uploads, cross-user access, file expiry and deletion before and after task commit, and retention cleanup. |
| Deployment | Verify route prefix and boot-time configuration checks over authenticated HTTPS with the selected client and synthetic data. Record supported methods and fields, selected client version, operator limits, and effective retention. Leave the feature disabled on other instances until provisioned. |
