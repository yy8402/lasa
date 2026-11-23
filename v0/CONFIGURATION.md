# LASA config.json reference

Use one `1.0.0` manifest for each LASA service. Keep it at a stable path such as `/etc/lasa/review/config.json`. It describes the service, its execution environment, and its optional downstream peers. The receiver policy and credentials live in separate files or secret sources.

Start with `lasa config init`. Add only the overrides your deployment needs. Run `lasa config check --config /path/to/config.json` as the service user with the same mounts and credentials before restarting. Use `--offline` for local validation when Docker or a remote JWKS is unavailable. A manifest change takes effect on restart. Policy files and file-backed credentials are reread during use. [Provisioning and deployment](RUNNING.md#provision-an-installed-service)

In the tables, **Required** means the field must appear in the supplied object. **None** means LASA supplies no value. Values written by `config init` are identified separately. The schema rejects unknown manifest fields. Use absolute paths for mounts and private files unless a field explicitly resolves relative paths beside the manifest. [Manifest schema](design/config.schema.json) · [Packaged defaults](lasa_service/config_defaults.json)

## Top-level fields

| Setting | Required | Default | Allowed values | What it does and when to set it |
| --- | --- | --- | --- | --- |
| `config_version` | Yes | None. Init writes `"1.0.0"`. | `"1.0.0"` | Selects the manifest format for this release. |
| `service` | Yes | See below | Object | Sets the stable service identity, advertised URL, and workspace settings. |
| `authentication` | Yes | See below | JWT or static-token object | Verifies incoming callers. Choose static tokens explicitly when provisioning an opaque bearer credential. |
| `authorization` | No | The policy file `authorization.json` beside the manifest | Object with optional `policy_file` | Points to the separate policy that determines what authenticated subjects can do. |
| `executors` | Yes | None | One or more executor objects with distinct IDs | Selects the model provider and any private connectors. Start with one executor. |
| `runtime` | Yes | See below | Object with `image` | Pins the Codex worker and controls its startup timeout. |
| `default_executor` | With multiple executors | The sole executor's ID | An ID in `executors` | Selects the executor for planning, verification, integration, and generated local bindings. Set it explicitly with multiple executors. |
| `peers` | No | `[]` | Ordered list of 0–16 peer objects with distinct, non-self service IDs | Supplies downstream routes. Order breaks ties among suitable peers. Leave it empty for standalone operation. |
| `routing` | No | Local preference and reject fallback | Object | Changes how eligible local and peer routes are selected. |
| `storage` | No | See below | Object | Overrides private state paths or listener settings. |
| `limits` | No | See below | Object | Sets service-wide task and lifecycle ceilings. |
| `discovery_cache` | No | See below | Object | Controls freshness and pagination for discovery. |
| `published_contracts` | No | `["design.review", "task.attempt"]` | Unique built-in names or exact contract references | Selects the outcomes the service may offer under caller policy. Change it when narrowing or expanding the service's capabilities. An empty list publishes no capability offers. |
| `bindings` | No | Local bindings for the published built-in `design.review` and `task.attempt`, using the default executor | List of binding objects, at most one per exact contract | Assigns local fulfillment. An explicit list replaces all generated bindings. Include every local binding you intend to use. |
| `contract_publishers` | No | `[]` | List of publisher objects | Registers additional trusted contract definitions alongside the built-ins. Use it for contracts your organization publishes. |
| `verifiers` | No | Built-in verifier mappings | List of additional exact contract-to-verifier mappings | Associates an approved verifier with a registered contract. Add an entry for an additional contract that fits an existing verifier profile. Built-in mappings are already registered. |
| `prompts_file` | No | Bundled `prompts.json` | Absolute path, 1–2,048 characters, to a complete valid prompts JSON object | Replaces the full LASA prompt set. Copy the bundled file before customizing it. Keep all eight keys and the `{purpose}` placeholder in `assessment_developer`. |

An **identifier** in the tables below is 3–128 characters. Its first character must be an ASCII letter or digit. The remaining characters may also include `.`, `_`, and `-`. A **credential reference** names a non-empty secret using `env:NAME` or `file:/absolute/path`. Put only the reference in the manifest.

## Service, state, and worker

| Setting | Required | Default | Allowed values | What it does and when to set it |
| --- | --- | --- | --- | --- |
| `service.id` | Yes | None | HTTPS URI with host, up to 2,048 characters | Stable identity used by caller policy, delegation, and JWT audience validation. Choose a distinct value at provisioning and keep it stable across deployments. |
| `service.base_url` | Yes | None | HTTPS URL with host, up to 2,048 characters | Public API base, typically ending in `/lasa/v1`. Change it for a proxy host or path change. The descriptor is served at `<base_url>/descriptor`. |
| `service.deployment_revision` | No | Derived from package version and effective configuration | Identifier | Label advertised in discovery. Set a release-specific value when tracking a coordinated rollout. |
| `service.publish_api_catalog` | No | `false` | Boolean | Enables the public `/.well-known/api-catalog` bootstrap endpoint. Enable it when clients need unauthenticated service discovery. |
| `service.session_retention_seconds` | No | `604800` (7 days) | Integer 3,600–9,007,199,254,740,991 | Sets session lifetime and the advertised idempotency retention window. Adjust for how long clients need to recover requests. |
| `storage.state_root` | No | `/var/lib/lasa` | Non-empty absolute directory path | Holds the derived `private/` store and `workspaces/` directory. Use one dedicated writable persistent root per service. Set it with `lasa config init --state-root` when provisioning a named instance. |
| `storage.listen_host` | No | `127.0.0.1` | `127.0.0.1` or `0.0.0.0` | Selects loopback or all IPv4 interfaces. Use `0.0.0.0` when the container must listen beyond loopback and supply TLS. |
| `storage.listen_port` | No | `8787` | Integer 1–65,535 | Sets the local bind port. Override to match the Docker port mapping or reverse proxy. |
| `storage.tls` | With a non-loopback listener | None | Object with `certificate_file` and `key_file` | Enables TLS on the LASA listener. Omit it for loopback HTTP behind a TLS-terminating local proxy. |
| `storage.tls.certificate_file` | With `storage.tls` | None | Non-empty absolute path to a readable certificate chain | Supplies the server certificate and chain. Use a certificate that covers the hostname clients use for that listener. |
| `storage.tls.key_file` | With `storage.tls` | None | Non-empty absolute path to the matching private key | Supplies the server key. Mount it privately and make it readable by the service user. |
| `runtime.image` | Yes | None | Immutable Docker image ID, `sha256:` plus 64 lowercase hex digits | Pins the installed Codex worker. Update it when installing a new compatible worker image. |
| `runtime.startup_timeout_ms` | No | `10000` | Integer 1,000–60,000 | Bounds worker readiness. Increase it for reliably slower hosts after checking worker startup logs. |

Use HTTPS service URLs without embedded credentials, a query, or a fragment. LASA keeps task records, receipts, and other private state in `<state_root>/private/` and session files in `<state_root>/workspaces/`. The two paths must be direct directories. For sibling Docker workers, bind-mount the state root at the same absolute path on the Docker host and inside the supervisor. The package pins the worker executable and expected version through its internal defaults. [Docker deployment](RUNNING.md#running-lasa-in-docker)

## Incoming authentication and authorization

| Setting | Required | Default | Allowed values | What it does and when to set it |
| --- | --- | --- | --- | --- |
| `authentication.mode` | For static tokens | `jwt` | `jwt` or `static_token` | Selects how this service verifies incoming requests. Set `static_token` explicitly for an opaque-token receiver. |
| `authentication.issuer` | For JWT | None | HTTPS URI with host, up to 2,048 characters | Must exactly match the JWT `iss` claim. Set it to the trusted issuer's identifier. |
| `authentication.jwks_url` | One JWKS source for JWT | None | HTTPS URL with host, up to 2,048 characters | Fetches public signing keys at startup. Use it when the issuer exposes a reachable JWKS endpoint. |
| `authentication.jwks_file` | One JWKS source for JWT | None | Non-empty path to a public JWKS JSON file | Loads signing keys from disk. Use it for a locally provisioned key set. Relative paths resolve beside `config.json`. |
| `authentication.allowed_algorithms` | For JWT | None. Init uses `["ES256"]` unless given `--jwt-algorithm`. | Non-empty list of distinct `ES256`, `EdDSA`, or `RS256` values | Restricts signing keys and token algorithms. Set only the algorithms used by your issuer. |
| `authentication.tokens_file` | No, static mode only | `static-tokens.json` beside the manifest | Path, 1–2,048 characters, to a valid static-token registry | Stores token digests, subjects, and expirations. Relative paths resolve beside `config.json`. Override for a separate registry mount. Use `lasa config issue-token` to create a token for a policy subject. |
| `authorization.policy_file` | No | `authorization.json` beside the manifest | Path, 1–2,048 characters, to a receiver policy JSON file | Maps subjects to permissions and controls trusted delegators and delegation grants. Relative paths resolve beside `config.json`. Change it when the policy lives in a separate mount. |

A JWT receiver uses exactly one of `jwks_url` and `jwks_file`. Give each caller a token with `aud` equal to the receiver's `service.id` and a `sub` that exists in the policy. For a static-token receiver, configure the registry and omit the JWT fields. Store the actual token in a private caller file or environment variable. The registry contains only its digest and associated metadata. [Token issuance and rotation](RUNNING.md#static-tokens)

## Executors and private connectors

| Setting | Required | Default | Allowed values | What it does and when to set it |
| --- | --- | --- | --- | --- |
| `executors[].id` | Yes | None. Init writes `codex`. | Identifier, unique among executors | Names the executor used by bindings and `default_executor`. Choose a stable name. |
| `executors[].model` | Yes | None | Provider model ID, 1–256 characters | Selects the model for this executor. Update it when changing model deployment or provider. |
| `executors[].provider_base_url` | Yes | None | HTTPS URL with host, up to 2,048 characters | Base of the provider's Responses API. LASA appends `/responses`. Give the base URL, such as `https://provider.example.net/v1`. |
| `executors[].provider_ca_file` | No | Normal TLS trust | Non-empty absolute path to a readable CA bundle | Supplies trust for a provider using a private CA. |
| `executors[].credential_ref` | Yes | None. Init uses `env:LASA_MODEL_API_KEY` unless overridden. | Credential reference, 1–2,048 characters | Supplies the executor's provider credential. Use a mounted private file or injected environment variable. |
| `executors[].connectors` | No | `[]` | List of 0–32 connector objects | Enables approved upstream reads for this executor. Add connectors when a local fulfillment binding needs source operations. |

### Connector fields

The field names below are relative to `executors[].connectors[]`. Required connector fields and their nested settings have no defaults. Include only fields supported by the selected `kind`. Set the operation and binding together to grant the precise source access the capability needs. [Connector design](design/connectors.md) · [Private schema](design/private.schema.json)

| Setting | Required | Default | Allowed values | What it does and when to set it |
| --- | --- | --- | --- | --- |
| `id` | Yes | None | Identifier | Names the private connector. Keep it unique within an executor. An identical definition may be shared across executors. |
| `kind` | Yes | None | `mcp-stdio`, `mcp-http`, or `json-get` | Selects a local MCP subprocess, HTTPS Streamable HTTP MCP, or fixed HTTPS JSON GET operations. Use the kind supported by the source. |
| `limits` | Yes | None | All five limit fields below | Bounds connector work and recovery. Size it for source latency, response size, and expected concurrency. |
| `limits.max_queue` | Yes | None | Integer 1–64 | Capacity for queued calls. Increase it for legitimate bursts within the task deadlines. |
| `limits.request_timeout_seconds` | Yes | None | Number 0.05–120 | Bounds connector waits. Use a value consistent with upstream latency and task budgets. |
| `limits.response_bytes` | Yes | None | Integer 1,024–1,048,576 | Caps upstream response size. Raise it only for expected larger results. |
| `limits.recovery_interval_seconds` | Yes | None | Number 0.05–3,600 | Controls how soon an unavailable connector can recover. Increase it for slow or rate-limited sources. |
| `limits.schema_refresh_seconds` | Yes | None | Number 0.05–3,600 | Controls discovery and availability refresh frequency. Lower it when upstream changes need faster detection. |
| `operations` | Yes | None | List of 1–128 operation objects of the selected kind | Defines the operations and schemas LASA can use. Include only operations relevant to approved bindings. |
| `command` | For `mcp-stdio` | None | Absolute path to an executable, 1–2,048 characters | Launches the MCP server. Point it at the installed program visible inside the supervisor. |
| `args` | For `mcp-stdio` | None | List of strings, including `[]` | Passes arguments to the subprocess. Include paths or flags needed by this installation. |
| `secret_env` | For `mcp-stdio` | None | Object mapping environment names to credential references of 1–2,048 characters, including `{}` | Injects only the named secrets into the subprocess. Use an empty map for a source that needs none. |
| `url` | For `mcp-http` | None | HTTPS URL with host | Selects the MCP Streamable HTTP endpoint. Use the server's configured MCP path. |
| `base_url` | For `json-get` | None | HTTPS URL with host | Bounds all JSON GET operation URLs to that origin and path. Use the narrowest shared API base. |
| `headers` | For `json-get` | None | String-to-string object, including `{}` | Sets non-secret headers such as `Accept`. LASA rejects `Authorization`, `Cookie`, and `Proxy-Authorization` here. Use `credential_ref` for authentication. |
| `credential_ref` | Optional for HTTP kinds | None | Credential reference, 1–2,048 characters | Supplies an upstream HTTP bearer token. Set it only for a source that requires one. |
| `ca_file` | Optional for HTTP kinds | Normal TLS trust | Path to a readable CA bundle, 1–2,048 characters | Supplies trust for a source with a private CA. Use an absolute mount path for portability. |

### Connector operation fields

These fields are relative to `executors[].connectors[].operations[]`. Every applicable field is required and has no default. Operation schemas are JSON Schema objects. Use Draft 2020-12 by default or declare Draft 7, use local `#/` references, and omit `$id`.

| Setting | Applies to | Allowed values | What it does and when to set it |
| --- | --- | --- | --- |
| `operation_id` | All | Identifier, unique within its executor and owned by only one connector | Names an operation referenced by a binding. Keep it stable for the same defined operation. |
| `description` | All | String, 1–2,048 characters | Describes the source action. Make it specific enough for a task executor to choose correctly. |
| `effect` | All | `external.read` | Declares the supported source effect. Use this literal for source operations. |
| `resource` | All | String, 1–2,048 characters | Names the resource checked against the binding and receiver policy. Use the same resource ID in all three. |
| `input_schema` | All | JSON Schema object | Validates operation arguments. For MCP, pin the server's advertised tool input schema. |
| `argument_constraints` | All | JSON Schema object | Restricts arguments beyond the input schema. Use it for an approved path, repository, or query allowlist. |
| `output_schema` | All | JSON Schema object | Validates the normalized result LASA records. Match the fields the fulfillment binding needs. |
| `task_input_bindings` | All | List of 0–16 objects with the three fields below | Ties arguments to the task input. Use it when a caller-selected identifier must govern which source item is read. |
| `task_input_bindings[].input_field` | Each match | Non-empty name of a contract input property | Selects the authoritative value from the task input. |
| `task_input_bindings[].argument_field` | Each match | Non-empty name of an operation input property | Selects the argument constrained by that value. |
| `task_input_bindings[].comparison` | Each match | `exact` or `basename` | Requires equality or compares the operation argument's POSIX basename with the task value. Use basename for an approved path chosen by a filename input. |
| `upstream_tool` | MCP | String, 1–2,048 characters | Selects the tool by its advertised MCP name. |
| `upstream_output_schema` | MCP | JSON Schema object or `null` | Pins the advertised structured-output schema. Use `null` when the tool advertises no output schema. |
| `result_format` | MCP | `structured` or `text` | Reads MCP structured content or normalizes text blocks into `{"text": ...}`. Match the upstream tool's response. |
| `url` | JSON GET | HTTPS URL within the connector's `base_url` | Sets the fixed GET endpoint. Task-supplied scalar arguments become query parameters. |
| `response_schema` | JSON GET | JSON Schema object | Validates the upstream response before projection. Pin the expected response shape. |
| `result_fields` | JSON GET | List of 1–32 distinct non-empty field names | Keeps only the selected top-level fields of each response object. Include only the data the binding needs. |
| `probe_arguments` | JSON GET | Object matching both input and argument constraint schemas | Sets safe arguments for the connector's availability probe. Use a known permitted read. |

## Publication and bindings

The built-in names are `design.review`, `task.attempt`, `documents.read`, `documents.search`, and `repository.inspect`. Source-backed local fulfillment requires explicit bindings and registered connector operations. Authorization policy still controls which callers can see and invoke published capabilities. [Advanced manifest example](design/examples/config.json)

| Setting | Required | Default | Allowed values | What it does and when to set it |
| --- | --- | --- | --- | --- |
| `contract_publishers[].namespace` | Yes | None | HTTPS URI prefix, up to 2,048 characters | Restricts the contract IDs accepted from this publisher. Use its controlled namespace. |
| `contract_publishers[].trusted_registry_file` | Yes | None | Path, 1–2,048 characters, to a JSON array of capability definitions | Loads the publisher's trusted definitions. Relative paths resolve beside `config.json`. |
| `verifiers[].contract` | Yes | None | Exact registered contract reference | Pins the verifier assignment to that contract version and digest. Add a single mapping per additional contract. |
| `verifiers[].verifier_id` | Yes | None | `design-review-v1`, `task-attempt-v1`, `documents-read-v1`, `documents-search-v1`, or `repository-inspect-v1` | Selects an approved verifier profile. Use the one that implements the contract's outcome and evidence obligations. |
| `bindings[].binding_id` | Yes | None | Identifier | Names the private local fulfillment binding. |
| `bindings[].contract` | Yes | None | Exact registered contract reference | Selects the outcome this binding fulfills locally. Use one binding per contract reference. |
| `bindings[].executor_id` | Yes | None | ID from `executors` | Chooses the executor responsible for the local step and its required operations. |
| `bindings[].approved_resources` | Yes | None | List of resource rules, including `[]` | Sets the binding's maximum resource access. Give it only the resources needed to fulfill the contract. |
| `bindings[].approved_resources[].resource` | Yes | None | String, 1–2,048 characters | Identifies the permitted resource, such as `workspace:self` or a connector's resource ID. |
| `bindings[].approved_resources[].actions` | Yes | None | Non-empty list of distinct `read`, `create`, `update`, `delete`, or `execute` values | Restricts usable actions on the resource. A required connector operation needs `read` on its resource. |
| `bindings[].allowed_effects` | Yes | None | List of distinct `workspace.read`, `workspace.write`, or `external.read` values, including `[]` | Sets the binding's effect ceiling within the contract. `lasa config check` rejects `external.write` bindings. |
| `bindings[].required_operations` | Yes | None | List of 0–128 distinct operation IDs registered on that executor | Sets the required source operations and their allowlist. Use `[]` when local fulfillment needs only core workspace tools or no tools. |

An exact contract reference, used by publication, bindings, and verifiers, has three required fields and no defaults.

| Field | Allowed values | What it does and when to set it |
| --- | --- | --- |
| `id` | HTTPS URI, up to 2,048 characters | Names the registered contract. Copy it from the trusted definition or offer. |
| `version` | Three dot-separated nonnegative integers, without leading zeros | Pins the contract version. Use the exact registered version. |
| `digest` | `sha256:` followed by 64 lowercase hex digits | Pins the registered definition's canonical JSON. Copy the digest from the exact reference. |

## Outgoing peers and routing

Incoming authentication and outgoing authentication are independent. Put only downstream services in `peers`. The sender grants the exact delegation edge. The receiver owns the `authorization_ref` and authorizes the peer principal for the contract. [Delegation and policy](design/multi-peer-delegation.md)

| Setting | Required | Default | Allowed values | What it does and when to set it |
| --- | --- | --- | --- | --- |
| `peers[].descriptor_url` | Yes | None | HTTPS URL up to 2,048 characters inside `allowed_base_url` | Locates the peer's descriptor. Normally use the peer's public API base plus `/descriptor`. |
| `peers[].expected_service_id` | Yes | None | HTTPS URI up to 2,048 characters, distinct from the local ID and other peers' IDs | Pins the identity advertised by the peer. Use the receiver's exact `service.id` and JWT audience. |
| `peers[].allowed_base_url` | Yes | None | HTTPS URL with host, up to 2,048 characters | Restricts requests to the approved host, port, and path. Set it to that peer's public API base. |
| `peers[].credential_ref` | Yes | None | Credential reference, 1–2,048 characters | Supplies a receiver-audience JWT or the opaque token issued by that peer. Use a distinct receiver-scoped credential for each link. |
| `peers[].authentication` | No | JWT | Object for the selected peer mode | Pins the peer's credential type independently of incoming authentication. Set it explicitly when the peer uses a static token. |
| `peers[].authentication.mode` | With an explicit peer authentication object | `jwt` when the object is omitted | `jwt` or `static_token` | Selects JWT identity or a static workload pin. Match the receiver's incoming mode. |
| `peers[].authentication.subject` | For a static peer | None | Non-empty subject string | Pins the static token's policy subject. Match the receiver's `kind: peer` principal for the sender. |
| `peers[].authorization_ref` | Yes | None | Receiver policy reference, 1–512 characters | Selects the receiver rule for this peer credential. Match the rule configured for the sender's subject on the receiver. |
| `peers[].request_timeout_seconds` | No | `15` | Integer 1–60 | Bounds peer HTTP requests and discovery. Adjust for a known network or discovery latency within the task deadline. |
| `peers[].ca_file` | No | Normal TLS trust | Non-empty path to a readable CA bundle | Supplies trust for this peer's private CA. Use an absolute mount path for portability. |
| `routing.preferred_executor` | No | `local` | `local` or `peer` | Breaks a tie between suitable local and peer routes. Set `peer` when you want the parent to prefer authorized delegates. |
| `routing.unclaimed_peer_fallback` | No | `reject` | `reject` or `attempt` | Controls generic `task.attempt` fallback. Use `attempt` only when the policy permits it and a generic attempt is acceptable after fresh, complete catalogs confirm no eligible peer claims the requested outcome and local fulfillment is insufficient. |

## Limits and budgets

The service ceiling combines with the caller's requested budget, the receiver policy and offer, and any parent allocation. Raising a service limit does not expand anyone's grants.

| Setting | Required | Default | Allowed values | What it does and when to set it |
| --- | --- | --- | --- | --- |
| `limits.max_task_budget` | No | See budget table | Complete budget object | Caps task usage. Adjust to the largest task this service is prepared to accept. |
| `limits.assessment_budget` | No | See budget table | Complete budget object | Sets the assessment envelope, including caps on planning calls, model tokens, and assessment time. Increase it for larger planning inputs or more complex decomposition. |
| `limits.integration_reserve` | No | See budget table | Complete budget object | Reserves part of the task budget for final integration. Adjust it for multi-step results and leave enough budget for fulfillment. |
| `limits.max_hops` | No | `2` | Integer 0–32 | Caps delegation depth. Use `0` to forbid onward delegation or raise it for a deeper authorized topology. |
| `limits.max_children` | No | `2` | Integer 0–64 | Caps immediate delegated children per task. Adjust for the intended fan-out. |
| `limits.max_plan_steps` | No | `16` | Integer 1–64 | Caps steps in a plan. Adjust to bound the complexity of admitted workflows. |
| `limits.max_active_tasks` | No | `4` | Integer 1–1,024 | Limits concurrent active tasks. Size it for your workers, provider quota, and host capacity. |
| `limits.max_clock_skew_seconds` | No | `5` | Integer 0–60 | Allows slack when comparing the requested task deadline to the service wall-time ceiling. Adjust for measured host clock differences. JWT expiry validation applies separately. |
| `limits.reconciliation_timeout_seconds` | No | `30` | Integer 1–300 | Bounds a recovery pass for unresolved child work. Adjust for the required receipt and cancellation round trips. |

Each supplied budget replaces the corresponding packaged object. Include all eight fields, even those set to zero. Each is an integer from 0 to 9,007,199,254,740,991. A zero allocates no capacity for that dimension. The table lists the defaults when the respective budget object is omitted.

| Budget field | Max task | Assessment | Integration reserve | What it measures and when to adjust it |
| --- | ---: | ---: | ---: | --- |
| `model_tokens` | 24,000 | 2,000 | 2,000 | Model token allowance. Account for prompts, responses, and delegated usage. |
| `model_calls` | 6 | 1 | 1 | Number of model requests. Increase for multiple execution or verification calls. |
| `tool_calls` | 12 | 0 | 0 | Number of tool calls. Size it for documented source or workspace operations. |
| `delegations` | 2 | 0 | 0 | Number of delegated calls charged to the task. Size it for the expected workflow. |
| `wall_time_ms` | 180,000 | 10,000 | 15,000 | Elapsed time in milliseconds. Budget for provider latency, child execution, and integration. |
| `input_bytes` | 64,000 | 64,000 | 0 | Input data size. Increase for larger request input or disclosed dependency data. |
| `output_bytes` | 32,000 | 4,000 | 4,000 | Result size allowance. Change it for workflows with larger structured results. |
| `artifact_bytes` | 128,000 | 0 | 0 | Artifact size allowance. Allocate it only where the task needs artifact data. |

## Discovery cache

| Setting | Required | Default | Allowed values | What it does and when to set it |
| --- | --- | --- | --- | --- |
| `discovery_cache.descriptor_max_age_seconds` | No | `300` | Integer 0–3,600 | Sets descriptor freshness. Lower it when changes must be picked up sooner. |
| `discovery_cache.catalog_max_age_seconds` | No | `60` | Integer 0–300 | Sets offer catalog freshness and caps the lifetime of a cached peer discovery response. Lower it when offers change frequently. |
| `discovery_cache.availability_max_age_seconds` | No | `5` | Integer 0–30 | Sets availability response freshness. Lower it for rapidly changing capacity. |
| `discovery_cache.page_size` | No | `50` | Integer 1–100 | Sets the number of offers per catalog page. Use smaller pages if responses are large. |

## Standalone JWT example

This is a complete manifest. Replace the example URLs, model ID, and all-zero placeholder image ID before deployment. Provide `authorization.json` beside the manifest and inject `LASA_MODEL_API_KEY` into the service environment. The omitted peer list defaults to `[]`, and LASA generates local bindings for the default built-in contracts.

```json
{
  "config_version": "1.0.0",
  "service": {
    "id": "https://identity.example.net/services/primary",
    "base_url": "https://primary.example.net/lasa/v1"
  },
  "authentication": {
    "issuer": "https://identity.example.net",
    "jwks_url": "https://identity.example.net/.well-known/jwks.json",
    "allowed_algorithms": ["ES256"]
  },
  "executors": [
    {
      "id": "codex",
      "model": "YOUR_MODEL_ID",
      "provider_base_url": "https://provider.example.net/v1",
      "credential_ref": "env:LASA_MODEL_API_KEY"
    }
  ],
  "runtime": {
    "image": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  }
}
```

## Mixed-auth delegation example

The parent uses JWT for incoming callers. It prefers two downstream services for eligible steps, with a JWT for primary and a static token for review. This is a complete parent manifest. Put the parent policy beside it and mount the two private peer credential files on the parent.

```json
{
  "config_version": "1.0.0",
  "service": {
    "id": "https://identity.example.net/services/parent",
    "base_url": "https://parent.example.net/lasa/v1"
  },
  "authentication": {
    "issuer": "https://identity.example.net",
    "jwks_url": "https://identity.example.net/.well-known/jwks.json",
    "allowed_algorithms": ["ES256"]
  },
  "storage": {"state_root": "/var/lib/lasa/parent"},
  "executors": [
    {
      "id": "codex",
      "model": "YOUR_MODEL_ID",
      "provider_base_url": "https://provider.example.net/v1",
      "credential_ref": "env:LASA_MODEL_API_KEY"
    }
  ],
  "runtime": {
    "image": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  },
  "routing": {"preferred_executor": "peer"},
  "peers": [
    {
      "expected_service_id": "https://identity.example.net/services/primary",
      "allowed_base_url": "https://primary.example.net/lasa/v1",
      "descriptor_url": "https://primary.example.net/lasa/v1/descriptor",
      "credential_ref": "file:/run/secrets/lasa-primary-jwt",
      "authentication": {"mode": "jwt"},
      "authorization_ref": "parent-checklist"
    },
    {
      "expected_service_id": "https://identity.example.net/services/review",
      "allowed_base_url": "https://review.example.net/lasa/v1",
      "descriptor_url": "https://review.example.net/lasa/v1/descriptor",
      "credential_ref": "file:/run/secrets/lasa-review-token",
      "authentication": {"mode": "static_token", "subject": "peer-parent"},
      "authorization_ref": "parent-review"
    }
  ]
}
```

- **Primary receiver.** Use the standalone JWT manifest on primary and set `published_contracts` to `["task.attempt"]` if this peer should specialize in checklists. Issue a JWT with primary's `service.id` as its audience and `peer-parent` as its subject. Its receiver policy maps that subject to the parent ID and grants `task.attempt` under `parent-checklist`.
- **Review receiver.** Use the standalone manifest as a base, with the review service ID and base URL from the parent peer entry. Replace the entire `authentication` object with `{"mode": "static_token"}`. Keep the registry at the default `static-tokens.json` path. Set `published_contracts` to `["design.review"]` if this peer should specialize in reviews. Its policy maps `peer-parent` to the parent ID and grants `design.review` under `parent-review`. Issue the token on review with `lasa config issue-token --config /etc/lasa/review/config.json --subject peer-parent --output /absolute/private/client/lasa-review-token` and mount it at the parent's referenced path.
- **Policies and state.** Each receiver lists the parent in `trusted_delegator_service_ids` and declares its subject as `kind: peer` with the parent's service ID. The parent's policy grants each exact contract and receiver in `delegation_grants`. Grant any predecessor disclosure explicitly for the chosen receiver. Give each service its own policy and state root, such as `/var/lib/lasa/primary` and `/var/lib/lasa/review` for the two receivers. Add user principals if operators also call the delegates directly.
- **Preflight.** Replace the placeholder deployment values on every service, set task and assessment budgets appropriate for the workflow, and run `lasa config check` for each service. Then test with the real credentials over HTTPS. [Air188 runbook](deployment/air188.md)
