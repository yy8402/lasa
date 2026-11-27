# Running the target service

## Provision an installed service

For a managed installation, start with the [deployment quickstart](deployment/DEPLOYMENT.md).

For a native development setup, install the LASA wheel with its production dependencies. The host-local launcher needs a Docker daemon and the matching Codex worker image. The supervisor connects to the launcher over a private Unix socket. From the extracted source distribution or the checkout’s `v0/` directory, build the worker and get the immutable image ID from the daemon that will run the workers.

```sh
docker build --platform linux/amd64 -t lasa-codex-worker:1.0.0 .
lasa_worker_image=$(docker image inspect --format '{{.Id}}' lasa-codex-worker:1.0.0)
```

For local development, run the launcher under your account with Docker access. The socket directory should be private and writable by your account. The supervisor connects to the owner-only socket. Use the [separate container deployment](#running-lasa-in-docker) to give Docker access only to the launcher.

```sh
install -d -m 0700 "$HOME/.local/state/lasa/launcher-locks"
lasa-launcher --lock-directory "$HOME/.local/state/lasa/launcher-locks" --image "$lasa_worker_image" \
  --scope https://identity.example.net/services/review \
  --socket /run/lasa/review/launcher.sock
```

Create one manifest and one receiver policy at a stable path for the service. This example uses a named instance, a TLS-terminating proxy, and an ES256 issuer. Choose the service identity once and use it as the JWT audience. Supply a public JWKS URL or use `--jwks-file` for a local public key set.

```sh
lasa config init --output /etc/lasa/review --state-root /var/lib/lasa/review \
  --service-id https://identity.example.net/services/review \
  --base-url https://review.example.net/lasa/v1 \
  --issuer https://identity.example.net \
  --jwks-url https://identity.example.net/.well-known/jwks.json \
  --launcher-socket /run/lasa/review/launcher.sock \
  --model YOUR_MODEL_ID --provider-url https://provider.example.net/v1 \
  --credential-ref file:/run/secrets/lasa/review/model-key
```

The initial policy denies access until the administrator adds issuer subjects and grants. Pass `--consumer-subject SUBJECT` to grant read-only `design.review`. Add `--consumer-capability task.attempt` to provision the bounded, effect-free offer used by the first-task command and portal. Use `--operator-subject SUBJECT` with a distinct subject to grant access to operator traces. `--jwt-algorithm` can be repeated for an issuer with multiple allowed algorithms. Keep signing keys at the issuer. Mount the model key at the referenced path or inject it via an `env:NAME` reference. The scaffold creates the two JSON files exclusively with owner-only permissions.

Before startup, run the check as the service user with the same mounts and credentials. It validates the manifest, bindings, policy, secrets, TLS, authentication, and connectivity to the matching launcher and Docker daemon. The launcher verifies its pinned worker image and Codex version before opening the socket. It leaves the service store untouched and sends no model or peer requests. `--offline` skips the launcher and remote JWKS access and still checks local artifacts.

```sh
lasa config check --config /etc/lasa/review/config.json
lasa --config /etc/lasa/review/config.json
```

[Field-by-field configuration guide](CONFIGURATION.md) · [Compact example](design/examples/config-no-peer.json) · [Manifest schema](design/config.schema.json) · [Packaged defaults](lasa_service/config_defaults.json)

For a single system-wide instance, `lasa config init` defaults to `/etc/lasa`. Startup, `lasa config check`, and token issuance default to `/etc/lasa/config.json`. Use a dedicated config directory and state root for each named instance. LASA derives `private/` and `workspaces/` from `storage.state_root`, which defaults to `/var/lib/lasa`. The private store belongs to one supervisor. Workers have an empty scratch workspace. The broker mediates access to the LASA session workspace.

LASA reads `authorization.json` beside the manifest by default. Set `authorization.policy_file` for a separate policy mount. A local JWKS path can also be relative to the manifest. Use absolute paths for the state root and secret file references. Keep active configuration and credentials at stable service-specific paths across releases.

```text
/etc/lasa/review/
  config.json
  authorization.json
/var/lib/lasa/review/
  private/
  workspaces/
/run/secrets/lasa/review/
  model-key
```

The manifest defaults to a loopback listener on port `8787`, local execution, and built-in review and task attempt capability definitions. It derives the descriptor URL and deployment revision. Manifest changes take effect on restart. Replace the receiver policy atomically to apply grant changes to subsequent checks. File-based credentials are reread on use. Environment secrets and issuer keys loaded at startup require a restart to refresh. [Managed configuration updates](deployment/OPERATIONS.md#update-configuration-or-upgrade-lasa)

### Content security gateways

Register local or remote scanner endpoints under `content_security.inspection_profiles` and select them in grouped `bindings`. Mount each profile's credential and any private CA only in the supervisor. Run `lasa config check` with those mounts to see the effective inspection rule for each direction, peer, connector, and operation. An enforced gateway failure holds protected data while authenticated task disposition remains available through `GET /tasks/{task_id}?view=control`. [Content security configuration](CONFIGURATION.md#content-security)

### Static tokens

JWT is the default. A service can opt into opaque bearer tokens with `authentication.mode: static_token`. The service’s incoming authentication mode and its outgoing peer choices are independent. An empty `peers` list enables local execution for capabilities with local bindings.

Initialize a static-token manifest with `--auth-mode static_token` and omit the JWT issuer and JWKS flags. For example, use the following from the repository root after starting the launcher.

```sh
lasa config init --output /etc/lasa/review --state-root /var/lib/lasa/review \
  --auth-mode static_token --consumer-subject consumer \
  --service-id https://identity.example.net/services/review \
  --base-url https://review.example.net/lasa/v1 \
  --launcher-socket /run/lasa/review/launcher.sock \
  --model YOUR_MODEL_ID --provider-url https://provider.example.net/v1 \
  --credential-ref file:/run/secrets/lasa/review/model-key

lasa config issue-token --config /etc/lasa/review/config.json \
  --subject consumer --output /absolute/private/client/lasa-token.txt
lasa config check --config /etc/lasa/review/config.json
```

Issue the token from an environment where the CLI can read the manifest's referenced credentials and update the registry. Use an existing private caller directory outside the server configuration directory for the output. The command creates an owner-only token file and stores its service-bound digest, subject, and expiration in `static-tokens.json` beside the manifest by default. Set `authentication.tokens_file` for a separate registry mount. An empty registry denies access. Client requests use `Authorization: Bearer <token>` over HTTPS, and `authorization.json` grants the subject its capabilities.

The default lifetime is 720 hours. Set `--ttl-hours` when issuing a shorter-lived credential. To rotate, issue a second token for the same subject into a new caller file and switch the client. Revoke the old token by removing its digest entry in an atomic replacement of the private registry, or let it expire. LASA reads the registry on each authenticated request, so rotation and revocation take effect without restarting the service.

### Mixed authentication for delegation

On the sender, a peer entry defaults to JWT. To call a static-token receiver, set that entry's `authentication` to `{"mode": "static_token", "subject": "peer-parent"}` and point `credential_ref` to the caller's opaque token. Pin the receiver service ID and allowed HTTPS base URL in that entry.

On the receiver, set up a `kind: peer` principal whose subject matches the sender's configured subject and whose `service_id` identifies the sender. Grant the allowed workload through receiver policy. Use `lasa config issue-token --subject peer-parent` with the receiver manifest and deliver the generated token file to the sender. The sender also needs its own delegation grant for that link.

LASA attaches a workload identity fingerprint to static peer requests. The receiver checks it against the authenticated token subject, the subject's configured service identity, and the receiver's own service ID. Keep those identities stable when rotating a token so child receipts and retries stay bound to the same workload. `lasa config check` validates the local credential against each peer's configured mode. Peer discovery checks the receiver's advertised mode and the exact wire-schema digest when the sender connects.

### Isolated development

For local experiments that need test JWTs, use [the development generator](tools/create_development_config.py) with Python dependencies installed in the checkout. It generates a development issuer, public JWKS, and 24-hour test tokens under an empty output directory. Use the normal issuer and receiver policy for an installed service.

```sh
uv sync --project v0 --frozen
uv run --project v0 python v0/tools/create_development_config.py \
  --output /absolute/path/to/lasa-dev \
  --base-url https://localhost:8443/lasa/v1 \
  --service-id https://identity.example.net/services/development \
  --launcher-socket /run/lasa/review/launcher.sock
```

## Running LASA in Docker

Use the [installation guide](deployment/DEPLOYMENT.md) to install a pinned supervisor and launcher
and verify HTTPS readiness. The deployment specification can opt into the [caller portal](portal/README.md)
and [DLPLite](deployment/LOCAL_DLP.md). Use the [operations runbook](deployment/OPERATIONS.md) to
update or roll back the installed site while preserving task receipts.

## Model service and prompts

In `config.json`, set `executors[].model` to the model ID, `provider_base_url` to the provider's HTTPS API base URL, and `credential_ref` to `env:NAME` or `file:/absolute/private/key.txt`. LASA appends `/responses`, so use a provider that supports the OpenAI Responses API, including structured outputs and streamed tool calls for Codex execution. Local task steps use the executor selected by their binding. Set `default_executor` explicitly when configuring multiple executors. Planning, verification, and unbound integration use that executor. Each LASA peer has its own configuration.

The bundled [prompts.json](lasa_service/prompts.json) contains the seven LASA instruction templates for proposal, plan review, outcome verification, execution, source retrieval, and integration. To customize them, copy that file to a private location and set the top-level `"prompts_file": "/absolute/path/to/prompts.json"` in `config.json`. LASA validates the complete file at startup. Keep the template keys and the `{purpose}` placeholder in `assessment_developer`. Restart the service after edits. LASA supplies typed inputs, assigned criteria, and evidence at runtime. Codex App Server supplies its built-in instructions.

LASA registers the approved tools for each step as immediately callable Codex App Server functions. Workspace writes and readback use `workspace_write` and `workspace_read`. The broker checks current permission and remaining allocation when a function is called. Private MCP connectors remain upstream of the broker.

## Submitting work

Set `LASA_ACCESS_TOKEN` to the caller’s receiver-scoped JWT or static token. Run this command from the extracted source archive or the checkout’s `v0/` directory with the installed environment active.

```sh
python run_task.py \
  'Explain the responsibilities of a parent service and its bounded worker.' \
  --base-url https://localhost:8443/lasa/v1 \
  --ca-file /absolute/path/to/ca.pem
```

The script discovers caller-visible offers, creates a session, submits typed input, and prints
consumer-visible status and events. If your scaffold grants `design.review`, use
`--capability design.review --input-json /path/to/review.json` with this input shape.

`{"design":"Text to review","criteria":[{"id":"ownership","description":"Identify the owner."}]}`

Use `--offer-id` when more than one offer matches. An operator can retrieve private traces using
the receiver’s [operator API](design/api.openapi.json) and an operator credential.

To delegate, add `peers` entries in preference order. Each entry names the downstream descriptor URL, expected service ID, allowed base URL, and receiver-scoped credential reference. Use its `ca_file` for private TLS. The sender’s receiver policy grants the exact sender, receiver and contract in `delegation_grants`. The downstream policy maps the workload subject to that service ID and separately defines its locally fulfillable read-only offers. [Multi-peer delegation](design/multi-peer-delegation.md)

List additional built-in capabilities by name in `published_contracts`. LASA accepts exact contract references for custom registry entries and validates those against the configured publisher and verifier. Define connector operations in `executors[].connectors`, and use explicit `bindings` with `required_operations` for source-backed capabilities. An explicit bindings list selects all local bindings for that service. See the [connector design](design/connectors.md) and the [advanced manifest example](design/examples/config.json) for the policy and binding structure.

After a lost acknowledgment, reuse the same operation ID and idempotency key. `GET /operations/{operation_id}` reconciles the original receipt without creating work. An uncertain terminal task remains immutable; `POST /tasks/{task_id}/reconcile` can append a resolution event. Do not resubmit uncertain effectful work as a new task automatically.
The task client prints each operation ID before sending its request so you can look up either receipt after a lost acknowledgment.

## Typed workflows

Publish `design.review-checklist` to run an inline review and dependent checklist using approved delegates. Configure verifier trust in the parent policy and select an outcome verification model in each service manifest. [Workflow registration and trust checks](design/execution.md#typed-workflows)

## Verification

```sh
v0/.venv/bin/python v0/design/validate.py
v0/.venv/bin/python -m ruff check v0/lasa_service v0/tests v0/evaluations v0/run_task.py v0/tools
v0/.venv/bin/python -m pytest -q v0/tests
v0/.venv/bin/python v0/evaluations/run_evaluations.py --output /absolute/path/to/evidence
```

The actual-model evaluator uses saved model credentials privately, ephemeral receiver keys/policies, two isolated HTTPS listeners, the immutable pinned Codex image, and a frozen assessment corpus. It does not contact or reconfigure installed services. See the acceptance matrix for recorded candidate results and limitations.
