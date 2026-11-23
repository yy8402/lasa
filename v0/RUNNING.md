# Running the target service

## Provision an installed service

Install the LASA wheel with its production dependencies. The supervisor needs a Docker daemon and the matching Codex worker image. From the source distribution or checkout, build the worker and get the immutable image ID from the daemon that will run the workers.

```sh
docker build -t lasa-codex:target-v1 v0
lasa_worker_image=$(docker image inspect --format '{{.Id}}' lasa-codex:target-v1)
```

Create one manifest and one receiver policy. This example assumes TLS terminates at a proxy and the issuer uses ES256. Choose the service identity once and use it as the JWT audience. Supply a public JWKS URL or use `--jwks-file` for a local public key set.

```sh
lasa config init --output /etc/lasa \
  --service-id https://identity.example.net/services/review \
  --base-url https://review.example.net/lasa/v1 \
  --issuer https://identity.example.net \
  --jwks-url https://identity.example.net/.well-known/jwks.json \
  --image "$lasa_worker_image" \
  --model YOUR_MODEL_ID --provider-url https://provider.example.net/v1 \
  --credential-ref file:/run/secrets/lasa-model-key
```

The initial policy denies access until the administrator adds issuer subjects and grants. Pass `--operator-subject SUBJECT` to generate a read-only `design.review` grant for one subject. `--jwt-algorithm` can be repeated for an issuer with multiple allowed algorithms. Keep signing keys at the issuer. Mount the model key at the referenced path or inject it via an `env:NAME` reference. The scaffold creates the two JSON files exclusively with owner-only permissions.

Before startup, run the check as the service user with the same mounts, credentials, and Docker access. It validates the effective manifest, bindings, policy, secret references, TLS files, the JWT signing keys or static token registry, and the installed worker image and version. It leaves the service store untouched and sends no model or peer requests. `--offline` skips Docker and remote JWKS access and still checks local artifacts.

```sh
lasa config check --config /etc/lasa/config.json
lasa --config /etc/lasa/config.json
```

[Compact example](design/examples/config-no-peer.json) · [Manifest schema](design/config.schema.json) · [Packaged defaults](lasa_service/config_defaults.json)

The manifest defaults to a loopback listener on port `8787`, local execution, and built-in review and task attempt capability definitions. It derives the descriptor URL and deployment revision. The state directories default to `/var/lib/lasa/private` and `/var/lib/lasa/workspaces`. Create writable locations for the service user or set `--state-root` during init. Use one service process per private store. Policy and local JWKS paths can be relative to the manifest. Use absolute paths for state roots and secret files.

Manifest v2 takes effect on restart. Replace the receiver policy atomically to apply grant changes to subsequent authorization checks. File-based credentials are reread on use. Environment secrets and issuer keys loaded at startup require a restart to refresh. The [managed deployment report](deployment/DEPLOYMENT.md) records the Docker rollout on the Mac and air188 and its live dependent-workflow verification.

### Static tokens

JWT is the default. A service can opt into opaque bearer tokens with `authentication.mode: static_token`. The service’s incoming authentication mode and its outgoing peer choices are independent. An empty `peers` list enables local execution for capabilities with local bindings.

Initialize a static-token manifest with `--auth-mode static_token` and omit the JWT issuer and JWKS flags. For example, use the following from the repository root with the worker image ID obtained above.

```sh
lasa config init --output /etc/lasa \
  --auth-mode static_token --operator-subject operator \
  --service-id https://identity.example.net/services/review \
  --base-url https://review.example.net/lasa/v1 \
  --image "$lasa_worker_image" \
  --model YOUR_MODEL_ID --provider-url https://provider.example.net/v1 \
  --credential-ref file:/run/secrets/lasa-model-key

lasa config issue-token --config /etc/lasa/config.json \
  --subject operator --output /absolute/private/client/lasa-token.txt
lasa config check --config /etc/lasa/config.json
```

Issue the token from the configured deployment environment so the CLI can read the manifest's referenced credentials. Use an existing private caller directory outside the server configuration directory for the output. The command creates an owner-only token file and stores only its service-bound digest, subject, and expiration in the server's `authentication.tokens_file`. It leaves any existing output file intact. An empty registry denies access. Client requests use `Authorization: Bearer <token>` over HTTPS, and `authorization.json` grants the subject its capabilities.

The default lifetime is 720 hours. Set `--ttl-hours` when issuing a shorter-lived credential. To rotate, issue a second token for the same subject into a new caller file and switch the client. Revoke the old token by removing its digest entry in an atomic replacement of the private registry, or let it expire. LASA reads the registry on each authenticated request, so rotation and revocation take effect without restarting the service.

### Mixed authentication for delegation

On the sender, a peer entry defaults to JWT. To call a static-token receiver, set that entry's `authentication` to `{"mode": "static_token", "subject": "peer-parent"}` and point `credential_ref` to the caller's opaque token. Keep the receiver service ID, allowed HTTPS base URL, and authorization reference in the same peer entry.

On the receiver, set up a `kind: peer` principal whose subject matches the sender's configured subject and whose `service_id` identifies the sender. List the sender in `trusted_delegator_service_ids` and grant the allowed workload through receiver policy. Use `lasa config issue-token --subject peer-parent` with the receiver manifest and deliver the generated token file to the sender. The sender also needs its own delegation grant for that link.

LASA attaches a workload identity fingerprint to static peer requests. The receiver checks it against the authenticated token subject, the subject's configured service identity, and the receiver's own service ID. Keep those identities stable when rotating a token so child receipts and retries stay bound to the same workload. `lasa config check` validates the local credential against each peer's configured mode. Peer discovery checks the receiver's advertised mode and the exact wire-schema digest when the sender connects.

### Isolated development

For local experiments that need test JWTs, use [the development generator](tools/create_development_config.py) with Python dependencies installed in the checkout. It generates a development issuer, public JWKS, and 24-hour test tokens under an empty output directory. Use the normal issuer and receiver policy for an installed service.

```sh
uv sync --project v0 --frozen
uv run --project v0 python v0/tools/create_development_config.py \
  --output /absolute/path/to/lasa-dev \
  --base-url https://localhost:8443/lasa/v1 \
  --service-id https://identity.example.net/services/development \
  --image "$lasa_worker_image"
```

## Running LASA in Docker

Build the supervisor image after building the Codex worker image above:

```sh
docker build -f v0/Dockerfile.service -t lasa-service:1.5.0 v0
```

The image installs LASA and its locked production dependencies. It runs `lasa --config /etc/lasa/config.json` by default. For a bridge-network listener, set `storage.listen_host` to `0.0.0.0` and set `storage.tls.certificate_file` and `storage.tls.key_file` to the absolute paths of your server certificate and key. The certificate must cover the hostname in `service.base_url`. A model provider with private TLS can set `executors[].provider_ca_file` to its CA bundle. Peers use their own `ca_file` setting.

Mount the manifest and receiver policy read-only where practical. Mount writable state and workspace directories at the same absolute paths inside the supervisor and on the Docker host. The daemon resolves those paths when creating sibling Codex containers. Run the supervisor as the state directory owner and give it access to the daemon socket. The task containers receive their scoped workspace and runtime mounts.

```sh
lasa_directory=/absolute/path/to/lasa-config
lasa_socket=/var/run/docker.sock
lasa_socket_group=$(docker run --rm --network none \
  --mount "type=bind,source=$lasa_socket,target=/var/run/docker.sock" \
  --entrypoint stat lasa-service:1.5.0 -c '%g' /var/run/docker.sock)
docker run --rm --user "$(id -u):$(id -g)" --group-add "$lasa_socket_group" \
  --mount "type=bind,source=$lasa_socket,target=/var/run/docker.sock" \
  --mount "type=bind,source=$lasa_directory,target=$lasa_directory" \
  --publish 127.0.0.1:8443:8787 \
  lasa-service:1.5.0 --config "$lasa_directory/config.json"
```

This example assumes the generated port `8787`, an HTTPS base URL on `localhost:8443`, and a model `credential_ref` pointing to a private file under the mounted directory.

Run the local multi-peer check with both images available:

```sh
(cd v0 && .venv/bin/python -m tests.container_smoke)
```

The check creates a private Docker network with one parent, two downstream LASA services, and a deterministic HTTPS model fixture. It submits a task, verifies both child traces and the parent result, checks receiver-specific authentication, and removes the temporary containers and network. It uses the installed LASA CLI and the real Codex worker image.

## Model service and prompts

In `config.json`, set `executors[].model` to the model ID, `provider_base_url` to the provider's HTTPS API base URL, and `credential_ref` to `env:NAME` or `file:/absolute/private/key.txt`. LASA appends `/responses`, so use a provider that supports the OpenAI Responses API, including structured outputs and streamed tool calls for Codex execution. Local task steps use the executor selected by their binding. Set `default_executor` explicitly when configuring multiple executors. Planning, verification, and unbound integration use that executor. Each LASA peer has its own configuration.

The bundled [prompts.json](lasa_service/prompts.json) contains all eight LASA-authored instruction templates used for planning, verification, execution, source retrieval, result integration, and fallback conversion. To customize them, copy that file to a private location and set the top-level `"prompts_file": "/absolute/path/to/prompts.json"` in `config.json`. LASA validates and loads the entire file when it starts. Keep all eight keys and the `{purpose}` placeholder in `assessment_developer`, then restart the service to apply edits. LASA supplies task inputs, contracts, and evidence at runtime. Codex App Server supplies its own built-in instructions.

LASA registers the approved tools for each step as immediately callable Codex App Server functions. Workspace writes and readback use `workspace_write` and `workspace_read`. The broker checks current permission and remaining allocation when a function is called. Private MCP connectors remain upstream of the broker.

## Submitting work

Submit work using a receiver-audience JWT in `LASA_ACCESS_TOKEN`:

```sh
uv run --project v0 python v0/run_task.py \
  'Explain the responsibilities of a parent service and its bounded worker.' \
  --base-url https://localhost:8443/lasa/v1 \
  --ca-file /absolute/path/to/ca.pem
```

The script discovers caller-visible offers, creates a session, submits typed input, polls the task, and prints routing, actual operation metadata, and parent-authorized child traces. Use `--input-json` and `--capability` for a named capability such as `design.review`. Multiple visible offers can be selected with `--offer-id`.

`--diagnostics content` additionally requires receiver policy permission. Metadata is always recorded. Content traces exclude service keys, private developer/system prompts, and hidden reasoning; truncation retains operation headers and digests. Child traces are retrieved by the parent using its own credentials, which are never returned to the caller.

To delegate, add `peers` entries in preference order. Each entry names the downstream descriptor URL, expected service ID, allowed base URL, receiver-scoped credential reference and authorization reference. Use its `ca_file` for private TLS. The sender’s receiver policy grants the exact sender, receiver and contract in `delegation_grants`. The downstream policy names the sender in `trusted_delegator_service_ids` and maps the workload subject to that service ID with its own grants. [Multi-peer delegation](design/multi-peer-delegation.md)

List additional built-in capabilities by name in `published_contracts`. LASA accepts exact contract references for custom registry entries and validates those against the configured publisher and verifier. Define connector operations in `executors[].connectors`, and use explicit `bindings` with `required_operations` for source-backed capabilities. An explicit bindings list selects all local bindings for that service. See the [connector design](design/connectors.md) and the [advanced manifest example](design/examples/config.json) for the policy and binding structure.

After a lost acknowledgment, reuse the same operation ID and idempotency key. `GET /operations/{operation_id}` reconciles the original receipt without creating work. An uncertain terminal task remains immutable; `POST /tasks/{task_id}/reconcile` can append a resolution event. Do not resubmit uncertain effectful work as a new task automatically.
The task client prints each operation ID before sending its request so you can look up either receipt after a lost acknowledgment.

Verification commands:

```sh
v0/.venv/bin/python v0/design/validate.py
v0/.venv/bin/python -m ruff check v0/lasa_service v0/tests v0/evaluations v0/run_task.py v0/tools
v0/.venv/bin/python -m pytest -q v0/tests
v0/.venv/bin/python v0/evaluations/run_evaluations.py --output /absolute/path/to/evidence
```

The actual-model evaluator uses saved model credentials privately, ephemeral receiver keys/policies, two isolated HTTPS listeners, the immutable pinned Codex image, and a frozen assessment corpus. It does not contact or reconfigure installed services. See the acceptance matrix for recorded candidate results and limitations.
