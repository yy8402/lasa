# Running the target service

For the installed local Mac/air188 system, use [the managed deployment instructions](deployment/DEPLOYMENT.md), including the private token-file reference, trusted CA, and launchd/systemd commands. The instructions below provision an independent configuration.

Use Python 3.11+ and Docker. All source and tests are in `v0`; commands below start at the checkout root.

```sh
uv sync --project v0 --frozen
docker build --build-arg CODEX_VERSION=0.169.0-alpha.11.1 -t lasa-codex:target-v1 v0
docker image inspect --format '{{.Id}}' lasa-codex:target-v1
```

Use the resulting immutable `sha256:...` ID when generating configuration. Runtime startup verifies the image and exact Codex version. The container has no network and a read-only workspace mount; authorized workspace writes pass through the durable LASA broker. An execution binding without workspace-read permission receives an empty mounted workspace.

Generate an isolated development configuration in an empty directory:

```sh
uv run --project v0 python v0/tools/create_development_config.py \
  --output /absolute/path/to/LASA/v0/.local-target \
  --base-url https://localhost:8443/lasa/v1 \
  --service-id https://identity.example.net/services/development \
  --image sha256:REPLACE_WITH_IMAGE_ID
```

The generator writes an administrator-controlled development signing key, public JWKS, private operator token, authority policy, immutable definition registry, runtime/tool profiles, and service configuration. Private files use mode `0600`. Its tokens expire after 24 hours. For normal operation configure your pretrusted issuer/JWKS and receiver policy instead of relying on development signing keys. No token or API key is printed.

Supply the model key using the configured environment reference, or use the existing private credential loader:

```sh
uv run --project v0 python v0/deployment/run_service.py \
  --config /absolute/path/to/LASA/v0/.local-target/config.json \
  --credentials /absolute/private/credentials.json
```

The credential JSON contains environment-variable names mapped to secret values. Its owner and mode are checked. The default generated model reference is `env:LASA_MODEL_API_KEY`. The generator binds the backend to `127.0.0.1` for use with a TLS proxy. The service can also terminate TLS directly.

## Running LASA in Docker

Build the supervisor image after building the Codex worker image above:

```sh
docker build -f v0/Dockerfile.service -t lasa-service:1.2.2 v0
```

The image installs LASA and its locked production dependencies. It runs `lasa --config /etc/lasa/config.json` by default. For a bridge-network listener, set `storage.listen_host` to `0.0.0.0` and set `storage.tls.certificate_file` and `storage.tls.key_file` to the absolute paths of your server certificate and key. The certificate must cover the hostname in `service.base_url`. A model provider with private TLS can set `executors[].provider_ca_file` to its CA bundle. Peers use their own `ca_file` setting.

Mount the generated configuration and writable state at the same absolute paths inside the supervisor and on the Docker host. The daemon resolves those paths when creating sibling Codex containers. Run the supervisor as the state directory owner and give it access to the daemon socket. The task containers receive their scoped workspace and runtime mounts.

```sh
lasa_directory=/absolute/path/to/lasa-config
lasa_socket=/var/run/docker.sock
lasa_socket_group=$(docker run --rm --network none \
  --mount "type=bind,source=$lasa_socket,target=/var/run/docker.sock" \
  --entrypoint stat lasa-service:1.2.2 -c '%g' /var/run/docker.sock)
docker run --rm --user "$(id -u):$(id -g)" --group-add "$lasa_socket_group" \
  --mount "type=bind,source=$lasa_socket,target=/var/run/docker.sock" \
  --mount "type=bind,source=$lasa_directory,target=$lasa_directory" \
  --publish 127.0.0.1:8443:8787 \
  lasa-service:1.2.2 --config "$lasa_directory/config.json"
```

This example assumes the generated port `8787`, an HTTPS base URL on `localhost:8443`, and a model `credential_ref` pointing to a private file under the mounted directory.

Run the local multi-peer check with both images available:

```sh
(cd v0 && .venv/bin/python -m tests.container_smoke)
```

The check creates a private Docker network with one parent, two downstream LASA services, and a deterministic HTTPS model fixture. It submits a task, verifies both child traces and the parent result, checks receiver-specific authentication, and removes the temporary containers and network. It uses the installed LASA CLI and the real Codex worker image.

## Model service and prompts

In `config.json`, set `executors[].model` to the model ID, `provider_base_url` to the provider's HTTPS API base URL, and `credential_ref` to `env:NAME` or `file:/absolute/private/key.txt`. LASA appends `/responses`, so use a provider that supports the OpenAI Responses API, including structured outputs and streamed tool calls for Codex execution. Local task steps use the executor selected by their binding. Planning, verification, and unbound integration use the first executor. Each LASA peer has its own configuration.

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

To configure two layers, generate layer 2 with `--trusted-parent-id` and `--trusted-parent-subject`. Give layer 1 the descriptor URL, expected service ID, and a private reference to a JWT issued for that layer-2 peer subject using `--peer-descriptor`, `--peer-service-id`, and `--peer-credential-ref`. For additional delegates, add entries in downstream preference order to `peers` and authorize each exact sender, receiver, and contract in `delegation_grants`. Configure and authorize the parent workload separately on each receiver. An empty `peers` list enables local-only execution. [Multi-peer delegation](design/multi-peer-delegation.md)

The private files have closed schemas in `design/private.schema.json`. One private `ConnectorPolicy.connectors` registry supports stdio MCP, Streamable HTTP MCP, and fixed HTTPS JSON GET application operations. Operations pin schemas and approved read-only resource effects. Binding `required_operations` defines both dependency readiness and the operation allowlist. The three source profiles assemble exact output fields from immutable operation-result artifacts before independent semantic verification. See [the connector design](design/connectors.md) and [managed connector verification](deployment/CONNECTORS.md). External-write bindings are rejected. Offer minimum budgets include required assessment/verification allocations; use smaller integration reserves for a leaf that only needs local verification. A generic attempt can report inability and does not claim expertise or missing access.

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
