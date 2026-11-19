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

The credential JSON contains environment-variable names mapped to secret values; its owner/mode are checked. The default generated model reference is `env:LASA_MODEL_API_KEY`. The backend listens on literal `127.0.0.1`; configure a TLS proxy so the generated HTTPS base URL reaches it. A private CA can be configured on the peer and CLI. HTTPS certificate validation remains enabled.

## Model service and prompts

In `config.json`, set `executors[].model` to the model ID, `provider_base_url` to the provider's HTTPS API base URL, and `credential_ref` to `env:NAME` or `file:/absolute/private/key.txt`. LASA appends `/responses`, so use a provider that supports the OpenAI Responses API, including structured outputs and streamed tool calls for Codex execution. Local task steps use the executor selected by their binding. Planning, verification, and unbound integration use the first executor. Each LASA peer has its own configuration.

The bundled [prompts.json](lasa_service/prompts.json) contains all eight LASA-authored instruction templates used for planning, verification, execution, source retrieval, result integration, and fallback conversion. To customize them, copy that file to a private location and set the top-level `"prompts_file": "/absolute/path/to/prompts.json"` in `config.json`. LASA validates and loads the entire file when it starts. Keep all eight keys and the `{purpose}` placeholder in `assessment_developer`, then restart the service to apply edits. LASA supplies task inputs, contracts, and evidence at runtime. Codex App Server supplies its own built-in instructions.

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

To configure two layers, generate layer 2 with `--trusted-parent-id` and `--trusted-parent-subject`. Give layer 1 the descriptor URL, expected service ID, and a private reference to a JWT issued for that layer-2 peer subject using `--peer-descriptor`, `--peer-service-id`, and `--peer-credential-ref`. Each receiver independently checks its policy. Absence of `peer` makes execution local and ignores both routing settings.

The private files have closed schemas in `design/private.schema.json`. One private `ConnectorPolicy.connectors` registry supports stdio MCP, Streamable HTTP MCP, and fixed HTTPS JSON GET application operations. Operations pin schemas and approved read-only resource effects. Binding `required_operations` defines both dependency readiness and the operation allowlist. The three source profiles assemble exact output fields from immutable operation-result artifacts before independent semantic verification. See [the connector design](design/connectors.md) and [managed connector verification](deployment/CONNECTORS.md). External-write bindings are rejected. Offer minimum budgets include required assessment/verification allocations; use smaller integration reserves for a leaf that only needs local verification. A generic attempt can report inability and does not claim expertise or missing access.

After a lost acknowledgment, reuse the same operation ID and idempotency key. `GET /operations/{operation_id}` reconciles the original receipt without creating work. An uncertain terminal task remains immutable; `POST /tasks/{task_id}/reconcile` can append a resolution event. Do not resubmit uncertain effectful work as a new task automatically.

Verification commands:

```sh
v0/.venv/bin/python v0/design/validate.py
v0/.venv/bin/python -m ruff check v0/lasa_service v0/tests v0/evaluations v0/run_task.py v0/tools
v0/.venv/bin/python -m pytest -q v0/tests
v0/.venv/bin/python v0/evaluations/run_evaluations.py --output /absolute/path/to/evidence
```

The actual-model evaluator uses saved model credentials privately, ephemeral receiver keys/policies, two isolated HTTPS listeners, the immutable pinned Codex image, and a frozen assessment corpus. It does not contact or reconfigure installed services. See the acceptance matrix for recorded candidate results and limitations.
