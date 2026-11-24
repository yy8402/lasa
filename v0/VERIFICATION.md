# LASA verification

Run these checks from the repository root. Build the pinned Codex worker image before the tests that exercise the real container boundary.

```sh
uv sync --project v0 --locked --all-groups
uv run --project v0 --locked python v0/design/validate.py
docker build --platform linux/amd64 -t lasa-codex-worker:1.0.0 v0
uv run --project v0 --locked pytest -q v0/tests
docker build --platform linux/amd64 -f v0/Dockerfile.service --target launcher -t lasa-launcher:1.0.0 v0
docker build --platform linux/amd64 -f v0/Dockerfile.service -t lasa-supervisor:1.0.0 v0
(cd v0 && .venv/bin/python -m tests.container_smoke)
```

The Docker smoke test starts isolated supervisors and separate deterministic HTTPS fixtures for model inference, inspection, and document retrieval. It checks allowed and denied transfers against captured synthetic requests and metadata-only content audit records. It exercises both JWT and static-token delegation, parent verification, and separate config and state mounts, one launcher per supervisor, and the absence of Docker daemon mounts in supervisors. The isolated builds check package metadata, installed files, examples, provisioning, and the config CLI.

Use the same harness to verify the separately built DLPLite image with real Presidio and Betterleaks detectors. It runs the pinned Presidio image on a private internal network alongside deterministic HTTPS fixtures for the model and connector. Separate LASA configurations isolate each stream group and mode so inspection at one boundary cannot mask the case at another. [DLPLite integration](deployment/LOCAL_DLP.md)

The matrix runs clean text, a synthetic email address, and a synthetic token in `observe` and `enforce` on model requests and streamed tool responses, caller intake and clarification questions, delegate dispatch and result intake, connector arguments and results, and candidate result and artifact release. It checks the receiving boundary, confirmed usage and effects, and correlates detector reason codes with metadata-only LASA audit records.

The harness uses `lasa deploy apply` and `lasa deploy check` for the real stack. It checks default-off behavior, disabled-binding rejection, repeat apply, profile and live readiness revision mismatches, private networks, and teardown. Build DLPLite for the Docker host's native architecture. On an ARM64 host configured to default to AMD64, pass `--platform linux/arm64` to the DLPLite build.

```sh
git clone --branch v0.1.0 https://github.com/yy8402/dlplite.git ../dlplite
docker build -t dlplite:0.1.0 ../dlplite
(cd v0 && .venv/bin/python -m tests.container_smoke --inspector-image dlplite:0.1.0)
```

```sh
release_dir=$(mktemp -d)
uv build --project v0 --out-dir "$release_dir"
uv venv --project v0 "$release_dir/venv"
uv export --project v0 --locked --no-dev --no-emit-project --no-hashes \
  --output-file "$release_dir/requirements.txt"
uv pip install --python "$release_dir/venv/bin/python" \
  --requirement "$release_dir/requirements.txt" "$release_dir"/*.whl
"$release_dir/venv/bin/python" -I v0/deployment/check_release.py \
  --wheel "$release_dir"/*.whl --sdist "$release_dir"/*.tar.gz
```

Use the [acceptance requirements](design/acceptance.md) for implementation scope and the [deployment report](deployment/DEPLOYMENT.md) for live verification. Keep task output and deployment evidence in private state outside version control.
