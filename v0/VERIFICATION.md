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

The Docker smoke test starts isolated supervisors and a deterministic model fixture. It exercises both JWT and static-token delegation, parent verification, and separate config and state mounts, one launcher per supervisor, and the absence of Docker daemon mounts in supervisors. The isolated builds check package metadata, installed files, examples, provisioning, and the config CLI.

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
