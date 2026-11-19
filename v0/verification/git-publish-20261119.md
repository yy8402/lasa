# Initial repository publication checks

Scope: initial `main` commit for LASA v0 1.1.0 at `https://github.com/yy8402/lasa.git`.

- The working directory had no Git history; the configured remote was empty.
- Source, tests, contracts, design, deployment tooling and reviewed JSON/log evidence are included. Local deployments, private credentials/keys/certificates, databases, runtime homes/workspaces, virtual environments, built distributions and older research/export directories are ignored and retained locally.
- The obsolete `demo` CI workflow was replaced with locked Python dependencies, offline contract validation, lint/format checks, a pinned Codex carrier build, credential-free tests and package builds. Action references are pinned to verified upstream commit hashes.
- `uv.lock` now records project version 1.1.0; locked dependency versions were retained.
- `uv sync --locked --all-groups --python 3.12 --project v0`: passed.
- Contract validation: 35 JSON documents, 27 positive examples, 32 negative cases, 153 references and 20 API operations passed.
- Scoped lint and formatting: passed for 74 authored Python files.
- Full test suite: **165 passed in 53.56s**, including controlled Codex container integration tests. No provider credentials were used by this test command.
- Wheel and source-distribution builds passed; archive hygiene checks found no deployment state, verification output or private key files.
- Candidate content was scanned for saved credentials, API/GitHub token patterns, JWT values and private-key headers before staging. The exact staged blobs are checked again before commit; matched values are never printed.

Managed deployment state and the earlier real-service evidence remain preserved separately. Initial publication does not redeploy either running LASA service.
