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

The real-model evaluation uses the configured inference credentials and the pinned worker image. Its cases check the observed route and child calls, exact typed selection, honest inability when evidence is missing, and a synthetic instruction embedded in task data. The acceptance oracle checks released outcomes independently of the model's plan verdicts.

```sh
(cd v0 && .venv/bin/python -m evaluations.run_evaluations --credentials /absolute/private/credentials.json)
```

Use the same harness to verify the separately built DLPLite image with real Presidio and Betterleaks detectors. It runs the pinned Presidio image on a private internal network alongside deterministic HTTPS fixtures for the model and connector. Separate LASA configurations isolate each stream group and mode so inspection at one boundary cannot mask the case at another. [DLPLite integration](deployment/LOCAL_DLP.md)

The matrix runs clean text, a synthetic email address, and a synthetic token in `observe` and `enforce` on model requests and streamed tool responses, caller intake and clarification questions, delegate dispatch and result intake, connector arguments and results, and candidate result and artifact release. It checks the receiving boundary, confirmed usage and effects, and correlates detector reason codes with metadata-only LASA audit records.

The harness uses `lasa deploy apply` and `lasa deploy check` for the real stack. It checks default-off behavior, disabled-binding rejection, repeat apply, profile and live readiness revision mismatches, private networks, and teardown. Build DLPLite for the Docker host's native architecture. On an ARM64 host configured to default to AMD64, pass `--platform linux/arm64` to the DLPLite build.

```sh
git clone --branch v0.1.0 https://github.com/yy8402/dlplite.git ../dlplite
docker build -t dlplite:0.1.0 ../dlplite
(cd v0 && .venv/bin/python -m tests.container_smoke --inspector-image dlplite:0.1.0)
```

Run the enforce recovery canary against the same real inspector image. It uses fresh state, checks optional-context revisions against captured destination requests, and injects scanner faults through a private HTTPS fixture. For model revisions it verifies that the final verifier receives the approved input and that the input evidence links back to the admitted plan and the delivered request.

```sh
(cd v0 && .venv/bin/python -m tests.container_smoke --inspector-image dlplite:0.1.0 --recovery-canary)
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

## Processing boundaries and recursive fulfillment qualification

On November 25, 2026, candidate `processing-recursive-20261125-37be3fc1cca5` used source fingerprint `37be3fc1cca5ba38c31fd986a880ef9f90ea9b71318d767043c9401dac7f25a3`. The private evidence root is `~/.local/state/lasa/releases/processing-recursive-20261125-37be3fc1cca5/`. `source-manifest.json` pins the candidate files. The composed-boundary follow-up added two maintained tests without changing candidate runtime inputs. `composed-regression-pin.json` pins that test source, and the refreshed source distribution and wheel passed the release checks.

| Acceptance area | Verified outcome | Private evidence relative to the release root |
| --- | --- | --- |
| Schema, packaging, and local suite | Design validation, lint, installed package verification, and 298 tests including Docker integration passed. All six processing-boundary tests passed after adding the two composed-routing cases. | `design-validation.json`, `lint.log`, `release-package.log`, `release-package-composed.log`, `pytest.log`, `processing-boundary-regression.log` |
| Processing scope and admission | Synthetic HTTPS endpoints confirmed in-domain execution and zero task-bearing requests to a healthy out-of-domain model fallback or intake inspector. A restricted root successfully used an authenticated child publishing the identical domain-only term. A registered same-domain child offering only externally dependent approved processing received zero restricted submissions. The outside endpoint received one approved control request. | `processing-https.log`, `composed-domain-positive.log`, `composed-domain-negative.log` |
| Recursive accounting and recovery | Fixtures exercised zero through three edges, provider re-entry, concurrent siblings, subtree exhaustion, mismatched ceiling before dispatch, lost acknowledgement at an intermediate provider, restart recovery, cancellation, and late-result quarantine. An independent four-provider HTTPS fixture verified three edges with charges of three, two, and one. | `pytest.log`, `recursive-https.log`, `recursive-domain-https.log`, `recursive-domain-negative-https.log` |
| Model and inspection | Five live-model routing cases passed with the configured credential and pinned worker. Container smoke passed. The real DLPLite matrix passed 60 cases across observe and enforce. The enforce recovery run passed 19 cases, including nine recovery scenarios. | `live-model/summary.json`, `container-smoke.log`, `dlp-matrix.log`, `dlp-recovery.log` |
| Authenticated deployment canary | The Mac parent and both air188 receivers matched the staged images. The dependent review-to-checklist and approved `documents.read` passed. The exact handoff and fresh disclosure matched operator evidence. The caller receipt matched its selected offer, and the caller was denied operator traces. | `mac-candidate-images.txt`, `air188-candidate-images.txt`, `canary-https/`, `canary-offer-receipt.json` |
| Deployed Mac and air188 HTTPS | The managed retry finished on the verified image IDs and worker pins. The dependent workflow and approved document read passed. Verified the exact handoff and fresh disclosure, source digest, caller offer and receipt binding, and trace access denial. | `managed-cutover.log`, `production-https/`, `postflight-running.json`, `rollback-retry/` |

The processing scope and recursive HTTPS fixtures use independent listeners, credentials, and stores on the Mac for synthetic tasks. Production domain-only publication requires qualifying the actual control boundary, including inference and egress, on each role. See [deployed verification and operational limits](deployment/DEPLOYMENT.md).

### Live three-hop HTTPS canary

On November 25, 2026, an isolated Mac root and three isolated air188 receivers completed a synthetic `design.review` task using the deployed supervisor, launcher, and worker image IDs. The three HTTPS edges used receiver-scoped JWT, static token with a workload pin, and receiver-scoped JWT respectively. The leaf executed with `gpt-5.5`. Each of the four roles completed an independent `gpt-6-luna` verification call with recorded provider token usage.

The four task stores recorded inherited slot ceilings and settled charges of `3 → 2 → 1 → 0`. Every edge reserved one slot plus the receiver's descendant ceiling. Child deadlines narrowed at each edge. A separate caller with two slots completed the same task locally with zero child submissions. Across 164 captured caller responses from success, failure, and the limited control, checks found no delegate identifiers, topology, private ceilings, or workload credentials. Both operator trace routes denied the consumer credentials. The review produced no artifacts.

Two earlier attempts traversed the chain. The first stopped on an inference transport error at the leaf. The second stopped when the first upstream verifier required direct citations in findings. The passing request clarified the synthetic task's citation requirement and used the same images and verification policy. The private evidence is under `~/.local/state/lasa/releases/processing-recursive-20261125-37be3fc1cca5/live-three-hop-0pia9Mrd/` on the Mac and the corresponding `evidence/live-three-hop-0pia9Mrd/` directory on air188. See `summary.json`, `authentication-probes.json`, the caller transcripts, and the private ledger captures.

### Deadline and fan-out candidate

On November 25, 2026, candidate `deadline-fanout-20261125-16e059602f54` passed two isolated three-hop live-model runs from a Mac root through three air188 receivers. Both hosts used the same immutable image IDs. The source fingerprint is `16e059602f54fe031183cd399015a936e9287dd2950b0e8560c1da2143dafb8d`.

| Image | ID |
| --- | --- |
| Supervisor | `sha256:b0c758e150c46523605da636d107445e19ce43f2720c1d038b3a3c8be6132f1f` |
| Launcher | `sha256:f52b6f38eab8816b1ee9cf475f160fec7e3c98f64770aa76f8f5807163c90203` |
| Worker | `sha256:d1f54d26b7053daa0797e0c100c81bb153870560e5ffa5750a88368bd97f74b3` |

The HTTPS chain used receiver-scoped JWT, static token with a workload pin, and receiver-scoped JWT. All three edges rejected anonymous access, and the static-token edge rejected the token without its workload pin. The leaf executed a synthetic design review using `gpt-5.5`. Every role independently verified it with `gpt-6-luna`, with provider usage recorded. Each forwarded deadline was 27.001 seconds earlier, which preserved the configured 25-second margin plus clock and timestamp allowance.

| Path | Verified accounting |
| --- | --- |
| Default | A derived worst case of 12 fit the operator maximum of 64. The four task stores recorded direct charges of `1 → 1 → 1 → 0` with no subtree charges. |
| Capped | A derived worst case of 12 exceeded the operator maximum of 3. Direct charges were `1 → 1 → 1 → 0`. The three forwarding roles recorded private subtree charges of `3 → 2 → 1`. |
| Cap too small | A maximum branch cost of 3 exceeded the control rule's cap of 2. LASA performed the review locally with zero downstream submissions. |

The consumer privacy checks covered 155 responses, including discovery, the single-offer read, status, events, receipts, and denied operator trace requests. The checks found no downstream identities, private accounting terms, or credentials. The review produced no artifacts. The three air188 receivers used separate role credentials, stores, containers, and launcher sockets on a shared host and canary Docker network. Cleanup removed both canary configurations from Docker and retained the private evidence. Postflight matched the original production container, image, launcher, and state mount records on both hosts.

Design validation, lint, and the installed wheel and source archive checks passed. The complete local suite passed 307 tests including Docker integration, and the final strengthened peer-commitment test passed for both margin and cap mismatch. The immutable-image container smoke completed on the diagnostic repeat with retained task stores. The initial run returned `deadline_exceeded`. Its logs did not establish the cause.

Mac evidence is under `~/.local/state/lasa/releases/deadline-fanout-canary-FDM6Thfr/`. See `source-manifest.json`, `image-pins.json`, `default/summary.json`, `capped/summary.json`, `postflight-summary.json`, and the two container smoke logs. The corresponding air188 private state is under `/home/yang/.local/state/lasa/releases/deadline-fanout-canary-FDM6Thfr/`. Production continues to run `processing-recursive-20261125-37be3fc1cca5`.
