# Managed LASA deployment

The Mac parent and both air188 backends use the `lasa-service` package and the `lasa-supervisor` and `lasa-codex-worker` images. The `1.0.0` release uses wire protocol `lasa/1.0.0`, the `1.0.0` service manifest and descriptor formats, and OpenAPI `info.version` set to `1.0.0`.

| Service | HTTPS API | Container | Authentication |
| --- | --- | --- | --- |
| Mac parent | `https://localhost:8443/lasa/v1` | `lasa-parent` | JWT |
| air188 primary | `https://192.168.0.188/lasa/v1` | `lasa-primary` | JWT |
| air188 review | `https://192.168.0.188/review/lasa/v1` | `lasa-review` | Static token with workload identity pin |

## Service paths

Each host keeps a role's `config.json` and `authorization.json` in `~/.config/lasa/<role>/`. Separate `~/.config/lasa/secrets/<role>/` directories supply credentials and certificates. The supervisor mounts config and secrets read-only. Each role gets one writable mount at `~/.local/state/lasa/<role>` containing its private store and workspaces.

The Mac's `com.lasa.layer1-https` user agent runs Caddy using `~/.config/lasa/proxy/Caddyfile`. The `com.lasa.tokens` agent runs the installed `lasa-issue-jwt` command against `~/.config/lasa/issuer/token-issuance.json`, with separate issuer keys and receiver-scoped token outputs. Operator credentials live in role-specific directories under `~/.config/lasa/clients/`. [Air188 runbook](air188.md)

## Roll out a candidate

Build and check the wheel and source distribution, then build the `linux/amd64` supervisor, launcher, and worker images. Give each launcher the immutable worker image ID and configure its supervisor's `runtime.launcher_socket`. The launcher owns Docker access. Run `lasa config check` with each supervisor's production identity and mounts. [Package verification](../VERIFICATION.md)

The split launcher runtime uses store schema revision 2. Provision fresh state roots for this candidate and retain the revision 1 stores with the previous release. Wait for all task stores to be idle. Stop the parent, then the two receivers. Start the matching launchers before starting their supervisors. Start and verify primary and review over authenticated HTTPS before starting the parent. Each state root belongs to a single running supervisor. Verify the advertised service IDs, authentication modes, catalogs, and live dependent workflow before retiring any stopped candidate or predecessor. [Provisioning guide](../RUNNING.md)

For deployments that use a managed DLPLite gateway, list the supervisor manifests in `deployment.json` and enable `local_dlp`. Run `lasa deploy apply` and require authenticated HTTPS readiness and matching profile pins before rolling out the affected supervisors. External scanners remain available with the managed stack disabled. [DLPLite deployment workflow](LOCAL_DLP.md)

## 1.0.0 deployment verification

On November 23, 2026, the Mac parent and both air188 backends passed `lasa config check` at deployment revision `docker-1.0.0-unified-43e45cad4420`. All three authenticated HTTPS endpoints advertised wire protocol `lasa/1.0.0`, descriptor format `1.0.0`, and OpenAPI `info.version` `1.0.0`. The Mac JWT renewal job also passed with the updated package.

The clean-slate cutover archived 16 previous Mac tasks, 13 air188 primary tasks, and 14 air188 review tasks. Each host keeps the verified archives and retired settings under `~/.local/state/lasa/archives/pre-1.0.0-20261123/`. The format alignment uses fresh SQLite stores at schema revision `1` and keeps the earlier verification stores under `~/.local/state/lasa/archives/pre-unified-1.0.0-20261123/`.

Live task `task-b37a936281b54a498dd5aaf6a510305e` finished with disposition `fulfilled`. Air188 review ran `design.review` with a pinned static-token workload identity, and air188 primary ran the dependent `task.attempt` using JWT. The primary verifier received the review output, and the Mac verified the original inputs from both steps. Both child traces remained readable after the predecessor containers were retired.

Air188 primary also completed `documents.read` in task `task-204474f7c39243e1a51b587f02053170`. The returned `README.md` digest matched the approved file. Run receipts and diagnostics are in the Mac's private `~/.local/state/lasa/releases/1.0.0/unified-formats/` directory.

## Typed workflow rollout and live benchmark

All three supervisors run revision `docker-1.0.0-typed-982347ae1b54` with their existing service identities, task stores, and workspaces. The Mac publishes `design.review-checklist` to the operator under `review-checklist`. The authorization rule pins the static-token review peer for `design.review` and the JWT primary peer for `task.attempt`, with a separate verifier revision pin for each grant. Both receivers use `gpt-6-luna` with low reasoning effort for outcome verification and `gpt-5.5` for execution. The Mac keeps its own verifier for independent checks when policy calls for them.

The typed benchmark used the cutover and rollback design from the earlier open-ended task. Elapsed time is measured from receipt to completion on the Mac. The first attempt reached both peers and failed verification because the checklist added conditions beyond the review evidence. The three timed runs specified readiness, rollback, and retirement as explicit review criteria and asked the checklist to preserve exactly those gates.

| Parent task | Elapsed | Model calls |
| --- | ---: | ---: |
| `task-ff7d8d424eb2445d95682079f7fee623` | 52.5 s | 4 |
| `task-b44087e4386e4c42a2ac6170ac0f362d` | 47.6 s | 4 |
| `task-c20b697350694366a5a1ec080d36c253` | 43.9 s | 4 |

Each air188 backend made one execution call and one verification call. The Mac accepted both exact, policy-pinned receipts, confirmed the review output matched primary's dependency, and assembled the result without asking a model. Earlier comparable open-ended tasks took 149–162 seconds and ten model calls. The Mac keeps benchmark inputs, traces, the initial rejection, and rollout evidence under `~/.local/state/lasa/releases/1.0.0/typed-workflows/`.
