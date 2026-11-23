# Managed LASA deployment

## 1.5.2 rollout on 2026-11-23

The Mac parent and both air188 backends run LASA **1.5.2**, protocol `lasa/1.2`, and deployment revision `docker-1.5.2-evidence-77a289b938cd`. Docker supervises all three services behind the managed HTTPS proxies.

| Service | HTTPS API | Stable service ID | Active container | Incoming authentication |
|---|---|---|---|---|
| Mac parent | `https://localhost:8443/lasa/v1` | `https://localhost:8443/lasa` | `lasa-parent-152` | JWT |
| air188 primary | `https://192.168.0.188/lasa/v1` | `https://192.168.0.188/lasa` | `lasa-primary-152` | JWT |
| air188 review | `https://192.168.0.188/review/lasa/v1` | `https://192.168.0.188/review/lasa` | `lasa-review-152` | Static token |

On each host, the role directories live under `v0/.deploy/target/docker-1.2.0`. The active v2 manifests are `<role>/deployment-1.5.2/config.json`, with separate receiver policies at `<role>/deployment-1.3.0/authorization.json`. Air188 primary uses its public JWKS and a receiver-scoped JWT from the Mac. The review peer entry pins the `peer-layer1` subject and references a private caller token file. Air188 review uses `review/deployment-1.5.0/static-tokens.json` for token digests, subjects, and expirations. The static tokens issued for the 1.5.0 rollout expire on 2026-12-23 in Asia/Shanghai. See the [issuance and rotation instructions](../RUNNING.md#static-tokens).

All three manifests passed `lasa config check` with their production mounts and Docker user settings. The images on the Mac and air188 each matched 81 files from the verified wheel, whose SHA-256 is `77a289b938cddd087655652801571748c13b8f838fcf358ca8e58c6086167b4f`. The rollout verified authenticated HTTPS readiness, the expected service identities and wire-schema digest, and unchanged capability catalogs. Review accepted the correctly pinned static workload and returned HTTP 401 for a missing or incorrect pin. Both cross-receiver credential probes returned HTTP 401. The completed 1.5.0 result and both child states remained readable.

### Historical review traces

The 1.5.1 fix introduced an explicit `authentication.historical_jwt_issuer` on the Mac's review peer entry. It lets the parent fetch events for finished review children originally pinned to that JWT issuer, provided the stored workload subject, caller, receiver, and receiver-side task owner match. The original JWT binding remains on the child record and continues to govern task operations, receipts, cancellation, and reconciliation.

The Mac retrieved both child traces for the 1.3.1, 1.4.0, and 1.5.0 workflow runs. In each case the review events matched a direct receiver read. The stored pin digests matched their pre-fix values. The Mac also retrieved both child traces for the new 1.5.2 run with the current mixed-auth pins.

The active containers use the Docker restart policy `unless-stopped`. Check them from the Mac.

```sh
docker inspect --format '{{.Name}} {{.State.Status}}' lasa-parent-152
ssh yang@192.168.0.188 \
  "docker inspect --format '{{.Name}} {{.State.Status}}' lasa-primary-152 lasa-review-152"
```

### 1.5.2 dependent workflow verification

The 1.5.1 replay completed both child steps. The final verifier rejected the integrated result because its evidence omitted the original step inputs required to check that both steps asked for structured text. In 1.5.2, the final verifier receives each input from the admitted plan by step ID, with redacted content and a digest of the original input. The audit records the digests and omission flags.

The Mac replayed the same workflow input as a new task after rollout. It completed with the live `gpt-5.5` model across all three services.

| Step | Service | Task ID | Verified result |
|---|---|---|---|
| Review the design | air188 review | `task-858fef5c9c87463994a2148b5ced7877` | `design.review` completed over static-token auth |
| Derive the operator checklist | air188 primary | `task-bf84f8a7c440409ab45f81eb608c4d7f` | `task.attempt` completed over JWT and consumed the verified review result |
| Verify and release the integrated result | Mac parent | `task-b51823ac0e7446c1ba73c102311aa943` | The parent accepted both child outputs and the final result |

The review output exactly matched the checklist's stored `dependency_results`. Its digest, `sha256:d8ede81dc0349b614c2e33e16707631af07faed56bede7921e669013a4307742`, matched in the checklist and Mac verification records. Both step inputs explicitly asked for text in the structured output. Their digests in the final verifier's evidence matched the admitted plan and both delegates' received inputs. The evidence was complete, and the workflow reported two delegations, ten model calls, zero tool calls, and zero artifact bytes.

The release passed 207 tests, offline design validation, isolated package verification, and the mixed-auth Docker smoke test. The Mac's private rollout and verification records are in `v0/.deploy/target/docker-1.5.2/activation.json` and `live-dependent-evidence.json`. The original trace recovery comparison is in `v0/.deploy/target/docker-1.5.1/traces-after.json`.

## Release upgrades and rollback

From the checkout root, build both archives in a fresh directory and verify them with an isolated installation.

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

For the live Docker rollout, build the supervisor for `linux/amd64`, load the same image on air188, and compare the installed runtime and contract files on both hosts with the verified wheel. Stage the v2 manifests and run `lasa config check` using each service's actual user, mounts, and daemon access before stopping any backend.

Wait until all three task stores are idle. Stop the Mac parent first, then the air188 backends. Start air188 primary and review, checking each HTTPS readiness endpoint and descriptor against the expected revision. Start and check the Mac parent last. The rollout keeps each role's database, workspace, and HTTPS binding at its existing location.

The 1.5.1 containers and manifests are retained for rollback from 1.5.2. If candidate startup or verification of readiness fails, stop the candidate containers, restore the previous backends before the parent, and verify their prior revision over authenticated HTTPS. Restore the running containers' restart policies so that only the active release restarts on daemon startup.

### Air188 configuration cleanup

After verifying 1.5.2, air188 removed the superseded Docker manifests through 1.5.0, their legacy settings files, and the unused review JWKS. The subsequent cleanup removed the old wheel deployment and staging files. Air188 archived the old task stores, workspaces, and backups, including the inactive `lasa-layer2.service` user unit. The live policies and review token registry still serve both 1.5.2 and the retained 1.5.1 rollback. A new mixed-auth dependent workflow completed after cleanup as `task-4c8c7455a5c1499fb7af8f443360dfd1`. See the [air188 runbook](air188.md) for the current layout, archive location, and verification.

## Historical deployment records

See the [1.1.0 connector report](CONNECTORS.md) for earlier source integration and outage/recovery observations.

### 1.5.0 mixed-auth rollout on 2026-11-23

LASA 1.5.0 introduced per-peer JWT and static-token authentication for delegation. The Mac parent and air188 primary used JWT. Air188 review switched to static tokens. All three services ran protocol `lasa/1.2` at revision `docker-1.5.0-mixed-965ca60c0a9d`. The release passed 206 tests, offline design validation, isolated package verification, and the mixed-auth Docker smoke test.

The first mixed-auth replay completed on the Mac as `task-0ff8535964ee49b09046b9cac31b812b`. Air188 review completed `task-67c6d6ad6ff44237b3b063aab4d305bd`, and air188 primary completed `task-d9d5b298de37487abbc97b639828ee55` using the exact review output. Its digest was `sha256:66ee7e98fffe66987c62cb66f2eecc35c6e7438a19dae2efc64b5b383ad3ff3b`. The rollout records are in `v0/.deploy/target/docker-1.5.0`.

The Mac could read the completed 1.4.0 parent result and both child states. The JWT-pinned review trace returned HTTP 403 through the Mac, and a direct read on review using the pinned static workload still succeeded. LASA 1.5.1 restored access through the Mac.

### 1.3.1 rollout on 2026-11-23

The Mac parent and two air188 backends ran LASA **1.3.1** with protocol `lasa/1.2` and deployment revision `docker-1.3.1-verifier-da669e167b96`. The supervisors run in Docker behind the existing HTTPS proxies. The Mac prefers an authorized peer. Air188 review handles delegated `design.review` work, and air188 primary handles delegated `task.attempt` work and the approved source capabilities.

| Service | HTTPS API | Stable service ID | Active container |
|---|---|---|---|
| Mac parent | `https://localhost:8443/lasa/v1` | `https://localhost:8443/lasa` | `lasa-parent-131` |
| air188 primary | `https://192.168.0.188/lasa/v1` | `https://192.168.0.188/lasa` | `lasa-primary-131` |
| air188 review | `https://192.168.0.188/review/lasa/v1` | `https://192.168.0.188/review/lasa` | `lasa-review-131` |

On each host, the role directories are under `v0/.deploy/target/docker-1.2.0` in the checkout. The active v2 manifest at that rollout was `<role>/deployment-1.3.1/config.json`. Its `authorization.policy_file` points to the receiver's existing `<role>/deployment-1.3.0/authorization.json`. The manifest references credential files. The Mac continues to issue receiver-scoped tokens and hold the issuer signing keys. For syntax and preflight options, see the [installed service instructions](../RUNNING.md).

All three manifests passed `lasa config check` in their target containers. On each host, 81 installed runtime and contract files matched the verified wheel. Its SHA-256 is `da669e167b96e30081177f3a981c4b0d0b1d285fe289955a8ade47ab373a7a33`. After startup, all three services passed authenticated HTTPS readiness and served the expected identity and revision. The before-and-after capability catalogs matched, both cross-audience token probes returned HTTP 401, and a previously completed parent result and its two child records remained readable.

The 1.3.1 containers used the Docker restart policy `unless-stopped`. The following commands inspected that release.

```sh
docker inspect --format '{{.Name}} {{.State.Status}}' lasa-parent-131
ssh yang@192.168.0.188 \
  "docker inspect --format '{{.Name}} {{.State.Status}}' lasa-primary-131 lasa-review-131"
```

#### 1.3.1 dependent workflow verification

The 1.3.0 attempt reached air188 review. Its candidate contained the two required fields, `coverage` and `findings`, but the semantic verifier treated fields from the surrounding evidence as extra candidate fields. LASA 1.3.1 checks the candidate schema before calling the verifier, then sends the candidate separately from the context and evidence. The verifier still makes an independent semantic decision.

The same workflow input was submitted as a new task after the rollout. It completed with the live `gpt-5.5` model on all three services.

| Step | Service | Task ID | Observed result |
|---|---|---|---|
| Review the design | air188 review | `task-e948641acf1247f58733ca44e6a9fa45` | `design.review` completed and passed semantic verification |
| Derive the operator checklist | air188 primary | `task-11e0d7d5aabb44da9fac54130a4f7402` | `task.attempt` completed using the authenticated review result |
| Verify both steps and release the result | Mac parent | `task-7ec95b790a834ca9ae1b89e77f4f4fb9` | Independently accepted both child outputs and the integrated outcome |

The durable task records matched the review output exactly to the checklist's `dependency_results`. The review output digest `sha256:95593daf010a633db0d3264d5fef7f546a01cc68c2a404deab51ad97c15591c7` also matched in air188 primary's verification evidence and in the Mac's step and final verification evidence. The completed parent reported two delegations and ten model calls, including child usage.

The release passed 200 tests, offline design validation, isolated package verification, and the Docker dependent-workflow smoke test. The Mac's local rollout and durable verification records are `v0/.deploy/target/docker-1.3.1/activation.json` and `v0/.deploy/target/docker-1.3.1/live-dependent-evidence.json`. The earlier rejected task is retained in the 1.3.0 run records.

### 2026-11-18 base deployment

The 2026-11-18 deployment passed acceptance with both services in the steady profile. Final identity, configuration, installed-file parity, restart, and ownership evidence is in [final-deployment.json](../verification/deployed-20261118/final-deployment.json).

| Layer | Canonical HTTPS API | Stable service identity | Managed backend |
|---|---|---|---|
| 1, local Mac | `https://localhost:8443/lasa/v1` | `https://localhost:8443/lasa` | launchd `com.lasa.layer1` |
| 2, air188 | `https://192.168.0.188/lasa/v1` | `https://192.168.0.188/lasa` | user systemd `lasa-layer2.service` |

Both use `gpt-5.5` at `https://api.openai.com/v1/`, through the actual Codex App Server enclosure. Runtime layer-to-layer traffic uses authenticated HTTPS. SSH to `yang@192.168.0.188` is administrative transport only. A private LAN CA remains explicitly trusted by clients; default trust correctly rejects these certificates. No TLS bypass is used. Local Caddy binds loopback on port 8443; air188 retains its system-managed HTTPS proxy on port 443.

Target configuration, venv, stores, and workspaces live under `v0/.deploy/target` on each host. Prototype data remains under `v0/.deploy/layer1` and `v0/.deploy/layer2`. Original service units are preserved under each target `backups` directory. Saved model credentials remain in the existing private `~/.config/lasa/two-layer` files. JWT signing private keys stay on the administrator Mac; air188 receives public JWKS and receiver policy only.

The intended steady profile publishes both shipped contracts, keeps local bindings on both layers, and sets layer 1 to `preferred_executor: peer`, `unclaimed_peer_fallback: attempt`. Layer 2 has no peer, so routing settings are ignored. The controlled fallback profiles remove layer 1's review binding and withdraw layer 2's review offer while retaining its generic attempt offer. They do not fabricate a capability claim or weaken verification. `set_profile.py steady` restores the intended configuration. All profile changes are logged privately under the target directory and summarized in sanitized verification evidence.

Workload and operator JWTs have receiver-specific audiences and a six-hour lifetime. launchd `com.lasa.tokens` refreshes private token files hourly using administrator-held keys. The peer client rereads its token on every outbound request, including artifact fetches. Configuration contains file/environment references, never credential values. The Mac and its Docker daemon must be available for local service execution; launchd retries startup when dependencies are unavailable. Air188 user lingering and restart-on-failure remain enabled.

From the checkout root, use the private layer-1 operator token to run the client:

```sh
LASA_ACCESS_TOKEN="$(cat v0/.deploy/target/layer1/operator-token.txt)" \
  v0/.deploy/target/venv/bin/python v0/run_task.py \
  'Explain how a parent retains responsibility for bounded child work.' \
  --base-url https://localhost:8443/lasa/v1 \
  --ca-file "$HOME/.config/lasa/two-layer/tls/ca.pem"
```

This client creates a session, submits a task, polls its result, and retrieves routing and child evidence through layer 1. It never needs a layer-2 credential. Add `--diagnostics content` only when the caller has the separate permission; metadata is the default. Token values are not printed.

Lifecycle commands:

```sh
launchctl print gui/$(id -u)/com.lasa.layer1
launchctl print gui/$(id -u)/com.lasa.layer1-https
launchctl print gui/$(id -u)/com.lasa.tokens
launchctl kickstart -k gui/$(id -u)/com.lasa.tokens
ssh yang@192.168.0.188 'systemctl --user status lasa-layer2.service --no-pager'
ssh yang@192.168.0.188 'systemctl status lasa-layer2-https.service --no-pager'
```

The original live file task is retained as a real counterexample: broker write/read operations succeeded, but independent semantic verification lacked those receipts and rejected release. The scoped correction sends task/step-relevant durable receipts and verified artifact content, with current authorization, redaction, bounds, provenance/digests, and a cache key that includes those facts. It preserves independent rejection; the original task is never rewritten or automatically retried.

Use `v0/deployment/verify_deployed.py` for explicitly named new observations and `v0/deployment/set_profile.py` for controlled profiles. Verification tools refuse to overwrite existing named observations and refuse profile changes while tasks are active.

### Historical wheel rollout and rollback

The launchd and systemd rollout staged and deployed the verified wheel from the Mac, then checked installed file hashes and HTTPS readiness on both layers.

```sh
uv run --project v0 python v0/deployment/deploy_release.py \
  --wheel "$release_dir"/*.whl
uv run --project v0 python v0/deployment/inspect_release.py \
  --wheel "$release_dir"/*.whl --output "$release_dir/installed-release.json"
```

The release tool verifies the wheel bytes and stages a separate Python environment on each host before stopping either backend. Stop order is Mac then air188. Start order is air188 then Mac, with authenticated HTTPS readiness and exact revision checked after each start. Rollback restores both previous environments and config files and checks their prior revisions over HTTPS. Task stores and workspaces stay at their configured paths throughout the rollout.

Use `--rollback-drill` with the same command to exercise rollback after air188 passes its candidate readiness check. Both backends restart during the drill. The release slot on each host is under `.deploy/target/backups/<release>`. It holds the staged environment, original config copies and the previous environment once activated. If the controller is interrupted before reporting an outcome, keep the release slots for recovery.

### Acceptance matrix

All work used the current checkout. No unrelated service was changed. The image was exported from the verified local build and loaded on air188; root filesystem layer digests match. Docker's two storage implementations expose different immutable image IDs, which are separately pinned in each runtime profile.

| Milestone | Outcome | Evidence |
|---|---|---|
| Host access and prerequisites | SSH administration confirmed; Python/Docker, exact Codex version/image, disk and managed lifecycle ready | Final host inventory and installed-file hashes |
| Layer 2 deployment | Actual HTTPS identity/catalog/OpenAPI/wire-schema negotiation; no peer; real local Codex/model completion | `layer2-no-peer.json` |
| Layer 1 deployment | Managed loopback backend and HTTPS proxy; receiver-audience trust and peer workload credential; both shipped bindings | Final inventory and profile changes |
| Routing and fallback | Both preferences, exact fresh-unclaimed fallback off/on, and no-peer behavior passed | Scenario matrix below |
| Evidence delivery correction | Original rejection retained; real write/read repeated successfully with independently assessed durable receipts | `local-tools.json`, `local-tools-disposition.json`, `local-tools-with-receipts.json` |
| Diagnostics and authority | Local model/tool calls, routing reasons/revisions, actual child identity/calls, verification and usage visible; child traces retrieved through layer 1 | Content-enabled observations and final post-restart child report check |
| Content protection | Caller without separate permission rejected before task admission; metadata observations omit content; credential/private-key scan clean | `content-permission-denied.json`, final privacy evidence |
| TLS and credentials | Private CA verification enabled; default trust rejects certificates; anonymous and wrong-audience requests rejected; token files `0600`, refreshed hourly | `tls-and-token-lifecycle.json`, final inventory |
| Restart and persistence | Both backends restarted; completed task bytes and session preserved; child traces remained accessible; services ready | `final-deployment.json` |
| Package and process ownership | 69 installed runtime/contract files match the verified wheel on both hosts; no owned task containers remain; only intended managed services left running | Final inventory and package checks |

The machine-readable [scenario matrix](../verification/deployed-20261118/scenario-matrix.json) records every named observation, including the original failure. Counts below are actual finished model operations on each layer, rather than the parent's aggregate usage total.

| Deployed scenario | Actual outcome | L1 model calls | L2 model calls | Child tasks |
|---|---|---:|---:|---:|
| Layer 2, no peer | completed locally | 0 | 2 | 0 |
| Local first, both suitable | completed locally | 4 | 0 | 0 |
| Delegate first, both suitable | completed through layer 2 | 4 | 2 | 1 |
| Local insufficient, peer unclaimed, fallback disabled | rejected without delegation | 1 | 0 | 0 |
| Same controlled capability profile, fallback enabled | completed through generic attempt and parent verification | 5 | 2 | 1 |
| Initial workspace tool task | write/read succeeded; semantic release rejected for missing independent receipts | 8 | 0 | 0 |
| Same workspace task after evidence correction | completed; two actual tool calls verified from durable receipts | 9 | 0 | 0 |
| Final steady profile after redeployment | completed through layer 2 | 4 | 2 | 1 |
| Content request without permission | HTTP 403; no inference | 0 | 0 | 0 |

The five required routing cases completed before the evidence-delivery correction. The affected real tool task and a final delegated task completed after both hosts received the corrected package. Unrelated paid cases were not rerun. The original rejection was never rewritten, automatically retried, or overridden.

Final wheel SHA-256: `756da6a87ce1e9fb1f1e8d4d38aad13bd67ffda3296781a348542bb7944c6b90`.

Final service deployment revision: `target-20261118-756da6a87ce1-steady` on both hosts. Final configuration and policy hashes are recorded per host in the inventory. Local runtime image: `sha256:4f09ec491ffad8efe8311b968e627308888f42912319da2744f16101d438f16e`; air188 runtime image: `sha256:227a150e354dd650b451ca20744e59751005b2a4002c1b9d6b0d228de64766a1`. Both contain Codex `0.169.0-alpha.11.1` and identical amd64 root filesystem layers.

Relevant checks after deployment-driven code changes: 12 credential/discovery/routing checks, 83 evidence/admission/durability/boundary/routing/native/MCP checks, 10 artifact/time-boundary checks, and 14 final evidence/gateway/native checks passed. These are distinct candidate/check groups and are not summed into a fictitious whole-suite total. Earlier valid implementation evidence remains in [VERIFICATION.md](../VERIFICATION.md).

Model judgment remains probabilistic. The earlier isolated semantic rejection is retained in the implementation report; successful live observations do not establish general semantic correctness. External-write bindings and adversarial federation remain outside the approved execution profile. The administrator Mac must remain available for layer 1 and hourly token issuance.
