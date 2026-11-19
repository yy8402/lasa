# Managed two-layer target deployment

Current deployment: **1.1.0 connector acceptance is complete**, with both managed services running. See [the current connector report](CONNECTORS.md) for actual source integrations, outage/recovery, final revisions and installed-package parity. The sections below retain the original 2026-11-18 base-deployment record and its historical wheel/revisions.

Deployment date: 2026-11-18. **Deployment acceptance is complete. Both managed services are running in the steady profile.** Final identity, configuration, installed-file parity, restart, and ownership evidence is in [final-deployment.json](../verification/deployed-20261118/final-deployment.json).

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

## Acceptance matrix

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
