# Use DLPLite with LASA

DLPLite provides the version 1 HTTPS inspection gateway. LASA selects which projections to send, applies the configured inspection mode, and records transfer decisions. [DLPLite source and scanner policy](https://github.com/yy8402/dlplite)

## Opt in to the managed deployment

`lasa-deploy` can manage DLPLite on the supervisor network. Use the same host deployment settings for the gateway and the supervisor that uses it. Build the image from the DLPLite repository for the host's native architecture. On ARM64 hosts configured to default to AMD64, pass `--platform linux/arm64` to the DLPLite build. Use a network dedicated to this managed gateway and its intended supervisors.

From the LASA source directory, clone DLPLite beside it and build the image.

```sh
git clone --branch v0.1.0 https://github.com/yy8402/dlplite.git ../dlplite
docker build -t dlplite:0.1.0 ../dlplite
docker pull \
  ghcr.io/data-privacy-stack/presidio-analyzer:2.2.366@sha256:036d2f9b3c274fb36497383acef8f2d5aea528a014801c2c3040fb067990c79c
```

Place `certificate.pem`, `key.pem`, `ca.pem`, and `token.txt` in an absolute private directory readable by the user running `lasa-deploy`. Issue the certificate for `lasa-inspection` and put the issuing CA in `ca.pem`. Generate the bearer token with `openssl rand -hex 32` and protect it as a service credential.

Add this section to the site’s generated `deployment.json` after [preparing the installation](DEPLOYMENT.md#guided-setup-for-a-new-deployment) or when updating an installed site. For users operating supervisors separately, the [standalone inspection settings](../host/docker-deployment.example.json) can plan, apply, and report gateway status on an existing Docker network. Set its release path to a manifest with the locally loaded supervisor image so it can resolve the effective inspection profiles.

```json
{
  "local_dlp": {
    "enabled": true,
    "secrets_directory": "/run/secrets/lasa/inspection"
  }
}
```

```sh
lasa-deploy apply --settings /etc/lasa/deployment.json
lasa-deploy status --settings /etc/lasa/deployment.json
```

An apply verifies the new credential bundle and starts the candidate on a private network.
The active gateway remains attached until the candidate passes authenticated HTTPS readiness.
The host deployment then verifies a synthetic inspection using the supervisor's mounted
credentials. If that check fails, recovery restores the previous release and its gateway bundle.
Each applied credential generation has its own private snapshot, so rotating a token or TLS
bundle triggers a new gateway generation.

To retire the stack, remove all referenced managed bindings and apply with
`local_dlp.enabled` set to `false`. An active binding to `lasa-inspection` blocks this change.

The optional `inspector_image`, `presidio_image`, and `policy_revision` settings select the image build and policy to deploy. The defaults are the DLPLite build tag and pinned Presidio image shown above, and the `english-dlp-v1` policy revision. LASA sets the managed gateway ID to `local-dlp`.

## Configure LASA

Mount a copy of the bearer token and the issuing CA into the supervisor. Use their paths inside the supervisor in `credential_ref` and `ca_file`. Add this section to its private `config.json`.

```json
{
  "content_security": {
    "inspection_profiles": [
      {
        "id": "local-text-dlp",
        "gateway_id": "local-dlp",
        "url": "https://lasa-inspection:8443/inspect",
        "credential_ref": "file:/run/lasa/secrets/inspection-token.txt",
        "policy_revision": "english-dlp-v1",
        "ca_file": "/run/lasa/secrets/inspection-ca.pem",
        "region": "local",
        "retention": "metadata-only"
      }
    ],
    "bindings": {
      "model": {
        "request": { "mode": "observe", "profile": "local-text-dlp" }
      }
    }
  }
}
```

Run `lasa-deploy plan` before rollout to verify the managed profile pins. Apply the change to qualify the gateway from the supervisor. Submit clean and synthetic sensitive requests in `observe` and inspect the decisions. Switch the binding to `enforce` and restart when ready to block. If the supervisor defines `content_disclosure` rules for classified data, authorize the applicable classes for `inspection:local-text-dlp` as well as the intended destination. Use the grouped example to bind additional streams. [Grouped inspection bindings](../design/examples/content-security-all-channels.json)

Use the deployment's policy revision in each managed profile. Change the revision when changing detector versions, rules, or thresholds. DLPLite rejects requests for a different revision. Its logs contain the inspection ID, projection digest, configured revision, verdict, and fixed reason codes without the content or matches. Join them to LASA's content audit using the inspection ID.
