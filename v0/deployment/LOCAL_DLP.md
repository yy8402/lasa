# Use DLPLite with LASA

DLPLite provides the version 1 HTTPS inspection gateway. LASA selects which projections to send, applies the configured inspection mode, and records transfer decisions. [DLPLite source and scanner policy](https://github.com/yy8402/dlplite)

## Deploy with Docker

`lasa deploy` manages one optional DLPLite stack on a user-defined supervisor network using Docker Compose. Build the image from the DLPLite repository for the host's native architecture. On ARM64 hosts configured to default to AMD64, pass `--platform linux/arm64` to the DLPLite build. Use an existing supervisor network or create one and connect the supervisors to it with `--network` when starting their containers.

From the LASA checkout, clone DLPLite beside it and build the image.

```sh
git clone --branch v0.1.0 https://github.com/yy8402/dlplite.git ../dlplite
docker build -t dlplite:0.1.0 ../dlplite
docker pull \
  ghcr.io/data-privacy-stack/presidio-analyzer:2.2.366@sha256:036d2f9b3c274fb36497383acef8f2d5aea528a014801c2c3040fb067990c79c
```

Place `certificate.pem`, `key.pem`, `ca.pem`, and `token.txt` in an absolute private directory readable by the user running `lasa deploy`. Issue the certificate for `lasa-inspection` and put the issuing CA in `ca.pem`. Generate the bearer token with `openssl rand -hex 32` and protect it as a service credential.

Save the following as `deployment.json`. List every supervisor manifest in this deployment. Manifest paths may be absolute or relative to the settings file. Use an empty list to stage the gateway before adding supervisor bindings. [Deployment JSON example](../design/examples/docker-deployment.json)

```json
{
  "supervisor_network": "lasa-supervisors",
  "supervisors": ["/etc/lasa/review/config.json"],
  "local_dlp": {
    "enabled": true,
    "secrets_directory": "/run/secrets/lasa/inspection"
  }
}
```

```sh
uv run --project v0 lasa deploy apply --settings /etc/lasa/deployment.json
uv run --project v0 lasa deploy check --settings /etc/lasa/deployment.json
```

`apply` starts or updates the managed stack and waits for authenticated HTTPS readiness at `lasa-inspection:8443`. `check` validates the listed manifests and checks readiness when enabled. The readiness response reports the gateway ID and policy revision after Presidio is reachable and Betterleaks is available. Compose puts Presidio on a private internal network and publishes no ports for either container.

`local_dlp.enabled` defaults to `false`. To retire the stack, update all effective bindings that use the managed endpoint, apply those changes to the supervisors, then set `enabled` to `false` and run `lasa deploy apply`. The deployment rejects disabling the stack while a listed manifest has an active binding to `lasa-inspection`. Disabling removes the managed containers and their private backend network. External inspection profiles work with either setting.

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

Run `lasa deploy check` before rollout to verify the managed profile pins and gateway readiness. Run `lasa config check` in the supervisor with its own mounts and credentials, then restart it to apply the settings. Submit clean and synthetic sensitive requests in `observe` and inspect the decisions. Switch the binding to `enforce` and restart when ready to block. If the supervisor defines `content_disclosure` rules for classified data, authorize the applicable classes for `inspection:local-text-dlp` as well as the intended destination. Use the grouped example to bind additional streams. [Grouped inspection bindings](../design/examples/content-security-all-channels.json)

Use the deployment's policy revision in each managed profile. Change the revision when changing detector versions, rules, or thresholds. DLPLite rejects requests for a different revision. Its logs contain the inspection ID, projection digest, configured revision, verdict, and fixed reason codes without the content or matches. Join them to LASA's content audit using the inspection ID.
