# Local LASA inspection gateway

The gateway accepts LASA's version 1 inspection request at `POST /inspect`. It authenticates the supervisor with a bearer token, validates the projection and its canonical digest, and returns a verdict bound to the inspection ID and the gateway's configured policy revision. A detector match returns `hard_deny`. An incomplete scan returns `indeterminate` unless a detector already found a match.

The initial policy uses English Presidio recognizers for credit card numbers, email addresses, phone numbers, and US Social Security numbers at a minimum score of `0.5`. It uses Betterleaks' bundled rules for credentials, with live validation disabled and inline allow comments ignored. Both detectors inspect the text in LASA's approved projection. The gateway returns `indeterminate` above 128 KiB of canonical projection JSON or when either detector fails or exceeds its 1.5-second budget. The service handles text and JSON projections supplied by LASA.

## Deploy with Docker

`lasa deploy` manages one optional inspector stack on a user-defined supervisor network using Docker Compose. Build the gateway image for the host's native architecture. Use an existing supervisor network or create one and connect the supervisors to it with `--network` when starting their containers.

```sh
docker build -f v0/Dockerfile.service --target inspector -t lasa-inspector:1.0.0 v0
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

`local_dlp.enabled` defaults to `false`. To retire the stack, update all effective bindings that use the bundled endpoint, apply those changes to the supervisors, then set `enabled` to `false` and run `lasa deploy apply`. The deployment rejects disabling the stack while a listed manifest has an active binding to `lasa-inspection`. Disabling removes the managed containers and their private backend network. External inspection profiles work with either setting.

The optional `inspector_image`, `presidio_image`, and `policy_revision` settings select the image build and policy to deploy. The defaults are the gateway build tag and pinned Presidio image shown above, and the `english-dlp-v1` policy revision. The bundled gateway ID is `local-dlp`.

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

Run `lasa deploy check` before rollout to verify the bundled profile pins and gateway readiness. Run `lasa config check` in the supervisor with its own mounts and credentials, then restart it to apply the settings. Submit clean and synthetic sensitive requests in `observe` and inspect the decisions. Switch the binding to `enforce` and restart when ready to block. If the supervisor defines `content_disclosure` rules for classified data, authorize the applicable classes for `inspection:local-text-dlp` as well as the intended destination. Use the grouped example to bind additional streams. [Grouped inspection bindings](../design/examples/content-security-all-channels.json)

Use the deployment's policy revision in each bundled profile. Change the revision when changing detector versions, rules, or thresholds. The gateway rejects requests for a different revision. Its logs contain the inspection ID, projection digest, configured revision, verdict, and fixed reason codes without the content or matches. Join them to LASA's content audit using the inspection ID.
