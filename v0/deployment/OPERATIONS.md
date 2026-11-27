# Operate an installed LASA site

Use this runbook to update, upgrade, or recover a site created with the
[installation guide](DEPLOYMENT.md). Set `settings` to its existing deployment file.

```sh
settings=/absolute/path/to/instance/deployment.json
```

## Update configuration or upgrade LASA

For a configuration update, edit the files referenced by `deployment.json`. For a release upgrade,
follow the [release preparation steps](DEPLOYMENT.md#install-from-a-release) to verify the bundle,
keep `images.tar.gz` beside the new `release.json`, and point the existing settings' `release`
field at that manifest. Use the same control directory.

Keep the control directory, referenced mounts, and credential generations through the rollback
window. Retain a SQLite-consistent snapshot of the state and a corresponding backup of the control
directory. Verify the restore before proceeding with a state-breaking release. In-place rollout
requires the same service identity, public URL, state roots, wire digest, and store schema. For a
release with an incompatible wire or store format, install at a new service URL with a fresh
state root and retain access to the prior receipts for their supported lifetime.

```sh
lasa-deploy plan --settings "$settings"
lasa-deploy apply --settings "$settings"
lasa-deploy status --settings "$settings"
```

`plan` leaves the Docker image cache and deployment state unchanged and reports the release's
readiness.

- **Ready** means candidate preflight passed and the required images are cached.
- **Deferred** means some images are missing and the required archives pass checksum verification.
  Run `apply` to load them and finish the checks.
- **Blocked** means a required archive is unusable. The summary lists the archive path and the
  fix. For a missing archive, copy `images.tar.gz` from that release bundle to the listed path.
  For a checksum mismatch, replace it with the original archive for that release.

For automation, run `lasa-deploy plan --settings "$settings" --json` and check `readiness`.
A generated plan exits successfully for all three readiness values. Its `image_imports` list
includes the archive path, release, purpose, missing roles and digests, and `archive_status`.
Entries that need a fix include `remediation`. A recovery entry covers images needed to
restore the active release if the switch fails.

When candidate images are missing, `plan` reports `preflight: "deferred"` and sets `state` and
`change` to `null`. With cached candidate images, it runs the usual read-only preflight and
reports `preflight: "complete"`.

`apply` verifies and loads the release archive, then checks the required pins and platform
before preflight. If a required archive is unavailable or invalid, the active release continues
serving.

Preflight checks the local daemon, configuration, state schema, and portal or inspection inputs.
Configuration and state checks run in the pinned images with networking disabled, no Docker
socket, and read-only state mounts. Apply then journals the change, drains active work, closes
writes, verifies the candidate over authenticated HTTPS, and opens admission. While draining,
users can resolve inputs and cancel existing tasks.

## Roll back and recover

A failed switch reinstalls and verifies the predecessor. To roll back explicitly, run

```sh
lasa-deploy rollback --settings "$settings"
lasa-deploy status --settings "$settings"
```

Rollback restores the previous configuration and images and uses the same task and workspace
state.

Before draining the active release, rollback checks the images needed for both revisions. If a
release image is missing, the installer verifies and loads `images.tar.gz` beside that revision's
original release manifest, then checks the recorded image ID again. If an image cannot be
restored, rollback exits while the active release continues serving. Keep each release's
manifest and verified image archive at their original paths through the rollback window.
Keep separately supplied DLPLite images available on the host.

Use `status` after an interrupted apply. The next `apply` recovers the last committed release
before retrying. `rollback` recovers it without attempting the interrupted candidate. If recovery
reports a failure, correct the indicated dependency and retry rollback with the same control
directory. A held release remains closed until `resume` verifies it.

## Maintain the managed HTTPS gateway

After the first application apply, the gateway has its own active and previous revisions. Patch
its image using a locally loaded Caddy image digest. Renew the public certificate by passing
its PEM certificate chain and matching key. You can combine both changes in one operation.

```sh
lasa-deploy gateway plan --settings "$settings" --image "$gateway_image_digest"
lasa-deploy gateway apply --settings "$settings" --image "$gateway_image_digest"
lasa-deploy gateway apply --settings "$settings" \
  --tls-cert /absolute/private/site.pem --tls-key /absolute/private/site-key.pem
lasa-deploy gateway status --settings "$settings"
lasa-deploy gateway rollback --settings "$settings"
```

`plan` checks the local image platform and TLS inputs without activating them. `apply` validates
the proxy configuration and verifies the published routes and portal connectivity. If verification
fails, the previous gateway is restored. A gateway change can briefly interrupt HTTPS while the
gateway container is replaced. The application containers keep running and admission stays in
its current mode. Application rollback keeps the active gateway revision.

For a changed public CA, supply `--ca-file` and establish trust in the new CA in clients and the
portal before applying. The gateway retains its backend trust bundle. Keep the previous gateway
image and the private TLS snapshots in the control directory available for rollback. After an
interruption, use gateway `status` to inspect the pending change and gateway `rollback` to restore
the last committed revision.

## Manage local Keycloak users

```sh
lasa-deploy users list --settings "$settings"
lasa-deploy users add --settings "$settings" \
  --username alice --email alice@example.net --credentials-file /absolute/private/new-user.json
lasa-deploy users reset --settings "$settings" \
  --username alice --credentials-file /absolute/private/reset-user.json
```

Add defaults the username to the full email address. Add and reset write temporary passwords
to new owner-only files. Retain the identity
directory and PostgreSQL backups together. Repeat apply and LASA rollback preserve the
issuer, users, credentials, and keys. The Keycloak and PostgreSQL image pins belong to the
identity database lifecycle.

## Rotate local issuer keys

For a local ES256 issuer, configure each receiver in the `lasa-issue-jwt` settings with its
`issuer`, `audience`, `key_id`, `signing_key_file`, public `jwks_file`, and `tokens` entries
containing `subject` and `output_file`. Configure the top-level `lifetime_seconds`. During rotation,
publish both public keys, redeploy the receivers with that key set, and verify each receiver before
switching the issuance job to the new key ID. The job reports expiration by receiver.

## Coordinate multiple hosts

Stage a canary with its own launcher instance, network, endpoint, and state root. Check the
dependent workflow and caller authorizations before cutting over production. Pause the parent
first while receivers finish its delegated work. Then pause the receivers. Apply the matching
receiver releases with `--hold` and verify their authenticated ingress before applying the parent.
Resume receivers before the parent once the whole group has passed its gates. Reverse the same
sequence for rollback. Use a launcher instance name distinct from production for every
concurrent canary, even when service identities are shared.

The [deployment history](HISTORY.md) records previous Mac and air188 rollouts.
