# Run the optional caller portal

The portal serves the caller UI and backend as a single image. Deploy one portal replica with its own writable state volume. Point it at a JWT LASA receiver that exposes the caller history route. LASA handles task admission, storage, execution, and release. The pilot runs a pure `task.attempt` offer. [Design and acceptance](../design/caller-portal.md)

## Provision the identity provider and receiver

Register a confidential OIDC client with the exact portal HTTPS callback `/auth/callback`. Configure Authorization Code, PKCE S256, client secret basic authentication, user assignment, and the resource or audience parameter supported by the provider. The portal accepts metadata endpoints on the configured issuer origin. It checks the issuer JWKS and requires LASA access tokens with a single audience equal to the LASA service ID, a subject matching the OIDC user, and an expiry, issue time, and token ID. Configure the LASA receiver's issuer, JWKS, and user policy to match.

Provision a user rule with the exact built-in `task.attempt` capability, no effects, resources, or delegation grants, and a bounded budget. Grant the named pilot users individually. Configure an assignment claim and value below if the provider expresses portal assignment in its ID token. The initial receiver qualification requires task history and the current LASA wire bundle. Qualify two pilot identities on the actual HTTPS origin and rehearse JWKS rotation before enablement.

## Build and configure

From the repository root, build the image for the target host and record its immutable ID.

```sh
docker build --platform linux/amd64 -f v0/Dockerfile.portal -t lasa-portal:pilot v0
docker image inspect --format '{{.Id}}' lasa-portal:pilot
```

Create a private configuration directory with the identity-provider client secret and three independent keys. Each key file contains 32 bytes encoded as hex. Use a separate key for token encryption, receipt fingerprints, and write-ticket signatures. Supply a certificate authority bundle for a private LASA or identity provider. Configure the portal state volume for UID/GID `10001:10001`.

The following example shows container paths. The service ID is the receiver's identity URI. The base URL includes the native protocol prefix.

```json
{
  "public_origin": "https://portal.example.net",
  "lasa_url": "https://lasa.example.net/lasa/v1",
  "lasa_service_id": "https://lasa.example.net/lasa",
  "issuer": "https://identity.example.net/lasa",
  "client_id": "lasa-caller-portal",
  "client_secret_file": "/etc/lasa-portal/client-secret",
  "state_dir": "/var/lib/lasa-portal",
  "encryption_key_file": "/etc/lasa-portal/encryption-key",
  "journal_key_file": "/etc/lasa-portal/journal-key",
  "ticket_key_file": "/etc/lasa-portal/ticket-key",
  "ca_file": "/etc/lasa-portal/ca.pem",
  "audience_parameter": "resource",
  "assignment_claim": "groups",
  "assignment_value": "lasa-pilot"
}
```

Mount configuration and keys read-only. Publish the application port to the HTTPS ingress on the same host or use a private container network. Preserve the configured public `Host` header. Configure the ingress to omit callback queries and request bodies from logs. Persist only the portal directory in the writable volume. The supervisor retains its own store and workspaces.

```sh
docker run -d --name lasa-portal --read-only \
  -p 127.0.0.1:8080:8080 \
  --mount "type=bind,src=/absolute/private/portal-config,dst=/etc/lasa-portal,readonly" \
  --mount "type=bind,src=/absolute/private/portal-state,dst=/var/lib/lasa-portal" \
  lasa-portal:pilot
```

Use `/health/live` and `/health/ready` to check the portal process and its store. Sign in over the configured HTTPS origin to check issuer and receiver compatibility. Configure `journal_seconds` to cover the receiver's advertised idempotency retention. Explicitly qualify any domain-only ingress before adding its URI to `allowed_processing_domains`.

## Restore and verification

Use SQLite-consistent backups. Keep the encryption and journal keys through the corresponding backup lifetime. After restoring an older copy, replace the ticket key before the portal starts. Existing journal entries still resolve through native receipts. Keep backups and test logs in private state.

Run the portal and native caller-history tests with all dependency groups installed. The browser test uses local Chrome or the Playwright-installed Chromium. Set `LASA_CHROME` to override the browser path.

```sh
uv sync --project v0 --locked --all-groups
(cd v0 && .venv/bin/pytest -q tests/test_portal.py tests/test_task_history.py)
```
