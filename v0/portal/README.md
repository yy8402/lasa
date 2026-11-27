# Run the optional caller portal

The portal serves the caller UI and backend as a single image. Deploy one portal replica with its own writable state volume. Point it at a JWT LASA receiver that exposes the caller history route. LASA handles task admission, storage, execution, and release. The pilot runs a pure `task.attempt` offer. [Design and acceptance](../design/caller-portal.md)

Choose the [local Keycloak profile](../deployment/DEPLOYMENT.md#caller-portal-with-local-keycloak)
or the [external identity provider profile](../deployment/DEPLOYMENT.md#caller-portal-with-an-existing-identity-provider)
in `install.json`. The installer configures the receiver and portal.

## Advanced portal settings

Use the installer's `--prepare-only` option to generate `portal/config.json` before applying.
Set `assignment_claim` and `assignment_value` if the issuer expresses portal assignment in
the ID token. For example, use `groups` and `lasa-pilot` to require membership in that group.
Set `journal_seconds` to cover the receiver's advertised idempotency retention.

For an external identity provider, the installer uses the caller token for portal qualification.
To qualify with a different assigned identity, set `portal.receiver_token_file` in the generated
`deployment.json` to its LASA-audience token file and grant the identity the `task.attempt`
capability. The token must carry the issuer's subject and `exp`, `iat`, and `jti` claims.
Qualify any domain-only ingress before adding its URI to `allowed_processing_domains`.

## Use an existing Keycloak realm

For an independently managed realm, use its stable HTTPS issuer URL, such as
`https://sso.example.net/realms/lasa`, in `oidc.issuer` in the
[external identity provider profile](../deployment/DEPLOYMENT.md#caller-portal-with-an-existing-identity-provider).
[Keycloak production setup](https://www.keycloak.org/server/configuration-production)

1. Create an OpenID Connect client for the portal. Enable **Client authentication** and
   **Standard flow**, require PKCE **S256**, and register the exact HTTPS callback, such as
   `https://lasa.example.net/app/auth/callback`. Reference the client secret file in
   `oidc.client_secret_file`. [Keycloak client settings](https://www.keycloak.org/docs/latest/server_admin/)
2. Add an **Audience** mapper to the portal client's dedicated scope. Set **Included Custom
   Audience** to the LASA service ID and add it to the access token only. Remove the default
   `roles` scope if its Audience Resolve mapper adds extra audiences such as `account`.
   Retain the `basic` scope for the subject claim. Confirm the access token's `aud` is a
   single string equal to the LASA service ID. The ID token audience remains the portal
   client ID. [Keycloak audience configuration](https://www.keycloak.org/docs/latest/server_admin/#_audience)
3. Supply current access tokens for the distinct caller and operator subjects. If portal
   assignment uses a group, map group membership into the ID token and set the portal's
   `assignment_value` to the emitted group. Verify sign-in and refresh through the public
   portal and submit a task. [Keycloak group mapping](https://www.keycloak.org/docs/latest/server_admin/)

## Restore and verification

Use SQLite-consistent backups. Keep the encryption and journal keys through the corresponding backup lifetime. After restoring an older copy, replace the ticket key before the portal starts. Existing journal entries still resolve through native receipts. Keep backups and test logs in private state.

Run the portal and native caller-history tests with all dependency groups installed. The browser test uses local Chrome or the Playwright-installed Chromium. Set `LASA_CHROME` to override the browser path.

```sh
uv sync --project v0 --locked --all-groups
(cd v0 && .venv/bin/pytest -q tests/test_portal.py tests/test_task_history.py)
```
