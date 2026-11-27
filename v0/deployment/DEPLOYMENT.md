# Install LASA

A guided deployment owns one HTTPS gateway, one supervisor, and its launcher. It can also run
a caller portal, local Keycloak with PostgreSQL, and a DLPLite gateway. The launcher alone
mounts the Docker socket. Backend ports bind to loopback for deployment checks. The HTTPS
gateway serves the site on one DNS hostname and port 443 by default.

For an installed site, use the [operations runbook](OPERATIONS.md) for configuration updates,
upgrades, recovery, and gateway maintenance.

## Install from a release

Use a local Docker Engine with API 1.49 or later, Compose, Python 3.12, and uv. Select the release for the target
platform. The release contains the host installer wheel, service wheel, source archive,
hashed host requirements, and a Docker image archive for all three profiles. Verify the hashes
in `release.json`.
Install the host wheel and its dependencies in a private environment. The supervisor,
launcher, and portal images carry the service wheel.

```sh
release=/absolute/path/to/release
install_root="$HOME/.local/share/lasa/review"
install -d -m 0700 "$install_root"
uv venv --python 3.12 "$install_root/venv"
. "$install_root/venv/bin/activate"
uv pip sync --require-hashes "$release/requirements-deploy.txt"
uv pip install --no-deps "$release"/lasa_deploy-*.whl
```

For a local build, run `python3 deployment/build_release.py --release-id RELEASE_ID --output
/absolute/path/to/release --export-images` from the source directory. You can use `--worker-image`
to reuse a local worker after validating its platform, Codex version, and entrypoint hash. In an extracted source
archive, supply `--source-revision` from the original release manifest. Use the recorded image
IDs, wire digest, and store schema when comparing hosts.

## Guided setup for a new deployment

Save one of the examples below as `install.json` beside `release.json` and `images.tar.gz`.
Point the site hostname at the host and make HTTPS port 443 available to the intended clients.

```sh
lasa-deploy install --config "$release/install.json"
```

The installer reads the file without prompts, checks and loads any missing release images,
generates the service configuration and `deployment.json`, and applies the release. Its
result includes the settings path and any generated credential files. Use `--prepare-only`
to review the settings before applying them with `lasa-deploy plan` and `lasa-deploy apply`.
If apply fails, the installer prints the saved settings path and the command to resume.

File paths in `install.json` resolve relative to that file. Keep credential values in the
files named by the settings. The hostname supplies the instance name, with dots converted
to hyphens. For `https://lasa.example.net`, the installer uses
`~/.local/share/lasa/lasa-example-net` and service ID
`https://lasa.example.net/services/lasa-example-net`. Set `release` to select a manifest
elsewhere, or `output`, `name`, and `service_id` when provisioning a custom instance.
Backend ports default to 8443, 8080, and 9443 for the supervisor, portal, and Keycloak.
Use `ports` to resolve a local port conflict and `gateway_listen_host` to bind a specific
IPv4 address. Supply `tls.ca_file`, `model.ca_file`, or `oidc.ca_file` for an endpoint that
uses a private CA.

| Site path | Managed route |
| --- | --- |
| `/lasa/v1` | Supervisor API |
| `/app/` | Caller portal, when selected |
| `/auth/realms/lasa/` and `/auth/resources/` | Local Keycloak sign-in and assets, when selected |

The managed Caddy gateway verifies upstream TLS for the supervisor and Keycloak. Its
allowlist keeps Keycloak administration, the master realm, and backend health endpoints
private. The launcher and PostgreSQL have no public routes. Deploy verifies the site routes
before opening admission, and application rollback reuses the gateway.

### LASA only

This is the default profile. LASA generates separate caller and operator credentials.

```json
{
  "site_url": "https://lasa.example.net",
  "model": {
    "id": "your-model",
    "base_url": "https://models.example.net/v1",
    "credential_file": "/etc/lasa/private/model-key"
  },
  "tls": {
    "certificate_file": "/etc/lasa/tls/site.pem",
    "key_file": "/etc/lasa/tls/site-key.pem"
  }
}
```

### Caller portal with local Keycloak

Set `profile` to `portal-keycloak` and list the users who should have caller access at
installation. Each user supplies an email and can set a username. When omitted, the username
defaults to the full email address. Omit the user list or use an empty array to add accounts
later with `lasa-deploy users add`.

```json
{
  "profile": "portal-keycloak",
  "site_url": "https://lasa.example.net",
  "model": {
    "id": "your-model",
    "base_url": "https://models.example.net/v1",
    "credential_file": "/etc/lasa/private/model-key"
  },
  "tls": {
    "certificate_file": "/etc/lasa/tls/site.pem",
    "key_file": "/etc/lasa/tls/site-key.pem"
  },
  "keycloak": {
    "users": [
      {"username": "alice", "email": "alice@example.net"},
      {"email": "bob@example.net"}
    ]
  }
}
```

The portal and Keycloak use the site hostname. With `https://lasa.example.net`, the issuer is
`https://lasa.example.net/auth/realms/lasa` and the portal callback is
`https://lasa.example.net/app/auth/callback`. The installer registers both automatically.
Allow 2 GiB of Docker memory for Keycloak in addition to PostgreSQL and LASA.

Apply creates a persistent PostgreSQL volume and provisions the realm, portal client,
readiness credentials, and receiver policy. The install result lists each initial account's
username, email, and private temporary-password file under `user_credentials`. Give each user
their own file through a private channel. They sign in with the listed username and change
their password on first use.

For account management and identity backups, see [Manage local Keycloak users](OPERATIONS.md#manage-local-keycloak-users).

### Caller portal with an existing identity provider

Register a confidential portal client with callback `https://lasa.example.net/app/auth/callback`.
Enable the authorization code flow with PKCE S256 and client secret basic authentication.
Assign the intended users and configure access tokens with a single audience of
`https://lasa.example.net/services/lasa-example-net`. The installer verifies the two token
files against that audience and the issuer, then uses their distinct subjects for the receiver
policy. The caller token also qualifies the portal. Keep both token files current for
deployment operations. [Existing Keycloak realm setup](../portal/README.md#use-an-existing-keycloak-realm)

```json
{
  "profile": "portal-oidc",
  "site_url": "https://lasa.example.net",
  "model": {
    "id": "your-model",
    "base_url": "https://models.example.net/v1",
    "credential_file": "/etc/lasa/private/model-key"
  },
  "tls": {
    "certificate_file": "/etc/lasa/tls/site.pem",
    "key_file": "/etc/lasa/tls/site-key.pem"
  },
  "oidc": {
    "issuer": "https://identity.example.net",
    "client_id": "lasa-caller-portal",
    "client_secret_file": "/etc/lasa/private/portal-client-secret",
    "caller_token_file": "/etc/lasa/private/caller.jwt",
    "operator_token_file": "/etc/lasa/private/operator.jwt"
  }
}
```

The installer discovers and saves the issuer signing keys for the receiver. Set
`oidc.jwks_file` when supplying a local key set. The signing algorithm defaults to
`RS256` and can be selected with `oidc.algorithm`. The portal requests the LASA audience
using `resource` by default. Set `oidc.audience_parameter` to `audience` if the provider
expects it. When the issuer rotates its signing keys, update the receiver's key set with
both generations during the overlap and apply the updated configuration.

## Custom deployments

Use `lasa-deploy install --config "$release/install.json" --prepare-only` to generate a site's
settings before making advanced changes. The installer reports the generated `deployment.json`
path. For example, list additional supervisor files or directories in `supervisor.mounts` using
absolute host paths. Apply mounts those paths at the same locations inside the container and
takes a snapshot of the supervisor configuration directory.

For an operator-managed HTTPS gateway, remove the generated `gateway` section before the first
apply. Forward `/lasa/v1` unchanged. Strip `/app` before forwarding portal requests and preserve
the public `Host` header. For local Keycloak, preserve `/auth` and forward the sign-in and asset
routes shown above. Verify upstream TLS and omit callback queries and request bodies from ingress
logs. Set `supervisor.tls_server_name` when the supervisor certificate uses a different name
from the public LASA URL.

Run `lasa-deploy plan` and `lasa-deploy apply` with `--settings` pointing to the generated file.
Verify the public API and, for portal profiles, sign in through the public origin and submit a test
task. For direct runtime provisioning with `lasa config init`, see [Running the target service](../RUNNING.md#provision-an-installed-service).
