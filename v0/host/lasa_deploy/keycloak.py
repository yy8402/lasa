"""Provision the local portal issuer and its persistent user directory."""

import json
import os
import secrets
import ssl
import time
from pathlib import Path
from uuid import uuid4

import httpx
import jwt

from .contracts import ConfigurationError, canonical, https_origin, require
from .deployment import bind, docker, read_json, secret, write_atomic
from .runtime import ReleaseImages

KEYCLOAK_IMAGES = {
    "keycloak": "quay.io/keycloak/keycloak:26.8.2@sha256:7e66a96e4739239070aeaf72e4c5decf0f7f682cfc725b9f7ea2b336eaba38b3",
    "postgres": "postgres:17-alpine@sha256:f9cf3e1f0066f0eb0c48707d864f0ac5941e9ff454a072077d97a4d278d07d73",
}
REALM = "lasa"
PORTAL_CLIENT = "lasa-portal"
CALLER_PROBE = "lasa-readiness"
OPERATOR_PROBE = "lasa-rollout"
USER_MANAGER = "lasa-user-manager"
USER_ROLES = ["manage-users", "query-users", "view-users"]
PROTOCOL = f"/realms/{REALM}/protocol/openid-connect"
ADMIN_USERS = f"/admin/realms/{REALM}/users"
KEYCLOAK_PORT = 8443
KEYCLOAK_PATH = "/auth"


def write_json(path, value):
    data = canonical(value).decode() + "\n"
    if not path.exists() or path.read_text() != data:
        write_atomic(path, data)


def client(client_id, password, audience=None, *, callback=None):
    settings = {
        "clientId": client_id,
        "secret": password,
        "enabled": True,
        "protocol": "openid-connect",
        "clientAuthenticatorType": "client-secret",
        "publicClient": False,
        "standardFlowEnabled": bool(callback),
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": callback is None,
        "fullScopeAllowed": False,
        "defaultClientScopes": ["basic"],
    }
    if callback:
        settings.update(redirectUris=[callback], attributes={"pkce.code.challenge.method": "S256"})
    if audience:
        settings["protocolMappers"] = [
            {
                "name": "lasa-audience",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {
                    "included.custom.audience": audience,
                    "access.token.claim": "true",
                    "id.token.claim": "false",
                },
            }
        ]
    else:
        settings["defaultClientScopes"] += ["roles", "kc-admin-api"]
    return settings


def validate_username(username, field="username"):
    require(
        1 <= len(username) <= 254
        and all(char.isprintable() and not char.isspace() for char in username)
        and not username.casefold().startswith("service-account-"),
        f"{field}: supply a portal username without spaces",
    )


def portal_account(email, username=None, *, field=""):
    require(
        3 <= len(email) <= 254
        and email.count("@") == 1
        and all(email.split("@"))
        and all(char.isprintable() and not char.isspace() for char in email),
        f"{field}email: supply a portal user's email address",
    )
    username = email if username is None else username
    validate_username(username, f"{field}username")
    return {"username": username, "email": email}


def initial_users(users):
    accounts = []
    usernames, emails = set(), set()
    for index, user in enumerate(users):
        field = f"keycloak.users.{index}."
        account = portal_account(user["email"], user.get("username"), field=field)
        username, email = account["username"].casefold(), account["email"].casefold()
        require(username not in usernames, f"{field}username: duplicate username")
        require(email not in emails, f"{field}email: duplicate email address")
        usernames.add(username)
        emails.add(email)
        accounts.append(account)
    return accounts


def user_document(account, password):
    return {
        **account,
        "firstName": "LASA",
        "lastName": "Caller",
        "enabled": True,
        "requiredActions": ["UPDATE_PASSWORD"],
        "credentials": [{"type": "password", "value": password, "temporary": True}],
    }


def new_user_credentials(username, output):
    password = secrets.token_urlsafe(24)
    fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as file:
        json.dump({"username": username, "temporary_password": password}, file)
        file.write("\n")
    return password


def scaffold_identity(directory, service_id, callback, portal_secret, accounts, credentials):
    directory.mkdir(mode=0o700)
    (directory / "realm").mkdir(mode=0o700)
    public = directory / "receiver"
    public.mkdir(mode=0o700)
    clients = {
        name: secrets.token_urlsafe(36) for name in (CALLER_PROBE, OPERATOR_PROBE, USER_MANAGER)
    }
    write_json(directory / "probes.json", {"service_id": service_id, "clients": clients})
    write_atomic(directory / "database-password", secrets.token_urlsafe(36) + "\n")
    users, receipts = [], []
    if accounts:
        credentials.mkdir(mode=0o700)
    for account in accounts:
        subject = str(uuid4())
        output = credentials / f"{subject}.json"
        password = new_user_credentials(account["username"], output)
        users.append({**user_document(account, password), "id": subject})
        receipts.append({**account, "credentials_file": str(output)})
    write_json(
        directory / "realm" / f"{REALM}-realm.json",
        {
            "realm": REALM,
            "enabled": True,
            "sslRequired": "all",
            "registrationAllowed": False,
            "loginWithEmailAllowed": False,
            "duplicateEmailsAllowed": False,
            "bruteForceProtected": True,
            "clients": [
                client(
                    PORTAL_CLIENT,
                    portal_secret,
                    service_id,
                    callback=callback,
                ),
                client(CALLER_PROBE, clients[CALLER_PROBE], service_id),
                client(OPERATOR_PROBE, clients[OPERATOR_PROBE], service_id),
                client(USER_MANAGER, clients[USER_MANAGER]),
            ],
            "clientScopeMappings": {
                "realm-management": [{"client": USER_MANAGER, "roles": USER_ROLES}]
            },
            "users": [
                *users,
                {
                    "username": f"service-account-{USER_MANAGER}",
                    "serviceAccountClientId": USER_MANAGER,
                    "enabled": True,
                    "clientRoles": {"realm-management": USER_ROLES},
                },
            ],
        },
    )
    return [user["id"] for user in users], receipts


class ManagedKeycloak:
    def __init__(self, spec, project, network, timeout):
        self.spec = spec
        self.project = project + "-identity"
        self.network = network
        self.timeout = timeout
        self.origin = https_origin(spec["origin"])
        self.issuer = spec["origin"] + KEYCLOAK_PATH + f"/realms/{REALM}"
        self.root = Path(spec["directory"])
        self.policy = self.root / "receiver/authorization.json"
        self.jwks = self.root / "receiver/keycloak-jwks.json"
        self.record = self.root / "provisioned.json"
        self.database = self.project + "-db"
        self.tokens = {}

    def check_inputs(self, service_id):
        require(
            self.root.is_dir()
            and not self.root.is_symlink()
            and self.root.stat().st_uid == os.getuid()
            and not self.root.stat().st_mode & 0o077,
            "Use the owner-only Keycloak directory created by deploy init",
        )
        require(
            read_json(self.root / "probes.json")["service_id"] == service_id,
            "The managed Keycloak identity belongs to a different LASA service",
        )
        require(
            (self.root / "realm" / f"{REALM}-realm.json").is_file(),
            "The generated Keycloak realm is missing",
        )
        secret(self.root / "database-password")
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(
            self.spec["certificate_file"], self.spec["key_file"], password=""
        )
        ssl.create_default_context(cafile=self.spec.get("ca_file"))

    def document(self, images, platform):
        password = self.root / "database-password"
        tls_file = "/run/lasa-identity/tls.pem"
        key_file = "/run/lasa-identity/key.pem"
        password_file = "/run/lasa-identity/database-password"
        keycloak = {
            "image": images["keycloak"],
            "platform": platform,
            "user": f"{os.getuid()}:0",
            "mem_limit": "2g",
            "restart": "unless-stopped",
            "networks": {
                "supervisors": {"aliases": [self.project + "-keycloak"]},
                "database": {},
            },
            "depends_on": {"postgres": {"condition": "service_healthy"}},
            "entrypoint": ["/bin/bash", "-ec"],
            "command": [
                f'export KC_DB_PASSWORD="$(cat {password_file})"\n'
                'exec /opt/keycloak/bin/kc.sh "$@"',
                "lasa-keycloak",
                "start",
                "--import-realm",
            ],
            "environment": {
                "KC_DB": "postgres",
                "KC_DB_URL": "jdbc:postgresql://postgres:5432/keycloak",
                "KC_DB_USERNAME": "keycloak",
                "KC_HOSTNAME": self.spec["origin"] + KEYCLOAK_PATH,
                "KC_HTTP_RELATIVE_PATH": KEYCLOAK_PATH,
                "KC_HTTPS_PORT": str(KEYCLOAK_PORT),
                "KC_HTTPS_CERTIFICATE_FILE": tls_file,
                "KC_HTTPS_CERTIFICATE_KEY_FILE": key_file,
                "KC_HTTP_ENABLED": "false",
            },
            "ports": [
                {
                    "target": KEYCLOAK_PORT,
                    "published": str(self.spec["port"]),
                    "host_ip": "127.0.0.1",
                }
            ],
            "volumes": [
                bind(password, password_file),
                bind(self.spec["certificate_file"], tls_file),
                bind(self.spec["key_file"], key_file),
                bind(self.root / "realm", "/opt/keycloak/data/import"),
            ],
        }
        postgres = {
            "image": images["postgres"],
            "platform": platform,
            "restart": "unless-stopped",
            "networks": ["database"],
            "environment": {
                "POSTGRES_DB": "keycloak",
                "POSTGRES_USER": "keycloak",
                "POSTGRES_PASSWORD_FILE": password_file,
            },
            "volumes": [
                bind(password, password_file),
                {"type": "volume", "source": "identity-db", "target": "/var/lib/postgresql/data"},
            ],
            "healthcheck": {
                "test": [
                    "CMD",
                    "pg_isready",
                    "-h",
                    "127.0.0.1",
                    "-U",
                    "keycloak",
                    "-d",
                    "keycloak",
                ],
                "interval": "2s",
                "timeout": "3s",
                "retries": 30,
            },
        }
        return {
            "services": {"keycloak": keycloak, "postgres": postgres},
            "volumes": {"identity-db": {"external": True, "name": self.database}},
            "networks": {
                "supervisors": {"external": True, "name": self.network},
                "database": {"internal": True},
            },
        }

    def request(self, method, path, **kwargs):
        headers = {"Host": self.origin.netloc, **kwargs.pop("headers", {})}
        with httpx.Client(
            verify=ssl.create_default_context(cafile=self.spec.get("ca_file")),
            trust_env=False,
            timeout=5,
        ) as http:
            response = http.request(
                method,
                f"https://127.0.0.1:{self.spec['port']}{KEYCLOAK_PATH}{path}",
                headers=headers,
                extensions={"sni_hostname": self.origin.hostname},
                **kwargs,
            )
        response.raise_for_status()
        return response

    def discovery(self):
        reply = self.request("GET", f"/realms/{REALM}/.well-known/openid-configuration").json()
        require(reply["issuer"] == self.issuer, "Managed Keycloak returned a different issuer")
        require("S256" in reply["code_challenge_methods_supported"], "Keycloak PKCE is unavailable")

    def available(self):
        try:
            self.discovery()
        except (ConfigurationError, httpx.HTTPError, OSError, ValueError, KeyError):
            return False
        return True

    def obtain(self, name):
        private = read_json(self.root / "probes.json")
        try:
            reply = self.request(
                "POST",
                PROTOCOL + "/token",
                auth=(name, private["clients"][name]),
                data={"grant_type": "client_credentials"},
            ).json()
            return reply["access_token"]
        except (httpx.HTTPError, ValueError, KeyError):
            raise ConfigurationError(
                "Managed Keycloak could not issue a service credential"
            ) from None

    def verified(self, token, keys, service_id):
        try:
            header = jwt.get_unverified_header(token)
            key = next(item for item in keys["keys"] if item["kid"] == header["kid"])
            return jwt.decode(
                token,
                jwt.PyJWK.from_dict(key),
                algorithms=["RS256"],
                issuer=self.issuer,
                audience=service_id,
                options={"strict_aud": True, "require": ["iss", "aud", "exp", "iat", "jti", "sub"]},
            )
        except (jwt.PyJWTError, StopIteration, KeyError, ValueError):
            raise ConfigurationError(
                "Managed Keycloak returned an invalid service credential"
            ) from None

    def token(self, *, operator=False):
        name = OPERATOR_PROBE if operator else CALLER_PROBE
        if name not in self.tokens or self.tokens[name][1] < time.time() + 20:
            token = self.obtain(name)
            claims = self.verified(
                token, read_json(self.jwks), read_json(self.root / "probes.json")["service_id"]
            )
            require(
                claims["sub"] == read_json(self.record)["subjects"][name],
                "The managed Keycloak service identity changed",
            )
            self.tokens[name] = (token, claims["exp"])
        return self.tokens[name][0]

    def compose(self, images, platform, *args):
        return docker(
            "compose",
            "-p",
            self.project,
            "-f",
            "-",
            *args,
            document=self.document(images, platform),
            timeout=self.timeout,
        )

    def install(self, entry):
        image_ids = {name: entry["identity_images"][name] for name in KEYCLOAK_IMAGES}
        platform = entry["release"]["platform"]
        previous = read_json(self.record) if self.record.exists() else None
        if previous:
            require(
                previous["images"] == image_ids and previous["issuer"] == self.issuer,
                "The Keycloak issuer and images are pinned for this identity database",
            )
        volume_exists = bool(docker("volume", "ls", "-q", "--filter", f"name=^{self.database}$"))
        require(
            volume_exists or not previous, "Restore the missing managed Keycloak database volume"
        )
        if not volume_exists:
            docker("volume", "create", self.database)
        self.compose(image_ids, platform, "up", "-d", "--pull", "never")
        deadline = time.monotonic() + self.timeout
        while not self.available():
            if time.monotonic() >= deadline:
                raise ConfigurationError("Managed Keycloak did not become ready over HTTPS")
            time.sleep(0.5)
        self.user_request("GET", ADMIN_USERS, headers=self.manager_headers(), params={"max": 1})
        try:
            document = self.request("GET", PROTOCOL + "/certs").json()
            keys = {
                "keys": [
                    key
                    for key in document["keys"]
                    if key.get("use") == "sig" and key.get("alg") == "RS256"
                ]
            }
        except (httpx.HTTPError, ValueError, KeyError):
            raise ConfigurationError("Cannot read managed Keycloak signing keys") from None
        subjects = {}
        for name in (CALLER_PROBE, OPERATOR_PROBE):
            token = self.obtain(name)
            claims = self.verified(token, keys, entry["service_id"])
            subjects[name] = claims["sub"]
            self.tokens[name] = (token, claims["exp"])
        if previous:
            require(previous["subjects"] == subjects, "The managed Keycloak realm identity changed")
        else:
            self.grant(
                ReleaseImages(entry["release"]),
                caller=subjects[CALLER_PROBE],
                operator=subjects[OPERATOR_PROBE],
            )
        write_json(self.jwks, keys)
        write_json(self.record, {"issuer": self.issuer, "images": image_ids, "subjects": subjects})

    def grant(self, images, *, caller, operator=None):
        result = images.supervisor(
            "policy", policy=read_json(self.policy), caller=caller, operator=operator
        )
        write_json(self.policy, result["policy"])

    def manager_headers(self):
        return {"Authorization": "Bearer " + self.obtain(USER_MANAGER)}

    def user_request(self, method, path, **kwargs):
        try:
            return self.request(method, path, **kwargs)
        except httpx.HTTPStatusError as exc:
            raise ConfigurationError(
                f"Managed Keycloak user management returned HTTP {exc.response.status_code} for {method}"
            ) from None
        except httpx.RequestError:
            raise ConfigurationError("Managed Keycloak user management is unreachable") from None

    def users(self, action, *, images, email=None, username=None, credentials=None):
        headers = self.manager_headers()
        try:
            if action == "list":
                reply = self.user_request(
                    "GET", ADMIN_USERS, headers=headers, params={"max": 1000}
                ).json()
                return {
                    "users": [
                        {
                            "username": user["username"],
                            "email": user.get("email"),
                            "enabled": user["enabled"],
                        }
                        for user in reply
                        if not user["username"].startswith("service-account-")
                    ]
                }
            require(credentials, "Supply an output file for the temporary password")
            if action == "add":
                require(email, "Supply the user's email address")
                account = portal_account(email, username)
                username = account["username"]
            else:
                require(username, "Supply the portal username")
                validate_username(username)
            query = {"username": username, "exact": "true"}
            users = self.user_request("GET", ADMIN_USERS, headers=headers, params=query).json()
            if action == "add":
                require(
                    not users, "That account exists; use reset to issue a new temporary password"
                )
                email_query = {"email": email, "exact": "true"}
                require(
                    not self.user_request(
                        "GET", ADMIN_USERS, headers=headers, params=email_query
                    ).json(),
                    "That email address already belongs to a portal user",
                )
                password = new_user_credentials(username, credentials)
                self.user_request(
                    "POST", ADMIN_USERS, headers=headers, json=user_document(account, password)
                )
                users = self.user_request("GET", ADMIN_USERS, headers=headers, params=query).json()
            require(len(users) == 1, "The managed Keycloak user could not be located")
            subject = users[0]["id"]
            policy = read_json(self.policy)
            if action == "reset":
                password = new_user_credentials(users[0]["username"], credentials)
                self.user_request(
                    "PUT",
                    f"{ADMIN_USERS}/{subject}/reset-password",
                    headers=headers,
                    json={"type": "password", "value": password, "temporary": True},
                )
            if not any(item["subject"] == subject for item in policy["principals"]):
                self.grant(images, caller=subject)
            return {
                "username": users[0]["username"],
                "email": users[0].get("email"),
                "credentials_file": str(credentials),
            }
        except (KeyError, TypeError) as exc:
            raise ConfigurationError(
                "Managed Keycloak could not complete the user operation"
            ) from exc
