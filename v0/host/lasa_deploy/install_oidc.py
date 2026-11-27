"""Resolve an external issuer and verify the initial LASA identities."""

import ssl
from urllib.parse import urlsplit

import httpx
import jwt

from .contracts import ConfigurationError, https_origin, parse_json, require
from .deployment import read_json, secret


def https_endpoint(url):
    parsed = urlsplit(url)
    origin = https_origin(f"{parsed.scheme}://{parsed.netloc}")
    require(
        parsed.port != 0 and not parsed.fragment and not parsed.query,
        "Use an HTTPS URL with a usable port and without a query or fragment",
    )
    return origin


def fetch_document(client, url):
    with client.stream("GET", url) as response:
        response.raise_for_status()
        data = bytearray()
        for chunk in response.iter_bytes(chunk_size=8192):
            data.extend(chunk)
            require(len(data) <= 65536, "Issuer document exceeds 64 KiB")
    return parse_json(data)


def signing_keys(oidc, site_ca):
    issuer = oidc["issuer"]
    try:
        origin = https_endpoint(issuer)
        require(
            not issuer.endswith("/")
            and not any(part in urlsplit(issuer).path for part in ("//", "..", "%", "\\")),
            "Use a canonical issuer URL without a trailing slash",
        )
    except ValueError as exc:
        raise ConfigurationError(f"oidc.issuer: {exc}") from None
    algorithm = oidc.get("algorithm", "RS256")
    try:
        if source := oidc.get("jwks_file"):
            document = read_json(source)
        else:
            context = ssl.create_default_context()
            for ca in (site_ca, oidc.get("ca_file")):
                if ca:
                    context.load_verify_locations(ca)
            with httpx.Client(verify=context, trust_env=False, timeout=5) as client:
                metadata = fetch_document(client, issuer + "/.well-known/openid-configuration")
                require(metadata["issuer"] == issuer, "Unexpected issuer in discovery")
                url = metadata["jwks_uri"]
                require(https_endpoint(url) == origin, "Signing keys must share the issuer origin")
                document = fetch_document(client, url)
        keys = {}
        public = []
        for key in document["keys"]:
            if key.get("use", "sig") != "sig" or key.get("alg", algorithm) != algorithm:
                continue
            kid = key.get("kid")
            require(
                isinstance(kid, str)
                and kid
                and kid not in keys
                and key.get("kty") in {"EC", "RSA", "OKP"}
                and "d" not in key,
                "Invalid or duplicate public signing key",
            )
            key = {**key, "alg": algorithm}
            keys[kid] = jwt.PyJWK.from_dict(key, algorithm=algorithm)
            public.append(key)
        require(keys, "No matching signing keys")
        return algorithm, keys, {"keys": public}
    except (
        AttributeError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
        httpx.HTTPError,
        jwt.PyJWTError,
    ):
        field = "oidc.jwks_file" if oidc.get("jwks_file") else "oidc.issuer"
        raise ConfigurationError(f"{field}: cannot read signing keys for {algorithm}") from None


def verify_subjects(oidc, site_ca, service_id):
    algorithm, keys, jwks = signing_keys(oidc, site_ca)
    subjects = []
    errors = []
    for role in ("caller", "operator"):
        field = f"{role}_token_file"
        try:
            token = secret(oidc[field])
            header = jwt.get_unverified_header(token)
            require(
                header.get("alg") == algorithm and not {"jku", "x5u", "crit"} & header.keys(),
                "Untrusted token header",
            )
            claims = jwt.decode(
                token,
                keys[header["kid"]],
                algorithms=[algorithm],
                issuer=oidc["issuer"],
                audience=service_id,
                options={"strict_aud": True, "require": ["iss", "aud", "exp", "iat", "jti", "sub"]},
            )
            require(isinstance(claims["sub"], str) and claims["sub"], "Empty subject")
            subjects.append(claims["sub"])
        except (OSError, KeyError, TypeError, ValueError, jwt.PyJWTError):
            errors.append(
                f"oidc.{field}: provide a current access token from {oidc['issuer']} with audience {service_id}"
            )
    require(not errors, "Invalid install credentials\n  " + "\n  ".join(errors))
    require(
        subjects[0] != subjects[1], "oidc: caller and operator tokens must have distinct subjects"
    )
    return algorithm, jwks, *subjects
