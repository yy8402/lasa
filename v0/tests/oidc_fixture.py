"""Synthetic OIDC server for portal tests, with a real token exchange."""

import base64
import hashlib
import secrets
import time
from urllib.parse import parse_qs, urlencode, urlsplit

import jwt
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from .smoke_support import ISSUER_SECRET, PORTAL_CLIENT_ID


class Issuer:
    """An isolated, interactive authorization server with PKCE and one-use codes."""

    def __init__(self, issuer, audience, key, jwk):
        self.issuer = issuer
        self.audience = audience
        self.client_id = PORTAL_CLIENT_ID
        self.prefix = urlsplit(issuer).path
        self.codes = {}
        self.refresh_tokens = {}
        self.key = key
        self.jwk = jwk
        self.bad_nonce = False
        self.bad_audience = False
        self.refresh_count = 0
        self.app = FastAPI()
        self.app.add_api_route(self.prefix + "/.well-known/openid-configuration", self.metadata)
        self.app.add_api_route(self.prefix + "/jwks", self.jwks)
        self.app.add_api_route(self.prefix + "/authorize", self.authorize)
        self.app.add_api_route(self.prefix + "/token", self.exchange, methods=["POST"])
        self.app.add_api_route(self.prefix + "/revoke", self.revoke, methods=["POST"])

    async def metadata(self):
        return {
            "issuer": self.issuer,
            "code_challenge_methods_supported": ["S256"],
            "authorization_endpoint": self.issuer + "/authorize",
            "token_endpoint": self.issuer + "/token",
            "jwks_uri": self.issuer + "/jwks",
            "revocation_endpoint": self.issuer + "/revoke",
        }

    async def jwks(self):
        return {"keys": [self.jwk]}

    async def authorize(self, request: Request):
        query = dict(request.query_params)
        user = query.pop("as_user", None)
        if not user:
            from html import escape

            href = self.prefix + "/authorize?" + urlencode(query)
            return HTMLResponse(
                "<h1>Test identity provider</h1>"
                f'<a href="{escape(href + "&as_user=alice")}">Sign in as Alice</a>'
                f'<a href="{escape(href + "&as_user=bob")}">Sign in as Bob</a>'
            )
        assert query["client_id"] == self.client_id
        assert query["resource"] == self.audience
        assert query["code_challenge_method"] == "S256"
        code = secrets.token_urlsafe(32)
        self.codes[code] = query | {"subject": user}
        return RedirectResponse(
            query["redirect_uri"]
            + "?"
            + urlencode(
                {
                    "code": code,
                    "state": query["state"],
                }
            ),
            status_code=303,
        )

    def response(self, subject, nonce=None):
        refresh = secrets.token_urlsafe(32)
        self.refresh_tokens[refresh] = subject

        def signed(audience, **claims):
            return jwt.encode(
                {
                    "iss": self.issuer,
                    "aud": audience,
                    "sub": subject,
                    "iat": int(time.time()),
                    "exp": int(time.time()) + 3600,
                    "jti": secrets.token_hex(12),
                    **claims,
                },
                self.key,
                algorithm="ES256",
                headers={"kid": self.jwk["kid"]},
            )

        values = {
            "access_token": signed(self.audience + ("/invalid" if self.bad_audience else "")),
            "refresh_token": refresh,
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        if nonce is not None:
            values["id_token"] = signed(
                self.client_id,
                nonce="incorrect" if self.bad_nonce else nonce,
                groups=["lasa-pilot"] if subject != "unassigned" else [],
            )
        return values

    async def exchange(self, request: Request):
        expected = (
            "Basic " + base64.b64encode((self.client_id + ":" + ISSUER_SECRET).encode()).decode()
        )
        assert request.headers["Authorization"] == expected
        fields = {k: v[0] for k, v in parse_qs((await request.body()).decode()).items()}
        if fields["grant_type"] == "refresh_token":
            subject = self.refresh_tokens.pop(fields["refresh_token"], None)
            if subject is None:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            self.refresh_count += 1
            return self.response(subject)
        saved = self.codes.pop(fields["code"], None)
        verifier = (
            base64.urlsafe_b64encode(hashlib.sha256(fields["code_verifier"].encode()).digest())
            .decode()
            .rstrip("=")
        )
        if (
            not saved
            or saved["code_challenge"] != verifier
            or saved["redirect_uri"] != fields["redirect_uri"]
        ):
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        return self.response(saved["subject"], saved["nonce"])

    async def revoke(self, request: Request):
        fields = parse_qs((await request.body()).decode())
        self.refresh_tokens.pop(fields["token"][0], None)
        return {}
