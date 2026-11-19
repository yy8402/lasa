"""Authenticated discovery resources and origin/policy-scoped conditional caches."""

import copy
import time
from urllib.parse import urlsplit

from fastapi import Request
from fastapi.responses import JSONResponse, Response

from . import PROTOCOL_VERSION
from .capabilities import epoch, instant, require
from .contracts import digest


class Discovery:
    def __init__(
        self, config, registry, publication, authentication, authorization, historical=None
    ):
        self.config, self.registry, self.publication = config, registry, publication
        self.authentication, self.authorization = authentication, authorization
        self.historical = historical or (lambda principal, contract_digest: False)
        self._descriptor = None

    def descriptor(self):
        if self._descriptor and epoch(self._descriptor["valid_until"]) > time.time():
            return copy.deepcopy(self._descriptor)
        config = self.config.document
        base = config["service"]["base_url"].rstrip("/")
        expiry = instant(
            time.time() + max(1, config["discovery_cache"]["descriptor_max_age_seconds"])
        )
        value = {
            "descriptor_version": "1.0",
            "service_id": self.config.service_id,
            "deployment_revision": config["service"]["deployment_revision"],
            "revision": "descriptor-"
            + digest({"config": self.config.revision, "expiry": expiry})[7:39],
            "valid_until": expiry,
            "protocols": [
                {
                    "version": PROTOCOL_VERSION,
                    "base_url": base,
                    "openapi_url": base + "/openapi.json",
                    "wire_schema_digest": digest(self.publication.config.contracts.bundle),
                    "features": [
                        "metadata-diagnostics",
                        "content-diagnostics",
                        "clarification",
                        "artifacts",
                        "bounded-delegation",
                    ],
                    "required_features": ["metadata-diagnostics", "bounded-delegation"],
                }
            ],
            "authentication": {
                "issuer": config["authentication"]["issuer"],
                "audience": config["authentication"]["audience"],
            },
            "catalog_url": base + "/capabilities",
            "contract_url_template": base + "/contracts/{digest}",
            "idempotency_retention_seconds": config["service"]["session_retention_seconds"],
        }
        self._descriptor = value
        return copy.deepcopy(value)

    def response(self, request, principal, value, max_age=0, media_type="application/json"):
        context = self.authorization.context_revision(principal)
        etag = (
            '"'
            + digest({"body": value, "context": context, "principal": principal["subject"]})[7:]
            + '"'
        )
        headers = {
            "ETag": etag,
            "Cache-Control": f"private, max-age={max_age}, must-revalidate",
            "Vary": "Authorization, Accept",
        }
        if request.headers.get("If-None-Match") == etag:
            return Response(status_code=304, headers=headers)
        return JSONResponse(value, headers=headers, media_type=media_type)

    def mount(self, app):
        base = urlsplit(self.config.document["service"]["base_url"]).path.rstrip("/")

        def principal(request):
            return self.authentication.authenticate(request.headers.get("Authorization"))

        @app.get(base + "/descriptor")
        async def descriptor(request: Request):
            return self.response(
                request,
                principal(request),
                self.descriptor(),
                self.config.document["discovery_cache"]["descriptor_max_age_seconds"],
            )

        @app.get(base + "/openapi.json")
        async def api(request: Request):
            value = copy.deepcopy(self.config.contracts.api)
            value["servers"] = [{"url": self.config.document["service"]["base_url"]}]
            return self.response(request, principal(request), value, 300)

        @app.get(base + "/contracts.schema.json")
        async def wire_schema(request: Request):
            return self.response(
                request,
                principal(request),
                self.config.contracts.bundle,
                300,
                media_type="application/schema+json",
            )

        @app.get(base + "/capabilities")
        async def catalog(request: Request):
            p = principal(request)
            q = request.query_params
            value = self.publication.catalog(
                p,
                cursor=q.get("cursor"),
                contract_id=q.get("contract_id"),
                contract_version=q.get("contract_version"),
            )
            return self.response(
                request,
                p,
                value,
                self.config.document["discovery_cache"]["catalog_max_age_seconds"],
            )

        @app.get(base + "/capabilities/{offer_id}")
        async def offer(offer_id: str, request: Request):
            p = principal(request)
            return self.response(
                request,
                p,
                self.publication.offer(p, offer_id),
                self.config.document["discovery_cache"]["catalog_max_age_seconds"],
            )

        @app.get(base + "/capabilities/{offer_id}/availability")
        async def availability(offer_id: str, request: Request):
            p = principal(request)
            return self.response(
                request,
                p,
                self.publication.availability(p, offer_id),
                self.config.document["discovery_cache"]["availability_max_age_seconds"],
            )

        @app.get(base + "/contracts/{contract_digest}")
        async def definition(contract_digest: str, request: Request):
            p = principal(request)
            visible = any(
                x["contract"]["digest"] == contract_digest
                for x in self.publication.snapshot(p)["offers"]
            )
            require(visible or self.historical(p, contract_digest), "not_found", 404)
            return self.response(request, p, self.registry.by_digest(contract_digest), 300)

        if self.config.document["service"]["publish_api_catalog"]:

            @app.head("/.well-known/api-catalog")
            async def bootstrap_head():
                base_url = urlsplit(self.config.document["service"]["base_url"])
                catalog_url = base_url.scheme + "://" + base_url.netloc + "/.well-known/api-catalog"
                return Response(
                    status_code=200,
                    headers={
                        "Link": "<" + catalog_url + '>; rel="api-catalog"',
                        "Cache-Control": "public, max-age=300",
                        "Content-Type": 'application/linkset+json; profile="https://www.rfc-editor.org/info/rfc9727"',
                    },
                )

            @app.get("/.well-known/api-catalog")
            async def bootstrap():
                url = self.config.document["service"]["base_url"].rstrip("/")
                return JSONResponse(
                    {
                        "linkset": [
                            {
                                "anchor": url,
                                "service-desc": [
                                    {"href": url + "/openapi.json", "type": "application/json"}
                                ],
                                "service-meta": [
                                    {
                                        "href": self.config.document["service"]["descriptor_url"],
                                        "type": "application/json",
                                    }
                                ],
                            }
                        ]
                    },
                    media_type='application/linkset+json; profile="https://www.rfc-editor.org/info/rfc9727"',
                    headers={"Cache-Control": "public, max-age=300"},
                )
