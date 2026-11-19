"""Bounded authenticated peer discovery with complete, coherent offer enumeration."""

import asyncio
import copy
import ssl
import time

import httpx

from . import PROTOCOL_VERSION, __version__
from .capabilities import epoch, require, validate_definition
from .config import within_url
from .contracts import Contracts, digest, parse_json
from .errors import LasaError


class PeerClient:
    def __init__(self, config, *, transport=None):
        self.config = config
        self.settings = config.peer
        self.contracts = Contracts()
        self.transport = transport
        self.client = None
        self.cache = {}
        self.descriptor = None
        self.base = None

    async def start(self):
        if not self.settings:
            return
        verify = (
            ssl.create_default_context(cafile=self.settings["ca_file"])
            if "ca_file" in self.settings
            else True
        )
        self.client = httpx.AsyncClient(
            verify=verify,
            transport=self.transport,
            timeout=self.settings["request_timeout_seconds"],
            follow_redirects=False,
            trust_env=False,
        )

    async def close(self):
        if self.client:
            await self.client.aclose()

    def authentication_headers(self):
        return {"Authorization": "Bearer " + self.config.secret(self.settings["credential_ref"])}

    async def request(self, method, url, body=None, key=None, etag=None):
        require(
            self.client is not None and within_url(url, self.settings["allowed_base_url"]),
            "peer_unavailable",
            503,
        )
        headers = self.authentication_headers()
        if key:
            headers["Idempotency-Key"] = key
        if etag:
            headers["If-Match"] = etag
        try:
            async with self.client.stream(
                method, url, json=body if body is not None else None, headers=headers
            ) as response:
                chunks = []
                total = 0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    require(total <= 1048576, "peer_unavailable", 503)
                    chunks.append(chunk)
                value = (
                    parse_json(b"".join(chunks)) if chunks and response.status_code != 304 else None
                )
                return value, response.status_code, dict(response.headers)
        except (httpx.HTTPError, ValueError):
            raise LasaError("peer_unavailable", 503, retry="readmission") from None

    async def get(self, url, *, refresh=False):
        require(within_url(url, self.settings["allowed_base_url"]), "incompatible_protocol", 502)
        entry = self.cache.get(url)
        if entry and not refresh and entry["expires"] > time.time():
            return copy.deepcopy(entry["body"])
        headers = self.authentication_headers()
        if entry:
            headers["If-None-Match"] = entry["etag"]
        try:
            async with self.client.stream("GET", url, headers=headers) as response:
                if response.status_code == 304 and entry:
                    require(
                        epoch(entry["body"].get("valid_until", "9999-01-01T00:00:00Z"))
                        > time.time(),
                        "peer_unavailable",
                        503,
                    )
                    entry["expires"] = min(
                        time.time() + 1,
                        epoch(entry["body"].get("valid_until", "9999-01-01T00:00:00Z")),
                    )
                    return copy.deepcopy(entry["body"])
                require(response.status_code == 200, "peer_unavailable", 503)
                chunks = []
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    require(size <= 1048576, "incompatible_protocol", 502)
                    chunks.append(chunk)
                value = parse_json(b"".join(chunks))
                if "valid_until" in value:
                    require(epoch(value["valid_until"]) > time.time(), "peer_unavailable", 503)
                expiry = epoch(value["valid_until"]) if "valid_until" in value else time.time() + 60
                expiry = min(
                    expiry,
                    time.time()
                    + self.config.document["discovery_cache"]["catalog_max_age_seconds"],
                )
                self.cache[url] = {
                    "body": value,
                    "etag": response.headers.get("etag", ""),
                    "expires": expiry,
                }
                return copy.deepcopy(value)
        except httpx.HTTPError:
            raise LasaError("peer_unavailable", 503, retry="readmission") from None

    async def discover(self, *, refresh=False):
        async with asyncio.timeout(self.settings["request_timeout_seconds"]):
            return await self._discover(refresh=refresh)

    async def _discover(self, *, refresh=False):
        descriptor = await self.get(self.settings["descriptor_url"], refresh=refresh)
        self.contracts.validate("ServiceDescriptor", descriptor, "incompatible_protocol", 502)
        require(
            descriptor["service_id"] == self.settings["expected_service_id"],
            "incompatible_protocol",
            502,
        )
        protocol = next(
            (p for p in descriptor["protocols"] if p["version"] == PROTOCOL_VERSION), None
        )
        require(protocol is not None, "incompatible_protocol", 502)
        require(
            within_url(protocol["base_url"], self.settings["allowed_base_url"]),
            "incompatible_protocol",
            502,
        )
        require(
            set(protocol["required_features"])
            <= set(
                self.contracts.schemas["ProtocolEndpoint"]["properties"]["features"]["items"][
                    "enum"
                ]
            ),
            "incompatible_protocol",
            502,
        )
        for url in [
            protocol["openapi_url"],
            descriptor["catalog_url"],
            descriptor["contract_url_template"],
        ]:
            require(
                within_url(url, self.settings["allowed_base_url"]), "incompatible_protocol", 502
            )
        require(
            protocol["wire_schema_digest"] == digest(self.contracts.bundle),
            "incompatible_protocol",
            502,
        )
        wire = await self.get(
            protocol["base_url"].rstrip("/") + "/contracts.schema.json", refresh=refresh
        )
        require(digest(wire) == protocol["wire_schema_digest"], "incompatible_protocol", 502)
        api = await self.get(protocol["openapi_url"], refresh=refresh)
        require(
            api.get("openapi") == "3.2.1" and api.get("info", {}).get("version") == __version__,
            "incompatible_protocol",
            502,
        )
        for path in ["/sessions", "/sessions/{session_id}/tasks", "/tasks/{task_id}"]:
            require(path in api.get("paths", {}), "incompatible_protocol", 502)
        self.base = protocol["base_url"].rstrip("/")
        self.descriptor = descriptor
        url = descriptor["catalog_url"]
        offers = []
        revision = None
        view = None
        cursors = set()
        for _ in range(100):
            page = await self.get(url, refresh=refresh)
            self.contracts.validate("OfferCatalog", page, "incompatible_protocol", 502)
            require(page["service_id"] == descriptor["service_id"], "incompatible_protocol", 502)
            if revision is None:
                revision, view = page["revision"], page["catalog_view"]
            require(
                page["revision"] == revision and page["catalog_view"] == view,
                "catalog_changed",
                409,
            )
            for offer in page["offers"]:
                require(
                    offer["catalog_view"] == view and epoch(offer["valid_until"]) > time.time(),
                    "catalog_changed",
                    409,
                )
                definition_url = descriptor["contract_url_template"].replace(
                    "{digest}", offer["contract"]["digest"]
                )
                definition = await self.get(definition_url, refresh=refresh)
                validate_definition(definition)
                require(
                    digest(definition) == offer["contract"]["digest"]
                    and definition["id"] == offer["contract"]["id"]
                    and definition["version"] == offer["contract"]["version"],
                    "unsupported_contract",
                    502,
                )
                require(
                    any(
                        definition["id"].startswith(x["namespace"])
                        for x in self.config.document["contract_publishers"]
                    ),
                    "unsupported_contract",
                    502,
                )
                require(
                    set(offer["restrictions"]["allowed_effects"]) <= set(definition["max_effects"]),
                    "unsupported_contract",
                    502,
                )
                offers.append({**offer, "definition": definition})
            cursor = page["next_cursor"]
            if cursor is None:
                require(len({x["offer_id"] for x in offers}) == len(offers), "catalog_changed", 409)
                return {
                    "service_id": descriptor["service_id"],
                    "revision": revision,
                    "catalog_view": view,
                    "offers": offers,
                    "valid_until": page["valid_until"],
                }
            require(cursor not in cursors, "catalog_changed", 409)
            cursors.add(cursor)
            # Cursors are data, never arbitrary URLs.
            url = str(httpx.URL(descriptor["catalog_url"]).copy_merge_params({"cursor": cursor}))
        raise LasaError("catalog_changed", 409)

    async def availability(self, offer):
        url = self.base + "/capabilities/" + offer["offer_id"] + "/availability"
        value = await self.get(url, refresh=True)
        self.contracts.validate("Availability", value, "incompatible_protocol", 502)
        require(
            value["offer_id"] == offer["offer_id"] and value["offer_revision"] == offer["revision"],
            "offer_changed",
            409,
        )
        return value["state"]

    async def refresh_offer(self, pinned):
        from .capabilities import offer_terms

        catalog = await self.discover(refresh=True)
        current = next((x for x in catalog["offers"] if x["offer_id"] == pinned["offer_id"]), None)
        require(
            current is not None and offer_terms(current) == offer_terms(pinned),
            "offer_changed",
            409,
        )
        state = await self.availability(current)
        require(
            state == "available",
            "authority_denied"
            if state == "unauthorized"
            else "capacity_exhausted"
            if state == "busy"
            else "peer_unavailable",
            403 if state == "unauthorized" else 429 if state == "busy" else 503,
        )
        return current
