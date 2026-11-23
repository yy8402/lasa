"""Bounded authenticated peer discovery with complete, coherent offer enumeration."""

import asyncio
import copy
import hashlib
import re
import ssl
import time
from collections import OrderedDict

import httpx
import jwt

from . import PROTOCOL_VERSION
from .capabilities import epoch, offer_terms, require, validate_definition
from .config import within_url
from .contracts import digest, parse_json
from .errors import LasaError


class PeerClient:
    def __init__(self, config, settings, *, transport=None):
        self.config = config
        self.settings = settings
        self.contracts = config.contracts
        self.transport = transport
        self.client = None
        self.cache = OrderedDict()
        self.descriptor = None
        self.base = None

    async def start(self):
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

    @property
    def service_id(self):
        return self.settings["expected_service_id"]

    async def close(self):
        if self.client:
            await self.client.aclose()

    @staticmethod
    def workload_identity(token):
        try:
            claims = jwt.decode(token, options={"verify_signature": False})
            return {key: claims[key] for key in ("iss", "sub", "aud")}
        except (jwt.InvalidTokenError, KeyError) as exc:
            raise LasaError("peer_unavailable", 503) from exc

    def binding(self):
        return {
            "base_url": self.base,
            "protocol": PROTOCOL_VERSION,
            "workload": self.workload_identity(self.authentication_headers()["Authorization"][7:]),
        }

    def authentication_headers(self, binding=None):
        try:
            token = self.config.secret(self.settings["credential_ref"])
        except (OSError, ValueError):
            raise LasaError("peer_unavailable", 503, retry="readmission") from None
        if binding is not None:
            require(self.workload_identity(token) == binding["workload"], "authority_denied", 403)
        return {"Authorization": "Bearer " + token}

    async def request(self, method, url, body=None, key=None, etag=None, *, binding=None):
        require(
            self.client is not None and within_url(url, self.settings["allowed_base_url"]),
            "peer_unavailable",
            503,
        )
        headers = self.authentication_headers(binding)
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

    async def get(self, url, *, refresh=False, missing_offer=False):
        require(within_url(url, self.settings["allowed_base_url"]), "incompatible_protocol", 502)
        headers = self.authentication_headers()
        key = (url, hashlib.sha256(headers["Authorization"].encode()).digest())
        entry = self.cache.get(key)
        if entry:
            self.cache.move_to_end(key)
        if entry and not refresh and entry["expires"] > time.time():
            return copy.deepcopy(entry["body"])
        if entry and entry["etag"]:
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
                if missing_offer and response.status_code == 404:
                    raise LasaError("offer_changed", 409)
                require(response.status_code == 200, "peer_unavailable", 503)
                chunks = []
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    require(size <= 1048576, "incompatible_protocol", 502)
                    chunks.append(chunk)
                value = parse_json(b"".join(chunks))
                require(isinstance(value, dict), "incompatible_protocol", 502)
                if "valid_until" in value:
                    require(epoch(value["valid_until"]) > time.time(), "peer_unavailable", 503)
                expiry = epoch(value["valid_until"]) if "valid_until" in value else time.time() + 60
                expiry = min(
                    expiry,
                    time.time()
                    + self.config.document["discovery_cache"]["catalog_max_age_seconds"],
                )
                self.cache[key] = {
                    "body": value,
                    "etag": response.headers.get("etag", ""),
                    "expires": expiry,
                }
                self.cache.move_to_end(key)
                if len(self.cache) > 256:
                    self.cache.popitem(last=False)
                return copy.deepcopy(value)
        except (ValueError, TypeError):
            raise LasaError("incompatible_protocol", 502) from None
        except httpx.HTTPError:
            raise LasaError("peer_unavailable", 503, retry="readmission") from None

    async def discover(self, *, refresh=False, contract=None):
        async with asyncio.timeout(self.settings["request_timeout_seconds"]):
            await self.negotiate()
            return await self.catalog(refresh=refresh, contract=contract)

    async def negotiate(self):
        descriptor = await self.get(self.settings["descriptor_url"])
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
        wire = await self.get(protocol["base_url"].rstrip("/") + "/contracts.schema.json")
        require(digest(wire) == protocol["wire_schema_digest"], "incompatible_protocol", 502)
        api = await self.get(protocol["openapi_url"])
        require(
            isinstance(api.get("openapi"), str) and re.fullmatch(r"3\.2\.\d+", api["openapi"]),
            "incompatible_protocol",
            502,
        )
        paths = api.get("paths", {})
        require(isinstance(paths, dict), "incompatible_protocol", 502)
        for path, method in [
            ("/sessions", "post"),
            ("/sessions/{session_id}/tasks", "post"),
            ("/tasks/{task_id}", "get"),
        ]:
            resource = paths.get(path)
            require(isinstance(resource, dict) and method in resource, "incompatible_protocol", 502)
        self.base = protocol["base_url"].rstrip("/")
        self.descriptor = descriptor

    async def catalog(self, *, refresh, contract=None):
        descriptor = self.descriptor
        params = {}
        if contract is not None:
            params = {"contract_id": contract["id"], "contract_version": contract["version"]}
        endpoint = httpx.URL(descriptor["catalog_url"]).copy_merge_params(params)
        url = str(endpoint)
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
                if contract is not None:
                    require(
                        offer["contract"]["id"] == contract["id"]
                        and offer["contract"]["version"] == contract["version"],
                        "incompatible_protocol",
                        502,
                    )
                offers.append(offer)
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
            url = str(endpoint.copy_merge_params({"cursor": cursor}))
        raise LasaError("catalog_changed", 409)

    async def definition(self, offer):
        ref = offer["contract"]
        url = self.descriptor["contract_url_template"].replace("{digest}", ref["digest"])
        definition = await self.get(url)
        validate_definition(definition)
        require(
            digest(definition) == ref["digest"]
            and definition["id"] == ref["id"]
            and definition["version"] == ref["version"]
            and any(
                definition["id"].startswith(publisher["namespace"])
                for publisher in self.config.publishers
            )
            and set(offer["restrictions"]["allowed_effects"]) <= set(definition["max_effects"]),
            "unsupported_contract",
            502,
        )
        return definition

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
        await self.negotiate()
        current = await self.get(
            self.base + "/capabilities/" + pinned["offer_id"], refresh=True, missing_offer=True
        )
        self.contracts.validate("CapabilityOffer", current, "incompatible_protocol", 502)
        require(
            offer_terms(current) == offer_terms(pinned),
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
