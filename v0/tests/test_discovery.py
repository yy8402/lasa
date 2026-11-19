import json
import time

import httpx
import jwt
import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from lasa_service.auth import Authentication, Authorization
from lasa_service.capabilities import CapabilityRegistry, Publication
from lasa_service.discovery import Discovery
from lasa_service.errors import LasaError
from lasa_service.peer import PeerClient

from .conftest import KEY, configuration, documents, token


async def discovery_service(tmp_path, layer="layer2"):
    raw = documents(tmp_path, layer)
    cfg = configuration(raw)
    root = tmp_path / "private"
    root.mkdir()
    registry = CapabilityRegistry(
        root,
        [
            {
                "namespace": x["namespace"],
                "file": __import__("pathlib").Path(x["trusted_registry_file"]),
            }
            for x in raw["contract_publishers"]
        ],
        raw["verifiers"],
    )
    auth = Authentication(cfg)
    await auth.start()
    authorization = Authorization(cfg)
    publication = Publication(
        cfg, registry, authorization.rules, lambda principal, offer: "available"
    )
    app = FastAPI()

    @app.exception_handler(LasaError)
    async def error(request, exc):
        return JSONResponse(exc.public(), status_code=exc.status)

    discovery = Discovery(cfg, registry, publication, auth, authorization)
    discovery.mount(app)
    return cfg, registry, auth, app, publication


async def test_authenticated_prefixed_discovery_etags_and_views(tmp_path):
    cfg, reg, auth, app, pub = await discovery_service(tmp_path)
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=cfg.document["service"]["base_url"]
        ) as client:
            assert (await client.get("/.well-known/lasa-service")).status_code == 404
            bootstrap = await client.get("https://layer2.example.net/.well-known/api-catalog")
            assert bootstrap.status_code == 200 and "profile=" in bootstrap.headers["content-type"]
            head = await client.head("https://layer2.example.net/.well-known/api-catalog")
            assert (
                head.status_code == 200
                and 'rel="api-catalog"' in head.headers["link"]
                and head.content == b""
            )
            assert (await client.get(cfg.document["service"]["descriptor_url"])).status_code == 401
            headers = {"Authorization": "Bearer " + token(audience=cfg.service_id)}
            descriptor = await client.get(
                cfg.document["service"]["descriptor_url"], headers=headers
            )
            assert descriptor.status_code == 200
            cached = await client.get(
                cfg.document["service"]["descriptor_url"],
                headers={**headers, "If-None-Match": descriptor.headers["etag"]},
            )
            assert cached.status_code == 304 and "private" in cached.headers["cache-control"]
            first = await client.get(
                cfg.document["service"]["base_url"] + "/capabilities", headers=headers
            )
            second = await client.get(
                cfg.document["service"]["base_url"] + "/capabilities",
                params={"cursor": first.json()["next_cursor"]},
                headers=headers,
            )
            assert first.json()["revision"] == second.json()["revision"]
            bob = await client.get(
                cfg.document["service"]["base_url"] + "/capabilities",
                headers={
                    "Authorization": "Bearer " + token("bob", cfg.service_id),
                    "If-None-Match": first.headers["etag"],
                },
            )
            assert bob.status_code == 200 and bob.json()["offers"] == []
    finally:
        reg.close()


@pytest.mark.parametrize(
    "claims",
    [
        {"aud": "https://wrong.example"},
        {"iss": "https://wrong.example"},
        {"exp": 1},
        {"sub": "unknown"},
    ],
)
async def test_jwt_claim_validation(tmp_path, claims):
    cfg, reg, auth, app, pub = await discovery_service(tmp_path)
    try:
        with pytest.raises(LasaError):
            auth.authenticate("Bearer " + token(audience=cfg.service_id, **claims))
    finally:
        reg.close()


async def test_jwt_disallows_algorithm_and_remote_keys(tmp_path):
    cfg, reg, auth, app, pub = await discovery_service(tmp_path)
    try:
        remote = jwt.encode(
            {
                "iss": "https://identity.example.net",
                "aud": cfg.service_id,
                "sub": "alice",
                "iat": int(time.time()),
                "exp": int(time.time()) + 60,
                "jti": "id",
            },
            KEY,
            algorithm="ES256",
            headers={"kid": "test-key", "jku": "https://attacker.example/keys"},
        )
        with pytest.raises(LasaError):
            auth.authenticate("Bearer " + remote)
        unsigned = jwt.encode({"sub": "alice"}, key="", algorithm="none")
        with pytest.raises(LasaError):
            auth.authenticate("Bearer " + unsigned)
    finally:
        reg.close()


async def test_real_http_peer_contract_discovery_and_boundary(tmp_path):
    cfg, reg, auth, app, pub = await discovery_service(tmp_path / "peer")
    parent = configuration(documents(tmp_path / "parent", peer=True))
    paths = []

    class RecordDiscovery(httpx.ASGITransport):
        async def handle_async_request(self, request):
            paths.append(request.url.path.removeprefix("/prefix/lasa/v1"))
            response = await super().handle_async_request(request)
            if paths[-1] == "/openapi.json" and response.status_code == 200:
                await response.aread()
                document = response.json()
                document["info"]["version"] = "9.8.7"
                return httpx.Response(200, json=document, headers={"cache-control": "max-age=60"})
            return response

    peer = PeerClient(parent, transport=RecordDiscovery(app=app))
    await peer.start()
    try:
        catalog = await peer.discover()
        assert len(catalog["offers"]) == 2 and "next_cursor" not in catalog
        assert paths.count("/capabilities") == 2
        assert not any(path.startswith("/contracts/") for path in paths)
        offer = catalog["offers"][0]
        paths.clear()
        assert (await peer.definition(offer))["id"] == offer["contract"]["id"]
        assert paths == ["/contracts/" + offer["contract"]["digest"]]
        paths.clear()
        assert (await peer.refresh_offer(offer))["offer_id"] == offer["offer_id"]
        detail = "/capabilities/" + offer["offer_id"]
        assert paths == [detail, detail + "/availability"]
        with pytest.raises(LasaError):
            await peer.get("https://attacker.example/keys")
        peer.settings["expected_service_id"] = "https://identity.example.net/services/other"
        with pytest.raises(LasaError, match="incompatible_protocol"):
            await peer.discover(refresh=True)
    finally:
        await peer.close()
        reg.close()


async def test_policy_revision_invalidates_catalog_even_with_same_offers(tmp_path):
    cfg, reg, auth, app, pub = await discovery_service(tmp_path)
    try:
        principal = auth.authenticate("Bearer " + token(audience=cfg.service_id))
        old = pub.catalog(principal)
        path = __import__("pathlib").Path(cfg.document["authorization"]["policy_file"])
        policy = json.loads(path.read_text())
        policy["revision"] = "policy-new"
        path.write_text(json.dumps(policy))
        with pytest.raises(LasaError, match="catalog_changed"):
            pub.catalog(principal, cursor=old["next_cursor"])
    finally:
        reg.close()


async def test_tls_real_socket_accepts_configured_ca_and_rejects_untrusted(tmp_path):
    from lasa_service.peer import PeerClient

    from .http_helpers import certificate, live_http

    cfg, reg, auth, app, pub = await discovery_service(tmp_path / "peer")
    tls = certificate(tmp_path)
    try:
        async with live_http(app, tls=tls) as origin:
            raw = documents(tmp_path / "parent", peer=True)
            raw["peer"].update(
                descriptor_url=origin + "/prefix/lasa/v1/descriptor",
                allowed_base_url=origin + "/prefix/lasa/v1",
                ca_file=str(tls[0]),
            )
            peer = PeerClient(configuration(raw))
            await peer.start()
            try:
                value = await peer.get(raw["peer"]["descriptor_url"])
                assert value["service_id"] == cfg.service_id
            finally:
                await peer.close()
            raw["peer"].pop("ca_file")
            peer = PeerClient(configuration(raw))
            await peer.start()
            try:
                with pytest.raises(LasaError, match="peer_unavailable"):
                    await peer.get(raw["peer"]["descriptor_url"])
            finally:
                await peer.close()
    finally:
        reg.close()
