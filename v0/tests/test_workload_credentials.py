"""A long-running peer client uses refreshed private workload credentials."""

import json
import secrets
import time
from pathlib import Path

import httpx
import pytest

from lasa_service.auth import static_token_digest
from lasa_service.config import ConfigurationError
from lasa_service.errors import LasaError
from lasa_service.peer import PeerClient

from .conftest import configuration, documents, token


async def test_peer_rereads_rotated_token_for_discovery_and_task_requests(tmp_path):
    token_file = tmp_path / "workload-token.txt"
    raw = documents(tmp_path, peer=True)
    raw["peers"][0]["credential_ref"] = "file:" + str(token_file)
    audience = raw["peers"][0]["expected_service_id"]
    first = token("peer-layer1", audience)
    refreshed = token("peer-layer1", audience)
    token_file.write_text(first)
    received = []

    async def receiver(request):
        received.append(request.headers["Authorization"])
        return httpx.Response(200, json={})

    peer = PeerClient(configuration(raw), raw["peers"][0], transport=httpx.MockTransport(receiver))
    await peer.start()
    try:
        url = raw["peers"][0]["descriptor_url"]
        await peer.get(url)
        token_file.write_text(refreshed)
        await peer.get(url)
        await peer.request("POST", raw["peers"][0]["allowed_base_url"] + "/sessions", {})
        assert received == [
            "Bearer " + first,
            "Bearer " + refreshed,
            "Bearer " + refreshed,
        ]
        token_file.write_text("opaque-static-credential")
        with pytest.raises(LasaError, match="peer_unavailable"):
            await peer.get(url)
        assert len(received) == 3
    finally:
        await peer.close()


def test_peer_configuration_rejects_jwt_for_another_receiver(tmp_path):
    token_file = tmp_path / "peer-token.txt"
    token_file.write_text(token())
    raw = documents(tmp_path, peer=True)
    raw["peers"][0]["credential_ref"] = "file:" + str(token_file)
    with pytest.raises(ConfigurationError, match="configured authentication mode or service ID"):
        configuration(raw)


async def test_static_workload_rotation_preserves_bound_session_owner(services, tmp_path):
    sender = documents(tmp_path / "parent", peer=True)
    receiver = documents(tmp_path / "receiver", "layer2")
    registry = tmp_path / "registry.json"
    receiver["authentication"] = {"mode": "static_token", "tokens_file": str(registry)}
    authority_path = Path(receiver["authorization"]["policy_file"])
    policy = json.loads(authority_path.read_text())
    parent = next(p for p in policy["principals"] if p["kind"] == "peer")
    policy["principals"].append({**parent, "subject": "other-workload"})
    authority_path.write_text(json.dumps(policy))

    first, rotated, wrong_subject = (secrets.token_urlsafe(32) for _ in range(3))
    receiver_id = receiver["service"]["id"]
    registry.write_text(
        json.dumps(
            {
                "tokens": [
                    {
                        "subject": subject,
                        "digest": static_token_digest(receiver_id, secret),
                        "expires_at": int(time.time()) + 3600,
                    }
                    for subject, secret in (
                        (parent["subject"], first),
                        (parent["subject"], rotated),
                        ("other-workload", wrong_subject),
                    )
                ]
            }
        )
    )
    token_file = tmp_path / "peer-token.txt"
    token_file.write_text(first)
    sender["peers"][0].update(
        credential_ref="file:" + str(token_file),
        authentication={"mode": "static_token", "subject": parent["subject"]},
    )
    _, app = await services(raw=receiver)
    config = configuration(sender)
    transport = httpx.ASGITransport(app=app)
    peer = PeerClient(config, config.peers[0], transport=transport)
    await peer.start()
    try:
        await peer.negotiate()
        pin = peer.binding()
        endpoint = peer.base + "/sessions"
        body = {"operation_id": "static-workload-operation"}
        session, status, _ = await peer.request(
            "POST", endpoint, body, key=body["operation_id"], binding=pin
        )
        assert status == 201
        token_file.write_text(rotated)
        repeated, status, _ = await peer.request(
            "POST", endpoint, body, key=body["operation_id"], binding=pin
        )
        assert status == 201 and repeated["session_id"] == session["session_id"]
        token_file.write_text(wrong_subject)
        _, status, _ = await peer.request(
            "POST", endpoint, body, key=body["operation_id"], binding=pin
        )
        assert status == 401
        async with httpx.AsyncClient(transport=transport) as client:
            response = await client.post(
                endpoint,
                json=body,
                headers={
                    "Authorization": "Bearer " + first,
                    "Idempotency-Key": body["operation_id"],
                },
            )
            assert response.status_code == 401
        store = app.state.coordinator.store
        assert (
            store.db.execute("SELECT owner FROM sessions").fetchall()[0]["owner"]
            == parent["subject"]
        )
        assert store.db.execute("SELECT count(*) FROM sessions").fetchone()[0] == 1
    finally:
        await peer.close()
