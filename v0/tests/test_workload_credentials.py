"""A long-running peer client uses refreshed private workload credentials."""

import json
import secrets
import time
from pathlib import Path

import httpx
import pytest

from lasa_service.auth import (
    WORKLOAD_IDENTITY_HEADER,
    static_token_digest,
    static_workload_identity,
)
from lasa_service.config import ConfigurationError
from lasa_service.contracts import digest
from lasa_service.errors import LasaError
from lasa_service.peer import PeerClient

from .conftest import ISSUER, configuration, documents, settled, submit, task_request, token


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


async def test_only_finished_child_traces_can_follow_jwt_to_static_transition(services, tmp_path):
    sender = documents(tmp_path / "parent", peer=True)
    sender["routing"]["preferred_executor"] = "peer"
    receiver = documents(tmp_path / "receiver", "layer2")
    _, receiver_app = await services(raw=receiver)
    transport = httpx.ASGITransport(app=receiver_app)
    client, app = await services(raw=sender, peer_transport=transport)
    coordinator = app.state.coordinator
    receiver_coordinator = receiver_app.state.coordinator
    receiver_config = receiver_coordinator.config
    sender_id, receiver_id = coordinator.config.service_id, receiver_config.service_id
    peer = coordinator.peers[receiver_id]

    old = await settled(client, await submit(client, app, await task_request(client, app)))
    assert old["status"] == "completed"
    (child,) = coordinator.store.children(old["task_id"])
    old_binding = child["peer_binding"]
    assert old_binding["workload"] == {"iss": ISSUER, "sub": "peer-layer1", "aud": receiver_id}
    endpoint = coordinator.config.document["service"]["base_url"]
    old_report = endpoint + "/tasks/" + old["task_id"] + "/delegations"
    assert "trace" in (await client.get(old_report)).json()["children"][0]

    secret = secrets.token_urlsafe(32)
    registry = tmp_path / "static-tokens.json"
    registry.write_text(
        json.dumps(
            {
                "tokens": [
                    {
                        "subject": "peer-layer1",
                        "digest": static_token_digest(receiver_id, secret),
                        "expires_at": int(time.time()) + 3600,
                    }
                ]
            }
        )
    )
    receiver_config.document["authentication"] = {
        "mode": "static_token",
        "tokens_file": str(registry),
    }
    token_file = tmp_path / "workload-token.txt"
    token_file.write_text(secret)
    peer.settings.update(
        credential_ref=f"file:{token_file}",
        authentication={"mode": "static_token", "subject": "peer-layer1"},
    )
    receiver_coordinator.discovery._descriptor = None
    peer.base = None
    blocked = (await client.get(old_report)).json()["children"][0]
    assert blocked["problem"]["status"] == 403 and "trace" not in blocked

    peer.settings["authentication"]["historical_jwt_issuer"] = ISSUER
    restored = (await client.get(old_report)).json()["children"][0]["trace"]
    assert restored["task_id"] == child["task_id"] and restored["events"]
    after = restored["events"][0]["sequence"]
    paged = (await client.get(old_report, params={"after_sequence": after})).json()
    assert all(event["sequence"] > after for event in paged["children"][0]["trace"]["events"])
    assert coordinator.store.children(old["task_id"])[0]["peer_binding"] == old_binding
    for method, suffix in (
        ("GET", "/operations/operation-example"),
        ("GET", "/tasks/" + child["task_id"]),
        ("POST", "/tasks/" + child["task_id"] + "/cancel"),
    ):
        with pytest.raises(LasaError, match="authority_denied"):
            await peer.request(method, old_binding["base_url"] + suffix, binding=old_binding)
    for invalid in (
        {**child, "state": "executing"},
        {**child, "state": "indeterminate"},
        {
            **child,
            "peer_binding": {
                **old_binding,
                "workload": {**old_binding["workload"], "iss": "https://wrong.example.net"},
            },
        },
        {
            **child,
            "peer_binding": {
                **old_binding,
                "workload": {**old_binding["workload"], "sub": "other"},
            },
        },
        {
            **child,
            "request": {
                **child["request"],
                "delegation": {
                    **child["request"]["delegation"],
                    "parent_service_id": "https://wrong.example.net",
                },
            },
        },
    ):
        with pytest.raises(LasaError, match="authority_denied"):
            await coordinator.delegation.child_trace(invalid, 0)

    new = await settled(client, await submit(client, app, await task_request(client, app)))
    assert new["status"] == "completed"
    reports = (await client.get(endpoint + "/tasks/" + new["task_id"] + "/delegations")).json()
    assert reports["children"][0]["trace"]["events"]
    (new_child,) = coordinator.store.children(new["task_id"])
    assert new_child["peer_binding"]["workload"] == static_workload_identity(
        "peer-layer1", sender_id, receiver_id
    )

    policy_path = Path(receiver["authorization"]["policy_file"])
    policy = json.loads(policy_path.read_text())
    principal = next(p for p in policy["principals"] if p["subject"] == "peer-layer1")
    principal["service_id"] = "https://reassigned.example.net/lasa"
    policy_path.write_text(json.dumps(policy))
    reassigned = static_workload_identity("peer-layer1", principal["service_id"], receiver_id)
    # Authenticate successfully under the new mapping, then reject access to the old peer-owned task.
    async with httpx.AsyncClient(
        transport=transport,
        headers={
            "Authorization": "Bearer " + secret,
            WORKLOAD_IDENTITY_HEADER: digest(reassigned),
        },
    ) as other:
        base = receiver["service"]["base_url"]
        assert (await other.get(base + "/descriptor")).status_code == 200
        assert (await other.get(base + "/tasks/" + child["task_id"] + "/events")).status_code == 403
