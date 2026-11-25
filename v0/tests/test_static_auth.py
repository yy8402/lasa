import json
import secrets
import time
from pathlib import Path

from lasa_service.auth import static_token_digest

from .conftest import documents, settled, submit, task_request


async def test_standalone_static_auth_uses_policy_and_reloads_credentials(services, tmp_path):
    raw = documents(tmp_path)
    registry = tmp_path / "static-tokens.json"
    raw["authentication"] = {"mode": "static_token", "tokens_file": str(registry)}
    policy = Path(raw["authorization"]["policy_file"])
    authority = json.loads(policy.read_text())
    authority["principals"] = [p for p in authority["principals"] if p["kind"] == "user"]
    policy.write_text(json.dumps(authority))
    service_id = raw["service"]["id"]
    active, expired, wrong_receiver, rotated = (secrets.token_urlsafe(32) for _ in range(4))
    now = int(time.time())

    def record(token, *, receiver=service_id, expires=now + 3600, subject="alice"):
        return {
            "subject": subject,
            "digest": static_token_digest(receiver, token),
            "expires_at": expires,
        }

    def update(records):
        replacement = registry.with_suffix(".next")
        replacement.write_text(json.dumps({"tokens": records}))
        replacement.replace(registry)

    update(
        [
            record(active),
            record(expired, expires=now - 1),
            record(wrong_receiver, receiver="https://elsewhere.example.net/lasa"),
            record(rotated, subject="absent"),
        ]
    )
    client, app = await services(raw=raw)
    coordinator = app.state.coordinator
    url = coordinator.config.descriptor_url
    assert (await client.get(url)).status_code == 401  # JWT

    def header(token):
        return {"Authorization": "Bearer " + token}

    for candidate in (expired, wrong_receiver, rotated, secrets.token_urlsafe(32)):
        assert (await client.get(url, headers=header(candidate))).status_code == 401
    response = await client.get(url, headers=header(active))
    assert response.status_code == 200
    descriptor = response.json()
    coordinator.config.contracts.validate("ServiceDescriptor", descriptor)
    assert descriptor["authentication"] == {"mode": "static_token"}
    assert "consumer-events" in descriptor["protocols"][0]["features"]

    client.headers.update(header(active))
    result = await settled(client, await submit(client, app, await task_request(client, app)))
    assert result["status"] == "completed"
    update([record(rotated)])
    assert (await client.get(url)).status_code == 401
    assert (await client.get(url, headers=header(rotated))).status_code == 200
    authority["principals"] = []
    policy.write_text(json.dumps(authority))
    assert (await client.get(url, headers=header(rotated))).status_code == 401
