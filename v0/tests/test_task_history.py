import json

from .conftest import settled, submit, task_request, token


async def test_history_owner_pagination_and_tied_timestamps(services):
    client, app = await services()
    coordinator = app.state.coordinator
    base = coordinator.config.document["service"]["base_url"]
    path = base + "/tasks"
    empty = await client.get(path)
    assert empty.json() == {"tasks": [], "next_cursor": None}
    assert empty.headers["cache-control"] == "no-store"

    ids = []
    for _ in range(3):
        result = await settled(client, await submit(client, app, await task_request(client, app)))
        ids.append(result["task_id"])
        coordinator.store.db.execute(
            "UPDATE tasks SET document=json_set(document,'$.received_at',?) WHERE id=?",
            ("2026-11-26T09:00:00.000Z", result["task_id"]),
        )
    coordinator.store.db.execute("DELETE FROM task_titles WHERE task_id=?", (ids[0],))
    history = []
    params = {"limit": 1}
    for _ in ids:
        response = await client.get(path, params=params)
        assert response.status_code == 200, response.text
        page = response.json()
        (item,) = page["tasks"]
        assert set(item) == {"task_id", "title", "contract", "status", "received_at"}
        assert item["status"] == "completed"
        assert item["title"] == "Explain a bounded service"
        history.append(item["task_id"])
        params["cursor"] = page["next_cursor"]
        if len(history) == 1:
            other = {"Authorization": "Bearer " + token("bob", coordinator.config.service_id)}
            assert (await client.get(path, headers=other)).json()["tasks"] == []
            assert (await client.get(path, headers=other, params=params)).status_code == 400
            assert (
                await client.get(path, params={"cursor": params["cursor"] + "a"})
            ).status_code == 400
    assert history == sorted(ids, reverse=True)
    assert params["cursor"] is None
    assert coordinator.store.task_title(ids[0])["title"] == "Explain a bounded service"
    assert (await client.get(path, params={"limit": 101})).status_code == 400

    for subject in ("operator", "peer-layer1"):
        headers = {"Authorization": "Bearer " + token(subject, coordinator.config.service_id)}
        assert (await client.get(path, headers=headers)).status_code == 403

    # History follows the same native retirement boundary as direct reads.
    row, task = coordinator.store.task(ids[0])
    coordinator.store.db.execute(
        "UPDATE sessions SET document=json_set(document,'$.retention_until',?) WHERE id=?",
        ("2026-01-01T00:00:00.000Z", row["session_id"]),
    )
    coordinator.store.retire_sessions("2026-01-02T00:00:00.000Z", 25)
    listed = (await client.get(path)).json()["tasks"]
    assert task["task_id"] not in {item["task_id"] for item in listed}
    assert coordinator.store.task_title(ids[0]) is None
    assert not any("task_request" in json.dumps(item) for item in listed)
