import asyncio
import copy
import json
from pathlib import Path

import httpx
import pytest

from lasa_service.contracts import canonical, digest
from lasa_service.planning import Planner

from .conftest import FakeRuntime, documents, new_session, settled, submit, task_request


async def test_lost_receipt_and_idempotent_identity_never_duplicate_work(services):
    runtime = FakeRuntime()
    client, app = await services(runtime=runtime)
    sid = await new_session(client, app)
    body = await task_request(client, app)
    first = await submit(client, app, body, sid)
    result = await settled(client, first)
    second = await submit(client, app, body, sid)
    assert second.json()["task_id"] == result["task_id"]
    url = (
        app.state.coordinator.config.document["service"]["base_url"] + "/sessions/" + sid + "/tasks"
    )
    third = await client.post(url, json=body, headers={"Idempotency-Key": "different-key"})
    assert third.json()["task_id"] == result["task_id"] and len(runtime.prompts) == 1
    changed = copy.deepcopy(body)
    changed["input"]["objective"] = "Changed under the same operation"
    assert (
        await client.post(url, json=changed, headers={"Idempotency-Key": body["operation_id"]})
    ).status_code == 409
    receipt = await client.get(
        app.state.coordinator.config.document["service"]["base_url"]
        + "/operations/"
        + body["operation_id"]
    )
    assert receipt.json()["resource_id"] == result["task_id"] and receipt.json()[
        "request_digest"
    ] == digest(body)


@pytest.mark.parametrize(
    "point,status",
    [
        ("after_receipt", "rejected"),
        ("after_admission", "failed"),
        ("before_release", "failed"),
        ("after_release", "completed"),
    ],
)
async def test_failure_boundaries_preserve_durable_status(services, point, status):
    client, app = await services()
    c = app.state.coordinator

    def fault(current, task_id):
        if current == point:
            raise RuntimeError("injected failure")

    c.fault = fault
    request = await task_request(client, app)
    sid = await new_session(client, app)
    response = await submit(client, app, request, sid)
    result = await settled(client, response)
    assert result["status"] == status
    replay = await submit(client, app, request, sid)
    assert replay.json()["task_id"] == result["task_id"]


async def test_effect_commit_unknown_is_not_replayed_and_resolution_is_append_only(services):
    calls = []

    async def handler(context):
        calls.append(True)
        await context.coordinator.broker.call(
            context.task_id,
            "stable-write",
            "workspace.write",
            {"relative_path": "proof.txt", "text": "committed once"},
        )
        return await FakeRuntime().run(context)

    client, app = await services(runtime=FakeRuntime(handler))
    c = app.state.coordinator
    c.fault = lambda point, task_id: (
        (_ for _ in ()).throw(RuntimeError("lost after commit"))
        if point == "after_effect"
        else None
    )
    request = await task_request(client, app)
    sid = await new_session(client, app)
    response = await submit(client, app, request, sid)
    result = await settled(client, response)
    assert (
        result["status"] == "indeterminate"
        and c.workspace(sid).read("proof.txt") == "committed once"
    )
    assert (await submit(client, app, request, sid)).json()["task_id"] == result["task_id"] and len(
        calls
    ) == 1
    before = canonical(result)
    url = response.headers["Location"] + "/reconcile"
    body = {"operation_id": "reconcile-write"}
    resolved = await client.post(url, json=body, headers={"Idempotency-Key": "reconcile-key"})
    assert resolved.status_code == 202 and canonical(resolved.json()) == before
    events = (await client.get(response.headers["Location"] + "/events")).json()["events"]
    assert any(
        e["kind"] == "resolution" and e["payload"]["resolved_effect_disposition"] == "known"
        for e in events
    )
    await client.post(url, json=body, headers={"Idempotency-Key": "reconcile-key"})
    assert (
        len(
            [
                e
                for e in (await client.get(response.headers["Location"] + "/events")).json()[
                    "events"
                ]
                if e["kind"] == "resolution"
            ]
        )
        == 1
    )


async def test_cancel_is_revision_guarded_and_stops_owned_work(services):
    entered = asyncio.Event()

    async def handler(context):
        entered.set()
        await asyncio.Event().wait()

    client, app = await services(runtime=FakeRuntime(handler))
    response = await submit(client, app, await task_request(client, app))
    await entered.wait()
    current = await client.get(response.headers["Location"])
    url = response.headers["Location"] + "/cancel"
    body = {"operation_id": "cancel-once"}
    assert (
        await client.post(url, json=body, headers={"Idempotency-Key": "cancel"})
    ).status_code == 428
    assert (
        await client.post(url, json=body, headers={"Idempotency-Key": "cancel", "If-Match": '"0"'})
    ).status_code == 412
    assert (
        await client.post(
            url,
            json=body,
            headers={"Idempotency-Key": "cancel", "If-Match": current.headers["etag"]},
        )
    ).status_code == 202
    assert (await settled(client, response))["status"] == "cancelled"
    assert not app.state.coordinator.contexts


async def test_deadline_stops_execution_without_silent_success(services):
    from datetime import UTC, datetime, timedelta

    async def handler(context):
        await asyncio.Event().wait()

    client, app = await services(runtime=FakeRuntime(handler))
    body = await task_request(client, app)
    body["requested_limits"]["deadline"] = (
        datetime.now(UTC) + timedelta(milliseconds=200)
    ).isoformat()
    result = await settled(client, await submit(client, app, body))
    assert result["status"] == "failed" and result["problem"]["code"] == "deadline_exceeded"


async def test_lost_child_response_reconciles_without_reexecuting(services, tmp_path):
    child_runtime = FakeRuntime()
    child_client, child_app = await services(
        raw=documents(tmp_path / "child", "layer2"), runtime=child_runtime
    )
    transport = httpx.ASGITransport(app=child_app)

    class LoseAck(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            response = await transport.handle_async_request(request)
            await response.aread()
            if request.method == "POST" and request.url.path.endswith("/tasks"):
                raise httpx.ReadError("ack lost", request=request)
            return response

    raw = documents(tmp_path / "parent", peer=True)
    raw["routing"]["preferred_executor"] = "peer"
    client, app = await services(raw=raw, peer_transport=LoseAck())
    response = await submit(client, app, await task_request(client, app))
    result = await settled(client, response)
    assert result["status"] == "indeterminate"
    await asyncio.sleep(0.05)
    task_id = result["task_id"]
    c = app.state.coordinator
    child = c.store.children(task_id)[0]
    assert "task_id" not in child
    body = {"operation_id": "reconcile-child"}
    resolved = await client.post(
        response.headers["Location"] + "/reconcile",
        json=body,
        headers={"Idempotency-Key": "reconcile-child"},
    )
    assert resolved.status_code == 202 and resolved.json()["status"] == "indeterminate"
    assert (
        len(child_runtime.prompts) == 1
        and len(child_app.state.coordinator.store.db.execute("SELECT id FROM tasks").fetchall())
        == 1
    )
    assert any(
        e["kind"] == "resolution"
        for e in (await client.get(response.headers["Location"] + "/events")).json()["events"]
    )


async def test_changed_requirements_cannot_reuse_semantic_verdict(services):
    client, app = await services()
    result = await settled(client, await submit(client, app, await task_request(client, app)))
    c = app.state.coordinator
    calls = []

    async def verify(c, task_id, definition, inputs, output, evidence, requirements):
        calls.append(requirements)
        return requirements is None

    planner = Planner(c, verifier=verify)
    definition = c.registry.get(result["selection"]["contract"])
    inputs = c.request(result["task_id"])["input"]
    output = result["result"]["output"]
    evidence = result["result"]["evidence"]
    assert await planner.verify(result["task_id"], definition, inputs, output, evidence)
    assert not await planner.verify(
        result["task_id"],
        definition,
        inputs,
        output,
        evidence,
        requirements=[{"stricter": "actual root obligation"}],
    )
    assert len(calls) == 2


async def test_actual_process_death_recovers_without_replay(tmp_path):
    import subprocess
    import sys

    from lasa_service.api import create_app

    from .conftest import JWK, configuration

    root = tmp_path / "crashed"
    result = await asyncio.to_thread(
        subprocess.run,
        [sys.executable, str(Path(__file__).parent / "fixtures/crash_service.py"), str(root)],
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 72, result.stderr.decode()
    raw = json.loads((root / "config.json").read_text())
    Path(raw["authentication"]["jwks_file"]).write_text(json.dumps({"keys": [JWK]}))
    runtime = FakeRuntime()
    app = create_app(configuration(raw), runtime=runtime)
    async with app.router.lifespan_context(app):
        c = app.state.coordinator
        row = c.store.db.execute("SELECT id FROM tasks").fetchone()
        task = c.store.task(row["id"])[1]
        assert task["status"] == "indeterminate" and runtime.prompts == []
        assert c.workspace(task["session_id"]).read("committed.txt") == "one committed write"
        events = c.diagnostics.page(task["task_id"], {"subject": "alice"})["events"]
        assert any(
            e["kind"] == "resolution" and e["payload"]["resolved_effect_disposition"] == "known"
            for e in events
        )
