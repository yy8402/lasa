import asyncio
import copy
import json
import sqlite3
from pathlib import Path

import httpx
import pytest

from lasa_service.capabilities import instant
from lasa_service.contracts import canonical, digest
from lasa_service.planning import Planner
from lasa_service.store import STORAGE_SCHEMA_VERSION, Store, encode, zero

from .conftest import FakeRuntime, documents, new_session, settled, submit, task_request


def test_accounting_totals_backfill_and_roll_back_with_source_rows(tmp_path):
    # An existing store can already have reserved work and content diagnostics.
    pending = {**zero(), "model_calls": 4, "tool_calls": 3}
    spent = {**zero(), "model_calls": 2, "tool_calls": 1}
    with sqlite3.connect(tmp_path / "tasks.sqlite3") as db:
        db.execute(f"PRAGMA user_version={STORAGE_SCHEMA_VERSION}")
        db.executescript("""
            CREATE TABLE allocations(task_id TEXT,operation_id TEXT,kind TEXT,state TEXT,reserved TEXT,usage TEXT,details TEXT,PRIMARY KEY(task_id,operation_id));
            CREATE TABLE events(task_id TEXT,sequence INTEGER,document TEXT,PRIMARY KEY(task_id,sequence));
        """)
        db.execute(
            "INSERT INTO allocations VALUES(?,?,?,?,?,?,?)",
            ("task", "call", "model", "reserved", encode(pending), encode(zero()), "{}"),
        )
        db.execute(
            "INSERT INTO events VALUES(?,?,?)", ("task", 1, encode({"content": {"text": "€"}}))
        )
    store = Store(tmp_path)
    try:
        assert store.usage("task", reserved=True) == pending
        assert store.usage("task") == zero() and store.diagnostic_bytes("task") == 3
        with pytest.raises(RuntimeError), store.transaction():
            store.settle("task", "call", spent)
            assert store.usage("task", reserved=True) == spent
            assert store.usage("task") == spent
            store.db.execute("DELETE FROM events WHERE task_id='task'")
            assert store.diagnostic_bytes("task") == 0
            raise RuntimeError("rollback")
        assert store.usage("task", reserved=True) == pending
        assert store.usage("task") == zero() and store.diagnostic_bytes("task") == 3
        store.settle("task", "call", spent)
    finally:
        store.close()
    reopened = Store(tmp_path)
    try:
        assert reopened.usage("task") == reopened.usage("task", reserved=True) == spent
        assert reopened.diagnostic_bytes("task") == 3
    finally:
        reopened.close()


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


async def test_cancel_before_job_starts_releases_session_and_job_state(services):
    client, app = await services()
    c = app.state.coordinator
    session_id = await new_session(client, app)
    request = await task_request(client, app)
    principal = c.authentication.authenticate(client.headers["Authorization"])
    task, _ = await c.submit(principal, session_id, request, "submit-key", "submit-route")
    task_id = task["task_id"]
    job = c.jobs[task_id]
    await c.mutation(
        principal,
        task_id,
        {"operation_id": "cancel-early"},
        "cancel-key",
        "cancel-route",
        '"1"',
        "cancel",
    )
    await asyncio.gather(job, return_exceptions=True)
    assert c.store.task(task_id)[1]["status"] == "cancelled"
    assert c.store.session(session_id)[1]["active_task_id"] is None
    assert not c.store.active() and not c.jobs and not c.expiries and not c.assessment_expiries
    assert not c.runtime.prompts


async def test_reconcile_concurrent_retries_share_one_operation(services, monkeypatch):
    client, app = await services()
    c = app.state.coordinator
    submission = await submit(client, app, await task_request(client, app))
    await settled(client, submission)
    entered, release = asyncio.Event(), asyncio.Event()
    calls = []

    async def reconcile(task_id):
        calls.append(task_id)
        entered.set()
        await release.wait()

    monkeypatch.setattr(c, "reconcile_internal", reconcile)
    url = submission.headers["Location"] + "/reconcile"
    body = {"operation_id": "reconcile-concurrent"}
    headers = {"Idempotency-Key": "reconcile-concurrent"}
    async with asyncio.timeout(2), asyncio.TaskGroup() as group:
        first = group.create_task(client.post(url, json=body, headers=headers))
        await entered.wait()
        second = group.create_task(client.post(url, json=body, headers=headers))
        await asyncio.sleep(0)
        release.set()
    assert first.result().status_code == second.result().status_code == 202
    assert calls == [submission.json()["task_id"]]


async def test_retention_retires_expired_records_and_retries_path_cleanup(services, monkeypatch):
    async def handler(context):
        if context.prompt["input"]["objective"] == "Preserve this unresolved task.":
            await context.coordinator.broker.call(
                context.task_id,
                "write",
                "workspace.write",
                {"relative_path": "uncertain.txt", "text": "keep"},
            )
        return await FakeRuntime().run(context)

    client, app = await services(runtime=FakeRuntime(handler))
    c = app.state.coordinator
    completed = await submit(client, app, await task_request(client, app))
    done = await settled(client, completed)
    c.fault = lambda point, task_id: (
        (_ for _ in ()).throw(RuntimeError("interrupted after write"))
        if point == "after_effect"
        else None
    )
    request = await task_request(client, app)
    request["input"]["objective"] = "Preserve this unresolved task."
    pending = await submit(client, app, request)
    unknown = await settled(client, pending)
    assert unknown["status"] == "indeterminate"
    fresh = await new_session(client, app)
    for task in (done, unknown):
        _, session = c.store.session(task["session_id"])
        session["retention_until"] = instant(0)
        c.store.db.execute(
            "UPDATE sessions SET document=? WHERE id=?", (encode(session), session["session_id"])
        )
    workspace = c.workspace(done["session_id"]).root

    from lasa_service import maintenance

    rmtree = maintenance.shutil.rmtree

    def fail_once(path):
        if path == workspace:
            raise PermissionError("temporarily unavailable")
        rmtree(path)

    with monkeypatch.context() as patch:
        patch.setattr(maintenance.shutil, "rmtree", fail_once)
        await c.maintenance.collect()
    assert workspace.exists()
    assert (await client.get(completed.headers["Location"])).status_code == 404
    base = c.config.document["service"]["base_url"]
    assert (await client.get(base + "/operations/" + done["operation_id"])).status_code == 404
    assert (await client.get(pending.headers["Location"])).status_code == 200
    assert (await client.get(base + "/sessions/" + fresh)).status_code == 200
    assert not c.store.db.execute(
        "SELECT 1 FROM events WHERE task_id=?", (done["task_id"],)
    ).fetchone()
    c.store.db.execute("UPDATE retired_paths SET retry_at=?", (instant(0),))
    await c.maintenance.collect()
    assert not workspace.exists() and not c.store.due_paths(instant(), 10)


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
    receipts_unavailable = True

    class LoseAck(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            if receipts_unavailable and "/operations/" in request.url.path:
                return httpx.Response(503, request=request)
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
    receipts_unavailable = False
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
    c = app.state.coordinator
    entered, resume, finished = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def delayed_peer_reconciliation(task_id):
        entered.set()
        await resume.wait()

    reconcile = c.reconcile_internal

    async def signal_reconciled(task_id):
        await reconcile(task_id)
        finished.set()

    c.delegation.reconcile_parent = delayed_peer_reconciliation
    c.reconcile_internal = signal_reconciled
    async with asyncio.timeout(3), app.router.lifespan_context(app):
        await entered.wait()
        assert c.availability() == "available"
        row = c.store.db.execute("SELECT id FROM tasks").fetchone()
        task = c.store.task(row["id"])[1]
        assert task["status"] == "indeterminate" and runtime.prompts == []
        assert c.workspace(task["session_id"]).read("committed.txt") == "one committed write"
        assert c.store.unresolved("", 4) == [task["task_id"]]
        resume.set()
        await finished.wait()
        assert c.store.unresolved("", 4) == []
        events = c.diagnostics.page(task["task_id"], {"subject": "alice"})["events"]
        assert any(e["kind"] == "resolution" for e in events)
