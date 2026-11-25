import asyncio
import json
import sqlite3
from pathlib import Path

import httpx
import pytest

from lasa_service.contracts import digest

from .conftest import FakeRuntime, documents, new_session, settled, submit, task_request
from .protocol_helpers import sse_final


def configure_inspection(raw, group, direction, *, mode="enforce"):
    security = raw.setdefault("content_security", {})
    security.setdefault(
        "inspection_profiles",
        [
            {
                "id": "fixture-profile",
                "gateway_id": "fixture",
                "url": "https://inspection.example.net/check",
                "credential_ref": "env:GATEWAY_KEY",
                "policy_revision": "revision-1",
                "region": "local",
                "retention": "none",
            }
        ],
    )
    security.setdefault("bindings", {}).setdefault(group, {})[direction] = {
        "mode": mode,
        "profile": "fixture-profile",
    }
    return raw


def policy_for(raw):
    return Path(raw["authorization"]["policy_file"])


def restrict_scanner(raw):
    path = policy_for(raw)
    policy = json.loads(path.read_text())
    policy["content_disclosure"] = {"destinations": {"inspection:fixture-profile": ["private"]}}
    path.write_text(json.dumps(policy))


def verdict(body, **overrides):
    return httpx.Response(
        200,
        json={
            "version": "1",
            "gateway_id": "fixture",
            "verdict": "permit",
            "reason_codes": [],
            **{
                key: body[key]
                for key in (
                    "inspection_id",
                    "gateway_policy_revision",
                    "inspection_digest",
                )
            },
            **overrides,
        },
    )


def audit_events(c):
    return [
        json.loads(row[0])
        for row in c.store.db.execute(
            "SELECT document FROM audit WHERE kind='content_decision' ORDER BY rowid"
        )
    ]


@pytest.mark.parametrize("purpose", ["planning", "verification", "execution", "compaction"])
async def test_denied_model_requests_do_not_reach_provider(services, tmp_path, purpose):
    raw = configure_inspection(documents(tmp_path), "model", "request")
    inspections = []
    provider_calls = []

    async def gateway(request):
        body = json.loads(request.content)
        assert request.headers["Authorization"] == "Bearer test-gateway-key"
        assert body["inspection_digest"] == digest(body["content"])
        inspections.append(body)
        return verdict(body, verdict="hard_deny")

    async def provider(request):
        provider_calls.append(request)
        return httpx.Response(200)

    async def execute(context):
        c = context.coordinator
        await c.model_client.exchange(
            context.task_id,
            c.config.executor(),
            {
                "input": [
                    {"role": "developer", "content": "internal prompt"},
                    {"role": "user", "content": "restricted fixture text"},
                ]
            },
            purpose,
            worker=purpose in {"execution", "compaction"},
        )
        raise AssertionError("Denied model request continued")

    client, app = await services(
        raw=raw,
        runtime=FakeRuntime(execute),
        model_transport=httpx.MockTransport(provider),
        inspection_transport=httpx.MockTransport(gateway),
    )
    task = await settled(client, await submit(client, app, await task_request(client, app)))
    assert task["problem"]["code"] == "disclosure_denied"
    assert not provider_calls
    assert [x["content"] for x in inspections] == [
        {"input": [{"role": "user", "content": "restricted fixture text"}]}
    ]
    evidence = json.dumps(audit_events(app.state.coordinator))
    for private in ("internal prompt", "restricted fixture text", "test-gateway-key"):
        assert private not in evidence


@pytest.mark.parametrize("streaming", [False, True])
async def test_denied_model_response_settles_usage_before_return(services, streaming):
    consumed = []

    async def provider(_):
        if streaming:
            raw = sse_final("test-model-key").replace(
                b'"delta": "test-model-key"',
                b'"delta": "test-model-"',
            )
            frame = next(frame for frame in raw.split(b"\n\n") if b'"delta"' in frame)
            raw = raw.replace(frame, frame + b"\n\n" + frame.replace(b"test-model-", b"key"))
            return httpx.Response(200, content=raw, headers={"Content-Type": "text/event-stream"})
        return httpx.Response(
            200,
            json={
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": "test-model-key"}],
                    }
                ],
                "usage": {"total_tokens": 21},
            },
        )

    async def execute(context):
        c = context.coordinator
        consumed.append(
            await c.model_client.exchange(
                context.task_id,
                c.config.executor(),
                {"input": []},
                "execution",
                worker=streaming,
            )
        )
        return await FakeRuntime().run(context)

    client, app = await services(
        runtime=FakeRuntime(execute), model_transport=httpx.MockTransport(provider)
    )
    task = await settled(client, await submit(client, app, await task_request(client, app)))
    assert task["problem"]["code"] == "disclosure_denied"
    assert not consumed
    assert app.state.coordinator.store.usage(task["task_id"])["model_calls"] == 1


@pytest.mark.parametrize(
    "failure,code",
    [
        ("timeout", "content_gateway_unavailable"),
        ("digest", "content_gateway_unavailable"),
        ("identity", "content_gateway_unavailable"),
        ("revision", "content_gateway_unavailable"),
        ("malformed", "content_gateway_unavailable"),
        ("replay", "content_gateway_unavailable"),
        ("audit", "content_gateway_unavailable"),
        ("class", "disclosure_denied"),
    ],
)
async def test_required_gateway_and_audit_fail_closed(
    services, tmp_path, monkeypatch, failure, code
):
    raw = configure_inspection(documents(tmp_path), "caller", "response")
    if failure == "class":
        restrict_scanner(raw)
    if failure == "timeout":
        monkeypatch.setattr("lasa_service.content_security.INSPECTION_TIMEOUT_SECONDS", 0.015)
    calls = []

    async def gateway(request):
        body = json.loads(request.content)
        calls.append(body)
        if failure == "timeout":
            await asyncio.sleep(1)
        if failure == "malformed":
            return httpx.Response(200, content=b"{}")
        return verdict(
            body,
            **{
                "digest": {"inspection_digest": "sha256:" + "0" * 64},
                "identity": {"gateway_id": "wrong"},
                "revision": {"gateway_policy_revision": "wrong"},
                "replay": {"inspection_id": "inspection-from-other-call"},
            }.get(failure, {}),
        )

    client, app = await services(raw=raw, inspection_transport=httpx.MockTransport(gateway))
    c = app.state.coordinator
    if failure == "audit":
        c.store.db.execute("""
            CREATE TRIGGER deny_audit BEFORE INSERT ON audit
            WHEN NEW.kind='content_decision' AND NEW.task_id IS NOT NULL BEGIN SELECT RAISE(FAIL, 'test'); END
        """)
    task = await settled(client, await submit(client, app, await task_request(client, app)))
    assert task["problem"]["code"] == code
    assert len(calls) == (2 if failure == "timeout" else int(failure not in {"class", "audit"}))
    assert "result" not in task


async def test_observe_still_checks_disclosure_before_sending(services, tmp_path):
    raw = configure_inspection(documents(tmp_path), "caller", "response", mode="observe")
    restrict_scanner(raw)

    async def gateway(_):
        pytest.fail("Unauthorized inspection attempt")

    client, app = await services(raw=raw, inspection_transport=httpx.MockTransport(gateway))
    task = await settled(client, await submit(client, app, await task_request(client, app)))
    assert task["status"] == "completed"
    assert any(
        record["reason_code"] == "scanner_disclosure_denied"
        for record in audit_events(app.state.coordinator)
    )


@pytest.mark.parametrize(
    "blocked", ["result", "artifact", "commit", "revocation", "policy_revocation"]
)
async def test_exact_release_and_replay_visibility(services, tmp_path, blocked):
    raw = documents(tmp_path)

    async def execute(context):
        c = context.coordinator
        result = await FakeRuntime().run(context)
        await c.broker.call(
            context.task_id,
            "known-write",
            "workspace.write",
            {"relative_path": "document.txt", "text": "Confined workspace content"},
        )
        artifact = c.snapshot_artifact(
            context.task_id,
            "text/plain",
            "test-model-key" if blocked == "artifact" else "allowable snapshot",
        )
        result["artifact_ids"] = [artifact["artifact_id"]]
        if blocked == "result":
            result["output"]["summary"] = "test-model-key"
        return result

    client, app = await services(raw=raw, runtime=FakeRuntime(execute))
    c = app.state.coordinator
    if blocked == "commit":

        def fail_before_commit(point, _):
            if point == "before_release_commit":
                raise sqlite3.OperationalError("injected commit interruption")

        c.fault = fail_before_commit
    request = await task_request(client, app)
    session = await new_session(client, app)
    response = await submit(client, app, request, session)
    task = await settled(client, response)
    artifact_id = c.store.db.execute("SELECT id FROM artifacts").fetchone()[0]
    artifact_url = response.headers["Location"] + "/artifacts/" + artifact_id
    if blocked in {"revocation", "policy_revocation"}:
        assert task["status"] == "completed"
        assert (await client.get(artifact_url)).text == "allowable snapshot"
        if blocked == "revocation":
            c.content.revision = digest({"revoked": True})
        else:
            path = policy_for(raw)
            policy = json.loads(path.read_text())
            policy["content_disclosure"] = {"destinations": {"caller:alice": ["private"]}}
            path.write_text(json.dumps(policy))
        assert (await client.get(response.headers["Location"])).status_code == 403
        assert (await client.get(artifact_url)).status_code == 403
        assert (await submit(client, app, request, session)).status_code == 403
    else:
        assert task["status"] == "failed" and "result" not in task
        assert task["problem"]["effect_disposition"] == "known"
        assert (await client.get(artifact_url)).status_code == 404
        assert "result" not in (await submit(client, app, request, session)).json()
        assert not c.store.db.execute("SELECT * FROM content_releases").fetchall()


async def test_inconsistent_earlier_sse_part_never_reaches_worker(services, tmp_path):
    raw = configure_inspection(documents(tmp_path), "model", "response")
    provider_calls = []
    gateway_calls = []
    returned = []

    async def provider(request):
        provider_calls.append(request)
        stream = sse_final("approved terminal text").replace(
            b'"text": "", "annotations": []', b'"text": "early unapproved bytes", "annotations": []'
        )
        return httpx.Response(200, content=stream, headers={"Content-Type": "text/event-stream"})

    async def scanner(request):
        gateway_calls.append(request)
        return verdict(json.loads(request.content))

    async def execute(context):
        from lasa_service.gateway import TaskGateway

        gateway = TaskGateway(context)
        try:
            await gateway.start()
            async with httpx.AsyncClient() as worker:
                reply = await worker.post(
                    gateway.url + "/model/responses",
                    json={"model": context.coordinator.config.executor()["model"], "input": []},
                    headers={"Authorization": "Bearer " + gateway.token},
                )
            returned.append(reply)
            assert gateway.failure.done()
            raise gateway.failure.result()
        finally:
            await gateway.close()

    client, app = await services(
        raw=raw,
        runtime=FakeRuntime(execute),
        model_transport=httpx.MockTransport(provider),
        inspection_transport=httpx.MockTransport(scanner),
    )
    task = await settled(client, await submit(client, app, await task_request(client, app)))
    assert task["problem"]["code"] == "verification_failed"
    assert len(provider_calls) == len(returned) == 1 and not gateway_calls
    assert b"early unapproved bytes" not in returned[0].content
    assert "text/event-stream" not in returned[0].headers["Content-Type"]


async def test_caller_denial_precedes_durable_task_and_planning(services, tmp_path):
    raw = configure_inspection(documents(tmp_path), "caller", "request")
    runtime = FakeRuntime()

    async def gateway(request):
        return verdict(json.loads(request.content), verdict="hard_deny")

    client, app = await services(
        raw=raw, runtime=runtime, inspection_transport=httpx.MockTransport(gateway)
    )
    body = await task_request(client, app)
    body["input"]["objective"] = "blocked caller test text"
    response = await submit(client, app, body)
    assert response.status_code == 403 and "blocked caller test text" not in response.text
    c = app.state.coordinator
    assert (
        not runtime.prompts and c.store.db.execute("SELECT count(*) FROM tasks").fetchone()[0] == 0
    )
    record = audit_events(c)[-1]
    assert record["operation_id"] == body["operation_id"] and record["task_id"] is None


@pytest.mark.parametrize("mode", ["question", "answer", "diagnostics"])
async def test_clarification_and_diagnostics_are_policy_gated(services, tmp_path, mode):
    direction = "request" if mode == "answer" else "response"
    purpose = "diagnostics" if mode == "diagnostics" else "clarification"
    raw = configure_inspection(documents(tmp_path), "caller", direction)
    path = policy_for(raw)
    rules = json.loads(path.read_text())
    rules["principals"][0]["rules"][0]["content_diagnostics"] = True
    path.write_text(json.dumps(rules))
    answers = []

    async def gateway(request):
        body = json.loads(request.content)
        deny = body["purpose"] == purpose and (
            mode != "answer" or body["content"]["answer"] == "blocked"
        )
        return verdict(body, verdict="hard_deny" if deny else "permit")

    async def execute(context):
        c = context.coordinator
        if mode == "diagnostics":
            c.diagnostics.call(
                context.task_id,
                "fixture-trace",
                "tool",
                "finished",
                {},
                content={"data": "blocked diagnostic text"},
            )
        else:
            answers.append(await c.request_input(context.task_id, "blocked question text"))
        return await FakeRuntime().run(context)

    client, app = await services(
        raw=raw, runtime=FakeRuntime(execute), inspection_transport=httpx.MockTransport(gateway)
    )
    body = await task_request(client, app)
    body["diagnostics"] = "content"
    response = await submit(client, app, body)
    location = response.headers["Location"]
    if mode == "answer":
        async with asyncio.timeout(5):
            while True:
                task = await client.get(location)
                if task.json()["status"] == "awaiting_input":
                    break
                await asyncio.sleep(0.01)
        question = task.json()["question"]
        answer = {
            "operation_id": "input-test",
            "question_id": question["question_id"],
            "question_revision": question["revision"],
            "answer": "blocked",
        }
        headers = {"Idempotency-Key": "input-test", "If-Match": task.headers["ETag"]}
        denied = await client.post(location + "/inputs", json=answer, headers=headers)
        assert denied.status_code == 403 and not answers
        answer["answer"] = "permitted"
        assert (
            await client.post(location + "/inputs", json=answer, headers=headers)
        ).status_code == 202
    terminal = await settled(client, response)
    if mode == "question":
        assert terminal["problem"]["code"] == "disclosure_denied" and "question" not in terminal
    elif mode == "answer":
        assert terminal["status"] == "completed" and answers == [{"answer": "permitted"}]
    else:
        events = (await client.get(location + "/events")).json()["events"]
        assert any(event["payload"].get("operation_id") == "fixture-trace" for event in events)
        assert not any("content" in event for event in events)


@pytest.mark.parametrize("blocked", ["dispatch", "result", "artifact", "revoked"])
async def test_child_bodies_and_disposition_have_independent_policy(services, tmp_path, blocked):
    child_posts = []
    control_reads = []

    async def execute(context):
        c = context.coordinator
        await c.broker.call(
            context.task_id,
            "known-child-write",
            "workspace.write",
            {"relative_path": "child.txt", "text": "fixture child effect"},
        )
        result = await FakeRuntime().run(context)
        result["output"]["summary"] = "fixture child output"
        if blocked == "artifact":
            result["artifact_ids"] = [
                c.snapshot_artifact(
                    context.task_id,
                    "text/plain",
                    "fixture child attachment",
                )["artifact_id"]
            ]
        return result

    _, child_app = await services(
        raw=documents(tmp_path / "child", "layer2"), runtime=FakeRuntime(execute)
    )
    if blocked == "revoked":

        def revoke(point, _task_id):
            if point == "after_release":
                child_app.state.coordinator.content.revision = digest({"revoked": True})

        child_app.state.coordinator.fault = revoke
    transport = httpx.ASGITransport(app=child_app)

    async def capture(request):
        if request.method == "POST" and request.url.path.endswith("/tasks"):
            child_posts.append(await request.aread())
        if request.url.params.get("view") == "control":
            control_reads.append(str(request.url))
        return await transport.handle_async_request(request)

    raw = documents(tmp_path / "parent", peer=True)
    raw["routing"]["preferred_executor"] = "peer"
    if blocked != "revoked":
        configure_inspection(raw, "delegates", "request" if blocked == "dispatch" else "response")

    async def gateway(request):
        body = json.loads(request.content)
        deny = body["purpose"] == ("task" if blocked == "dispatch" else blocked)
        return verdict(body, verdict="hard_deny" if deny else "permit")

    client, app = await services(
        raw=raw,
        peer_transport=httpx.MockTransport(capture),
        inspection_transport=httpx.MockTransport(gateway),
    )
    terminal = await settled(client, await submit(client, app, await task_request(client, app)))
    assert terminal["problem"]["code"] == "disclosure_denied"
    assert "fixture child" not in json.dumps(terminal)
    parent = app.state.coordinator
    child = parent.store.children(terminal["task_id"])[0]
    assert child["service_id"] == child_app.state.coordinator.config.service_id
    if blocked == "dispatch":
        assert not child_posts and not child["dispatched"] and "request" not in child
        assert terminal["problem"]["effect_disposition"] == "none"
    else:
        assert len(child_posts) == 1 and terminal["problem"]["effect_disposition"] == "known"
        assert child["effect_disposition"] == "known" and child["state"] == "completed"
        assert parent.store.usage(terminal["task_id"])["tool_calls"] == 1
        assert bool(control_reads) == (blocked == "revoked")


@pytest.mark.parametrize("mode", ["allowed", "argument", "result", "credential"])
async def test_connector_content_policy_preserves_source_receipts(services, tmp_path, mode):
    from .test_source_outcomes import read_workflow, register_read

    raw = documents(tmp_path)
    register_read(raw)
    direction = "request" if mode == "argument" else "response"
    if mode != "credential":
        configure_inspection(raw, "connectors", direction)
    connector_calls = []
    gateway_calls = []

    async def gateway(request):
        body = json.loads(request.content)
        gateway_calls.append(body["content"])
        return verdict(body, verdict="permit" if mode == "allowed" else "hard_deny")

    client, app = await services(
        raw=raw,
        runtime=FakeRuntime(read_workflow),
        inspection_transport=httpx.MockTransport(gateway),
    )
    c = app.state.coordinator
    connector, _ = c.broker.operations["documents.read"]

    async def source(name, arguments, _seconds):
        connector_calls.append((name, arguments))
        return {"text": "test-model-key" if mode == "credential" else "controlled source text"}

    connector.call = source
    body = await task_request(
        client,
        app,
        profile="documents.read",
        inputs={"collection": "lasa-docs", "document_id": "guide.md"},
    )
    task = await settled(client, await submit(client, app, body))
    if mode == "allowed":
        assert task["status"] == "completed"
        result = task["result"]
        assert result["output"]["content"] == "controlled source text"
        (manifest,) = result["artifacts"]
        assert manifest["provenance"]["operation_id"] == "source-read"
        assert manifest["digest"] == digest({"text": "controlled source text"})
        assert c.store.usage(task["task_id"])["tool_calls"] == 1
    else:
        assert task["problem"]["code"] == "disclosure_denied"
        assert not c.store.db.execute("SELECT content FROM artifacts").fetchall()
        assert c.store.usage(task["task_id"])["tool_calls"] == int(mode != "argument")
    assert len(connector_calls) == int(mode != "argument")
    assert len(gateway_calls) == int(mode != "credential")


@pytest.mark.parametrize("permitted_intake", [False, True])
async def test_delegated_trace_inherits_peer_class_before_result_intake(
    services, tmp_path, permitted_intake
):
    from lasa_service.capabilities import instant

    peer_service = "https://identity.example.net/services/source-peer"
    source = "peer:" + peer_service
    raw = documents(tmp_path)
    path = policy_for(raw)
    policy = json.loads(path.read_text())
    policy["content_disclosure"] = {
        "source_classes": {source: ["restricted"]},
        "destinations": {source: ["unknown", "restricted"]} if permitted_intake else {},
    }
    policy["principals"][0]["rules"][0]["content_diagnostics"] = True
    path.write_text(json.dumps(policy))
    client, app = await services(raw=raw)
    body = await task_request(client, app)
    body["diagnostics"] = "content"
    request = await submit(client, app, body)
    task = await settled(client, request)
    c = app.state.coordinator
    child = {
        "delegation_id": "delegation-fixture",
        "state": "executing",
        "service_id": peer_service,
        "parent_task_id": task["task_id"],
        "task_id": "task-child",
    }
    c.store.save_child(child)
    events = [
        {
            "event_id": "event-fixture",
            "task_id": child["task_id"],
            "service_id": peer_service,
            "sequence": 1,
            "timestamp": instant(),
            "causal_parent_event_id": None,
            "kind": "call",
            "redacted": True,
            "payload": {
                "operation_id": "operation-fixture",
                "call_type": "model",
                "phase": "finished",
                "input_digest": digest({}),
                "input_bytes": 2,
                "output_digest": None,
                "output_bytes": 0,
                "reserved": c.store.usage(child["task_id"]),
                "usage": c.store.usage(child["task_id"]),
                "payload_truncated": False,
            },
            "content": {"media_type": "application/json", "text": "restricted trace payload"},
        }
    ]

    async def trace(_child, _after):
        return {"task_id": "task-child", "next_sequence": 2, "events": events}, 200, {}

    c.delegation.child_trace = trace
    result = await client.get(request.headers["Location"] + "/delegations")
    reply = result.json()["children"][0]
    assert reply["state"] == "executing" and reply["service_id"] == peer_service
    assert reply["trace"]["events"][0]["payload"]["operation_id"] == "operation-fixture"
    assert "restricted trace payload" not in result.text
    denied = [event for event in audit_events(c) if event["reason_code"] == "content_class_denied"]
    assert [event["channel"] for event in denied] == [
        "caller.response" if permitted_intake else "delegation.response"
    ]


async def test_compaction_keeps_opaque_state_on_the_issuing_model_route(services, tmp_path):
    raw = documents(tmp_path)
    configure_inspection(raw, "model", "request")
    configure_inspection(raw, "model", "response")
    urls = []
    projections = []

    async def provider(request):
        urls.append(request.url.path)
        return httpx.Response(
            200,
            json={
                "output": [{"type": "compaction", "encrypted_content": "opaque-fixture"}],
                "usage": {"total_tokens": 10},
            },
        )

    async def scanner(request):
        body = json.loads(request.content)
        projections.append(body["content"])
        return verdict(body)

    async def execute(context):
        from lasa_service.errors import LasaError

        c = context.coordinator

        async def compact(items):
            return await c.model_client.exchange(
                context.task_id,
                c.config.executor(),
                {"input": items},
                "compaction",
                worker=True,
                suffix="/responses/compact",
            )

        with pytest.raises(LasaError, match="disclosure_denied"):
            await compact([{"type": "compaction", "encrypted_content": "unissued-state"}])
        issued = await compact([])
        await compact(issued.value["output"])
        return await FakeRuntime().run(context)

    client, app = await services(
        raw=raw,
        runtime=FakeRuntime(execute),
        model_transport=httpx.MockTransport(provider),
        inspection_transport=httpx.MockTransport(scanner),
    )
    body = await task_request(client, app)
    body["requested_limits"]["budget"]["model_tokens"] = 48000
    task = await settled(client, await submit(client, app, body))
    assert task["status"] == "completed"
    assert urls == ["/v1/responses/compact"] * 2
    assert projections == [{"input": []}, {"output": []}] * 2
