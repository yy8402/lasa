"""Discovery leases may expire during bounded planning without widening task pins."""

import json
import time
from pathlib import Path

import httpx
import pytest

from lasa_service.capabilities import instant
from lasa_service.contracts import digest

from .conftest import deterministic_planner, documents, settled, submit, task_request


def expire(publication):
    for snapshot in publication.snapshots.values():
        snapshot["valid_until"] = instant(time.time() - 1)
        for offer in snapshot["offers"]:
            offer["valid_until"] = snapshot["valid_until"]


@pytest.mark.parametrize("change", ["lease", "widened-policy", "withdrawal"])
async def test_received_selection_survives_lease_only_and_keeps_original_terms(services, change):
    async def planning(c, task_id, request, catalog, requirements):
        expire(c.publication)
        if change == "widened-policy":
            path = Path(c.config.document["authorization"]["policy_file"])
            policy = json.loads(path.read_text())
            policy["principals"][0]["rules"][0]["effects"].append("external.read")
            path.write_text(json.dumps(policy))
        elif change == "withdrawal":
            c.config.document["published_contracts"] = []
        return await deterministic_planner(c, task_id, request, catalog, requirements)

    client, app = await services(planner=planning)
    request = await task_request(client, app)
    result = await settled(client, await submit(client, app, request))
    assert result["selection"] == request["selection"]
    if change == "lease":
        assert result["status"] == "completed", result
        assert (
            app.state.coordinator.authority(result["task_id"])["selected_offer"]["revision"]
            == request["selection"]["offer_revision"]
        )
    else:
        assert result["status"] == "rejected" and result["problem"]["code"] == "offer_changed"
        assert not app.state.coordinator.runtime.prompts


@pytest.mark.parametrize("changed_terms", [False, True])
async def test_peer_freshness_after_planning_and_before_dispatch_is_bounded(
    services, tmp_path, changed_terms
):
    child_raw = documents(tmp_path / "child", "layer2")
    _, child_app = await services(raw=child_raw)
    child = child_app.state.coordinator
    proposals = []
    admitted_revisions = []

    async def planning(c, task_id, request, catalog, requirements):
        proposals.append(catalog)
        expire(c.publication)
        expire(child.publication)
        return await deterministic_planner(c, task_id, request, catalog, requirements)

    raw = documents(tmp_path / "parent", peer=True)
    raw["routing"]["preferred_executor"] = "peer"
    client, app = await services(
        raw=raw, planner=planning, peer_transport=httpx.ASGITransport(app=child_app)
    )

    async def plan_check(task_id, request, private_plan):
        (routes,) = private_plan["offers"].values()
        admitted_revisions.append(routes[0]["offer"]["revision"])
        expire(child.publication)
        if changed_terms:
            path = Path(child_raw["authorization"]["policy_file"])
            policy = json.loads(path.read_text())
            next(p for p in policy["principals"] if p["kind"] == "peer")["rules"][0][
                "effects"
            ].append("external.read")
            path.write_text(json.dumps(policy))
        return True

    app.state.coordinator.planner.verify_plan = plan_check
    result = await settled(client, await submit(client, app, await task_request(client, app)))
    assert len(proposals) == 1
    assert all(key == digest(definition) for key, definition in proposals[0].items())
    children = app.state.coordinator.store.children(result["task_id"])
    if changed_terms:
        assert result["status"] == "failed" and result["problem"]["code"] == "offer_changed"
        assert not children
    else:
        assert result["status"] == "completed" and len(children) == 1, result
        assert children[0]["request"]["selection"]["offer_revision"] != admitted_revisions[0]
