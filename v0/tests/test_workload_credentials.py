"""A long-running peer client uses refreshed private workload credentials."""

import httpx

from lasa_service.peer import PeerClient

from .conftest import configuration, documents


async def test_peer_rereads_rotated_token_for_discovery_and_task_requests(tmp_path):
    token_file = tmp_path / "workload-token.txt"
    token_file.write_text("first-private-token")
    raw = documents(tmp_path, peer=True)
    raw["peer"]["credential_ref"] = "file:" + str(token_file)
    received = []

    async def receiver(request):
        received.append(request.headers["Authorization"])
        return httpx.Response(200, json={})

    peer = PeerClient(configuration(raw), transport=httpx.MockTransport(receiver))
    await peer.start()
    try:
        url = raw["peer"]["descriptor_url"]
        await peer.get(url)
        token_file.write_text("refreshed-private-token")
        await peer.get(url, refresh=True)
        await peer.request("POST", raw["peer"]["allowed_base_url"] + "/sessions", {})
        assert received == [
            "Bearer first-private-token",
            "Bearer refreshed-private-token",
            "Bearer refreshed-private-token",
        ]
    finally:
        await peer.close()
