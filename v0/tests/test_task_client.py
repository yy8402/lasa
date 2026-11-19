import asyncio
import os
import sys
from pathlib import Path

import pytest

from .conftest import documents, token
from .http_helpers import certificate, live_http


@pytest.mark.integration
async def test_runnable_client_uses_target_api_over_real_https(services, tmp_path):
    raw = documents(tmp_path / "service")
    client, app = await services(raw=raw)
    tls = certificate(tmp_path)
    async with live_http(app, tls=tls) as origin:
        c = app.state.coordinator
        prefix = "/prefix/lasa/v1"
        c.config.document["service"].update(
            base_url=origin + prefix, descriptor_url=origin + prefix + "/descriptor"
        )
        env = {**os.environ, "LASA_ACCESS_TOKEN": token(audience=c.config.service_id)}
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            str(Path(__file__).resolve().parents[1] / "run_task.py"),
            "Explain bounded service work.",
            "--base-url",
            origin + prefix,
            "--ca-file",
            str(tls[0]),
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        async with asyncio.timeout(15):
            stdout, stderr = await process.communicate()
        assert process.returncode == 0, stderr.decode()
        assert b'"status": "completed"' in stdout and b'"kind": "routing"' in stdout
        assert env["LASA_ACCESS_TOKEN"].encode() not in stdout
