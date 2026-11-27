"""Docker commands and shared inputs for the packaged smoke tests."""

import subprocess

MODEL_KEY = "local-responses-fixture"
ISSUER_SECRET = "synthetic-confidential-client-secret"
PORTAL_CLIENT_ID = "test-portal-client"


def docker(*args, timeout=30, check=True):
    result = subprocess.run(
        ["docker", *map(str, args)], capture_output=True, text=True, timeout=timeout, check=False
    )
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    if args[0] == "logs" and result.returncode:
        return ""
    return (result.stdout + result.stderr if args[0] == "logs" else result.stdout).strip()


def mount(source, target=None, *, read_only=True):
    return f"type=bind,source={source},target={target or source}" + (
        ",readonly" if read_only else ""
    )
