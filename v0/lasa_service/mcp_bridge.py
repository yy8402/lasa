"""Isolated stdio MCP carrier. Only stdlib and task-scoped HTTP are available."""

import json
import os
import sys
import urllib.error
import urllib.request


def main():
    base_url = os.environ["LASA_GATEWAY_URL"]
    token = os.environ["LASA_GATEWAY_TOKEN"]
    timeout = float(os.environ["LASA_GATEWAY_TIMEOUT"])
    protocols = {"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            base_url + path,
            data=data,
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        )
        with opener.open(req, timeout=timeout) as response:
            return json.loads(response.read(2 * 1024 * 1024))

    for line in sys.stdin:
        message = json.loads(line)
        if "id" not in message:
            continue
        method, params = message.get("method"), message.get("params", {})
        try:
            if method == "initialize":
                version = params.get("protocolVersion")
                result = {
                    "protocolVersion": version if version in protocols else "2025-11-25",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "lasa-broker", "version": "1.0.0"},
                }
            elif method == "tools/list":
                result = {"tools": request("/broker/tools")["tools"]}
            elif method == "tools/call":
                value = request(
                    "/broker/call",
                    {
                        "action_id": str(message["id"]),
                        "name": params["name"],
                        "arguments": params.get("arguments", {}),
                    },
                )
                result = {
                    "content": [{"type": "text", "text": json.dumps(value)}],
                    "structuredContent": value,
                    "isError": "error" in value,
                }
            elif method == "ping":
                result = {}
            else:
                raise ValueError("unsupported method")
            response = {"jsonrpc": "2.0", "id": message["id"], "result": result}
        except Exception:
            response = {
                "jsonrpc": "2.0",
                "id": message["id"],
                "error": {"code": -32603, "message": "LASA broker request failed"},
            }
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
