"""Deterministic read-only connector fixture using the standard stdio protocol."""

import json
import os
import sys

INPUT = {
    "type": "object",
    "properties": {"report_id": {"type": "string", "maxLength": 128}},
    "required": ["report_id"],
    "additionalProperties": False,
}
OUTPUT = {
    "type": "object",
    "properties": {"text": {"type": "string", "maxLength": 65536}},
    "required": ["text"],
    "additionalProperties": False,
}

if "--optional-note" in sys.argv:
    INPUT["properties"]["note"] = {"type": "string"}
if "--required-with-report" in sys.argv:
    INPUT["dependentRequired"] = {"report_id": ["note"]}

for line in sys.stdin:
    request = json.loads(line)
    if "id" not in request:
        continue
    method = request["method"]
    if method == "initialize":
        result = {
            "protocolVersion": request["params"]["protocolVersion"],
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "test-reports", "version": "1"},
        }
    elif method == "tools/list":
        result = {
            "tools": [{"name": "inspect_report", "inputSchema": INPUT, "outputSchema": OUTPUT}]
        }
    elif method == "tools/call":
        identifier = request["params"]["arguments"]["report_id"]
        value = {
            "text": "x" * 50000
            if identifier == "large"
            else os.environ.get("REPORT_PREFIX", "Report ") + identifier
        }
        result = {
            "content": [{"type": "text", "text": json.dumps(value)}],
            "structuredContent": value,
        }
    elif method == "ping":
        result = {}
    else:
        result = {}
    print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)
