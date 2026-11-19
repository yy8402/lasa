import json
import time


def sse_final(text, sequence=1):
    message = {
        "id": f"msg_{sequence}",
        "type": "message",
        "role": "assistant",
        "status": "completed",
        "content": [{"type": "output_text", "text": text, "annotations": []}],
    }
    response = {
        "id": f"resp_{sequence}",
        "object": "response",
        "created_at": int(time.time()),
        "status": "completed",
        "output": [message],
        "usage": {"input_tokens": 10, "output_tokens": 10, "total_tokens": 20},
    }
    events = [
        ("response.created", {"response": {**response, "status": "in_progress", "output": []}}),
        (
            "response.output_item.added",
            {"output_index": 0, "item": {**message, "status": "in_progress", "content": []}},
        ),
        (
            "response.content_part.added",
            {
                "item_id": message["id"],
                "output_index": 0,
                "content_index": 0,
                "part": {"type": "output_text", "text": "", "annotations": []},
            },
        ),
        (
            "response.output_text.delta",
            {"item_id": message["id"], "output_index": 0, "content_index": 0, "delta": text},
        ),
        (
            "response.output_text.done",
            {"item_id": message["id"], "output_index": 0, "content_index": 0, "text": text},
        ),
        ("response.output_item.done", {"output_index": 0, "item": message}),
        ("response.completed", {"response": response}),
    ]
    return "".join(
        f"event: {kind}\ndata: {json.dumps({'type': kind, **payload})}\n\n"
        for kind, payload in events
    ).encode()
