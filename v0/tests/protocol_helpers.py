import json
import time


def response_events(item, events, sequence):
    response = {
        "id": f"resp_{sequence}",
        "object": "response",
        "created_at": int(time.time()),
        "status": "completed",
        "output": [item],
        "usage": {"input_tokens": 10, "output_tokens": 10, "total_tokens": 20},
    }
    output = [
        ("response.created", {"response": {**response, "status": "in_progress", "output": []}}),
        *events,
        ("response.output_item.done", {"output_index": 0, "item": item}),
        ("response.completed", {"response": response}),
    ]
    return "".join(
        f"event: {kind}\ndata: {json.dumps({'type': kind, **payload})}\n\n"
        for kind, payload in output
    ).encode()


def sse_final(text, sequence=1):
    message = {
        "id": f"msg_{sequence}",
        "type": "message",
        "role": "assistant",
        "status": "completed",
        "content": [{"type": "output_text", "text": text, "annotations": []}],
    }
    events = [
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
    ]
    return response_events(message, events, sequence)


def sse_tool(name, arguments, sequence):
    call = {
        "type": "function_call",
        "id": f"fc_{sequence}",
        "call_id": f"call_{sequence}",
        "name": name,
        "arguments": json.dumps(arguments),
        "status": "completed",
    }
    events = [
        (
            "response.output_item.added",
            {"output_index": 0, "item": {**call, "status": "in_progress", "arguments": ""}},
        ),
        (
            "response.function_call_arguments.delta",
            {"item_id": call["id"], "output_index": 0, "delta": call["arguments"]},
        ),
        (
            "response.function_call_arguments.done",
            {"item_id": call["id"], "output_index": 0, "arguments": call["arguments"]},
        ),
    ]
    return response_events(call, events, sequence)
