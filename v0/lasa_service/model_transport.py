"""Single supervisor-owned transport for bounded model requests and responses."""

import asyncio
import re
import time
from dataclasses import dataclass

import httpx

from .capabilities import require
from .content_security import Transfer
from .contracts import canonical, parse_json
from .errors import LasaError
from .store import identity


class EventStream:
    """Read complete SSE data frames across arbitrary transport chunks."""

    line_end = re.compile(rb"\r\n?|\n")

    def __init__(self):
        self.partial = bytearray()
        self.data = []
        self.trailing_cr = False
        self.first_line = True

    def feed(self, chunk):
        if not chunk:
            return
        start = int(self.trailing_cr and chunk.startswith(b"\n"))
        self.trailing_cr = chunk.endswith(b"\r")
        for separator in self.line_end.finditer(chunk, start):
            self.partial.extend(chunk[start : separator.start()])
            start = separator.end()
            line = self.partial
            self.partial = bytearray()
            if self.first_line:
                line = line.removeprefix(b"\xef\xbb\xbf")
                self.first_line = False
            if line.startswith(b"data:"):
                self.data.append(bytes(line[5:]).removeprefix(b" "))
            elif not line and self.data:
                yield b"\n".join(self.data)
                self.data.clear()
        self.partial.extend(chunk[start:])


VISIBLE_ITEMS = {"message", "function_call", "custom_tool_call", "tool_search_call"}
STREAM_FIELDS = {
    "response.output_text": "text",
    "response.refusal": "refusal",
    "response.function_call_arguments": "arguments",
    "response.custom_tool_call_input": "input",
}
DELTA_EVENTS = {kind + ".delta" for kind in STREAM_FIELDS}
ITEM_FIELDS = {
    "message": {"role", "content"},
    "function_call": {"name", "call_id", "arguments"},
    "custom_tool_call": {"name", "call_id", "input"},
    "reasoning": {"summary", "content", "encrypted_content"},
    "compaction": {"encrypted_content"},
    "tool_search_call": {"arguments", "call_id", "execution"},
}
PART_FIELDS = {
    "output_text": {"text", "annotations", "logprobs"},
    "refusal": {"refusal"},
}
SSE_EVENTS = DELTA_EVENTS | {
    "response.created",
    "response.in_progress",
    "response.completed",
    "response.output_item.added",
    "response.output_item.done",
    "response.content_part.added",
    "response.content_part.done",
    "response.output_text.done",
    "response.refusal.done",
    "response.function_call_arguments.done",
    "response.custom_tool_call_input.done",
    "response.reasoning_summary_part.added",
    "response.reasoning_summary_part.done",
    "response.reasoning_summary_text.delta",
    "response.reasoning_summary_text.done",
    "response.reasoning_text.delta",
    "response.reasoning_text.done",
}


def visible_items(value):
    output = value.get("output", [])
    require(
        isinstance(output, list) and all(isinstance(item, dict) for item in output),
        "verification_failed",
        502,
    )
    return [item for item in output if item.get("type") in VISIBLE_ITEMS]


def request_projection(body):
    return {
        "input": [
            item
            for item in body.get("input", [])
            if isinstance(item, dict)
            and (
                item.get("role") == "user"
                or item.get("type") in {"function_call_output", "custom_tool_call_output"}
            )
        ]
    }


def opaque_fields(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "encrypted_content" and isinstance(item, str):
                yield item
            else:
                yield from opaque_fields(item)
    elif isinstance(value, list):
        for item in value:
            yield from opaque_fields(item)


@dataclass(frozen=True)
class ModelResponse:
    value: dict
    body: bytes
    media_type: str
    projection: dict
    inspected: object


def fields(value, keys):
    require(isinstance(value, dict), "verification_failed", 502)
    return {key: value[key] for key in keys if key in value}


def protocol_part(value):
    kind = fields(value, {"type"}).get("type")
    require(isinstance(kind, str) and kind in PART_FIELDS, "verification_failed", 502)
    return fields(value, PART_FIELDS[kind] | {"type"})


def protocol_item(value):
    kind = fields(value, {"type"}).get("type")
    require(isinstance(kind, str) and kind in ITEM_FIELDS, "verification_failed", 502)
    item = fields(value, ITEM_FIELDS[kind] | {"id", "type", "status"})
    if kind == "message":
        require(item.get("role", "assistant") == "assistant", "verification_failed", 502)
        require(isinstance(item.get("content", []), list), "verification_failed", 502)
        item["content"] = [protocol_part(part) for part in item.get("content", [])]
    return item


def protocol_response(value):
    response = fields(value, {"id", "object", "created_at", "status", "model", "usage", "output"})
    output = response.get("output", [])
    require(isinstance(output, list), "verification_failed", 502)
    response["output"] = [protocol_item(item) for item in output]
    return response


def indexed(values, index):
    require(type(index) is int and 0 <= index < len(values), "verification_failed", 502)
    return values[index]


def prefix_matches(partial, final, key=""):
    if isinstance(partial, dict) and isinstance(final, dict):
        return all(
            item == "status" or (item in final and prefix_matches(val, final[item], item))
            for item, val in partial.items()
        )
    if isinstance(partial, list) and isinstance(final, list):
        return len(partial) <= len(final) and all(
            prefix_matches(a, b, key) for a, b in zip(partial, final, strict=False)
        )
    if key in {"text", "refusal", "arguments", "input"} and isinstance(final, str):
        return isinstance(partial, str) and final.startswith(partial)
    return partial == final


def checked_frames(events, completed):
    output = completed["output"]
    deltas = {}
    projected = []
    approved = []
    for raw in events:
        kind = raw["type"]
        event = fields(raw, {"type", "sequence_number"})
        if kind in {"response.created", "response.in_progress", "response.completed"}:
            response = protocol_response(raw.get("response"))
            require(prefix_matches(response["output"], output), "verification_failed", 502)
            event["response"] = response
            projected.extend(visible_items(response))
        else:
            event.update(fields(raw, {"item_id", "output_index", "content_index", "summary_index"}))
            item = indexed(output, event.get("output_index"))
            require(
                "item_id" not in event or event["item_id"] == item.get("id"),
                "verification_failed",
                502,
            )
            if kind in {"response.output_item.added", "response.output_item.done"}:
                seen = protocol_item(raw.get("item"))
                matches = prefix_matches(seen, item) if kind.endswith(".added") else seen == item
                require(matches, "verification_failed", 502)
                event["item"] = seen
                if item["type"] in VISIBLE_ITEMS:
                    projected.append(seen)
            elif kind.startswith("response.content_part."):
                part = indexed(item.get("content", []), event.get("content_index"))
                seen = protocol_part(raw.get("part"))
                matches = prefix_matches(seen, part) if kind.endswith(".added") else seen == part
                require(matches, "verification_failed", 502)
                event["part"] = seen
                projected.append(seen)
            elif (prefix := kind.rsplit(".", 1)[0]) in STREAM_FIELDS:
                key = STREAM_FIELDS[prefix]
                field = "delta" if kind in DELTA_EVENTS else key
                final = item
                if key in {"text", "refusal"}:
                    final = indexed(item.get("content", []), event.get("content_index"))
                value = raw.get(field)
                require(
                    isinstance(value, str) and isinstance(final.get(key), str),
                    "verification_failed",
                    502,
                )
                event[field] = value
                if field == "delta":
                    position = (prefix, event["output_index"], event.get("content_index"))
                    deltas.setdefault(position, ([], final[key]))[0].append(value)
                else:
                    require(value == final[key], "verification_failed", 502)
            else:
                require(item["type"] == "reasoning", "verification_failed", 502)
                event.update(fields(raw, {"part", "delta", "text"}))
        approved.append(event)
    assembled = ["".join(parts) for parts, _ in deltas.values()]
    require(
        all(text == final for text, (_, final) in zip(assembled, deltas.values(), strict=True)),
        "verification_failed",
        502,
    )
    return approved, {"output": projected, "deltas": assembled}


def decode_sse(raw):
    parser = EventStream()
    events = []
    completed = None
    done_marker = False
    for data in parser.feed(raw):
        require(not done_marker, "verification_failed", 502)
        if data == b"[DONE]":
            require(completed is not None, "verification_failed", 502)
            done_marker = True
            continue
        event = parse_json(data)
        kind = fields(event, {"type"}).get("type")
        require(
            isinstance(kind, str) and kind in SSE_EVENTS and completed is None,
            "verification_failed",
            502,
        )
        if kind == "response.completed":
            completed = protocol_response(event.get("response"))
            require(completed.get("status") == "completed", "verification_failed", 502)
        events.append(event)
    require(
        not parser.partial and not parser.data and completed is not None,
        "verification_failed",
        502,
    )
    approved, projection = checked_frames(events, completed)
    frames = [
        b"event: " + event["type"].encode() + b"\ndata: " + canonical(event) + b"\n\n"
        for event in approved
    ]
    if done_marker:
        frames.append(b"data: [DONE]\n\n")
    return ModelResponse(
        completed,
        b"".join(frames),
        "text/event-stream",
        projection,
        {"events": approved, "assembled_deltas": projection["deltas"]},
    )


def decode_json(raw):
    value = protocol_response(parse_json(raw))
    return ModelResponse(
        value,
        canonical(value),
        "application/json",
        {"output": visible_items(value)},
        value,
    )


class ModelTransport:
    def __init__(self, coordinator, transport):
        self.c = coordinator
        self.clients = {
            executor["id"]: httpx.AsyncClient(
                verify=coordinator.config.provider_verify(executor),
                transport=transport,
                trust_env=False,
                follow_redirects=False,
            )
            for executor in coordinator.config.document["executors"]
        }
        self.opaque = {}

    async def close(self):
        await asyncio.gather(*(client.aclose() for client in self.clients.values()))

    def forget(self, task_id):
        self.opaque.pop(task_id, None)

    async def exchange(
        self,
        task_id,
        executor,
        body,
        purpose,
        *,
        suffix="/responses",
        worker=False,
        revise=None,
        input_revision=None,
    ):
        c = self.c
        operation = identity("model")
        source = c.request(task_id)["selection"]["contract"]["id"]
        destination = "model:" + executor["id"]
        opaque = self.opaque.setdefault(task_id, {}).setdefault(destination, set())
        require(set(opaque_fields(body)) <= opaque, "disclosure_denied", 403)
        body, outgoing = await c.content.check_request(
            Transfer("reasoning.request", destination, purpose, operation, task_id, source),
            body,
            project=request_projection,
            revise=revise,
            remaining=lambda: c.remaining_seconds(task_id),
        )
        c.check_active(task_id, evaluating=not worker)
        c.begin_model(task_id, operation, body, purpose)
        started = time.monotonic()
        try:
            async with asyncio.timeout(c.remaining_seconds(task_id, operation_id=operation)):
                media_type, raw = await self.fetch(executor, suffix, body, worker)
        except TimeoutError:
            c.content.outcome(outgoing, "delivery_unknown")
            raise LasaError("deadline_exceeded", 422) from None
        except httpx.HTTPError:
            c.content.outcome(outgoing, "delivery_unknown")
            raise LasaError("peer_unavailable", 503, retry="readmission") from None
        except LasaError:
            c.content.outcome(outgoing, "delivered")
            raise
        except asyncio.CancelledError:
            c.content.outcome(outgoing, "delivery_unknown")
            raise
        if input_revision is not None and outgoing["candidate_revision"] == 1:
            with c.store.transaction():
                c.content.outcome(outgoing, "delivered")
                c.content.record(
                    {
                        **input_revision,
                        "task_id": task_id,
                        "operation_id": operation,
                        "transfer_id": outgoing["transfer_id"],
                        "model_request_digest": outgoing["payload_digest"],
                    },
                    "model_input_revision",
                )
        else:
            c.content.outcome(outgoing, "delivered")
        result = decode_sse(raw) if media_type == "text/event-stream" else decode_json(raw)
        incoming = Transfer("reasoning.response", destination, purpose, operation, task_id, source)
        elapsed = int((time.monotonic() - started) * 1000)
        try:
            decision = await c.content.check(
                incoming,
                result.inspected,
                projection=result.projection,
                media_type=media_type,
                remaining=lambda: c.remaining_seconds(task_id, operation_id=operation),
                wire=result.body,
            )
            c.check_active(task_id, evaluating=not worker)
        except (LasaError, asyncio.CancelledError):
            c.finish_model(task_id, operation, result.value.get("usage", {}), elapsed, None)
            raise
        c.finish_model(
            task_id,
            operation,
            result.value.get("usage", {}),
            elapsed,
            {"output": visible_items(result.value)},
        )
        opaque.update(opaque_fields(result.value))
        c.content.outcome(decision, "delivered")
        return result

    async def fetch(self, executor, suffix, body, worker):
        client = self.clients[executor["id"]]
        credential = self.c.config.secret(executor["credential_ref"])
        async with client.stream(
            "POST",
            executor["provider_base_url"].rstrip("/") + suffix,
            content=canonical(body),
            headers={"Authorization": "Bearer " + credential, "Content-Type": "application/json"},
        ) as response:
            require(response.status_code == 200, "peer_unavailable", 503)
            media = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            supported = (
                {"text/event-stream", "application/json"} if worker else {"application/json"}
            )
            require(media in supported, "verification_failed", 502)
            limit = 2097152 if worker else 1048576
            content = bytearray()
            async for chunk in response.aiter_bytes():
                require(len(content) + len(chunk) <= limit, "capacity_exhausted", 429)
                content.extend(chunk)
            return media, bytes(content)
