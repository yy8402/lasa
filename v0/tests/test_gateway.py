import pytest

from lasa_service.errors import LasaError
from lasa_service.gateway import EventStream, validate_local_tools


@pytest.mark.parametrize(
    "payload",
    [
        {"tools": [{"type": "web_search"}]},
        {"tools": [{"type": "tool_search", "execution": "server"}]},
        {
            "input": [
                {
                    "role": "user",
                    "content": [
                        {"type": "input_image", "image_url": "https://unapproved.example/private"}
                    ],
                }
            ]
        },
        {"previous_response_id": "another-task-response"},
        {"background": True},
    ],
)
def test_provider_route_performs_only_bounded_inference(payload):
    with pytest.raises(LasaError):
        validate_local_tools(payload)


def test_client_tool_search_is_allowed():
    validate_local_tools(
        {
            "tools": [
                {"type": "tool_search", "execution": "client"},
                {"type": "namespace", "tools": [{"type": "function", "name": "workspace_read"}]},
            ]
        }
    )


@pytest.mark.parametrize("newline", [b"\n", b"\r\n", b"\r"])
def test_sse_frames_accept_split_line_endings_and_join_data(newline):
    stream = EventStream()
    raw = newline.join(
        [b"\xef\xbb\xbf: comment", b"data: {", b'data:  "a": 1}', b"", b"data: [DONE]", b"", b""]
    )
    assert [event for char in raw for event in stream.feed(bytes([char]))] == [
        b'{\n "a": 1}',
        b"[DONE]",
    ]


def test_tool_operation_identity_is_scoped_to_app_server_thread():
    from lasa_service.rpc import tool_operation_id

    assert tool_operation_id("first", "2") == tool_operation_id("first", "2")
    assert tool_operation_id("first", "2") != tool_operation_id("second", "2")
    assert len(tool_operation_id("first", "x" * 128)) <= 128
