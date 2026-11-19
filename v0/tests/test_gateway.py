import pytest

from lasa_service.errors import LasaError
from lasa_service.gateway import validate_local_tools


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


async def test_tool_operation_identity_is_scoped_to_app_server_execution():
    from lasa_service.gateway import TaskGateway

    first = TaskGateway(None)
    second = TaskGateway(None)
    assert first.tool_operation_id("2") == first.tool_operation_id("2")
    assert first.tool_operation_id("2") != second.tool_operation_id("2")
    assert len(first.tool_operation_id("x" * 128)) <= 128
