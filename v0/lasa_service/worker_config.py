"""Codex settings enforced by the host-local launcher."""

DISABLED_FEATURES = (
    "shell_tool",
    "unified_exec",
    "shell_snapshot",
    "apps",
    "hooks",
    "plugins",
    "remote_plugin",
    "recommended_plugins",
    "multi_agent_v2",
    "multi_agent_v2_dynamic_tools",
    "computer_use",
    "browser_use",
    "browser_use_external",
    "code_mode",
    "code_mode_host",
    "image_generation",
    "view_image",
    "skill_mcp_dependency_install",
    "skill_search",
    "memories",
    "sleep_tool",
    "goals",
    "unbounded_connection_retries",
    "workspace_dependencies",
    "api_key_model_discovery",
    "api_key_cyber_access_programs",
    "tool_suggest",
    "incremental_tools",
    "request_permissions_tool",
    "enable_request_compression",
)


def worker_configuration(model):
    return {
        "model": model,
        "model_provider": "lasa",
        "approval_policy": "never",
        "sandbox_mode": "workspace-write",
        "web_search": "disabled",
        "project_doc_max_bytes": 0,
        "cli_auth_credentials_store": "file",
        "features": dict.fromkeys(DISABLED_FEATURES, False),
        "agents": {"enabled": False},
        "analytics": {"enabled": False},
        "sandbox_workspace_write": {"network_access": False},
        "projects": {"/workspace": {"trust_level": "untrusted"}},
        "model_providers": {
            "lasa": {
                "name": "LASA controlled model route",
                "wire_api": "responses",
                "base_url": "http://127.0.0.1:39231/model",
                "env_key": "LASA_LOCAL_MODEL_KEY",
                "request_max_retries": 0,
                "stream_max_retries": 0,
                "supports_websockets": False,
                "requires_openai_auth": False,
                "stream_idle_timeout_ms": 60000,
            }
        },
    }
