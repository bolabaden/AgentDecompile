from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from agentdecompile_cli.server import _loopback_backend_host
from agentdecompile_cli.webui import WebUiConfig, _webui_enabled, create_app


class FakeBackend:
    async def list_tools(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "search-everything",
                "description": "Search across scopes",
                "inputSchema": {"type": "object", "properties": {"query": {"type": "string", "default": "main"}}},
            }
        ]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return {"content": [{"type": "text", "text": '{"ok": true, "name": "' + name + '"}'}], "isError": False}

    async def list_prompts(self) -> list[dict[str, Any]]:
        return [{"name": "re-scout-broad-sweep", "description": "Scout", "arguments": []}]

    async def list_resources(self) -> list[dict[str, Any]]:
        return [{"name": "Debug Info", "uri": "agentdecompile://debug-info", "description": "Debug", "mimeType": "application/json"}]

    async def read_resource(self, uri: str) -> dict[str, Any]:
        return {"uri": uri, "raw": '{"status": "ok"}', "parsed": {"status": "ok"}}

    async def get_open_programs(self) -> dict[str, Any]:
        return {"/sort.exe": {"name": "sort.exe"}}

    async def close(self) -> None:
        return None


def test_webui_meta_and_docs_hub() -> None:
    app = create_app(WebUiConfig(port=8002), backend=FakeBackend())
    client = TestClient(app)

    meta = client.get("/api/meta")
    assert meta.status_code == 200
    payload = meta.json()
    assert payload["application"]["port"] == 8002
    assert payload["application"]["backendMode"] == "embedded-local"
    assert payload["live"]["advertisedToolCount"] == 1
    assert any(link["title"] == "JFrame" for link in payload["docs"]["swing"])


def test_webui_tool_call_endpoint_parses_result() -> None:
    app = create_app(WebUiConfig(port=8002), backend=FakeBackend())
    client = TestClient(app)

    response = client.post("/api/tools/call", json={"name": "search-everything", "arguments": {"query": "main"}})
    assert response.status_code == 200
    payload = response.json()
    assert payload["tool"] == "search-everything"
    assert payload["parsed"]["ok"] is True


def test_webui_root_serves_html() -> None:
    app = create_app(WebUiConfig(port=8002), backend=FakeBackend())
    client = TestClient(app)

    response = client.get("/")
    assert response.status_code == 200
    assert "AgentDecompile Web UI" in response.text


def test_webui_enabled_honors_falsy_env(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_DECOMPILE_WEBUI_ENABLED", "false")
    assert _webui_enabled() is False


def test_loopback_backend_host_normalizes_wildcards() -> None:
    assert _loopback_backend_host("0.0.0.0") == "127.0.0.1"
    assert _loopback_backend_host("::") == "127.0.0.1"
    assert _loopback_backend_host("127.0.0.1") == "127.0.0.1"