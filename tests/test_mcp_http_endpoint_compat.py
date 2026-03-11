from __future__ import annotations

import pytest

from starlette.testclient import TestClient

from agentdecompile_cli.mcp_server.proxy_server import (
    AgentDecompileMcpProxyServer,
    ProxyServerConfig,
)
from agentdecompile_cli.mcp_server.server import PythonMcpServer

pytestmark = pytest.mark.unit


def _initialize_payload() -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "pytest", "version": "1.0"},
        },
    }


def _assert_initialize_ok(client: TestClient, path: str) -> None:
    response = client.post(
        path,
        json=_initialize_payload(),
        headers={"Accept": "application/json, text/event-stream"},
    )
    assert response.status_code == 200, f"{path} returned {response.status_code}: {response.text}"
    body = response.json()
    assert body["jsonrpc"] == "2.0"
    assert body["id"] == 1
    assert body["result"]["serverInfo"]["name"] == "AgentDecompile"


def test_python_server_accepts_root_and_mcp_compat_paths() -> None:
    server = PythonMcpServer()
    with TestClient(server.app) as client:
        root = client.get("/")
        assert root.status_code == 200
        assert root.json()["docs"]["swagger_ui"] == "/docs"
        _assert_initialize_ok(client, "/mcp")
        _assert_initialize_ok(client, "/mcp/message")
        _assert_initialize_ok(client, "/mcp/message/")

        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["server"] == "AgentDecompile"


def test_proxy_server_accepts_root_and_mcp_compat_paths() -> None:
    proxy = AgentDecompileMcpProxyServer(
        ProxyServerConfig(
            host="127.0.0.1",
            port=18080,
            backend_url="http://127.0.0.1:8080/mcp/message",
        )
    )
    with TestClient(proxy.app) as client:
        root = client.get("/")
        assert root.status_code == 200
        assert root.json()["docs"]["swagger_ui"] == "/docs"
        _assert_initialize_ok(client, "/mcp")
        _assert_initialize_ok(client, "/mcp/message")
        _assert_initialize_ok(client, "/mcp/message/")

        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["mode"] == "proxy"


def test_python_server_openapi_advertises_mcp_routes() -> None:
    server = PythonMcpServer()
    with TestClient(server.app) as client:
        reference_response = client.get("/api/reference")
        assert reference_response.status_code == 200

        response = client.get("/openapi.json")
        assert response.status_code == 200
        openapi = response.json()
        paths = openapi["paths"]
        assert "/" in paths
        assert "/api/reference" in paths
        assert "/api/tool-reference" in paths
        assert "/api/usage-examples" in paths
        assert "/mcp" in paths
        assert "/mcp/message" in paths
        mcp_post = paths["/mcp"]["post"]
        assert "requestBody" in mcp_post
        assert "application/json" in mcp_post["requestBody"]["content"]


def test_proxy_server_openapi_advertises_mcp_routes() -> None:
    proxy = AgentDecompileMcpProxyServer(
        ProxyServerConfig(
            host="127.0.0.1",
            port=18080,
            backend_url="http://127.0.0.1:8080/mcp/message",
        )
    )
    with TestClient(proxy.app) as client:
        reference_response = client.get("/api/reference")
        assert reference_response.status_code == 200

        response = client.get("/openapi.json")
        assert response.status_code == 200
        openapi = response.json()
        paths = openapi["paths"]
        assert "/" in paths
        assert "/api/reference" in paths
        assert "/mcp" in paths
        assert "/mcp/message" in paths
        mcp_post = paths["/mcp"]["post"]
        assert "requestBody" in mcp_post
        assert "application/json" in mcp_post["requestBody"]["content"]
