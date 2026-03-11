"""Transport integration tests using real MCP client transports.

These tests exercise the repository's supported transport entry points against
live local servers without mocking:
- streamable-http via the official MCP Python SDK client
- stdio via the official MCP Python SDK stdio client and this repo's stdio bridge
- sse transport flag via the repo's HTTP server mode using real MCP HTTP requests
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import time

from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

from agentdecompile_cli.executor import normalize_backend_url
from agentdecompile_cli.mcp_server.providers import project as project_provider_module
from agentdecompile_cli.mcp_server.providers.project import ProjectToolProvider
from agentdecompile_cli.mcp_server.session_context import SESSION_CONTEXTS
from agentdecompile_cli.mcp_server.server import PythonMcpServer, ServerConfig


REPO_ROOT = Path(__file__).resolve().parents[1]
HTTP_TIMEOUT = 30.0


@pytest.mark.parametrize(
    ("raw_url", "expected_url"),
    [
        ("http://127.0.0.1:8080", "http://127.0.0.1:8080/mcp/message"),
        ("http://127.0.0.1:8080/mcp", "http://127.0.0.1:8080/mcp"),
        ("http://127.0.0.1:8080/mcp/", "http://127.0.0.1:8080/mcp"),
        ("http://127.0.0.1:8080/mcp/message", "http://127.0.0.1:8080/mcp/message"),
    ],
)
def test_normalize_backend_url_accepts_supported_mcp_paths(raw_url: str, expected_url: str) -> None:
    assert normalize_backend_url(raw_url) == expected_url


@pytest.mark.asyncio
async def test_list_project_files_bootstraps_shared_listing_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    session_id = "test-shared-list-bootstrap"
    provider = ProjectToolProvider()
    SESSION_CONTEXTS.set_project_binaries(session_id, [])

    monkeypatch.setattr(project_provider_module, "get_current_mcp_session_id", lambda: session_id)
    monkeypatch.setenv("AGENT_DECOMPILE_GHIDRA_SERVER_HOST", "170.9.241.140")
    monkeypatch.setenv("AGENT_DECOMPILE_GHIDRA_SERVER_PORT", "13100")
    monkeypatch.setenv("AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME", "OpenKotOR")
    monkeypatch.setenv("AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD", "idekanymore")
    monkeypatch.setenv("AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY", "Odyssey")

    async def _fake_connect(args: dict[str, Any]) -> list[Any]:
        assert args["serverhost"] == "170.9.241.140"
        assert str(args["serverport"]) == "13100"
        assert args["serverusername"] == "OpenKotOR"
        assert args["serverpassword"] == "idekanymore"
        assert args["path"] == "Odyssey"
        SESSION_CONTEXTS.set_project_binaries(
            session_id,
            [{"name": "k1_win_gog_swkotor.exe", "path": "/K1/k1_win_gog_swkotor.exe", "type": "Program"}],
        )
        return []

    monkeypatch.setattr(provider, "_handle_connect_shared_project", _fake_connect)

    response = await provider._handle_list({})
    payload = json.loads(response[0].text)

    assert payload["source"] == "shared-server-session"
    assert payload["count"] == 1
    assert payload["files"][0]["path"] == "/K1/k1_win_gog_swkotor.exe"


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_health(base_url: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(f"{base_url}/health", timeout=1.0)
            if resp.status_code == 200:
                return
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout):
            pass
        time.sleep(0.2)
    raise RuntimeError(f"Server at {base_url} did not become healthy within {timeout}s")


def _stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


@pytest.fixture()
def backend_server():
    port = _find_free_port()
    server = PythonMcpServer(ServerConfig(host="127.0.0.1", port=port))
    server.start()
    base_url = f"http://127.0.0.1:{port}"
    _wait_for_health(base_url)
    yield base_url


def _extract_text_blocks(result: Any) -> str:
    content = getattr(result, "content", []) or []
    texts: list[str] = []
    for item in content:
        text = getattr(item, "text", None)
        if isinstance(text, str):
            texts.append(text)
    return "\n".join(texts)


@pytest.mark.asyncio
async def test_streamable_http_sdk_client_lists_tools_resources_and_calls_tool(backend_server: str) -> None:
    async with streamable_http_client(f"{backend_server}/mcp") as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            tools = await session.list_tools()
            tool_names = {tool.name for tool in tools.tools}
            assert "execute-script" in tool_names or "execute_script" in tool_names
            assert "list-project-files" in tool_names or "list_project_files" in tool_names

            resources = await session.list_resources()
            resource_uris = {str(resource.uri) for resource in resources.resources}
            assert "ghidra://programs" in resource_uris
            assert "ghidra://static-analysis-results" in resource_uris
            assert "ghidra://agentdecompile-debug-info" in resource_uris

            resource = await session.read_resource("ghidra://programs")
            resource_texts = [getattr(content, "text", "") for content in resource.contents]
            programs_payload = json.loads("\n".join(t for t in resource_texts if t))
            assert "programs" in programs_payload

            result = await session.call_tool("execute-script", arguments={"code": "__result__ = 42", "format": "json"})
            result_payload = json.loads(_extract_text_blocks(result))
            assert result_payload["success"] is True
            assert result_payload["result"] == "42"


@pytest.mark.asyncio
async def test_stdio_sdk_client_lists_tools_resources_and_calls_tool(backend_server: str) -> None:
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-c",
            "from agentdecompile_cli.server import proxy_main; proxy_main()",
            "--backend-url",
            backend_server,
            "-t",
            "stdio",
        ],
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )

    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            tools = await session.list_tools()
            tool_names = {tool.name for tool in tools.tools}
            assert "execute-script" in tool_names or "execute_script" in tool_names

            resources = await session.list_resources()
            resource_uris = {str(resource.uri) for resource in resources.resources}
            assert "ghidra://programs" in resource_uris

            result = await session.call_tool("execute-script", arguments={"code": "__result__ = 'stdio_ok'", "format": "json"})
            result_payload = json.loads(_extract_text_blocks(result))
            assert result_payload["success"] is True
            assert result_payload["result"] == "stdio_ok"


def test_sse_transport_mode_serves_tools_resources_and_tool_calls(backend_server: str) -> None:
    port = _find_free_port()
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "from agentdecompile_cli.server import proxy_main; proxy_main()",
            "--backend-url",
            backend_server,
            "-t",
            "sse",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )

    sse_base_url = f"http://127.0.0.1:{port}"
    try:
        _wait_for_health(sse_base_url)
        headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}

        init_resp = httpx.post(
            f"{sse_base_url}/mcp/",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "pytest-sse-transport", "version": "1.0"},
                },
            },
            headers=headers,
            timeout=HTTP_TIMEOUT,
        )
        assert init_resp.status_code == 200
        session_id = init_resp.headers.get("mcp-session-id", "")
        session_headers = dict(headers)
        if session_id:
            session_headers["Mcp-Session-Id"] = session_id

        tools_resp = httpx.post(
            f"{sse_base_url}/mcp/",
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            headers=session_headers,
            timeout=HTTP_TIMEOUT,
        )
        assert tools_resp.status_code == 200
        tool_names = {tool["name"] for tool in tools_resp.json()["result"]["tools"]}
        assert "execute-script" in tool_names or "execute_script" in tool_names

        resource_resp = httpx.post(
            f"{sse_base_url}/mcp/",
            json={"jsonrpc": "2.0", "id": 3, "method": "resources/read", "params": {"uri": "ghidra://programs"}},
            headers=session_headers,
            timeout=HTTP_TIMEOUT,
        )
        assert resource_resp.status_code == 200
        resource_payload = json.loads(resource_resp.json()["result"]["contents"][0]["text"])
        assert "programs" in resource_payload

        tool_resp = httpx.post(
            f"{sse_base_url}/mcp/",
            json={
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "execute-script",
                    "arguments": {"code": "__result__ = 'sse_mode_ok'", "format": "json"},
                },
            },
            headers=session_headers,
            timeout=HTTP_TIMEOUT,
        )
        assert tool_resp.status_code == 200
        tool_payload = json.loads(tool_resp.json()["result"]["content"][0]["text"])
        assert tool_payload["success"] is True
        assert tool_payload["result"] == "sse_mode_ok"
    finally:
        _stop_process(process)