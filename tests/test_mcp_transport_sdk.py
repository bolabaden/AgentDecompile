"""Transport integration tests using real MCP client transports.

These tests exercise the repository's supported transport entry points against
live local servers without mocking:
- streamable-http via the official MCP Python SDK client
- stdio via the official MCP Python SDK stdio client and this repo's stdio bridge
- sse transport flag via the repo's HTTP server mode using real MCP HTTP requests
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time

from pathlib import Path
from typing import Any

import click
import httpx
import pytest

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
from pydantic import AnyUrl

import agentdecompile_cli.project_manager as project_manager_module

from agentdecompile_cli import bridge as bridge_module, cli as cli_module
from agentdecompile_cli.bridge import AgentDecompileStdioBridge
from agentdecompile_cli.mcp_server.providers import project as project_provider_module
from agentdecompile_cli.mcp_server.providers.import_export import ImportExportToolProvider
from agentdecompile_cli.mcp_server.providers.project import ProjectToolProvider
from agentdecompile_cli.mcp_server.server import PythonMcpServer, ServerConfig
from agentdecompile_cli.mcp_server.session_context import SESSION_CONTEXTS
from agentdecompile_cli.registry import tool_registry

REPO_ROOT = Path(__file__).resolve().parents[1]
HTTP_TIMEOUT = 30.0


@pytest.mark.unit
def test_raw_mcp_http_backend_headers_keep_cli_persisted_session_id() -> None:
    """Regression: _headers must not drop Mcp-Session-Id from extra_headers when _session_id is unset."""
    from agentdecompile_cli.bridge import RawMcpHttpBackend

    backend = RawMcpHttpBackend(
        "http://127.0.0.1:8080/mcp/message",
        extra_headers={"Mcp-Session-Id": "cli-persisted-abc"},
    )
    assert backend._headers()["Mcp-Session-Id"] == "cli-persisted-abc"
    backend._apply_mcp_session_from_response("server-bound-xyz")
    assert backend._headers()["Mcp-Session-Id"] == "server-bound-xyz"


def test_import_binary_alias_corrections_override_tools_list_alias_pollution() -> None:
    parsed = tool_registry.parse_arguments(
        {
            "path": "/good/input.exe",
            "filePath": "/bad/input.exe",
            "binaryPath": "/worse/input.exe",
            "destFolder": "/imports",
            "recurse": True,
            "depth": 3,
            "autoAnalyze": True,
            "stripPath": True,
            "stripContainer": True,
            "mirror": True,
            "versioning": True,
        },
        "import-binary",
    )

    assert parsed["path"] == "/good/input.exe"
    assert parsed["destinationFolder"] == "/imports"
    assert parsed["recursive"] is True
    assert parsed["maxDepth"] == 3
    assert parsed["analyzeAfterImport"] is True
    assert parsed["stripLeadingPath"] is True
    assert parsed["stripAllContainerPath"] is True
    assert parsed["mirrorFs"] is True
    assert parsed["enableVersionControl"] is True


def test_shared_open_project_creates_missing_requested_repository() -> None:
    provider = ProjectToolProvider()
    created_names: list[str] = []

    class _FakeServerAdapter:
        def createRepository(self, name: str) -> object:
            created_names.append(name)
            return object()

        def getRepository(self, name: str) -> object | None:
            return object() if name in created_names else None

    repository_names, repository_created = provider._ensure_shared_repository_exists(
        server_adapter=_FakeServerAdapter(),
        repository_names=["LocalRepo"],
        requested_repository="MissingRepo",
        auth_provided=True,
        server_host="127.0.0.1",
        server_port=13100,
    )

    assert repository_created is True
    assert created_names == ["MissingRepo"]
    assert repository_names == ["LocalRepo", "MissingRepo"]


@pytest.mark.asyncio
async def test_import_binary_handler_prefers_path_before_filepath(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    provider = ImportExportToolProvider()
    good_path = tmp_path / "good.bin"
    good_path.write_bytes(b"MZ")
    imported_paths: list[Path] = []

    class _FakeProgram:
        def getName(self) -> str:
            return "good.bin"

    class _FakeManager:
        def import_binary(self, item: Path, program_name: str | None = None) -> _FakeProgram:
            imported_paths.append(item)
            return _FakeProgram()

        def cleanup(self) -> None:
            return None

    monkeypatch.setattr(project_manager_module, "ProjectManager", _FakeManager)

    response = await provider._handle_import(
        {
            "path": str(good_path),
            "filePath": str(tmp_path / "missing.bin"),
        }
    )
    payload = json.loads(response[0].text)

    assert payload["success"] is True
    assert imported_paths == [good_path.resolve()]


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


@pytest.mark.asyncio
async def test_list_project_files_returns_shared_server_session_when_handle_is_shared_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With session in shared-server mode and no binaries, list-project-files returns source=shared-server-session."""
    session_id = "test-shared-handle-only"
    monkeypatch.setattr(project_provider_module, "get_current_mcp_session_id", lambda: session_id)

    SESSION_CONTEXTS.set_project_handle(
        session_id,
        {
            "mode": "shared-server",
            "server_host": "ghidra",
            "server_port": 13100,
            "repository_name": "agentrepo",
        },
    )
    SESSION_CONTEXTS.set_project_binaries(session_id, [])

    provider = ProjectToolProvider()
    provider._manager = None

    response = await provider._handle_list({})
    payload = json.loads(response[0].text)

    assert payload.get("source") == "shared-server-session"
    assert payload.get("count") == 0
    assert payload.get("folder") == "/"
    assert "note" in payload


@pytest.mark.asyncio
async def test_open_project_shared_flag_forces_shared_route(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    provider = ProjectToolProvider()
    existing_local_path = tmp_path / "ExistingProject"
    existing_local_path.mkdir()
    monkeypatch.setattr(provider, "_get_shared_server_host", lambda: "127.0.0.1")

    async def _fake_connect(args: dict[str, Any]) -> list[Any]:
        return project_provider_module.create_success_response(
            {"route": "shared", "shared": args.get("shared"), "serverhost": args.get("serverhost")}
        )

    async def _fake_open(args: dict[str, Any]) -> list[Any]:
        return project_provider_module.create_success_response({"route": "local"})

    monkeypatch.setattr(provider, "_handle_connect_shared_project", _fake_connect)
    monkeypatch.setattr(provider, "_handle_open", _fake_open)

    response = await provider._handle_open_project({"path": str(existing_local_path), "shared": True})
    payload = json.loads(response[0].text)

    assert payload["route"] == "shared"
    assert payload["shared"] is True
    assert payload["serverhost"] == "127.0.0.1"


@pytest.mark.asyncio
async def test_svr_admin_runs_with_passthrough_arguments(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    provider = ProjectToolProvider()

    install_dir = tmp_path / "ghidra"
    server_dir = install_dir / "server"
    server_dir.mkdir(parents=True)
    (server_dir / "svrAdmin.bat").write_text("@echo off\n", encoding="utf-8")
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(install_dir))

    observed: dict[str, Any] = {}

    class _Completed:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def _fake_run(cmd: list[str], capture_output: bool, text: bool, timeout: int, check: bool) -> _Completed:
        observed["cmd"] = cmd
        observed["capture_output"] = capture_output
        observed["text"] = text
        observed["timeout"] = timeout
        observed["check"] = check
        return _Completed()

    monkeypatch.setattr(project_provider_module.subprocess, "run", _fake_run)

    response = await provider._handle_svr_admin({"args": ["-list", "-all"], "timeoutseconds": 45})
    payload = json.loads(response[0].text)

    assert payload["success"] is True
    assert payload["action"] == "svr-admin"
    assert payload["argv"] == ["-list", "-all"]
    assert payload["exitCode"] == 0
    assert observed["cmd"][0].endswith("svrAdmin.bat")
    assert observed["cmd"][1:] == ["-list", "-all"]
    assert observed["timeout"] == 45


@pytest.mark.asyncio
async def test_get_current_program_surfaces_stateless_open_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = ProjectToolProvider()

    async def _fake_open(args: dict[str, Any]) -> list[Any]:
        return project_provider_module.create_success_response(
            {"success": False, "error": "Authentication failed for shared repository"}
        )

    monkeypatch.setattr(provider, "_handle_open_project", _fake_open)

    with pytest.raises(project_provider_module.ActionableError, match="Authentication failed for shared repository"):
        await provider._handle_get_current_program({"programpath": "/K1/k1_win_gog_swkotor.exe"})


@pytest.mark.asyncio
async def test_stdio_bridge_forwards_proxy_shared_headers_to_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class _FakeBackend:
        def __init__(self, url: str, *, connect_timeout: float = 0.0, op_timeout: float = 0.0, extra_headers: dict[str, str] | None = None) -> None:
            captured["url"] = url
            captured["extra_headers"] = dict(extra_headers or {})
            self._initialized = False

        async def initialize(self) -> None:
            self._initialized = True

        async def close(self) -> None:
            return None

    monkeypatch.setattr(bridge_module, "RawMcpHttpBackend", _FakeBackend)

    bridge = AgentDecompileStdioBridge("http://127.0.0.1:8080/mcp")
    bridge._set_streamable_http_headers(
        "frontend-session",
        {
            # Proxy must forward client MCP session id so backend reuses the same logical session (see proxy_server _forwardable_shared_headers).
            "mcp-session-id": "cli-persisted-session-abc",
            "X-Ghidra-Server-Host": "170.9.241.140",
            "X-Ghidra-Server-Port": "13100",
            "X-Ghidra-Repository": "Odyssey",
            "X-Agent-Server-Username": "OpenKotOR",
            "X-Agent-Server-Password": "idekanymore",
        },
    )

    await bridge._ensure_backend("frontend-session")

    assert captured["url"] == "http://127.0.0.1:8080/mcp/message"
    assert captured["extra_headers"]["mcp-session-id"] == "cli-persisted-session-abc"
    assert captured["extra_headers"]["X-Ghidra-Server-Host"] == "170.9.241.140"
    assert captured["extra_headers"]["X-Ghidra-Server-Port"] == "13100"
    assert captured["extra_headers"]["X-Ghidra-Repository"] == "Odyssey"
    assert captured["extra_headers"]["X-Agent-Server-Username"] == "OpenKotOR"
    assert captured["extra_headers"]["X-Agent-Server-Password"] == "idekanymore"


def test_import_export_checkout_path_not_resolved_error_copy() -> None:
    """Regression: checkout path-not-resolved must not claim each CLI run is a new session."""
    import_export_path = Path(__file__).resolve().parents[1] / "src/agentdecompile_cli/mcp_server/providers/import_export.py"
    content = import_export_path.read_text(encoding="utf-8")
    assert "Each CLI run uses a new session" not in content
    assert "This server session has no shared project open" in content


@pytest.mark.asyncio
async def test_execute_tool_call_preopens_requested_program_for_get_current_program(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, dict[str, Any]]] = []

    class _FakeClient:
        async def __aenter__(self) -> "_FakeClient":
            return self

        async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
            return None

        async def call_tool(self, name: str, payload: dict[str, Any]) -> dict[str, Any]:
            calls.append((name, dict(payload)))
            if name == "open":
                return {"content": [{"type": "text", "text": json.dumps({"success": True})}], "isError": False}
            if name == "manage_files":
                return {"content": [], "isError": False}
            return {"loaded": True, "name": "swkotor.exe"}

    monkeypatch.setattr(cli_module, "_client", lambda ctx: _FakeClient())
    monkeypatch.setattr(
        cli_module,
        "_shared_server_defaults",
        lambda ctx: {
            "host": "170.9.241.140",
            "port": 13100,
            "username": "OpenKotOR",
            "password": "idekanymore",
            "repository": "Odyssey",
        },
    )

    ctx = click.Context(click.Command("test"), obj={"format": "json", "server_url": "http://170.9.241.140:8080/mcp/"})

    result = await cli_module._execute_tool_call(
        ctx,
        "get_current_program",
        {"programPath": "/K1/k1_win_gog_swkotor.exe", "format": "json"},
    )

    assert result["loaded"] is True
    assert calls[0][0] == "open"
    assert calls[0][1]["path"] == "/K1/k1_win_gog_swkotor.exe"
    assert calls[1][0] == "manage_files"
    assert calls[2][0] == "get_current_program"


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
    async with streamable_http_client(f"{backend_server}/mcp/message") as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            tools = await session.list_tools()
            tool_names = {tool.name for tool in tools.tools}
            assert "execute-script" in tool_names or "execute_script" in tool_names
            assert "list-project-files" in tool_names or "list_project_files" in tool_names

            resources = await session.list_resources()
            resource_uris = {str(resource.uri) for resource in resources.resources}
            assert "agentdecompile://debug-info" in resource_uris

            resource = await session.read_resource(AnyUrl(url="ghidra://programs"))
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
            assert "agentdecompile://debug-info" in resource_uris

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


def test_shared_project_verification_criteria() -> None:
    """Pass/fail criteria used by scripts/verify_shared_project_full.py: shared-server-session in stdout and exit 0."""
    # Same logic as verify_shared_project_full.py (returncode and "shared-server-session" in output)
    def passed(returncode: int, stdout: str) -> bool:
        if returncode != 0:
            return False
        return "shared-server-session" in stdout

    assert passed(0, '{"source": "shared-server-session", "count": 0}') is True
    assert passed(0, "source: shared-server-session") is True
    assert passed(0, "local-ghidra-project") is False
    assert passed(1, "shared-server-session") is False
    assert passed(1, "") is False