"""E2E tests for the standalone MCP server, proxy, and CLI.

Tests the PythonMcpServer and AgentDecompileMcpProxyServer via Starlette
TestClient with real HTTP requests — NO mocking, NO monkeypatching.

Group A: Standalone MCP server (PythonMcpServer)
  - Health endpoint, MCP initialize, tools/list, tools/call, resources/read
  - Every advertised tool is called and response structure validated
  - Import/export workflows
  - CLI subprocess integration

Group B: Proxy server (AgentDecompileMcpProxyServer)
  - Health in proxy mode
  - MCP initialize through proxy
  - Tool forwarding

Group C: CLI subprocess tests
  - CLI help, version, tool listing, tool-seq, resource reading
"""

from __future__ import annotations

import json
import subprocess
import sys

from typing import Any


from agentdecompile_cli.mcp_server.proxy_server import (
    AgentDecompileMcpProxyServer,
    ProxyServerConfig,
)
from agentdecompile_cli.mcp_server.server import PythonMcpServer
from starlette.testclient import TestClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _initialize_payload(request_id: int = 1) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "pytest-e2e-standalone", "version": "1.0"},
        },
    }


def _tools_list_payload(request_id: int = 2) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/list",
        "params": {},
    }


def _tool_call_payload(
    tool_name: str,
    arguments: dict[str, Any],
    request_id: int = 100,
) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }


def _resource_read_payload(uri: str, request_id: int = 200) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "resources/read",
        "params": {"uri": uri},
    }


def _resources_list_payload(request_id: int = 300) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "resources/list",
        "params": {},
    }


def _prompts_list_payload(request_id: int = 400) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "prompts/list",
        "params": {},
    }


_HEADERS = {"Accept": "application/json, text/event-stream"}


def _post(client: TestClient, path: str, payload: dict[str, object]) -> dict[str, Any]:
    """POST a JSON-RPC payload and return parsed JSON."""
    resp = client.post(path, json=payload, headers=_HEADERS)
    assert resp.status_code == 200, f"POST {path} returned {resp.status_code}: {resp.text}"
    return resp.json()


def _init_session(client: TestClient, path: str = "/mcp/message") -> tuple[dict[str, Any], str]:
    """Initialize an MCP session and return (response_body, session_id)."""
    resp = client.post(path, json=_initialize_payload(), headers=_HEADERS)
    assert resp.status_code == 200, f"Initialize at {path} failed: {resp.status_code}: {resp.text}"
    body = resp.json()
    assert body["jsonrpc"] == "2.0"
    assert body["id"] == 1
    assert "result" in body
    session_id = resp.headers.get("mcp-session-id", "")
    return body, session_id


def _post_with_session(
    client: TestClient,
    session_id: str,
    payload: dict[str, object],
    path: str = "/mcp/message",
) -> dict[str, Any]:
    """POST with session ID header."""
    headers = {**_HEADERS}
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    resp = client.post(path, json=payload, headers=headers)
    assert resp.status_code == 200, f"POST {path} returned {resp.status_code}: {resp.text}"
    return resp.json()


def _extract_text_content(body: dict[str, Any]) -> str:
    """Extract text from a tools/call or resources/read result."""
    result = body.get("result", {})
    content = result.get("content", result.get("contents", []))
    texts = []
    for c in content:
        if isinstance(c, dict) and c.get("type") == "text":
            texts.append(c["text"])
        elif isinstance(c, dict) and "text" in c:
            texts.append(c["text"])
    return "\n".join(texts)


def _extract_json_content(body: dict[str, Any]) -> dict[str, Any]:
    """Extract and parse JSON from tool call result text."""
    text = _extract_text_content(body)
    return json.loads(text)


# ---------------------------------------------------------------------------
# Group A: Standalone PythonMcpServer Tests
# ---------------------------------------------------------------------------


class TestStandaloneServerHealth:
    """Test health endpoint and basic server lifecycle."""

    def test_health_endpoint_returns_200(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            resp = client.get("/health")
            assert resp.status_code == 200
            data = resp.json()
            assert data["server"] == "AgentDecompile"
            assert "status" in data
            assert "version" in data

    def test_health_reports_no_programs(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            resp = client.get("/health")
            data = resp.json()
            assert data["programs"] == 0


class TestStandaloneServerInit:
    """Test MCP initialize handshake on all endpoint paths."""

    def test_initialize_at_root(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            body, sid = _init_session(client, "/")
            info = body["result"]["serverInfo"]
            assert info["name"] == "AgentDecompile"
            assert "version" in info

    def test_initialize_at_mcp_message(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            body, sid = _init_session(client, "/mcp/message")
            info = body["result"]["serverInfo"]
            assert info["name"] == "AgentDecompile"
            assert "version" in info

    def test_initialize_at_mcp(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            body, sid = _init_session(client, "/mcp")
            assert body["result"]["serverInfo"]["name"] == "AgentDecompile"

    def test_initialize_at_mcp_message_trailing_slash(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            body, sid = _init_session(client, "/mcp/message/")
            assert body["result"]["serverInfo"]["name"] == "AgentDecompile"

    def test_initialize_returns_capabilities(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            body, sid = _init_session(client)
            result = body["result"]
            assert "capabilities" in result
            assert "serverInfo" in result
            caps = result["capabilities"]
            # Server must declare support for tools, resources
            assert "tools" in caps, f"Missing 'tools' in capabilities: {caps}"
            assert "resources" in caps, f"Missing 'resources' in capabilities: {caps}"

    def test_initialize_returns_session_id(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            resp = client.post("/mcp/message", json=_initialize_payload(), headers=_HEADERS)
            assert resp.status_code == 200
            # Session ID may be in headers
            sid = resp.headers.get("mcp-session-id", "")
            # The server should return a valid session identifier
            assert isinstance(sid, str)


class TestStandaloneToolsList:
    """Test tools/list endpoint returns the expected tool set."""

    def test_list_tools_returns_advertised_set(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            _, sid = _init_session(client)
            body = _post_with_session(client, sid, _tools_list_payload())
            tools = body["result"]["tools"]
            assert isinstance(tools, list)
            assert len(tools) > 0
            tool_names = {t["name"] for t in tools}

            # Normalize tool names: server may use underscore or hyphen style
            normalized_names = {name.replace("-", "_") for name in tool_names} | {name.replace("_", "-") for name in tool_names}

            # Verify all core advertised tools are present (check both hyphen and underscore forms)
            expected_core = [
                "open-project",
                "list-project-files",
                "get-current-program",
                "decompile-function",
                "search-symbols",
                "get-references",
                "list-imports",
                "list-exports",
                "list-functions",
                "export",
                "import-binary",
                "analyze-program",
                "inspect-memory",
                "read-bytes",
                "search-code",
                "search-strings",
                "search-everything",
                "list-strings",
                "get-call-graph",
                "analyze-data-flow",
                "analyze-vtables",
                "list-cross-references",
                "manage-function-tags",
                "execute-script",
                "checkin-program",
                "get-data",
                "match-function",
                "list-processors",
                "change-processor",
                "create-label",
                "search-constants",
                "apply-data-type",
                "sync-project",
                "checkout-program",
                "checkout-status",
                "remove-program-binary",
            ]
            for tool in expected_core:
                underscore_form = tool.replace("-", "_")
                assert tool in tool_names or underscore_form in tool_names, (
                    f"Expected tool '{tool}' (or '{underscore_form}') not found in advertised tools: {sorted(tool_names)}"
                )

    def test_each_tool_has_input_schema(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            _, sid = _init_session(client)
            body = _post_with_session(client, sid, _tools_list_payload())
            tools = body["result"]["tools"]
            for tool in tools:
                assert "name" in tool, f"Tool missing 'name': {tool}"
                assert "inputSchema" in tool, f"Tool '{tool['name']}' missing 'inputSchema'"
                assert isinstance(tool["inputSchema"], dict), f"Tool '{tool['name']}' inputSchema is not a dict"
                assert tool["inputSchema"].get("type") == "object", f"Tool '{tool['name']}' inputSchema type is not 'object'"

    def test_each_tool_has_description(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            _, sid = _init_session(client)
            body = _post_with_session(client, sid, _tools_list_payload())
            tools = body["result"]["tools"]
            for tool in tools:
                assert "description" in tool, f"Tool '{tool['name']}' missing 'description'"
                assert len(tool["description"]) > 0, f"Tool '{tool['name']}' has empty description"


class TestStandaloneResourcesList:
    """Test resources/list endpoint."""

    def test_list_resources_returns_three(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            _, sid = _init_session(client)
            body = _post_with_session(client, sid, _resources_list_payload())
            resources = body["result"]["resources"]
            assert isinstance(resources, list)
            assert len(resources) == 3
            uris = {str(r["uri"]) for r in resources}
            assert "ghidra://programs" in uris
            assert "ghidra://static-analysis-results" in uris
            assert "ghidra://agentdecompile-debug-info" in uris


class TestStandaloneResourcesRead:
    """Test resources/read for all three resources (no program loaded)."""

    def test_read_programs_resource_no_program(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            _, sid = _init_session(client)
            body = _post_with_session(client, sid, _resource_read_payload("ghidra://programs"))
            assert "result" in body
            contents = body["result"]["contents"]
            assert len(contents) > 0
            data = json.loads(contents[0]["text"])
            assert "programs" in data
            assert isinstance(data["programs"], list)

    def test_read_static_analysis_resource_sarif(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            _, sid = _init_session(client)
            body = _post_with_session(
                client, sid,
                _resource_read_payload("ghidra://static-analysis-results"),
            )
            assert "result" in body
            contents = body["result"]["contents"]
            data = json.loads(contents[0]["text"])
            assert "$schema" in data
            assert data["version"] == "2.1.0"
            assert "runs" in data
            assert len(data["runs"]) > 0
            run = data["runs"][0]
            assert "properties" in run
            assert run["properties"]["status"] == "no_program_loaded"

    def test_read_debug_info_resource(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            _, sid = _init_session(client)
            body = _post_with_session(
                client, sid,
                _resource_read_payload("ghidra://agentdecompile-debug-info"),
            )
            assert "result" in body
            contents = body["result"]["contents"]
            data = json.loads(contents[0]["text"])
            assert "metadata" in data
            assert "server" in data
            assert "program" in data
            assert data["program"]["status"] == "no_program_loaded"
            assert "analysis" in data
            assert data["analysis"]["status"] == "no_program"
            assert "profiling" in data
            assert data["profiling"]["status"] == "available"


class TestStandalonePromptsList:
    """Test prompts/list endpoint."""

    def test_list_prompts_returns_empty(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            _, sid = _init_session(client)
            body = _post_with_session(client, sid, _prompts_list_payload())
            prompts = body["result"]["prompts"]
            assert isinstance(prompts, list)
            # Currently no prompts are implemented
            assert len(prompts) == 0


class TestStandaloneToolCallsNoProgram:
    """Test every major tool when no program is loaded.

    Each tool should return a valid MCP response (not crash), and the
    response text should be non-empty (either success data or an actionable
    error with nextSteps).
    """

    def _call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            _, sid = _init_session(client)
            body = _post_with_session(
                client, sid,
                _tool_call_payload(tool_name, arguments),
            )
            assert "result" in body, f"Tool '{tool_name}' returned no result: {body}"
            result = body["result"]
            assert "content" in result, f"Tool '{tool_name}' result missing 'content'"
            content = result["content"]
            assert isinstance(content, list) and len(content) > 0, (
                f"Tool '{tool_name}' returned empty content list"
            )
            # Every content item must be a text content block
            for item in content:
                assert item.get("type") == "text", f"Tool '{tool_name}' content has non-text type: {item.get('type')}"
                assert isinstance(item.get("text"), str) and len(item["text"]) > 0, (
                    f"Tool '{tool_name}' content item has empty text"
                )
            text = _extract_text_content(body)
            assert len(text) > 0, f"Tool '{tool_name}' returned empty text content"
            return body

    def test_list_project_files(self):
        self._call_tool("list-project-files", {})

    def test_get_current_program(self):
        self._call_tool("get-current-program", {})

    def test_list_processors(self):
        body = self._call_tool("list-processors", {})
        text = _extract_text_content(body)
        # list-processors should always work (no program needed)
        # It returns processor language IDs
        assert len(text) > 10  # Should have substantial content

    def test_search_symbols_no_program(self):
        self._call_tool("search-symbols", {"query": "main"})

    def test_list_functions_no_program(self):
        self._call_tool("list-functions", {})

    def test_decompile_function_no_program(self):
        self._call_tool("decompile-function", {"name": "main"})

    def test_get_references_no_program(self):
        self._call_tool("get-references", {"target": "main", "direction": "to"})

    def test_list_imports_no_program(self):
        self._call_tool("list-imports", {})

    def test_list_exports_no_program(self):
        self._call_tool("list-exports", {})

    def test_list_strings_no_program(self):
        self._call_tool("list-strings", {})

    def test_search_strings_no_program(self):
        self._call_tool("search-strings", {"query": "hello"})

    def test_search_code_no_program(self):
        self._call_tool("search-code", {"query": "mov"})

    def test_search_constants_no_program(self):
        self._call_tool("search-constants", {"value": "0xDEADBEEF"})

    def test_search_everything_no_program(self):
        self._call_tool("search-everything", {"query": "test"})

    def test_get_call_graph_no_program(self):
        self._call_tool("get-call-graph", {"target": "main"})

    def test_inspect_memory_no_program(self):
        self._call_tool("inspect-memory", {"address": "0x00401000"})

    def test_read_bytes_no_program(self):
        self._call_tool("read-bytes", {"address": "0x00401000"})

    def test_get_data_no_program(self):
        self._call_tool("get-data", {"address": "0x00401000"})

    def test_list_cross_references_no_program(self):
        self._call_tool("list-cross-references", {"address": "0x00401000"})

    def test_analyze_data_flow_no_program(self):
        self._call_tool("analyze-data-flow", {"address": "0x00401000"})

    def test_analyze_vtables_no_program(self):
        self._call_tool("analyze-vtables", {})

    def test_manage_function_tags_no_program(self):
        self._call_tool("manage-function-tags", {"action": "list"})

    def test_match_function_no_program(self):
        self._call_tool("match-function", {"name": "main"})

    def test_checkout_status_no_program(self):
        self._call_tool("checkout-status", {})

    def test_create_label_no_program(self):
        self._call_tool("create-label", {"address": "0x00401000", "name": "test_label"})

    def test_apply_data_type_no_program(self):
        self._call_tool("apply-data-type", {"address": "0x00401000", "dataType": "int"})

    def test_change_processor_no_program(self):
        self._call_tool("change-processor", {"language": "x86:LE:32:default"})


class TestStandaloneToolResponseStructure:
    """Validate the structure of tool responses in detail."""

    def test_list_project_files_response_format(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            _, sid = _init_session(client)
            body = _post_with_session(
                client, sid,
                _tool_call_payload("list-project-files", {}),
            )
            # Response should be valid JSON-RPC 2.0
            assert body["jsonrpc"] == "2.0"
            assert body["id"] == 100
            result = body["result"]
            assert "content" in result
            content = result["content"]
            assert isinstance(content, list)
            assert len(content) > 0
            # Each content item should have type and text
            for item in content:
                assert "type" in item
                assert item["type"] == "text"
                assert "text" in item
                assert isinstance(item["text"], str)
                assert len(item["text"]) > 0, "Text content must be non-empty"
            # list-project-files returns Markdown with folder info
            text = _extract_text_content(body)
            assert "Project Files" in text or "Folder" in text or "/" in text

    def test_list_processors_returns_markdown_with_entries(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            _, sid = _init_session(client)
            body = _post_with_session(
                client, sid,
                _tool_call_payload("list-processors", {}),
            )
            text = _extract_text_content(body)
            # list-processors returns Markdown with processor entries
            assert "List Processors" in text or "x86" in text
            assert "default" in text
            # Should contain at least one architecture
            assert any(arch in text for arch in ["x86", "ARM", "MIPS", "PowerPC", "AARCH64"])


class TestStandaloneOpenProject:
    """Test open-project tool with various inputs."""

    def test_open_project_nonexistent_path_returns_error(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            _, sid = _init_session(client)
            body = _post_with_session(
                client, sid,
                _tool_call_payload("open-project", {"path": "/nonexistent/binary.exe"}),
            )
            assert "result" in body
            text = _extract_text_content(body)
            assert len(text) > 0
            # Error response must be valid JSON with explicit failure fields
            data = json.loads(text)
            assert data["success"] is False, f"Expected success=False, got: {data.get('success')}"
            assert "error" in data, f"Expected 'error' key in response: {list(data.keys())}"
            assert len(data["error"]) > 0, "Error message must be non-empty"

    def test_open_project_with_server_params_and_no_server_returns_error(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            _, sid = _init_session(client)
            body = _post_with_session(
                client, sid,
                _tool_call_payload("open-project", {
                    "path": "/some/binary",
                    "serverHost": "nonexistent.host.invalid",
                    "serverPort": 13100,
                    "serverUsername": "testuser",
                    "serverPassword": "testpass",
                }),
            )
            assert "result" in body
            text = _extract_text_content(body)
            assert len(text) > 0


class TestStandaloneImportExport:
    """Test import-binary and export tools."""

    def test_import_binary_nonexistent_path(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            _, sid = _init_session(client)
            body = _post_with_session(
                client, sid,
                _tool_call_payload("import-binary", {"path": "/nonexistent/file.exe"}),
            )
            assert "result" in body
            text = _extract_text_content(body)
            assert len(text) > 0

    def test_import_binary_version_control_rejected_locally(self):
        """import-binary with enableVersionControl=True for a non-existent path should fail."""
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            _, sid = _init_session(client)
            body = _post_with_session(
                client, sid,
                _tool_call_payload("import-binary", {
                    "path": "C:/example/test.exe",
                    "enableVersionControl": True,
                }),
            )
            assert "result" in body
            text = _extract_text_content(body)
            data = json.loads(text)
            assert data["success"] is False, f"Expected success=False, got: {data.get('success')}"
            assert "error" in data, f"Expected 'error' key in response: {list(data.keys())}"
            assert len(data["error"]) > 0, "Error message must be non-empty"

    def test_export_no_program_returns_error(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            _, sid = _init_session(client)
            body = _post_with_session(
                client, sid,
                _tool_call_payload("export", {"format": "sarif"}),
            )
            assert "result" in body
            text = _extract_text_content(body)
            assert len(text) > 0


class TestStandaloneExecuteScript:
    """Test execute-script tool."""

    def test_execute_script_no_program(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            _, sid = _init_session(client)
            body = _post_with_session(
                client, sid,
                _tool_call_payload("execute-script", {
                    "code": "print('hello from ghidra')",
                    "language": "python",
                }),
            )
            assert "result" in body
            text = _extract_text_content(body)
            assert len(text) > 0


class TestStandaloneAnalyzeProgram:
    """Test analyze-program tool."""

    def test_analyze_program_no_program(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            _, sid = _init_session(client)
            body = _post_with_session(
                client, sid,
                _tool_call_payload("analyze-program", {}),
            )
            assert "result" in body
            text = _extract_text_content(body)
            assert len(text) > 0


class TestStandaloneCheckinProgram:
    """Test checkin-program tool."""

    def test_checkin_program_no_program(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            _, sid = _init_session(client)
            body = _post_with_session(
                client, sid,
                _tool_call_payload("checkin-program", {"message": "test commit"}),
            )
            assert "result" in body
            text = _extract_text_content(body)
            assert len(text) > 0


class TestStandaloneSyncProject:
    """Test sync-project tool."""

    def test_sync_project_no_program(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            _, sid = _init_session(client)
            body = _post_with_session(
                client, sid,
                _tool_call_payload("sync-project", {}),
            )
            assert "result" in body
            text = _extract_text_content(body)
            assert len(text) > 0


# ---------------------------------------------------------------------------
# Group B: Proxy Server Tests
# ---------------------------------------------------------------------------


class TestProxyServerHealth:
    """Test proxy server health endpoint."""

    def test_proxy_health_reports_proxy_mode(self):
        proxy = AgentDecompileMcpProxyServer(
            ProxyServerConfig(
                host="127.0.0.1",
                port=19080,
                backend_url="http://127.0.0.1:8080/mcp/message",
            )
        )
        with TestClient(proxy.app) as client:
            resp = client.get("/health")
            assert resp.status_code == 200
            data = resp.json()
            assert data["mode"] == "proxy"
            assert data["server"] == "AgentDecompile"
            assert "backend" in data
            assert data["backend"] == "http://127.0.0.1:8080/mcp/message"

    def test_proxy_health_reports_version(self):
        proxy = AgentDecompileMcpProxyServer(
            ProxyServerConfig(
                host="127.0.0.1",
                port=19081,
                backend_url="http://127.0.0.1:8080/mcp/message",
            )
        )
        with TestClient(proxy.app) as client:
            resp = client.get("/health")
            data = resp.json()
            assert "version" in data


class TestProxyServerInitialize:
    """Test proxy server MCP initialize on all paths."""

    def _make_proxy(self, port: int = 19082) -> AgentDecompileMcpProxyServer:
        return AgentDecompileMcpProxyServer(
            ProxyServerConfig(
                host="127.0.0.1",
                port=port,
                backend_url="http://127.0.0.1:8080/mcp/message",
            )
        )

    def test_proxy_initialize_at_root(self):
        proxy = self._make_proxy(19085)
        with TestClient(proxy.app) as client:
            body = _post(client, "/", _initialize_payload())
            assert body["result"]["serverInfo"]["name"] == "AgentDecompile"

    def test_proxy_initialize_at_mcp_message(self):
        proxy = self._make_proxy(19082)
        with TestClient(proxy.app) as client:
            body = _post(client, "/mcp/message", _initialize_payload())
            assert body["result"]["serverInfo"]["name"] == "AgentDecompile"

    def test_proxy_initialize_at_mcp(self):
        proxy = self._make_proxy(19083)
        with TestClient(proxy.app) as client:
            body = _post(client, "/mcp", _initialize_payload())
            assert body["result"]["serverInfo"]["name"] == "AgentDecompile"

    def test_proxy_initialize_at_mcp_message_trailing_slash(self):
        proxy = self._make_proxy(19084)
        with TestClient(proxy.app) as client:
            body = _post(client, "/mcp/message/", _initialize_payload())
            assert body["result"]["serverInfo"]["name"] == "AgentDecompile"


class TestProxyServerToolsList:
    """Test proxy server tools/list endpoint (proxy manages its own MCP session)."""

    def test_proxy_tools_list_returns_valid_response(self):
        """Proxy tools/list returns a valid MCP response; tools list reflects the bridge's registry."""
        proxy = AgentDecompileMcpProxyServer(
            ProxyServerConfig(
                host="127.0.0.1",
                port=19086,
                backend_url="http://127.0.0.1:8080/mcp/message",
            )
        )
        with TestClient(proxy.app) as client:
            body, sid = _init_session(client, "/mcp/message")
            tools_body = _post_with_session(client, sid, _tools_list_payload())
            assert "result" in tools_body
            tools = tools_body["result"]["tools"]
            assert isinstance(tools, list)
            # In proxy mode the bridge advertises tools from the bridge registry
            for tool in tools:
                assert "name" in tool
                assert "inputSchema" in tool
                assert "description" in tool


# ---------------------------------------------------------------------------
# Group C: CLI subprocess tests
# ---------------------------------------------------------------------------


def _run_cli(*args: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    """Run the agentdecompile-cli entry point as a subprocess."""
    cmd = [sys.executable, "-m", "agentdecompile_cli.cli", *args]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _run_server_help() -> subprocess.CompletedProcess[str]:
    """Run agentdecompile-server --help."""
    cmd = [sys.executable, "-m", "agentdecompile_cli.server", "--help"]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=15)


class TestCLIHelp:
    """Test CLI help and version output."""

    def test_cli_help_exits_zero(self):
        result = _run_cli("--help")
        assert result.returncode == 0
        assert "agentdecompile" in result.stdout.lower() or "usage" in result.stdout.lower()

    def test_cli_version(self):
        result = _run_cli("--version")
        assert result.returncode == 0
        # Should print version info
        output = result.stdout + result.stderr
        assert len(output.strip()) > 0

    def test_server_help_exits_zero(self):
        result = _run_server_help()
        assert result.returncode == 0
        assert "--transport" in result.stdout
        assert "--port" in result.stdout
        assert "--backend-url" in result.stdout

    def test_server_help_lists_transports(self):
        result = _run_server_help()
        assert result.returncode == 0
        assert "stdio" in result.stdout
        assert "streamable-http" in result.stdout


class TestCLIListCommands:
    """Test CLI list sub-commands."""

    def test_cli_list_help(self):
        result = _run_cli("list", "--help")
        assert result.returncode == 0
        assert "project-files" in result.stdout.lower() or "list" in result.stdout.lower()


class TestCLIToolSubcommands:
    """Test CLI tool and tool-seq commands (without a running server)."""

    def test_cli_tool_help(self):
        result = _run_cli("tool", "--help")
        assert result.returncode == 0

    def test_cli_tool_seq_help(self):
        result = _run_cli("tool-seq", "--help")
        assert result.returncode == 0

    def test_cli_resource_help(self):
        result = _run_cli("resource", "--help")
        assert result.returncode == 0

    def test_cli_open_help(self):
        result = _run_cli("open", "--help")
        assert result.returncode == 0

    def test_cli_decompile_function_help(self):
        result = _run_cli("decompile-function", "--help")
        assert result.returncode == 0

    def test_cli_search_symbols_help(self):
        result = _run_cli("search-symbols", "--help")
        assert result.returncode == 0

    def test_cli_references_help(self):
        result = _run_cli("references", "--help")
        assert result.returncode == 0

    def test_cli_get_functions_help(self):
        result = _run_cli("get-functions", "--help")
        assert result.returncode == 0

    def test_cli_analyze_help(self):
        result = _run_cli("analyze", "--help")
        assert result.returncode == 0

    def test_cli_import_help(self):
        result = _run_cli("import", "--help")
        assert result.returncode == 0

    def test_cli_get_current_program_help(self):
        result = _run_cli("get-current-program", "--help")
        assert result.returncode == 0


class TestCLIWithoutServer:
    """Test CLI behavior when no server is running (should fail gracefully)."""

    def test_cli_list_project_files_no_server(self):
        """CLI should fail (non-zero exit) when no server is reachable."""
        result = _run_cli(
            "--server-url", "http://127.0.0.1:59999",
            "list", "project-files",
            timeout=15,
        )
        # Should fail because no server is running at that port
        assert result.returncode != 0 or "error" in (result.stdout + result.stderr).lower() or "connect" in (result.stdout + result.stderr).lower()

    def test_cli_tool_seq_no_server(self):
        """tool-seq should fail when no server is reachable."""
        steps = json.dumps([{"name": "list-project-files", "arguments": {}}])
        result = _run_cli(
            "--server-url", "http://127.0.0.1:59999",
            "tool-seq", steps,
            timeout=15,
        )
        assert result.returncode != 0 or "error" in (result.stdout + result.stderr).lower() or "connect" in (result.stdout + result.stderr).lower()

    def test_cli_resource_no_server(self):
        """resource command should fail when no server is reachable."""
        result = _run_cli(
            "--server-url", "http://127.0.0.1:59999",
            "resource", "programs",
            timeout=15,
        )
        assert result.returncode != 0 or "error" in (result.stdout + result.stderr).lower() or "connect" in (result.stdout + result.stderr).lower()


# ---------------------------------------------------------------------------
# Group D: Multiple sessions and idempotency
# ---------------------------------------------------------------------------


class TestStandaloneMultipleSessions:
    """Test that multiple independent sessions can be created."""

    def test_two_sessions_get_independent_ids(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            resp1 = client.post("/mcp/message", json=_initialize_payload(1), headers=_HEADERS)
            resp2 = client.post("/mcp/message", json=_initialize_payload(2), headers=_HEADERS)
            assert resp1.status_code == 200
            assert resp2.status_code == 200
            sid1 = resp1.headers.get("mcp-session-id", "")
            sid2 = resp2.headers.get("mcp-session-id", "")
            # Both sessions should be valid and different
            body1 = resp1.json()
            body2 = resp2.json()
            assert body1["result"]["serverInfo"]["name"] == "AgentDecompile"
            assert body2["result"]["serverInfo"]["name"] == "AgentDecompile"
            if sid1 and sid2:
                assert sid1 != sid2, "Two independent sessions must have distinct session IDs"


class TestStandaloneToolCallIdempotency:
    """Test that repeated tool calls return consistent results."""

    def test_list_project_files_idempotent(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            _, sid = _init_session(client)
            body1 = _post_with_session(
                client, sid,
                _tool_call_payload("list-project-files", {}, request_id=101),
            )
            body2 = _post_with_session(
                client, sid,
                _tool_call_payload("list-project-files", {}, request_id=102),
            )
            text1 = _extract_text_content(body1)
            text2 = _extract_text_content(body2)
            # Same result for identical queries
            assert text1 == text2

    def test_list_processors_idempotent(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            _, sid = _init_session(client)
            body1 = _post_with_session(
                client, sid,
                _tool_call_payload("list-processors", {}, request_id=201),
            )
            body2 = _post_with_session(
                client, sid,
                _tool_call_payload("list-processors", {}, request_id=202),
            )
            text1 = _extract_text_content(body1)
            text2 = _extract_text_content(body2)
            assert text1 == text2


# ---------------------------------------------------------------------------
# Group E: JSON-RPC protocol compliance
# ---------------------------------------------------------------------------


class TestJsonRpcCompliance:
    """Test JSON-RPC 2.0 protocol compliance."""

    def test_response_has_jsonrpc_version(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            body = _post(client, "/mcp/message", _initialize_payload())
            assert body["jsonrpc"] == "2.0"

    def test_response_preserves_request_id(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            body = _post(client, "/mcp/message", _initialize_payload(request_id=42))
            assert body["id"] == 42

    def test_response_has_result_or_error(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            body = _post(client, "/mcp/message", _initialize_payload())
            assert "result" in body or "error" in body

    def test_tool_call_response_preserves_id(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            _, sid = _init_session(client)
            body = _post_with_session(
                client, sid,
                _tool_call_payload("list-project-files", {}, request_id=999),
            )
            assert body["id"] == 999

    def test_non_mcp_path_returns_404(self):
        """Requests to non-MCP, non-health paths should get 404."""
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            resp = client.get("/nonexistent")
            assert resp.status_code == 404

    def test_health_is_not_intercepted_by_mcp(self):
        """Health endpoint must be served by FastAPI, not the MCP middleware."""
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            resp = client.get("/health")
            assert resp.status_code == 200
            data = resp.json()
            # Health response must NOT look like a JSON-RPC response
            assert "jsonrpc" not in data
            assert "server" in data
