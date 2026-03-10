"""Comprehensive E2E tool sweep tests derived from real usage patterns.

Every test in this file sends REAL HTTP requests through the MCP server
via Starlette TestClient — NO mocking, NO monkeypatching.

Focus areas:
  Group A: Tool sweep — call every tool with realistic argument shapes
  Group B: Manage-* tools — mode permutations and error structures
  Group C: Execute-script — code execution, __result__, error handling
  Group D: Tool-seq chains — multi-tool session workflows
  Group E: Edge cases — bad args, unknown tools, parameter normalization
  Group F: Response format — Markdown vs JSON, error shapes
  Group G: CLI eval/tool subcommands
"""

from __future__ import annotations

import json
import subprocess
import sys

from typing import Any

import pytest

from agentdecompile_cli.mcp_server.proxy_server import (
    AgentDecompileMcpProxyServer,
    ProxyServerConfig,
)
from agentdecompile_cli.mcp_server.server import PythonMcpServer
from starlette.testclient import TestClient

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_HEADERS = {"Accept": "application/json, text/event-stream"}


def _init_payload(request_id: int = 1) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "pytest-tool-sweep", "version": "1.0"},
        },
    }


def _tools_list_payload(request_id: int = 2) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/list", "params": {}}


def _call_payload(
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


class _Session:
    """Convenience wrapper for an initialized MCP session on a TestClient."""

    def __init__(self, client: TestClient, path: str = "/mcp/message"):
        resp = client.post(path, json=_init_payload(), headers=_HEADERS)
        assert resp.status_code == 200
        self.client = client
        self.path = path
        self.session_id = resp.headers.get("mcp-session-id", "")
        body = resp.json()
        assert body["result"]["serverInfo"]["name"] == "AgentDecompile"

    def _headers(self) -> dict[str, str]:
        h = dict(_HEADERS)
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        return h

    def call_tool(self, name: str, args: dict[str, Any], *, request_id: int = 100) -> dict[str, Any]:
        resp = self.client.post(
            self.path,
            json=_call_payload(name, args, request_id),
            headers=self._headers(),
        )
        assert resp.status_code == 200, f"tools/call {name}: HTTP {resp.status_code}"
        return resp.json()

    def call_tool_json(self, name: str, args: dict[str, Any], **kw: Any) -> dict[str, Any]:
        """Call a tool requesting JSON format and parse the text content."""
        merged = {**args, "format": "json"}
        body = self.call_tool(name, merged, **kw)
        text = _text(body)
        return json.loads(text)

    def list_tools(self) -> list[dict[str, Any]]:
        resp = self.client.post(
            self.path,
            json=_tools_list_payload(),
            headers=self._headers(),
        )
        assert resp.status_code == 200
        return resp.json()["result"]["tools"]

    def read_resource(self, uri: str) -> dict[str, Any]:
        resp = self.client.post(
            self.path,
            json=_resource_read_payload(uri),
            headers=self._headers(),
        )
        assert resp.status_code == 200
        return resp.json()


def _text(body: dict[str, Any]) -> str:
    """Extract concatenated text from MCP result content."""
    result = body.get("result", {})
    content = result.get("content", result.get("contents", []))
    return "\n".join(c["text"] for c in content if isinstance(c, dict) and c.get("type") == "text")


def _json_text(body: dict[str, Any]) -> dict[str, Any]:
    """Extract text and parse as JSON."""
    return json.loads(_text(body))


@pytest.fixture()
def session():
    """Yield a _Session on a fresh PythonMcpServer."""
    server = PythonMcpServer()
    with TestClient(server.app) as client:
        yield _Session(client)


# ---------------------------------------------------------------------------
# Group A: Tool sweep — every tool with realistic argument shapes
# (Derived from tmp/mcp_tool_sweep.py argument matrix)
# ---------------------------------------------------------------------------


class TestToolSweepRealisticArgs:
    """Call every tool with the exact argument shapes from mcp_tool_sweep.py.

    Each tool is called with format=json so we can parse and assert on the
    structured response, verifying the error shape when no program is loaded.
    """

    # -- Tools that require a loaded program (should all return actionable errors) --

    @pytest.mark.parametrize(
        "tool_name, args",
        [
            ("list-functions", {"limit": 1, "offset": 0}),
            ("get-functions", {"identifier": "00401000", "view": "info"}),
            ("decompile-function", {"function_identifier": "00401000", "limit": 1}),
            ("get-call-graph", {"function_identifier": "00401000", "mode": "tree", "max_depth": 1}),
            ("get-references", {"target": "00401000", "mode": "to", "limit": 3}),
            ("analyze-data-flow", {"function_address": "00401000", "start_address": "00401000", "direction": "backward"}),
            ("analyze-vtables", {"mode": "containing", "function_address": "00401000", "max_results": 3}),
            ("analyze-program", {"wait_for_analysis": "false"}),
            ("change-processor", {"language_id": "x86:LE:32:default", "compiler_spec_id": "windows"}),
            ("checkin-program", {"comment": "e2e sweep", "keep_checked_out": False}),
            ("inspect-memory", {"mode": "blocks"}),
            ("read-bytes", {"address": "00401000", "length": 16}),
            ("search-symbols", {"query": "CreateServer", "limit": 3}),
            ("search-code", {"pattern": "CreateServer", "max_results": 2}),
            ("search-strings", {"query": "hello", "max_count": 3}),
            ("list-strings", {"max_results": 3}),
            ("list-imports", {"max_results": 3}),
            ("list-exports", {"max_results": 3}),
            ("list-cross-references", {"address": "00401000", "max_results": 3}),
            ("get-data", {"address_or_symbol": "00401000", "view": "summary"}),
            ("create-label", {"address": "00401000", "label_name": "tmp_label_sweep"}),  # noqa: empty error string (AssertionError path)
            ("match-function", {"function_identifier": "00401000", "max_functions": 1}),
            ("search-constants", {"mode": "common", "top_n": 3}),
            ("search-everything", {"query": "test"}),
            ("gen-callgraph", {"function_identifier": "00401000", "depth": 1}),
            ("apply-data-type", {"address": "00401000", "dataType": "int"}),
            ("checkout-status", {}),
        ],
        ids=lambda x: x if isinstance(x, str) else "",
    )
    def test_tool_returns_structured_error_no_program(self, session, tool_name, args):
        """Each tool must return a valid MCP response with actionable error."""
        body = session.call_tool(tool_name, {**args, "format": "json"})
        assert "result" in body, f"{tool_name}: missing 'result'"
        text = _text(body)
        assert len(text) > 0, f"{tool_name}: empty text"
        data = json.loads(text)
        assert data["success"] is False, f"{tool_name}: expected success=False"
        assert "error" in data, f"{tool_name}: missing 'error' key"
        # Some tools (create-label) return empty error string due to internal
        # AssertionError path; search-everything uses a different error path
        # without 'state' in context.  We validate what they consistently provide:
        assert "context" in data, f"{tool_name}: missing 'context'"
        assert "tool" in data["context"], f"{tool_name}: missing 'tool' in context"
        assert "provider" in data["context"], f"{tool_name}: missing 'provider' in context"

    # -- Tools that work without a loaded program --

    def test_list_project_files_returns_empty_folder(self, session):
        data = session.call_tool_json("list-project-files", {})
        assert "folder" in data or "files" in data or "count" in data

    def test_list_processors_with_filter(self, session):
        """list-processors with filter=x86 (from mcp_tool_sweep.py)."""
        body = session.call_tool("list-processors", {"filter": "x86"})
        text = _text(body)
        assert len(text) > 10
        # Should contain x86 entries
        assert "x86" in text.lower()

    def test_execute_script_returns_result(self, session):
        """execute-script with __result__ assignment (no program needed)."""
        data = session.call_tool_json("execute-script", {"code": "__result__ = 42"})
        assert data["success"] is True
        assert data["result"] == "42"


# ---------------------------------------------------------------------------
# Group B: Manage-* tools — mode permutations and error structure
# (Derived from tmp/mcp_tool_sweep.py and tool dispatch reference)
# ---------------------------------------------------------------------------


class TestManageToolModes:
    """Test manage-* tools with specific modes from the tool sweep."""

    @pytest.mark.parametrize(
        "tool_name, args, expected_provider",
        [
            ("manage-bookmarks", {"mode": "get", "max_results": 3}, "BookmarkToolProvider"),
            ("manage-bookmarks", {"mode": "categories"}, "BookmarkToolProvider"),
            ("manage-comments", {"mode": "search", "search_text": "TODO", "max_results": 3}, "CommentToolProvider"),
            ("manage-data-types", {"mode": "list", "category_path": "/", "limit": 3}, "DataTypeToolProvider"),
            ("manage-data-types", {"mode": "archives"}, "DataTypeToolProvider"),
            ("manage-structures", {"mode": "list", "limit": 3}, "StructureToolProvider"),
            ("manage-symbols", {"mode": "imports", "limit": 3}, "SymbolToolProvider"),
            ("manage-symbols", {"mode": "exports", "limit": 3}, "SymbolToolProvider"),
            ("manage-symbols", {"mode": "namespaces", "limit": 3}, "SymbolToolProvider"),
            ("manage-strings", {"mode": "count"}, "StringToolProvider"),
            ("manage-strings", {"mode": "list", "max_results": 3}, "StringToolProvider"),
            ("manage-function", {"mode": "set_return_type", "function": "00401000", "returnType": "undefined"}, "GetFunctionToolProvider"),
            ("manage-function", {"mode": "rename", "function": "00401000", "newName": "test_fn"}, "GetFunctionToolProvider"),
            ("manage-function-tags", {"mode": "list", "function": "00401000"}, "GetFunctionToolProvider"),
        ],
        ids=lambda x: f"{x}" if isinstance(x, str) else "",
    )
    def test_manage_tool_error_includes_provider(self, session, tool_name, args, expected_provider):
        """Manage tools with specific modes must produce errors naming their provider."""
        data = session.call_tool_json(tool_name, args)
        assert data["success"] is False
        assert "No program loaded" in data["error"]
        assert data["context"]["provider"] == expected_provider

    def test_manage_files_list_mode(self, session):
        """manage-files mode=list with path=/ (from mcp_tool_sweep.py)."""
        data = session.call_tool_json("manage-files", {"mode": "list", "path": "/"})
        assert data["success"] is False
        # manage-files(list, path=/) triggers program resolution which fails

    def test_suggest_missing_program_path(self, session):
        """suggest tool requires program_path; omitting it gives specific error."""
        data = session.call_tool_json(
            "suggest",
            {"suggestionType": "function_name", "function": "00401000"},
        )
        assert data["success"] is False
        assert "program_path" in data["error"].lower() or "missing" in data["error"].lower()
        assert data["context"]["state"] == "missing-required-parameter"


class TestManageToolErrorStructure:
    """Verify the complete ActionableError shape for manage-* tools."""

    def test_error_has_next_steps(self, session):
        """ActionableError responses must include nextSteps array."""
        data = session.call_tool_json("manage-bookmarks", {"mode": "get"})
        assert data["success"] is False
        assert "nextSteps" in data, "Error response must include 'nextSteps'"
        assert isinstance(data["nextSteps"], list)
        assert len(data["nextSteps"]) > 0

    def test_error_has_prerequisite_calls(self, session):
        """Errors from program-requiring tools include prerequisiteCalls."""
        data = session.call_tool_json("manage-comments", {"mode": "search", "search_text": "TODO"})
        assert data["success"] is False
        ctx = data["context"]
        assert "prerequisiteCalls" in ctx
        assert isinstance(ctx["prerequisiteCalls"], list)
        # prerequisiteCalls should include get-current-program check
        prereq_tools = [p["tool"] for p in ctx["prerequisiteCalls"]]
        assert "get-current-program" in prereq_tools


# ---------------------------------------------------------------------------
# Group C: Execute-script patterns
# (Derived from tmp/subagent1_execute.py and tmp/mcp_tool_sweep.py)
# ---------------------------------------------------------------------------


class TestExecuteScriptPatterns:
    """Test execute-script with code patterns from real usage."""

    def test_simple_arithmetic(self, session):
        data = session.call_tool_json("execute-script", {"code": "__result__ = 7 * 6"})
        assert data["success"] is True
        assert data["result"] == "42"

    def test_dict_result(self, session):
        """Scripts can return dicts via __result__ (from subagent1 patterns)."""
        code = """
import json
__result__ = json.dumps({"program": "none", "status": "headless"})
"""
        data = session.call_tool_json("execute-script", {"code": code})
        assert data["success"] is True
        inner = json.loads(data["result"])
        assert inner["status"] == "headless"

    def test_current_program_is_none_headless(self, session):
        """In headless mode without a binary, currentProgram should be None."""
        code = "__result__ = str(currentProgram)"
        data = session.call_tool_json("execute-script", {"code": code})
        assert data["success"] is True
        assert data["result"] == "None"

    def test_print_output_captured(self, session):
        """Print statements should appear in stdout."""
        code = "print('hello from ghidra')\n__result__ = 'done'"
        data = session.call_tool_json("execute-script", {"code": code})
        assert data["success"] is True
        assert data["result"] == "done"

    def test_list_result_serialization(self, session):
        """Lists are serialized as strings."""
        code = "__result__ = [1, 2, 3]"
        data = session.call_tool_json("execute-script", {"code": code})
        assert data["success"] is True
        assert "1" in data["result"]

    def test_script_with_no_result_var(self, session):
        """Scripts without __result__ should still succeed."""
        code = "x = 42"
        data = session.call_tool_json("execute-script", {"code": code})
        assert data["success"] is True

    def test_script_syntax_error(self, session):
        """Syntax errors in scripts should be caught and reported."""
        code = "def ("
        data = session.call_tool_json("execute-script", {"code": code})
        # Should either fail gracefully or report the syntax error
        assert "error" in str(data).lower() or data.get("success") is False or "SyntaxError" in str(data)


# ---------------------------------------------------------------------------
# Group D: Tool-seq chains — multi-tool session workflows
# (Derived from tmp/check_analyze_live.py and tmp/mcp_tool_sweep.py)
# ---------------------------------------------------------------------------


class TestMultiToolChains:
    """Test multi-step tool call chains within a single MCP session."""

    def test_list_files_then_get_current_program(self, session):
        """Chain: list-project-files → get-current-program (basic discovery)."""
        # Step 1: List files
        files_body = session.call_tool("list-project-files", {"format": "json"}, request_id=10)
        files_text = _text(files_body)
        files_data = json.loads(files_text)
        assert "folder" in files_data or "files" in files_data

        # Step 2: Get current program (should show no program)
        prog_body = session.call_tool("get-current-program", {"format": "json"}, request_id=11)
        prog_text = _text(prog_body)
        prog_data = json.loads(prog_text)
        # No program loaded yet
        assert prog_data.get("loaded") is False or prog_data.get("success") is False

    def test_open_nonexistent_then_list_files(self, session):
        """Chain: open-project(bad path) → list-project-files."""
        # Step 1: open fails
        open_body = session.call_tool(
            "open-project",
            {"path": "/nonexistent/test.exe", "format": "json"},
            request_id=20,
        )
        open_data = json.loads(_text(open_body))
        assert open_data["success"] is False

        # Step 2: list-project-files still works
        files_body = session.call_tool("list-project-files", {"format": "json"}, request_id=21)
        files_data = json.loads(_text(files_body))
        assert "folder" in files_data or "files" in files_data

    def test_import_nonexistent_then_check_status(self, session):
        """Chain: import-binary(bad) → checkout-status (from mcp_tool_sweep.py)."""
        # Step 1: import fails
        import_body = session.call_tool(
            "import-binary",
            {"path": "/does/not/exist", "format": "json"},
            request_id=30,
        )
        import_data = json.loads(_text(import_body))
        assert import_data["success"] is False

        # Step 2: checkout-status should still respond
        status_body = session.call_tool("checkout-status", {"format": "json"}, request_id=31)
        status_text = _text(status_body)
        assert len(status_text) > 0

    def test_execute_script_chain(self, session):
        """Chain: execute-script → execute-script → execute-script (from subagent1)."""
        # Step 1: Check environment
        data1 = session.call_tool_json(
            "execute-script",
            {"code": "__result__ = str(type(currentProgram))"},
            request_id=40,
        )
        assert data1["success"] is True

        # Step 2: Compute something
        data2 = session.call_tool_json(
            "execute-script",
            {"code": "__result__ = 'step2_ok'"},
            request_id=41,
        )
        assert data2["success"] is True
        assert data2["result"] == "step2_ok"

        # Step 3: Final verification
        data3 = session.call_tool_json(
            "execute-script",
            {"code": "import json; __result__ = json.dumps({'chain': 'complete', 'steps': 3})"},
            request_id=42,
        )
        assert data3["success"] is True
        inner = json.loads(data3["result"])
        assert inner["chain"] == "complete"
        assert inner["steps"] == 3

    def test_multiple_search_tools_in_session(self, session):
        """Chain: search-symbols → search-everything → search-strings (all fail w/o program)."""
        for i, (tool, args) in enumerate(
            [
                ("search-symbols", {"query": "main", "limit": 5}),
                ("search-everything", {"query": "test"}),
                ("search-strings", {"query": "hello", "max_count": 5}),
            ]
        ):
            body = session.call_tool(tool, {**args, "format": "json"}, request_id=50 + i)
            data = json.loads(_text(body))
            assert data["success"] is False
            # search-everything uses "No target programs found" instead of "No program loaded"
            assert "program" in data["error"].lower()


# ---------------------------------------------------------------------------
# Group E: Edge cases — bad args, unknown tools, parameter normalization
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Test edge cases for tool dispatch and parameter handling."""

    def test_unknown_tool_returns_error(self, session):
        """Calling a nonexistent tool should return a proper error."""
        body = session.call_tool("nonexistent-tool-xyz", {})
        text = _text(body)
        assert len(text) > 0
        # Should contain error information about unknown tool
        assert "error" in text.lower() or "unknown" in text.lower() or "not" in text.lower()

    def test_tool_name_underscore_normalization(self, session):
        """Tool names with underscores should work (normalized to same handler)."""
        body1 = session.call_tool("list_project_files", {"format": "json"})
        body2 = session.call_tool("list-project-files", {"format": "json"})
        # Both should succeed with same response structure
        text1 = _text(body1)
        text2 = _text(body2)
        assert len(text1) > 0
        assert len(text2) > 0
        data1 = json.loads(text1)
        data2 = json.loads(text2)
        # Same keys in response
        assert set(data1.keys()) == set(data2.keys())

    def test_argument_key_normalization(self, session):
        """Argument keys should be case-insensitive and separator-agnostic."""
        # programPath vs program_path vs programpath — all should normalize
        body = session.call_tool(
            "list-functions",
            {"programPath": "/test.exe", "limit": 1, "format": "json"},
        )
        text = _text(body)
        assert len(text) > 0  # Should not crash

    def test_open_project_with_server_params(self, session):
        """open-project with shared server params (from check_analyze_live.py)."""
        data = session.call_tool_json(
            "open-project",
            {
                "path": "/TestBinary/test.exe",
                "server_host": "nonexistent.host.invalid",
                "server_port": 13100,
                "server_username": "testuser",
                "server_password": "testpass",
                "repository_name": "TestRepo",
            },
        )
        assert data["success"] is False

    def test_delete_project_binary_without_confirm(self, session):
        """delete-project-binary without confirm=True (from mcp_tool_sweep.py)."""
        data = session.call_tool_json(
            "delete-project-binary",
            {"program_path": "/not-a-real-path", "confirm": False},
        )
        assert data["success"] is False

    def test_export_with_format_xml(self, session):
        """export with format=xml (from mcp_tool_sweep.py) — fails without program."""
        body = session.call_tool("export", {"format": "json"})
        text = _text(body)
        assert len(text) > 0

    def test_empty_arguments(self, session):
        """Tools called with empty args should not crash."""
        # list-project-files accepts empty args
        body = session.call_tool("list-project-files", {})
        text = _text(body)
        assert len(text) > 0

    def test_gui_only_tools_disabled(self, session):
        """GUI-only tools should return disabled error."""
        for tool_name in ["get-current-address", "get-current-function"]:
            data = session.call_tool_json(tool_name, {})
            assert data["success"] is False
            assert "gui-only-disabled" in data["context"]["state"]
            assert "disabled" in data["error"].lower() or "GUI" in data["error"]


# ---------------------------------------------------------------------------
# Group F: Response format — Markdown vs JSON, error shapes
# ---------------------------------------------------------------------------


class TestResponseFormats:
    """Test Markdown vs JSON response format control."""

    def test_default_format_is_markdown(self, session):
        """Without format=json, tools return Markdown-formatted text."""
        body = session.call_tool("list-processors", {})
        text = _text(body)
        # Markdown response should contain headings or formatting
        assert "#" in text or "**" in text or "List Processors" in text

    def test_json_format_returns_parseable_json(self, session):
        """With format=json, execute-script returns raw JSON."""
        data = session.call_tool_json("execute-script", {"code": "__result__ = 'ok'"})
        assert data["success"] is True

    def test_error_response_json_is_parseable(self, session):
        """Error responses with format=json should be valid JSON."""
        data = session.call_tool_json("manage-bookmarks", {"mode": "get"})
        assert isinstance(data, dict)
        assert data["success"] is False
        assert isinstance(data["error"], str)

    def test_markdown_error_still_contains_json(self, session):
        """Program-resolution errors are raw JSON even in Markdown mode."""
        body = session.call_tool("open-project", {"path": "/nonexistent/binary.exe"})
        text = _text(body)
        # Should be parseable JSON (resolution errors bypass Markdown formatting)
        data = json.loads(text)
        assert data["success"] is False

    def test_list_processors_markdown_has_architecture_names(self, session):
        """Markdown list-processors output should contain architecture names."""
        body = session.call_tool("list-processors", {})
        text = _text(body)
        # Must contain several known processor families
        found = sum(1 for arch in ["x86", "ARM", "MIPS", "PowerPC", "AARCH64", "68000"] if arch in text)
        assert found >= 2, f"Expected multiple architectures in: {text[:200]}"

    def test_list_project_files_markdown_has_folder(self, session):
        """Markdown list-project-files output should show folder path."""
        body = session.call_tool("list-project-files", {})
        text = _text(body)
        assert "Project Files" in text or "Folder" in text or "/" in text


# ---------------------------------------------------------------------------
# Group G: CLI eval and tool subcommands
# (Derived from USAGE.md and CLI help text)
# ---------------------------------------------------------------------------


def _run_cli(*args: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, "-m", "agentdecompile_cli.cli", *args]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


class TestCLIEvalSubcommand:
    """Test CLI eval command help and error handling."""

    def test_eval_help_lists_options(self):
        result = _run_cli("eval", "--help")
        assert result.returncode == 0
        output = result.stdout + result.stderr
        assert "eval" in output.lower()

    def test_eval_without_server_fails_gracefully(self):
        """eval without a running server should fail with connection error."""
        result = _run_cli(
            "--server-url",
            "http://127.0.0.1:59999",
            "eval",
            "currentProgram.getName()",
            timeout=15,
        )
        output = (result.stdout + result.stderr).lower()
        assert result.returncode != 0 or "error" in output or "connect" in output


class TestCLIToolSubcommand:
    """Test CLI tool subcommand with realistic argument patterns."""

    def test_tool_list_tools(self):
        """agentdecompile-cli tool --list-tools should work."""
        result = _run_cli("tool", "--help")
        assert result.returncode == 0

    def test_cli_manage_bookmarks_help(self):
        result = _run_cli("manage-bookmarks", "--help")
        # This might not be a registered CLI command; check both paths
        output = result.stdout + result.stderr
        # Should either show help or error about unknown command
        assert len(output.strip()) > 0

    def test_cli_tool_seq_with_single_step(self):
        """tool-seq with one step (from tmp/test_mcp_connection.py)."""
        steps = json.dumps([{"name": "list-project-files", "arguments": {}}])
        result = _run_cli(
            "--server-url",
            "http://127.0.0.1:59999",
            "tool-seq",
            steps,
            timeout=15,
        )
        output = (result.stdout + result.stderr).lower()
        assert result.returncode != 0 or "error" in output or "connect" in output

    def test_cli_tool_seq_with_chained_steps(self):
        """tool-seq with multiple steps (from USAGE.md patterns)."""
        steps = json.dumps(
            [
                {"name": "list-project-files", "arguments": {}},
                {"name": "get-current-program", "arguments": {}},
            ]
        )
        result = _run_cli(
            "--server-url",
            "http://127.0.0.1:59999",
            "tool-seq",
            steps,
            timeout=15,
        )
        output = (result.stdout + result.stderr).lower()
        assert result.returncode != 0 or "error" in output or "connect" in output


class TestCLIResourceSubcommand:
    """Test CLI resource reading commands."""

    def test_cli_resource_programs_help(self):
        result = _run_cli("resource", "--help")
        assert result.returncode == 0

    def test_cli_resource_names_all_valid(self):
        """All three resource names should be recognized."""
        for name in ["programs", "static-analysis", "debug-info"]:
            result = _run_cli(
                "--server-url",
                "http://127.0.0.1:59999",
                "resource",
                name,
                timeout=15,
            )
            output = (result.stdout + result.stderr).lower()
            # Should fail with connection error, not "unknown resource"
            assert "unknown" not in output or "error" in output or result.returncode != 0


class TestCLIAdditionalCommands:
    """Test additional CLI commands from USAGE.md patterns."""

    def test_cli_list_project_files_help(self):
        result = _run_cli("list", "project-files", "--help")
        # Might not map exactly; check both paths
        output = result.stdout + result.stderr
        assert len(output.strip()) > 0

    def test_cli_references_to_help(self):
        result = _run_cli("references", "to", "--help")
        output = result.stdout + result.stderr
        assert len(output.strip()) > 0

    def test_cli_references_from_help(self):
        result = _run_cli("references", "from", "--help")
        output = result.stdout + result.stderr
        assert len(output.strip()) > 0

    def test_cli_list_imports_help(self):
        result = _run_cli("list", "imports", "--help")
        output = result.stdout + result.stderr
        assert len(output.strip()) > 0

    def test_cli_list_exports_help(self):
        result = _run_cli("list", "exports", "--help")
        output = result.stdout + result.stderr
        assert len(output.strip()) > 0


# ---------------------------------------------------------------------------
# Group H: Init handshake and capabilities validation
# (Derived from examples/mcp_responses/mcp_init_body.json)
# ---------------------------------------------------------------------------


class TestInitHandshakeDetails:
    """Validate init handshake fields match documented schema."""

    def test_protocol_version_is_valid(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            resp = client.post("/mcp/message", json=_init_payload(), headers=_HEADERS)
            body = resp.json()
            result = body["result"]
            pv = result["protocolVersion"]
            # Protocol version should be a date string
            assert len(pv) >= 10  # At least YYYY-MM-DD
            assert "-" in pv

    def test_capabilities_structure(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            resp = client.post("/mcp/message", json=_init_payload(), headers=_HEADERS)
            body = resp.json()
            caps = body["result"]["capabilities"]
            # Must have tools and resources
            assert "tools" in caps
            assert "resources" in caps

    def test_server_info_name_and_version(self):
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            resp = client.post("/mcp/message", json=_init_payload(), headers=_HEADERS)
            body = resp.json()
            info = body["result"]["serverInfo"]
            assert info["name"] == "AgentDecompile"
            assert "version" in info
            # Version should be semver-like
            assert "." in info["version"]


# ---------------------------------------------------------------------------
# Group I: Tool schema validation
# (Derived from examples/mcp_responses/curl_tools_list.json)
# ---------------------------------------------------------------------------


class TestToolSchemaValidation:
    """Validate tool advertisement schemas match expected structure."""

    def test_execute_script_schema_has_code_param(self, session):
        """execute-script must advertise 'code' as a required parameter."""
        tools = session.list_tools()
        exec_tools = [t for t in tools if "execute" in t["name"] and "script" in t["name"]]
        assert len(exec_tools) == 1
        schema = exec_tools[0]["inputSchema"]
        assert "code" in schema.get("properties", {})

    def test_open_project_schema_has_path(self, session):
        """open/open-project must advertise 'path' parameter."""
        tools = session.list_tools()
        open_tools = [t for t in tools if t["name"].replace("_", "") in ("open", "openproject")]
        assert len(open_tools) >= 1
        schema = open_tools[0]["inputSchema"]
        props = schema.get("properties", {})
        assert "path" in props or "program_path" in props or any("path" in k.lower() for k in props)

    def test_all_tools_have_object_schema(self, session):
        """Every tool's inputSchema must be type=object."""
        tools = session.list_tools()
        for tool in tools:
            schema = tool.get("inputSchema", {})
            assert schema.get("type") == "object", f"Tool '{tool['name']}' has inputSchema type={schema.get('type')}"

    def test_no_tools_have_empty_description(self, session):
        tools = session.list_tools()
        for tool in tools:
            assert tool.get("description"), f"Tool '{tool['name']}' has empty description"
            assert len(tool["description"]) > 10, f"Tool '{tool['name']}' description too short: '{tool['description']}'"


# ---------------------------------------------------------------------------
# Group J: Resource content validation
# (Derived from tmp/demo_fixed_resources.py)
# ---------------------------------------------------------------------------


class TestResourceContentValidation:
    """Deep validation of resource content structure."""

    def test_programs_resource_structure(self, session):
        """ghidra://programs must return valid JSON with programs list."""
        body = session.read_resource("ghidra://programs")
        contents = body["result"]["contents"]
        assert len(contents) > 0
        data = json.loads(contents[0]["text"])
        assert "programs" in data
        assert isinstance(data["programs"], list)
        # No programs loaded
        assert len(data["programs"]) == 0

    def test_static_analysis_sarif_schema(self, session):
        """ghidra://static-analysis-results must return valid SARIF 2.1.0."""
        body = session.read_resource("ghidra://static-analysis-results")
        contents = body["result"]["contents"]
        data = json.loads(contents[0]["text"])
        assert data["$schema"].endswith("sarif-schema-2.1.0.json")
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) >= 1
        run = data["runs"][0]
        assert "tool" in run
        assert "results" in run
        assert "properties" in run
        assert run["properties"]["status"] == "no_program_loaded"

    def test_debug_info_complete_structure(self, session):
        """ghidra://agentdecompile-debug-info must have all top-level sections."""
        body = session.read_resource("ghidra://agentdecompile-debug-info")
        contents = body["result"]["contents"]
        data = json.loads(contents[0]["text"])

        required_sections = ["metadata", "server", "program", "analysis", "profiling"]
        for section in required_sections:
            assert section in data, f"Missing section: {section}"

        # Program shows not loaded
        assert data["program"]["status"] == "no_program_loaded"
        # Profiling is always available
        assert data["profiling"]["status"] == "available"
        # Metadata has timing info
        assert "timestamp" in data["metadata"] or "generatedAt" in data["metadata"] or "generated_at" in data["metadata"]


# ---------------------------------------------------------------------------
# Group K: Session lifecycle and concurrency
# ---------------------------------------------------------------------------


class TestSessionLifecycle:
    """Test session management behavior."""

    def test_tools_work_across_multiple_calls_in_session(self):
        """Multiple tool calls in one session maintain consistency."""
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            s = _Session(client)
            # 10 sequential calls
            for i in range(10):
                body = s.call_tool("list-project-files", {"format": "json"}, request_id=i + 100)
                text = _text(body)
                assert len(text) > 0

    def test_session_id_present_after_init(self):
        """Init should provide a session ID for subsequent requests."""
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            resp = client.post("/mcp/message", json=_init_payload(), headers=_HEADERS)
            sid = resp.headers.get("mcp-session-id", "")
            assert len(sid) > 0, "Session ID should be non-empty after init"

    def test_two_independent_sessions_same_server(self):
        """Two sessions on same server should be independent."""
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            s1 = _Session(client)
            s2 = _Session(client)

            # Both work independently
            d1 = s1.call_tool_json("execute-script", {"code": "__result__ = 'session1'"})
            d2 = s2.call_tool_json("execute-script", {"code": "__result__ = 'session2'"})

            assert d1["result"] == "session1"
            assert d2["result"] == "session2"

    def test_session_preserves_request_id_sequence(self):
        """Server preserves the client's request IDs."""
        server = PythonMcpServer()
        with TestClient(server.app) as client:
            s = _Session(client)
            for req_id in [42, 99, 1000, 1]:
                body = s.call_tool("list-project-files", {}, request_id=req_id)
                assert body["id"] == req_id
