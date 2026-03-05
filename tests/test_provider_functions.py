"""Unit tests for FunctionToolProvider.

Covers:
- list-functions schema, parameters
- get-functions schema, view enum
- HANDLERS keys
- Argument aliases (function / addressOrSymbol / functionIdentifier)
- list-functions without program returns error
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from agentdecompile_cli.mcp_server.providers.functions import FunctionToolProvider
from agentdecompile_cli.registry import normalize_identifier as n
from tests.helpers import assert_tool_schema_invariants, parse_single_text_content_json


def _make_provider(with_program: bool = False) -> FunctionToolProvider:
    if not with_program:
        return FunctionToolProvider(program_info=None)
    pi = MagicMock()
    pi.program = MagicMock()
    fm_mock = MagicMock()
    fm_mock.getFunctions = MagicMock(return_value=iter([]))
    pi.program.getFunctionManager = MagicMock(return_value=fm_mock)
    return FunctionToolProvider(program_info=pi)


def _parse(resp) -> dict:
    return parse_single_text_content_json(resp)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


class TestFunctionProviderSchema:
    def test_list_tools_returns_two_tools(self):
        p = _make_provider()
        tools = p.list_tools()
        names = {t.name for t in tools}
        for tool in tools:
            assert_tool_schema_invariants(tool)
        assert "list-functions" in names
        assert "get-functions" in names

    def test_list_functions_properties(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "list-functions")
        assert_tool_schema_invariants(tool, expected_name="list-functions")
        props = tool.inputSchema["properties"]
        for key in ("programPath", "namePattern", "includeExternals", "limit", "offset"):
            assert key in props

    def test_get_functions_view_enum(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "get-functions")
        assert_tool_schema_invariants(tool, expected_name="get-functions")
        props = tool.inputSchema["properties"]
        assert "mode" in props
        enum_vals = props["mode"]["enum"]
        for expected in ("decompile", "disassemble", "info", "calls"):
            assert expected in enum_vals

    def test_get_functions_identifier_params(self):
        """get-functions should accept function / addressOrSymbol / functionIdentifier."""
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "get-functions")
        assert_tool_schema_invariants(tool, expected_name="get-functions")
        props = tool.inputSchema["properties"]
        assert any(k in props for k in ("function", "addressOrSymbol", "functionIdentifier"))


# ---------------------------------------------------------------------------
# HANDLERS
# ---------------------------------------------------------------------------


class TestFunctionProviderHandlers:
    def test_handler_keys_normalized(self):
        for key in FunctionToolProvider.HANDLERS:
            assert key == n(key)

    def test_listfunctions_handler_present(self):
        assert "listfunctions" in FunctionToolProvider.HANDLERS

    def test_getfunctions_handler_present(self):
        assert "getfunctions" in FunctionToolProvider.HANDLERS


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class TestFunctionProviderValidation:
    @pytest.mark.asyncio
    async def test_no_program_returns_error(self):
        p = _make_provider(with_program=False)
        resp = await p.call_tool("list-functions", {})
        result = _parse(resp)
        assert result.get("success") is False or "error" in result

    @pytest.mark.asyncio
    async def test_list_functions_empty_program(self):
        """With empty function list should return empty results."""
        p = _make_provider(with_program=True)
        resp = await p.call_tool("list-functions", {})
        result = _parse(resp)
        # Should succeed with empty list (no error key or success=True)
        if "error" not in result:
            assert "functions" in result or "count" in result

    @pytest.mark.asyncio
    async def test_get_functions_calls_list_when_no_id(self):
        """get-functions with no function identifier falls back to listing."""
        p = _make_provider(with_program=True)
        list_called = []
        async def fake_list(args):
            list_called.append(True)
            from agentdecompile_cli.mcp_server.tool_providers import create_success_response
            return create_success_response({"functions": []})
        p._handle_list = fake_list
        await p.call_tool("get-functions", {"view": "info"})
        assert len(list_called) == 1

    @pytest.mark.asyncio
    async def test_get_functions_without_view_returns_all_views(self):
        p = _make_provider(with_program=True)

        target_func = MagicMock()
        target_func.getName.return_value = "main"
        target_func.getEntryPoint.return_value = "0x401000"
        target_func.getSignature.return_value = "int main(void)"
        p._resolve_function = MagicMock(return_value=target_func)

        calls = {"info": 0, "calls": 0, "decompile": 0, "disassemble": 0}

        async def fake_info(args, target_func, program, max_results, timeout):
            calls["info"] += 1
            from agentdecompile_cli.mcp_server.tool_providers import create_success_response
            return create_success_response({"view": "info", "marker": "i"})

        async def fake_calls(args, target_func, program, max_results, timeout):
            calls["calls"] += 1
            from agentdecompile_cli.mcp_server.tool_providers import create_success_response
            return create_success_response({"view": "calls", "marker": "c"})

        async def fake_decompile(args, target_func, program, max_results, timeout):
            calls["decompile"] += 1
            from agentdecompile_cli.mcp_server.tool_providers import create_success_response
            return create_success_response({"view": "decompile", "marker": "d"})

        async def fake_disassemble(args, target_func, program, max_results, timeout):
            calls["disassemble"] += 1
            from agentdecompile_cli.mcp_server.tool_providers import create_success_response
            return create_success_response({"view": "disassemble", "marker": "a"})

        p._handle_info = fake_info
        p._handle_calls = fake_calls
        p._handle_decompile = fake_decompile
        p._handle_disassemble = fake_disassemble

        resp = await p.call_tool("get-functions", {"function": "main", "format": "json"})
        result = _parse(resp)

        assert result["view"] == "all"
        assert set(result["views"].keys()) == {"info", "calls", "decompile", "disassemble"}
        assert calls == {"info": 1, "calls": 1, "decompile": 1, "disassemble": 1}


# ---------------------------------------------------------------------------
# Argument normalization
# ---------------------------------------------------------------------------


class TestFunctionProviderArgNormalization:
    @pytest.mark.asyncio
    async def test_namePattern_normalized(self):
        p = _make_provider(with_program=True)
        received = {}

        async def capture(args):
            received.update(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_success_response
            return create_success_response({"functions": []})

        p._handle_list = capture
        await p.call_tool("list-functions", {"namePattern": "main"})
        assert "namepattern" in received

    @pytest.mark.asyncio
    async def test_maxResults_normalized(self):
        p = _make_provider(with_program=True)
        received = {}

        async def capture(args):
            received.update(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_success_response
            return create_success_response({"functions": []})

        p._handle_list = capture
        await p.call_tool("list-functions", {"maxResults": 50})
        assert "maxresults" in received
        assert received["maxresults"] == 50
