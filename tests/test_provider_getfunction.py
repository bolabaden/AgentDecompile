"""Unit tests for GetFunctionToolProvider.

Covers:
- manage-function schema and action enum
- manage-function-tags schema and action enum
- match-function schema and mode enum
- HANDLERS: managefunction, managefunctiontags, matchfunction
- Action-specific required args (rename needs newName, etc.)
- View alias normalization
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from agentdecompile_cli.mcp_server.providers.getfunction import GetFunctionToolProvider
from agentdecompile_cli.registry import normalize_identifier as n
from tests.helpers import assert_tool_schema_invariants, parse_single_text_content_json


def _make_provider(with_program: bool = False) -> GetFunctionToolProvider:
    if not with_program:
        return GetFunctionToolProvider(program_info=None)
    pi = MagicMock()
    pi.program = MagicMock()
    fm_mock = MagicMock()
    fm_mock.getFunctions = MagicMock(return_value=iter([]))
    pi.program.getFunctionManager = MagicMock(return_value=fm_mock)
    pi.program.startTransaction = MagicMock(return_value=1)
    pi.program.endTransaction = MagicMock()
    return GetFunctionToolProvider(program_info=pi)


def _parse(resp) -> dict:
    return parse_single_text_content_json(resp)


class TestGetFunctionProviderSchema:
    def test_tools_advertised(self):
        p = _make_provider()
        names = {t.name for t in p.list_tools()}
        for tool in p.list_tools():
            assert_tool_schema_invariants(tool)
        assert "manage-function" in names
        assert "manage-function-tags" in names
        assert "match-function" in names

    def test_manage_function_action_enum(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "manage-function")
        assert_tool_schema_invariants(tool, expected_name="manage-function")
        actions = tool.inputSchema["properties"]["action"]["enum"]
        for a in ("rename", "set_prototype", "set_calling_convention", "set_return_type", "delete", "create"):
            assert a in actions

    def test_manage_function_tags_action_enum(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "manage-function-tags")
        assert_tool_schema_invariants(tool, expected_name="manage-function-tags")
        actions = tool.inputSchema["properties"]["action"]["enum"]
        for a in ("list", "add", "remove", "search"):
            assert a in actions

    def test_match_function_mode_enum(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "match-function")
        assert_tool_schema_invariants(tool, expected_name="match-function")
        modes = tool.inputSchema["properties"]["mode"]["enum"]
        for m in ("similar", "callers", "callees", "signature"):
            assert m in modes

    def test_match_function_mode_default_similar(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "match-function")
        assert_tool_schema_invariants(tool, expected_name="match-function")
        assert tool.inputSchema["properties"]["mode"].get("default") == "similar"

    def test_function_identifier_params(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "manage-function")
        assert_tool_schema_invariants(tool, expected_name="manage-function")
        props = tool.inputSchema["properties"]
        assert any(k in props for k in ("function", "addressOrSymbol"))

    def test_new_name_param(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "manage-function")
        assert_tool_schema_invariants(tool, expected_name="manage-function")
        assert "newName" in tool.inputSchema["properties"]


class TestGetFunctionProviderHandlers:
    def test_handler_keys_normalized(self):
        for key in GetFunctionToolProvider.HANDLERS:
            assert key == n(key)

    def test_managefunction_present(self):
        assert "managefunction" in GetFunctionToolProvider.HANDLERS

    def test_managefunctiontags_present(self):
        assert "managefunctiontags" in GetFunctionToolProvider.HANDLERS

    def test_matchfunction_present(self):
        assert "matchfunction" in GetFunctionToolProvider.HANDLERS


class TestGetFunctionProviderValidation:
    @pytest.mark.asyncio
    async def test_no_program_returns_error_manage_function(self):
        p = _make_provider(with_program=False)
        resp = await p.call_tool("manage-function", {"action": "rename", "function": "main"})
        result = _parse(resp)
        assert result.get("success") is False or "error" in result

    @pytest.mark.asyncio
    async def test_no_program_returns_error_match_function(self):
        p = _make_provider(with_program=False)
        resp = await p.call_tool("match-function", {"function": "main"})
        result = _parse(resp)
        assert result.get("success") is False or "error" in result

    @pytest.mark.asyncio
    async def test_manage_function_requires_action(self):
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        resp = await p.call_tool("manage-function", {"function": "main"})
        result = _parse(resp)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_rename_dispatches_to_handle_manage(self):
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        called = []

        async def capture(args):
            called.append(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_error_response
            return create_error_response("mocked")

        p._handle_manage = capture
        await p.call_tool("manage-function", {"action": "rename", "function": "main", "newName": "renamed"})
        assert len(called) == 1

    @pytest.mark.asyncio
    async def test_manage_function_tags_dispatches_correctly(self):
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        called = []

        async def capture(args):
            called.append(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_error_response
            return create_error_response("mocked")

        p._handle_tags = capture
        await p.call_tool("manage-function-tags", {"action": "list", "function": "main"})
        assert len(called) == 1

    @pytest.mark.asyncio
    async def test_match_function_dispatches_correctly(self):
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        called = []

        async def capture(args):
            called.append(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_error_response
            return create_error_response("mocked")

        p._handle_match = capture
        await p.call_tool("match-function", {"function": "main", "mode": "similar"})
        assert len(called) == 1


class TestGetFunctionProviderArgNormalization:
    @pytest.mark.asyncio
    async def test_function_identifier_normalized(self):
        p = _make_provider(with_program=True)
        received = {}

        async def capture(args):
            received.update(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_error_response
            return create_error_response("mocked")

        p._handle_manage = capture
        await p.call_tool("manage-function", {"functionIdentifier": "main", "action": "rename", "newName": "foo"})
        assert "functionidentifier" in received

    @pytest.mark.asyncio
    async def test_address_or_symbol_as_function_id(self):
        p = _make_provider(with_program=True)
        received = {}

        async def capture(args):
            received.update(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_error_response
            return create_error_response("mocked")

        p._handle_manage = capture
        await p.call_tool("manage-function", {"addressOrSymbol": "0x401000", "action": "rename", "newName": "bar"})
        assert "addressorsymbol" in received
