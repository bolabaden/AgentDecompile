"""Unit tests for StringToolProvider.

Covers:
- manage-strings schema and mode enum
- list-strings alias always sets mode=list
- search-strings alias
- HANDLERS normalization
- Error handling without program
- Argument normalization: pattern/query/search/text all resolve
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from agentdecompile_cli.mcp_server.providers.strings import StringToolProvider
from agentdecompile_cli.registry import normalize_identifier as n
from tests.helpers import assert_tool_schema_invariants, parse_single_text_content_json


def _make_provider(with_program: bool = False) -> StringToolProvider:
    if not with_program:
        return StringToolProvider(program_info=None)
    pi = MagicMock()
    pi.program = MagicMock()
    return StringToolProvider(program_info=pi)


def _parse(resp) -> dict:
    return parse_single_text_content_json(resp)


class TestStringProviderSchema:
    def test_tools_advertised(self):
        p = _make_provider()
        names = {t.name for t in p.list_tools()}
        for tool in p.list_tools():
            assert_tool_schema_invariants(tool)
        assert "manage-strings" in names
        assert "list-strings" in names
        assert "search-strings" in names

    def test_manage_strings_mode_enum(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "manage-strings")
        assert_tool_schema_invariants(tool, expected_name="manage-strings")
        modes = tool.inputSchema["properties"]["mode"]["enum"]
        for m in ("list", "regex", "count", "similarity"):
            assert m in modes

    def test_manage_strings_mode_default_list(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "manage-strings")
        assert_tool_schema_invariants(tool, expected_name="manage-strings")
        assert tool.inputSchema["properties"]["mode"].get("default") == "list"

    def test_manage_strings_pattern_param(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "manage-strings")
        assert_tool_schema_invariants(tool, expected_name="manage-strings")
        props = tool.inputSchema["properties"]
        assert "pattern" in props or "query" in props

    def test_list_strings_has_min_length(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "list-strings")
        assert_tool_schema_invariants(tool, expected_name="list-strings")
        assert "minLength" in tool.inputSchema["properties"]

    def test_search_strings_has_mode(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "search-strings")
        assert_tool_schema_invariants(tool, expected_name="search-strings")
        props = tool.inputSchema["properties"]
        assert "mode" in props

    def test_include_referencing_functions_param(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "manage-strings")
        assert_tool_schema_invariants(tool, expected_name="manage-strings")
        assert "includeReferencingFunctions" in tool.inputSchema["properties"]


class TestStringProviderHandlers:
    def test_handler_keys_normalized(self):
        for key in StringToolProvider.HANDLERS:
            assert key == n(key)

    def test_managestrings_present(self):
        assert "managestrings" in StringToolProvider.HANDLERS

    def test_liststrings_alias_present(self):
        assert "liststrings" in StringToolProvider.HANDLERS

    def test_searchstrings_alias_present(self):
        assert "searchstrings" in StringToolProvider.HANDLERS


class TestStringProviderValidation:
    @pytest.mark.asyncio
    async def test_no_program_returns_error(self):
        p = _make_provider(with_program=False)
        resp = await p.call_tool("manage-strings", {})
        result = _parse(resp)
        assert result.get("success") is False or "error" in result

    @pytest.mark.asyncio
    async def test_list_strings_sets_mode_list(self):
        """list-strings alias should force mode=list."""
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        captured = {}

        async def capture(args):
            captured.update(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_error_response
            return create_error_response("mocked")

        p._handle = capture
        await p.call_tool("list-strings", {})
        assert captured.get("mode") == "list"

    @pytest.mark.asyncio
    async def test_search_strings_routes_to_handle(self):
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        called = []

        async def capture(args):
            called.append(True)
            from agentdecompile_cli.mcp_server.tool_providers import create_error_response
            return create_error_response("mocked")

        p._handle = capture
        await p.call_tool("search-strings", {"query": "hello"})
        assert len(called) == 1


class TestStringProviderArgNormalization:
    @pytest.mark.asyncio
    async def test_query_accepted_as_pattern(self):
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        received = {}

        async def capture(args):
            received.update(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_error_response
            return create_error_response("mocked")

        p._handle = capture
        await p.call_tool("manage-strings", {"query": "test_str", "mode": "regex"})
        assert "query" in received

    @pytest.mark.asyncio
    async def test_minlength_normalized(self):
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        received = {}

        async def capture(args):
            received.update(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_error_response
            return create_error_response("mocked")

        p._handle = capture
        await p.call_tool("manage-strings", {"minLength": 8})
        assert "minlength" in received
        assert received["minlength"] == 8
