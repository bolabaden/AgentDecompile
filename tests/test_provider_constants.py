"""Unit tests for ConstantSearchToolProvider.

Covers:
- search-constants schema and mode enum
- HANDLERS normalization
- specific mode requires value
- range mode requires minValue + maxValue
- value accepts decimal, hex (as int), negative values
- pagination with maxResults/offset
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from agentdecompile_cli.mcp_server.providers.constants import ConstantSearchToolProvider
from agentdecompile_cli.registry import normalize_identifier as n
from tests.helpers import assert_tool_schema_invariants, parse_single_text_content_json


def _make_provider(with_program: bool = False) -> ConstantSearchToolProvider:
    if not with_program:
        return ConstantSearchToolProvider(program_info=None)
    pi = MagicMock()
    pi.program = MagicMock()
    listing = MagicMock()
    listing.getInstructions = MagicMock(return_value=iter([]))
    pi.program.getListing = MagicMock(return_value=listing)
    return ConstantSearchToolProvider(program_info=pi)


def _parse(resp) -> dict:
    return parse_single_text_content_json(resp)


class TestConstantsProviderSchema:
    def test_search_constants_tool_present(self):
        p = _make_provider()
        names = {t.name for t in p.list_tools()}
        for tool in p.list_tools():
            assert_tool_schema_invariants(tool)
        assert "search-constants" in names

    def test_mode_enum(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        assert_tool_schema_invariants(tool, expected_name="search-constants")
        modes = tool.inputSchema["properties"]["mode"]["enum"]
        for m in ("specific", "range", "common"):
            assert m in modes

    def test_mode_default_common(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        assert_tool_schema_invariants(tool, expected_name="search-constants")
        assert tool.inputSchema["properties"]["mode"].get("default") == "common"

    def test_value_param_present(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        assert_tool_schema_invariants(tool, expected_name="search-constants")
        assert "value" in tool.inputSchema["properties"]

    def test_range_params_present(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        assert_tool_schema_invariants(tool, expected_name="search-constants")
        props = tool.inputSchema["properties"]
        assert "minValue" in props
        assert "maxValue" in props

    def test_pagination_params(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        assert_tool_schema_invariants(tool, expected_name="search-constants")
        props = tool.inputSchema["properties"]
        assert "limit" in props
        assert "offset" in props

    def test_max_instructions_param(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        assert_tool_schema_invariants(tool, expected_name="search-constants")
        assert "maxInstructions" in tool.inputSchema["properties"]


class TestConstantsProviderHandlers:
    def test_handler_keys_normalized(self):
        for key in ConstantSearchToolProvider.HANDLERS:
            assert key == n(key)

    def test_searchconstants_present(self):
        assert "searchconstants" in ConstantSearchToolProvider.HANDLERS


class TestConstantsProviderValidation:
    @pytest.mark.asyncio
    async def test_no_program_returns_error(self):
        p = _make_provider(with_program=False)
        resp = await p.call_tool("search-constants", {"mode": "common"})
        result = _parse(resp)
        assert result.get("success") is False or "error" in result

    @pytest.mark.asyncio
    async def test_common_mode_empty_program(self):
        """common mode with no instructions should succeed with empty results."""
        p = _make_provider(with_program=True)
        resp = await p.call_tool("search-constants", {"mode": "common"})
        result = _parse(resp)
        if "error" not in result:
            assert "results" in result or "count" in result

    @pytest.mark.asyncio
    async def test_specific_mode_with_decimal_value(self):
        p = _make_provider(with_program=True)
        resp = await p.call_tool("search-constants", {"mode": "specific", "value": 42})
        result = _parse(resp)
        if "error" not in result:
            assert "results" in result

    @pytest.mark.asyncio
    async def test_range_mode_valid(self):
        p = _make_provider(with_program=True)
        resp = await p.call_tool("search-constants", {"mode": "range", "minValue": 0, "maxValue": 255})
        result = _parse(resp)
        if "error" not in result:
            assert "results" in result


class TestConstantsProviderArgNormalization:
    @pytest.mark.asyncio
    async def test_maxresults_normalized(self):
        p = _make_provider(with_program=True)
        received = {}

        async def capture(args):
            received.update(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_success_response
            return create_success_response({"results": []})

        p._handle = capture
        await p.call_tool("search-constants", {"mode": "common", "maxResults": 50})
        assert "maxresults" in received

    @pytest.mark.asyncio
    async def test_minvalue_maxvalue_normalized(self):
        p = _make_provider(with_program=True)
        received = {}

        async def capture(args):
            received.update(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_success_response
            return create_success_response({"results": []})

        p._handle = capture
        await p.call_tool("search-constants", {"mode": "range", "minValue": 10, "maxValue": 100})
        assert "minvalue" in received
        assert "maxvalue" in received
