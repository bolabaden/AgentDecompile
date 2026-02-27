"""Unit tests for DataFlowToolProvider.

Covers:
- analyze-data-flow schema and direction enum
- HANDLERS normalization
- Requires addressOrSymbol or functionIdentifier
- Direction: backward, forward, variable_accesses
- maxOps, maxDepth, timeout parameters
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from agentdecompile_cli.mcp_server.providers.dataflow import DataFlowToolProvider
from agentdecompile_cli.registry import normalize_identifier as n
from tests.helpers import assert_tool_schema_invariants, parse_single_text_content_json


def _make_provider(with_program: bool = False) -> DataFlowToolProvider:
    if not with_program:
        return DataFlowToolProvider(program_info=None)
    pi = MagicMock()
    pi.program = MagicMock()
    fm_mock = MagicMock()
    fm_mock.getFunctionContaining = MagicMock(return_value=None)
    pi.program.getFunctionManager = MagicMock(return_value=fm_mock)
    return DataFlowToolProvider(program_info=pi)


def _parse(resp) -> dict:
    return parse_single_text_content_json(resp)


class TestDataFlowProviderSchema:
    def test_analyze_data_flow_tool_present(self):
        p = _make_provider()
        names = {t.name for t in p.list_tools()}
        for tool in p.list_tools():
            assert_tool_schema_invariants(tool)
        assert "analyze-data-flow" in names

    def test_direction_enum(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        assert_tool_schema_invariants(tool, expected_name="analyze-data-flow")
        directions = tool.inputSchema["properties"]["direction"]["enum"]
        for d in ("backward", "forward", "variable_accesses"):
            assert d in directions

    def test_direction_default_backward(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        assert_tool_schema_invariants(tool, expected_name="analyze-data-flow")
        assert tool.inputSchema["properties"]["direction"].get("default") == "backward"

    def test_max_ops_param(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        assert_tool_schema_invariants(tool, expected_name="analyze-data-flow")
        assert "maxOps" in tool.inputSchema["properties"]

    def test_max_depth_param(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        assert_tool_schema_invariants(tool, expected_name="analyze-data-flow")
        assert "maxDepth" in tool.inputSchema["properties"]

    def test_timeout_param(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        assert_tool_schema_invariants(tool, expected_name="analyze-data-flow")
        assert "timeout" in tool.inputSchema["properties"]

    def test_address_and_function_params(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        assert_tool_schema_invariants(tool, expected_name="analyze-data-flow")
        props = tool.inputSchema["properties"]
        assert any(k in props for k in ("addressOrSymbol", "functionIdentifier"))


class TestDataFlowProviderHandlers:
    def test_handler_keys_normalized(self):
        for key in DataFlowToolProvider.HANDLERS:
            assert key == n(key)

    def test_analyzedataflow_present(self):
        assert "analyzedataflow" in DataFlowToolProvider.HANDLERS


class TestDataFlowProviderValidation:
    @pytest.mark.asyncio
    async def test_no_program_returns_error(self):
        p = _make_provider(with_program=False)
        resp = await p.call_tool("analyze-data-flow", {"addressOrSymbol": "0x1000"})
        result = _parse(resp)
        assert result.get("success") is False or "error" in result

    @pytest.mark.asyncio
    async def test_missing_address_returns_error(self):
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        resp = await p.call_tool("analyze-data-flow", {"direction": "backward"})
        result = _parse(resp)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_function_identifier_accepted(self):
        """functionIdentifier should be accepted as alternative to addressOrSymbol."""
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        received = {}

        async def capture(args):
            received.update(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_error_response
            return create_error_response("mocked")

        p._handle = capture
        await p.call_tool("analyze-data-flow", {"functionIdentifier": "main"})
        assert "functionidentifier" in received


class TestDataFlowProviderArgNormalization:
    @pytest.mark.asyncio
    async def test_address_or_symbol_camelcase_normalized(self):
        p = _make_provider(with_program=True)
        received = {}

        async def capture(args):
            received.update(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_error_response
            return create_error_response("mocked")

        p._handle = capture
        await p.call_tool("analyze-data-flow", {"addressOrSymbol": "0x1000", "maxOps": 100})
        assert "addressorsymbol" in received
        assert "maxops" in received
        assert received["maxops"] == 100

    @pytest.mark.asyncio
    async def test_snake_case_args_normalized(self):
        p = _make_provider(with_program=True)
        received = {}

        async def capture(args):
            received.update(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_error_response
            return create_error_response("mocked")

        p._handle = capture
        await p.call_tool("analyze-data-flow", {"address_or_symbol": "main", "max_ops": 250, "max_depth": 5})
        assert "addressorsymbol" in received
        assert "maxops" in received
        assert "maxdepth" in received
