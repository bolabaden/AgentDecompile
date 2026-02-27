"""Unit tests for CallGraphToolProvider.

Covers:
- get-call-graph and gen-callgraph (pyghidra-mcp alias) schema
- HANDLERS normalization
- Mode enum: graph, tree, callers, callees, callers_decomp, common_callers
- Direction enum: calling, called
- Requires function/addressOrSymbol
- maxDepth, condenseThreshold, topLayers, bottomLayers, maxNodes params
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from agentdecompile_cli.mcp_server.providers.callgraph import CallGraphToolProvider
from agentdecompile_cli.registry import normalize_identifier as n
from tests.helpers import assert_tool_schema_invariants, parse_single_text_content_json


def _make_provider(with_program: bool = False) -> CallGraphToolProvider:
    if not with_program:
        return CallGraphToolProvider(program_info=None)
    pi = MagicMock()
    pi.program = MagicMock()
    return CallGraphToolProvider(program_info=pi)


def _parse(resp) -> dict:
    return parse_single_text_content_json(resp)


class TestCallGraphProviderSchema:
    def test_tools_advertised(self):
        p = _make_provider()
        names = {t.name for t in p.list_tools()}
        for tool in p.list_tools():
            assert_tool_schema_invariants(tool)
        assert "get-call-graph" in names
        assert "gen-callgraph" in names

    def test_mode_enum(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "get-call-graph")
        assert_tool_schema_invariants(tool, expected_name="get-call-graph")
        modes = tool.inputSchema["properties"]["mode"]["enum"]
        for m in ("graph", "tree", "callers", "callees", "callers_decomp", "common_callers"):
            assert m in modes

    def test_direction_enum(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "get-call-graph")
        assert_tool_schema_invariants(tool, expected_name="get-call-graph")
        props = tool.inputSchema["properties"]
        assert "direction" in props
        assert "calling" in props["direction"]["enum"]
        assert "called" in props["direction"]["enum"]

    def test_pyghidra_mcp_params_present(self):
        """pyghidra-mcp-specific params should be present in schema."""
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "gen-callgraph")
        assert_tool_schema_invariants(tool, expected_name="gen-callgraph")
        props = tool.inputSchema["properties"]
        for param in ("condenseThreshold", "topLayers", "bottomLayers", "maxRunTime"):
            assert param in props, f"Missing pyghidra-mcp param '{param}'"

    def test_second_function_param(self):
        """common_callers mode needs a secondFunction parameter."""
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "get-call-graph")
        assert_tool_schema_invariants(tool, expected_name="get-call-graph")
        props = tool.inputSchema["properties"]
        assert "secondFunction" in props

    def test_function_identifier_params(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "get-call-graph")
        assert_tool_schema_invariants(tool, expected_name="get-call-graph")
        props = tool.inputSchema["properties"]
        assert any(k in props for k in ("function", "addressOrSymbol", "functionIdentifier"))


class TestCallGraphProviderHandlers:
    def test_handler_keys_normalized(self):
        for key in CallGraphToolProvider.HANDLERS:
            assert key == n(key)

    def test_getcallgraph_present(self):
        assert "getcallgraph" in CallGraphToolProvider.HANDLERS

    def test_gencallgraph_alias_present(self):
        """gen-callgraph is the pyghidra-mcp alias and must be routed."""
        assert "gencallgraph" in CallGraphToolProvider.HANDLERS

    def test_both_aliases_route_to_same_method(self):
        assert CallGraphToolProvider.HANDLERS["getcallgraph"] == CallGraphToolProvider.HANDLERS["gencallgraph"]


class TestCallGraphProviderValidation:
    @pytest.mark.asyncio
    async def test_no_program_returns_error(self):
        p = _make_provider(with_program=False)
        resp = await p.call_tool("get-call-graph", {"function": "main"})
        result = _parse(resp)
        assert result.get("success") is False or "error" in result

    @pytest.mark.asyncio
    async def test_missing_function_returns_error(self):
        """Function is required because callgraph needs an entry point."""
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        resp = await p.call_tool("get-call-graph", {})
        result = _parse(resp)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_gen_callgraph_routes_to_same_handler(self):
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        calls = []

        async def capture(args):
            calls.append(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_error_response

            return create_error_response("mocked")

        p._handle = capture
        await p.call_tool("gen-callgraph", {"function": "main"})
        await p.call_tool("get-call-graph", {"function": "main"})
        assert len(calls) == 2

    @pytest.mark.asyncio
    async def test_mode_normalized_in_args(self):
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        received = {}

        async def capture(args):
            received.update(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_error_response

            return create_error_response("mocked")

        p._handle = capture
        await p.call_tool("get-call-graph", {"function": "main", "maxDepth": "5"})
        # maxDepth → "maxdepth" after normalization
        assert "maxdepth" in received
