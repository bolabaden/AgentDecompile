"""Unit tests for DecompilerToolProvider.

Covers:
- decompile-function schema
- HANDLERS: decompile + decompilefunction both present
- Requires function/addressOrSymbol
- Argument normalization
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from agentdecompile_cli.mcp_server.providers.decompiler import DecompilerToolProvider
from agentdecompile_cli.registry import normalize_identifier as n
from tests.helpers import assert_tool_schema_invariants, parse_single_text_content_json


def _make_provider(with_program: bool = False) -> DecompilerToolProvider:
    if not with_program:
        return DecompilerToolProvider(program_info=None)
    pi = MagicMock()
    pi.program = MagicMock()
    return DecompilerToolProvider(program_info=pi)


def _parse(resp) -> dict:
    return parse_single_text_content_json(resp)


class TestDecompilerProviderSchema:
    def test_list_tools_has_decompile_function(self):
        p = _make_provider()
        names = {t.name for t in p.list_tools()}
        for tool in p.list_tools():
            assert_tool_schema_invariants(tool)
        assert "decompile-function" in names

    def test_decompile_function_schema(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "decompile-function")
        assert_tool_schema_invariants(tool, expected_name="decompile-function")
        props = tool.inputSchema["properties"]
        assert "programPath" in props
        # Should accept function OR addressOrSymbol OR functionIdentifier
        assert any(k in props for k in ("function", "addressOrSymbol", "functionIdentifier"))

    def test_timeout_param_exists(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "decompile-function")
        assert_tool_schema_invariants(tool, expected_name="decompile-function")
        props = tool.inputSchema["properties"]
        assert "timeout" in props


class TestDecompilerProviderHandlers:
    def test_handler_keys_normalized(self):
        for key in DecompilerToolProvider.HANDLERS:
            assert key == n(key)

    def test_decompile_handler_present(self):
        assert "decompile" in DecompilerToolProvider.HANDLERS

    def test_decompilefunction_handler_present(self):
        """decompilefunction is a GhidraMCP/pyghidra-mcp alias."""
        assert "decompilefunction" in DecompilerToolProvider.HANDLERS

    def test_both_aliases_route_to_same_method(self):
        assert (DecompilerToolProvider.HANDLERS["decompile"]
                == DecompilerToolProvider.HANDLERS["decompilefunction"])


class TestDecompilerProviderValidation:
    @pytest.mark.asyncio
    async def test_no_program_returns_error(self):
        p = _make_provider(with_program=False)
        resp = await p.call_tool("decompile-function", {"function": "main"})
        result = _parse(resp)
        assert result.get("success") is False or "error" in result

    @pytest.mark.asyncio
    async def test_missing_function_returns_error(self):
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        resp = await p.call_tool("decompile-function", {})
        result = _parse(resp)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_function_arg_aliases(self):
        """function, addressOrSymbol, functionIdentifier all map to same field."""
        p = _make_provider(with_program=True)
        received = {}

        async def capture(args):
            received.update(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_error_response
            return create_error_response("mocked")

        p._handle = capture
        await p.call_tool("decompile-function", {"functionIdentifier": "my_func"})
        assert "functionidentifier" in received

    @pytest.mark.asyncio
    async def test_addressorsymbol_alias(self):
        p = _make_provider(with_program=True)
        received = {}

        async def capture(args):
            received.update(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_error_response
            return create_error_response("mocked")

        p._handle = capture
        await p.call_tool("decompile-function", {"addressOrSymbol": "0x401000"})
        assert "addressorsymbol" in received
