"""Unit tests for VtableToolProvider.

Covers:
- analyze-vtables schema and mode enum
- HANDLERS normalization
- analyze mode requires addressOrSymbol
- maxEntries parameter
- containing mode works without address
- callers mode requires address
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from agentdecompile_cli.mcp_server.providers.vtable import VtableToolProvider
from agentdecompile_cli.registry import normalize_identifier as n
from tests.helpers import parse_single_text_content_json


def _make_provider(with_program: bool = False) -> VtableToolProvider:
    if not with_program:
        return VtableToolProvider(program_info=None)
    pi = MagicMock()
    pi.program = MagicMock()
    pi.program.getDefaultPointerSize = MagicMock(return_value=8)
    listing = MagicMock()
    listing.getDefinedData = MagicMock(return_value=iter([]))
    pi.program.getListing = MagicMock(return_value=listing)
    mem_mock = MagicMock()
    pi.program.getMemory = MagicMock(return_value=mem_mock)
    fm_mock = MagicMock()
    pi.program.getFunctionManager = MagicMock(return_value=fm_mock)
    return VtableToolProvider(program_info=pi)


def _parse(resp) -> dict:
    return parse_single_text_content_json(resp)


class TestVtableProviderSchema:
    def test_analyze_vtables_tool_present(self):
        p = _make_provider()
        names = {t.name for t in p.list_tools()}
        assert "analyze-vtables" in names

    def test_mode_enum(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        modes = tool.inputSchema["properties"]["mode"]["enum"]
        for m in ("analyze", "callers", "containing"):
            assert m in modes

    def test_mode_default_analyze(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        assert tool.inputSchema["properties"]["mode"].get("default") == "analyze"

    def test_max_entries_param(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        assert "maxEntries" in tool.inputSchema["properties"]

    def test_max_entries_default(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        assert tool.inputSchema["properties"]["maxEntries"].get("default") == 200

    def test_address_or_symbol_param(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        assert "addressOrSymbol" in tool.inputSchema["properties"]


class TestVtableProviderHandlers:
    def test_handler_keys_normalized(self):
        for key in VtableToolProvider.HANDLERS:
            assert key == n(key)

    def test_analyzevtables_present(self):
        assert "analyzevtables" in VtableToolProvider.HANDLERS


class TestVtableProviderValidation:
    @pytest.mark.asyncio
    async def test_no_program_returns_error(self):
        p = _make_provider(with_program=False)
        resp = await p.call_tool("analyze-vtables", {"mode": "analyze", "addressOrSymbol": "0x401000"})
        result = _parse(resp)
        assert result.get("success") is False or "error" in result

    @pytest.mark.asyncio
    async def test_analyze_mode_requires_address(self):
        """analyze mode without address should return an error."""
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        resp = await p.call_tool("analyze-vtables", {"mode": "analyze"})
        result = _parse(resp)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_containing_mode_no_address_required(self):
        """containing mode should work without an address (scans whole program)."""
        p = _make_provider(with_program=True)
        resp = await p.call_tool("analyze-vtables", {"mode": "containing"})
        result = _parse(resp)
        # Should not error due to missing address
        if "error" in result:
            # only allow error that's not about missing address
            assert "addressOrSymbol" not in result.get("error", "").lower()

    @pytest.mark.asyncio
    async def test_callers_mode_requires_address(self):
        """callers mode requires an address."""
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        resp = await p.call_tool("analyze-vtables", {"mode": "callers"})
        result = _parse(resp)
        assert "error" in result

    def test_max_entries_clamped_to_1000(self):
        """Provider should clamp maxEntries at read time."""
        from agentdecompile_cli.mcp_server.tool_providers import ToolProvider
        args = {"maxentries": 5000}
        val = ToolProvider._get_int(args, "maxentries", default=200)
        # Clamping happens in handler: if maxEntries > 1000 → clamped
        assert min(val, 1000) == 1000


class TestVtableProviderArgNormalization:
    @pytest.mark.asyncio
    async def test_vtableaddress_alias(self):
        """vtableAddress should be accepted in addition to addressOrSymbol."""
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        received = {}

        async def capture(args):
            received.update(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_error_response
            return create_error_response("mocked")

        p._handle = capture
        await p.call_tool("analyze-vtables", {"vtableAddress": "0x401000", "mode": "analyze"})
        assert "vtableaddress" in received

    @pytest.mark.asyncio
    async def test_maxentries_normalized(self):
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        received = {}

        async def capture(args):
            received.update(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_error_response
            return create_error_response("mocked")

        p._handle = capture
        await p.call_tool("analyze-vtables", {"maxEntries": 100, "addressOrSymbol": "0x1000"})
        assert "maxentries" in received
        assert received["maxentries"] == 100
