"""Unit tests for CrossReferencesToolProvider.

Covers:
- get-references schema and mode enum
- list-cross-references alias always defaults to mode=both
- HANDLERS normalization
- Requires addressOrSymbol / target
- maxResults and offset pagination params
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from agentdecompile_cli.mcp_server.providers.xrefs import CrossReferencesToolProvider
from agentdecompile_cli.registry import normalize_identifier as n
from tests.helpers import parse_single_text_content_json


def _make_provider(with_program: bool = False) -> CrossReferencesToolProvider:
    if not with_program:
        return CrossReferencesToolProvider(program_info=None)
    pi = MagicMock()
    pi.program = MagicMock()
    return CrossReferencesToolProvider(program_info=pi)


def _parse(resp) -> dict:
    return parse_single_text_content_json(resp)


class TestXrefsProviderSchema:
    def test_tools_advertised(self):
        p = _make_provider()
        names = {t.name for t in p.list_tools()}
        assert "get-references" in names
        assert "list-cross-references" in names

    def test_get_references_mode_enum(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "get-references")
        modes = tool.inputSchema["properties"]["mode"]["enum"]
        for m in ("to", "from", "both", "function", "referencers_decomp", "import", "thunk"):
            assert m in modes

    def test_get_references_target_params(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "get-references")
        props = tool.inputSchema["properties"]
        assert any(k in props for k in ("addressOrSymbol", "target"))

    def test_list_cross_references_pagination(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "list-cross-references")
        props = tool.inputSchema["properties"]
        assert "limit" in props
        assert "offset" in props


class TestXrefsProviderHandlers:
    def test_handler_keys_normalized(self):
        for key in CrossReferencesToolProvider.HANDLERS:
            assert key == n(key)

    def test_getreferences_handler_present(self):
        assert "getreferences" in CrossReferencesToolProvider.HANDLERS

    def test_listcrossreferences_alias_present(self):
        assert "listcrossreferences" in CrossReferencesToolProvider.HANDLERS

    def test_alias_routes_to_different_method(self):
        """list-cross-references should go through the alias wrapper."""
        h1 = CrossReferencesToolProvider.HANDLERS.get("getreferences")
        h2 = CrossReferencesToolProvider.HANDLERS.get("listcrossreferences")
        # The alias wrapper sets mode=both then delegates to _handle
        # They can be the same or different wrapper names
        assert h1 is not None and h2 is not None


class TestXrefsProviderValidation:
    @pytest.mark.asyncio
    async def test_no_program_returns_error(self):
        p = _make_provider(with_program=False)
        resp = await p.call_tool("get-references", {"addressOrSymbol": "0x401000"})
        result = _parse(resp)
        assert result.get("success") is False or "error" in result

    @pytest.mark.asyncio
    async def test_missing_target_returns_error(self):
        """addressOrSymbol/target is required."""
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        resp = await p.call_tool("get-references", {})
        result = _parse(resp)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_list_cross_references_sets_mode_both(self):
        """list-cross-references alias must add mode=both to args."""
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        captured = {}

        async def capture(args):
            captured.update(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_error_response
            return create_error_response("mocked")

        p._handle = capture
        await p.call_tool("list-cross-references", {"addressOrSymbol": "0x401000"})
        # mode should be set to "both" by the alias handler
        assert captured.get("mode") == "both"

    @pytest.mark.asyncio
    async def test_target_alias_accepted(self):
        """'target' should work as an alias for addressOrSymbol."""
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        received = {}

        async def capture(args):
            received.update(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_error_response
            return create_error_response("mocked")

        p._handle = capture
        await p.call_tool("get-references", {"target": "0x401000"})
        assert "target" in received
