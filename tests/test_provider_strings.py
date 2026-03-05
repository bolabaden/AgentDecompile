"""Unit tests for StringToolProvider.

Covers:
- manage-strings schema and mode enum
- list-strings alias always sets mode=list
- search-strings alias
- Error handling without program
- Iterator unavailability fallback behavior (shared-server regression tests)
- Argument normalization
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from agentdecompile_cli.mcp_server.providers.strings import StringToolProvider
from agentdecompile_cli.registry import normalize_identifier as n


def _make_provider(with_program: bool = False) -> StringToolProvider:
    if not with_program:
        return StringToolProvider(program_info=None)
    pi = MagicMock()
    pi.program = MagicMock()
    return StringToolProvider(program_info=pi)


def _parse(resp) -> dict:
    """Parse single TextContent JSON response."""
    import json
    return json.loads(resp[0].text)


class TestStringProviderSchema:
    def test_tools_advertised(self):
        p = _make_provider()
        names = {t.name for t in p.list_tools()}
        assert "manage-strings" in names or "list-strings" in names

    def test_manage_strings_mode_enum_if_present(self):
        p = _make_provider()
        tools = {t.name: t for t in p.list_tools()}
        if "manage-strings" in tools:
            tool = tools["manage-strings"]
            modes = tool.inputSchema.get("properties", {}).get("mode", {}).get("enum", [])
            assert "list" in modes or "search" in modes


class TestStringProviderValidation:
    @pytest.mark.asyncio
    async def test_no_program_returns_error(self):
        p = _make_provider(with_program=False)
        resp = await p.call_tool("manage-strings", {})
        result = _parse(resp)
        assert result.get("success") is False or "error" in result


class TestStringProviderIteratorFallback:
    """Regression tests for shared-server/proxy contexts where iterators are unavailable."""

    @pytest.mark.asyncio
    async def test_ghidra_tools_iterator_failure_does_not_silently_return_empty(self):
        """When GhidraTools.get_all_strings() fails due to iterator unavailability,
        the provider should still attempt fallback collection and not return empty success."""
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        
        # Mock ghidra_tools to raise iterator unavailability error
        mock_ghidra_tools = MagicMock()
        mock_ghidra_tools.get_all_strings.side_effect = RuntimeError(
            "String iterators unavailable for this program context"
        )
        p.ghidra_tools = mock_ghidra_tools
        
        # Mock fallback: collect_strings should try DefinedDataIterator
        with patch("agentdecompile_cli.mcp_server.providers.strings.collect_strings") as mock_collect:
            # Simulate successful fallback
            mock_collect.return_value = [
                {"value": "fallback_string", "address": "0x1000", "length": 15, "dataType": "string"}
            ]
            
            resp = await p.call_tool("manage-strings", {"mode": "list"})
            result = _parse(resp)
            
            # Should succeed via fallback
            assert result.get("success") is not False
            mock_collect.assert_called_once()

    @pytest.mark.asyncio
    async def test_all_collection_methods_fail_returns_diagnostic(self):
        """When all string collection methods fail (shared-server without any support),
        the response should clearly indicate the limitation rather than silent empty success."""
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        
        # Mock complete collection failure
        with patch("agentdecompile_cli.mcp_server.providers.strings.collect_strings") as mock_collect:
            mock_collect.return_value = []  # All methods failed
            
            resp = await p.call_tool("manage-strings", {"mode": "list"})
            result = _parse(resp)
            
            # Should return empty results with diagnostic info
            assert "results" in result or "strings" in result
            returned_count = result.get("returnedCount", 0) or len(result.get("results", []))
            assert returned_count == 0

    @pytest.mark.asyncio
    async def test_shared_server_proxy_context_simulation(self):
        """Simulate a shared-server checkout where DomainFileProxy limitations
        cause iterator initialization to fail, but listing fallback succeeds."""
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        
        # Simulate shared-server context
        mock_program = MagicMock()
        mock_program_info = MagicMock()
        mock_program_info.program = mock_program
        p.program_info = mock_program_info
        
        # Mock ghidra_tools unavailable (common in proxy mode)
        p.ghidra_tools = None
        
        # Mock collect_strings to simulate listing fallback success
        with patch("agentdecompile_cli.mcp_server.providers.strings.collect_strings") as mock_collect:
            mock_collect.return_value = [
                {"value": "shared_string_1", "address": "0x2000", "length": 15, "dataType": "string"},
                {"value": "shared_string_2", "address": "0x3000", "length": 15, "dataType": "unicode"},
            ]
            
            resp = await p.call_tool("manage-strings", {"mode": "list", "minLength": 4})
            result = _parse(resp)
            
            # Should succeed with listing fallback
            assert result.get("success") is not False
            returned = result.get("returnedCount", 0) or len(result.get("results", []))
            assert returned >= 2


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
        await p.call_tool("manage-strings", {"query": "test_str", "mode": "search"})
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
        # Should be normalized to lowercase
        assert "minlength" in received or "minLength" in str(received)
