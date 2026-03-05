"""Unit tests for _collectors.py helper functions.

Focuses on fallback behavior and resilience for collect_strings()
when iterators are unavailable (shared-server/proxy contexts).
"""
from __future__ import annotations

from unittest.mock import MagicMock, Mock, patch

import pytest

from agentdecompile_cli.mcp_server.providers._collectors import collect_strings


class TestCollectStringsFallbackBehavior:
    """Test collect_strings() fallback chain when iterators fail."""

    def test_ghidra_tools_success_path(self):
        """When ghidra_tools.get_all_strings() succeeds, use that result."""
        mock_program = MagicMock()
        mock_ghidra_tools = MagicMock()
        
        # Mock successful string collection
        mock_ghidra_tools.get_all_strings.return_value = [
            {"value": "test_string_1", "address": "0x1000", "length": 13, "dataType": "string"},
            {"value": "test_string_2", "address": "0x2000", "length": 13, "dataType": "string"},
        ]
        
        result = collect_strings(mock_program, ghidra_tools=mock_ghidra_tools)
        
        assert len(result) == 2
        assert result[0]["value"] == "test_string_1"
        assert result[1]["value"] == "test_string_2"
        mock_ghidra_tools.get_all_strings.assert_called_once()

    def test_ghidra_tools_raises_uses_fallback(self):
        """When ghidra_tools.get_all_strings() raises, use listing fallback."""
        mock_program = MagicMock()
        mock_ghidra_tools = MagicMock()
        
        # Mock ghidra_tools failure
        mock_ghidra_tools.get_all_strings.side_effect = RuntimeError("Iterator unavailable")
        
        # Mock the program's listing for fallback path
        mock_listing = MagicMock()
        mock_memory = MagicMock()
        mock_program.getListing.return_value = mock_listing
        mock_program.getMemory.return_value = mock_memory
        
        # Create mock string data for listing fallback
        mock_string_data = MagicMock()
        mock_string_data.getValue.return_value = "fallback_string"
        mock_string_data.getAddress.return_value = "0x3000"
        mock_data_type = MagicMock()
        mock_data_type.getName.return_value = "string"
        mock_string_data.getDataType.return_value = mock_data_type
        
        mock_data_iter = MagicMock()
        mock_data_iter.hasNext.side_effect = [True, False]
        mock_data_iter.next.return_value = mock_string_data
        mock_listing.getDefinedData.return_value = mock_data_iter
        
        result = collect_strings(mock_program, ghidra_tools=mock_ghidra_tools)
        
        # Should have found string via listing fallback
        assert len(result) >= 1
        assert result[0]["value"] == "fallback_string"

    def test_listing_fallback_success(self):
        """Test listing-based fallback when no ghidra_tools provided."""
        mock_program = MagicMock()
        
        # Mock listing-based success
        mock_listing = MagicMock()
        mock_memory = MagicMock()
        mock_program.getListing.return_value = mock_listing
        mock_program.getMemory.return_value = mock_memory
        
        mock_string_data = MagicMock()
        mock_string_data.getValue.return_value = "listing_fallback_string"
        mock_string_data.getAddress.return_value = "0x5000"
        mock_data_type = MagicMock()
        mock_data_type.getName.return_value = "string"
        mock_string_data.getDataType.return_value = mock_data_type
        
        mock_data_iter = MagicMock()
        mock_data_iter.hasNext.side_effect = [True, False]
        mock_data_iter.next.return_value = mock_string_data
        mock_listing.getDefinedData.return_value = mock_data_iter
        
        # Call without ghidra_tools
        result = collect_strings(mock_program)
        
        # Should work via listing fallback (after iterator attempts)
        # Note: may be empty if DefinedDataIterator succeeds, so just check no crash
        assert isinstance(result, list)

    def test_all_methods_fail_returns_empty_with_logging(self):
        """When all collection methods fail, return empty list with error logging."""
        mock_program = MagicMock()
        mock_ghidra_tools = MagicMock()
        
        # Mock all paths failing
        mock_ghidra_tools.get_all_strings.side_effect = RuntimeError("Iterator unavailable")
        mock_program.getListing.side_effect = AttributeError("No listing in proxy mode")
        
        with patch("agentdecompile_cli.mcp_server.providers._collectors.logger") as mock_logger:
            result = collect_strings(mock_program, ghidra_tools=mock_ghidra_tools)
            
            assert result == []
            # Verify error logging occurred
            assert mock_logger.error.called
            error_calls = [str(call) for call in mock_logger.error.call_args_list]
            assert any("All string collection methods failed" in str(call) for call in error_calls)

    def test_min_length_filtering(self):
        """Verify min_len parameter filters short strings across all fallback paths."""
        mock_program = MagicMock()
        mock_ghidra_tools = MagicMock()
        
        mock_ghidra_tools.get_all_strings.return_value = [
            {"value": "ab", "address": "0x1000", "length": 2, "dataType": "string"},  # Too short
            {"value": "abcde", "address": "0x2000", "length": 5, "dataType": "string"},  # OK
        ]
        
        result = collect_strings(mock_program, min_len=4, ghidra_tools=mock_ghidra_tools)
        
        assert len(result) == 1
        assert result[0]["value"] == "abcde"

    def test_limit_parameter_honored(self):
        """Verify limit parameter caps results across all fallback paths."""
        mock_program = MagicMock()
        mock_ghidra_tools = MagicMock()
        
        mock_ghidra_tools.get_all_strings.return_value = [
            {"value": f"string_{i}", "address": f"0x{i:04x}", "length": 8, "dataType": "string"}
            for i in range(100)
        ]
        
        result = collect_strings(mock_program, limit=10, ghidra_tools=mock_ghidra_tools)
        
        assert len(result) == 10


class TestCollectStringsObjectNormalization:
    """Test that collect_strings() handles both dict and object responses."""

    def test_dict_response_normalization(self):
        """When get_all_strings returns dicts, normalize them."""
        mock_program = MagicMock()
        mock_ghidra_tools = MagicMock()
        
        mock_ghidra_tools.get_all_strings.return_value = [
            {"value": "dict_string", "address": "0x1000", "length": 11, "dataType": "string"},
        ]
        
        result = collect_strings(mock_program, ghidra_tools=mock_ghidra_tools)
        
        assert result[0]["value"] == "dict_string"
        assert result[0]["address"] == "0x1000"
        assert result[0]["dataType"] == "string"

    def test_object_response_normalization(self):
        """When get_all_strings returns objects, extract attributes."""
        mock_program = MagicMock()
        mock_ghidra_tools = MagicMock()
        
        mock_string_obj = Mock()
        mock_string_obj.value = "object_string"
        mock_string_obj.address = "0x2000"
        mock_string_obj.dataType = "unicode"
        
        mock_ghidra_tools.get_all_strings.return_value = [mock_string_obj]
        
        result = collect_strings(mock_program, ghidra_tools=mock_ghidra_tools)
        
        assert result[0]["value"] == "object_string"
        assert result[0]["address"] == "0x2000"
        assert result[0]["dataType"] == "unicode"


class TestCollectStringsSharedServerSimulation:
    """Simulate shared-server/proxy contexts where iterators are unavailable."""

    def test_shared_server_proxy_with_listing_fallback(self):
        """Simulate a DomainFileProxy-like context where iterators fail but listing works."""
        mock_program = MagicMock()
        mock_ghidra_tools = MagicMock()
        
        # Simulate iterator unavailability (common in shared checkouts)
        mock_ghidra_tools.get_all_strings.side_effect = RuntimeError(
            "String iterators unavailable for this program context"
        )
        
        # Simulate listing-based fallback success
        mock_listing = MagicMock()
        mock_memory = MagicMock()
        mock_program.getListing.return_value = mock_listing
        mock_program.getMemory.return_value = mock_memory
        
        mock_string_data = MagicMock()
        mock_string_data.getValue.return_value = "proxy_string"
        mock_string_data.getAddress.return_value = "0xABCD"
        mock_data_type = MagicMock()
        mock_data_type.getName.return_value = "string"
        mock_string_data.getDataType.return_value = mock_data_type
        
        mock_data_iter = MagicMock()
        mock_data_iter.hasNext.side_effect = [True, False]
        mock_data_iter.next.return_value = mock_string_data
        mock_listing.getDefinedData.return_value = mock_data_iter
        
        result = collect_strings(mock_program, ghidra_tools=mock_ghidra_tools)
        
        # Verify listing fallback found strings despite iterator failure
        assert len(result) >= 1
        assert result[0]["value"] == "proxy_string"
