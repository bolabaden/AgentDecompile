"""Tests for the debug-info MCP resource."""

import json
import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from agentdecompile_cli.mcp_server.resources.debug_info import DebugInfoResource
from agentdecompile_cli.launcher import ProgramInfo


class TestDebugInfoResource:
    """Test suite for DebugInfoResource."""

    @pytest.fixture
    def debug_resource(self):
        """Create a DebugInfoResource instance."""
        return DebugInfoResource()

    def test_list_resources(self, debug_resource):
        """Test that the resource is properly advertised."""
        resources = debug_resource.list_resources()
        assert len(resources) == 1
        assert str(resources[0].uri) == "ghidra://agentdecompile-debug-info"
        assert resources[0].mimeType == "application/json"

    @pytest.mark.asyncio
    async def test_read_resource_without_program(self, debug_resource):
        """Test reading debug info without a loaded program."""
        result = await debug_resource.read_resource("ghidra://agentdecompile-debug-info")
        data = json.loads(result)

        # Verify structure
        assert "metadata" in data
        assert "server" in data
        assert "program" in data
        assert "analysis" in data
        assert "resources" in data

        # Verify metadata
        assert data["metadata"]["version"] == "2.0.0"
        assert "python_version" in data["metadata"]
        assert "platform" in data["metadata"]

        # Verify server state
        assert data["server"]["status"] == "running"
        assert "uptime" in data["server"]

        # Verify program state (no program loaded)
        assert data["program"]["status"] == "no_program_loaded"
        assert data["program"]["current_program"] is None

        # Verify analysis state
        assert data["analysis"]["status"] == "no_program"
        assert data["analysis"]["functions_count"] == 0

    @pytest.mark.asyncio
    async def test_read_resource_with_program(self, debug_resource):
        """Test reading debug info with a loaded program."""
        # Mock ProgramInfo with a program
        mock_program = MagicMock()
        mock_program.getName.return_value = "test_binary"

        mock_listing = MagicMock()
        mock_listing.getNumFunctions.return_value = 42

        mock_program.getListing.return_value = mock_listing

        mock_symbol_table = MagicMock()
        mock_symbol_table.getGlobalSymbolCount.return_value = 100

        mock_program.getSymbolTable.return_value = mock_symbol_table

        mock_dtm = MagicMock()
        mock_dtm.getAllDataTypes.return_value = [MagicMock(isBuiltIn=lambda: False) for _ in range(5)]
        mock_program.getDataTypeManager.return_value = mock_dtm

        program_info = MagicMock(spec=ProgramInfo)
        program_info.current_program = mock_program
        program_info.file_path = "/path/to/binary"
        program_info.load_time = 1.23
        program_info.metadata = {
            "architecture": "x86-64",
            "format": "ELF",
            "language": "x86:LE:64:default",
            "compiler_spec": "gcc",
            "image_base": 0x400000,
        }
        program_info.analysis_complete = True
        program_info.strings_collection = ["string1", "string2", "string3"]

        debug_resource.set_program_info(program_info)

        result = await debug_resource.read_resource("ghidra://agentdecompile-debug-info")
        data = json.loads(result)

        # Verify program state with loaded program
        assert data["program"]["status"] == "loaded"
        assert data["program"]["current_program"] == "test_binary"
        assert data["program"]["file_path"] == "/path/to/binary"
        assert data["program"]["architecture"] == "x86-64"
        assert data["program"]["analysis_complete"] is True

        # Verify analysis state
        assert data["analysis"]["status"] == "available"
        assert data["analysis"]["functions_count"] == 42
        assert data["analysis"]["symbols_count"] == 100
        assert data["analysis"]["strings_count"] == 3
        assert data["analysis"]["data_types_count"] == 5

    @pytest.mark.asyncio
    async def test_read_resource_invalid_uri(self, debug_resource):
        """Test reading an invalid URI raises NotImplementedError."""
        with pytest.raises(NotImplementedError):
            await debug_resource.read_resource("ghidra://invalid-uri")

    @pytest.mark.asyncio
    async def test_read_resource_increments_counter(self, debug_resource):
        """Test that resource reads are counted."""
        assert debug_resource._resource_read_count == 0

        result = await debug_resource.read_resource("ghidra://agentdecompile-debug-info")
        data = json.loads(result)

        # First read increments counter
        assert data["resources"]["debug_info_reads"] == 1

        # Second read increments counter
        result = await debug_resource.read_resource("ghidra://agentdecompile-debug-info")
        data = json.loads(result)
        assert data["resources"]["debug_info_reads"] == 2

    @pytest.mark.asyncio
    async def test_json_serializable(self, debug_resource):
        """Test that the debug info is always valid JSON."""
        result = await debug_resource.read_resource("ghidra://agentdecompile-debug-info")

        # Should not raise an exception
        data = json.loads(result)
        assert isinstance(data, dict)

        # Verify we can re-serialize it
        serialized_again = json.dumps(data)
        assert isinstance(serialized_again, str)
