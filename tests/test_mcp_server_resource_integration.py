"""Integration tests for MCP server resource handling."""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agentdecompile_cli.mcp_server.server import PythonMcpServer, ServerConfig
from agentdecompile_cli.launcher import ProgramInfo


class TestMcpServerResourceIntegration:
    """Test MCP server resource integration."""

    @pytest.fixture
    def server(self):
        """Create a test MCP server."""
        config = ServerConfig(
            name="TestServer",
            version="1.0.0",
            host="127.0.0.1",
            port=8080,
        )
        return PythonMcpServer(config)

    def test_server_has_resource_providers(self, server):
        """Test that the server has registered resource providers."""
        assert server.resource_providers is not None
        assert len(server.resource_providers.providers) >= 3

    def test_resources_advertised(self, server):
        """Test that resources are properly advertised."""
        resources = server.resource_providers.list_resources()
        assert len(resources) >= 3

        uris = [str(r.uri) for r in resources]
        assert "ghidra://agentdecompile-debug-info" in uris

    @pytest.mark.asyncio
    async def test_read_debug_info_via_server(self, server):
        """Test reading debug-info resource through the server."""
        result = await server.resource_providers.read_resource(
            "ghidra://agentdecompile-debug-info"
        )

        # Verify result is valid JSON
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

    @pytest.mark.asyncio
    async def test_mcp_server_list_resources(self, server):
        """Test MCP server's list_resources handler."""
        # Just verify we have resources
        resources = server.resource_providers.list_resources()

        assert len(resources) >= 3
        assert any(
            "ghidra://agentdecompile-debug-info" in str(r.uri)
            for r in resources
        )

    @pytest.mark.asyncio
    async def test_program_info_affects_debug_info(self, server):
        """Test that program_info updates are reflected in debug-info."""
        # Initially no program
        result1 = await server.resource_providers.read_resource(
            "ghidra://agentdecompile-debug-info"
        )
        data1 = json.loads(result1)
        assert data1["program"]["status"] == "no_program_loaded"

        # Set up mock program info with proper JSON serialization
        mock_program = MagicMock()
        mock_program.getName.return_value = "test_binary"
        mock_program.getListing.return_value = MagicMock()
        mock_program.getListing.return_value.getNumFunctions.return_value = 0
        mock_program.getSymbolTable.return_value = MagicMock()
        mock_program.getSymbolTable.return_value.getGlobalSymbolCount.return_value = 0
        mock_program.getDataTypeManager.return_value = MagicMock()
        mock_program.getDataTypeManager.return_value.getAllDataTypes.return_value = []

        mock_program_info = MagicMock(spec=ProgramInfo)
        mock_program_info.current_program = mock_program
        mock_program_info.file_path = "/test/path"
        mock_program_info.load_time = 1.0
        mock_program_info.metadata = {"architecture": "x86-64"}
        mock_program_info.analysis_complete = True
        mock_program_info.strings_collection = None

        # Update server's program info
        server.resource_providers.set_program_info(mock_program_info)

        # Read again
        result2 = await server.resource_providers.read_resource(
            "ghidra://agentdecompile-debug-info"
        )
        data2 = json.loads(result2)
        assert data2["program"]["status"] == "loaded"
        assert data2["program"]["current_program"] == "test_binary"
