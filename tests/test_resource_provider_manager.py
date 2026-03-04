"""Tests for the ResourceProviderManager integration."""

import json
import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from agentdecompile_cli.mcp_server.resource_providers import ResourceProviderManager
from agentdecompile_cli.launcher import ProgramInfo


class TestResourceProviderManager:
    """Test suite for ResourceProviderManager."""

    @pytest.fixture
    def manager(self):
        """Create a ResourceProviderManager instance."""
        return ResourceProviderManager()

    def test_list_resources(self, manager):
        """Test that all resources are advertised."""
        resources = manager.list_resources()
        
        # Should have at least 3 resources
        assert len(resources) >= 3
        
        # Check for our resources
        uris = [str(r.uri) for r in resources]
        assert "ghidra://programs" in uris
        assert "ghidra://static-analysis-results" in uris
        assert "ghidra://agentdecompile-debug-info" in uris

    @pytest.mark.asyncio
    async def test_read_debug_info_resource(self, manager):
        """Test reading the debug-info resource."""
        result = await manager.read_resource("ghidra://agentdecompile-debug-info")
        data = json.loads(result)

        # Verify structure
        assert "metadata" in data
        assert "server" in data
        assert "program" in data
        assert "analysis" in data
        assert "resources" in data

    @pytest.mark.asyncio
    async def test_read_unknown_resource(self, manager):
        """Test that unknown resources raise ValueError with detailed info."""
        with pytest.raises(ValueError) as exc_info:
            await manager.read_resource("ghidra://unknown-resource")

        error_msg = str(exc_info.value)
        assert "Unknown resource" in error_msg
        assert "Attempted providers" in error_msg

    def test_resources_list_display(self, manager):
        """Test that resources can be listed for client."""
        resources = manager.list_resources()
        
        # Verify each resource has required fields
        for resource in resources:
            assert resource.name is not None
            assert str(resource.uri) is not None
            assert resource.mimeType is not None

    @pytest.mark.asyncio
    async def test_program_info_propagation(self, manager):
        """Test that program_info is propagated to all providers."""
        mock_program_info = MagicMock(spec=ProgramInfo)
        mock_program_info.current_program = None

        manager.set_program_info(mock_program_info)

        # Verify all providers have the program info
        for provider in manager.providers:
            assert provider.program_info is mock_program_info
