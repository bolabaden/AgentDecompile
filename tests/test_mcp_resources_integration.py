"""Integration tests for MCP resource providers.

Tests that all resource providers work correctly with and without a program loaded.
"""

import asyncio
import json
import pytest

from agentdecompile_cli.mcp_server.resource_providers import ResourceProviderManager
from agentdecompile_cli.launcher import ProgramInfo


class TestResourceProvidersIntegration:
    """Integration tests for resource providers."""

    @pytest.fixture
    def resource_manager(self):
        """Create a ResourceProviderManager instance."""
        return ResourceProviderManager()

    @pytest.mark.asyncio
    async def test_list_resources_returns_canonical_resource(self, resource_manager):
        """Test that listResources advertises only the canonical unified resource."""
        resources = resource_manager.list_resources()
        assert len(resources) == 1, f"Expected 1 resource, got {len(resources)}"
        
        uris = [str(r.uri) for r in resources]
        assert "agentdecompile://debug-info" in uris

    @pytest.mark.asyncio
    async def test_read_programs_without_program(self, resource_manager):
        """Test reading programs resource without a program loaded."""
        result = await resource_manager.read_resource("ghidra://programs")
        
        # Should return valid JSON
        data = json.loads(result)
        assert "programs" in data
        assert isinstance(data["programs"], list)
        print(f"✓ Programs resource (no program): {len(data['programs'])} programs")

    @pytest.mark.asyncio
    async def test_read_static_analysis_without_program(self, resource_manager):
        """Test reading static analysis resource without a program loaded."""
        result = await resource_manager.read_resource("ghidra://static-analysis-results")
        
        # Should return valid JSON
        data = json.loads(result)
        assert "$schema" in data
        assert data["version"] == "2.1.0"
        assert "runs" in data
        assert len(data["runs"]) > 0
        
        # Check for no_program_loaded status
        run = data["runs"][0]
        assert "properties" in run
        assert run["properties"]["status"] == "no_program_loaded"
        print(f"✓ Static analysis resource (no program): SARIF 2.1.0, status={run['properties']['status']}")

    @pytest.mark.asyncio
    async def test_read_debug_info_without_program(self, resource_manager):
        """Test reading debug info resource without a program loaded."""
        result = await resource_manager.read_resource("agentdecompile://debug-info")
        
        # Should return valid JSON
        data = json.loads(result)
        assert "metadata" in data
        assert "server" in data
        assert "program" in data
        assert "analysis" in data
        assert "profiling" in data
        
        # Check program status
        assert data["program"]["status"] == "no_program_loaded"
        assert data["analysis"]["status"] == "no_program"
        assert data["profiling"]["status"] == "available"
        print(f"✓ Debug info resource (no program): server uptime={data['server']['uptime']['seconds']}s")

    @pytest.mark.asyncio
    async def test_read_unknown_resource_fails_gracefully(self, resource_manager):
        """Test that reading unknown resource raises ValueError."""
        with pytest.raises(ValueError) as exc_info:
            await resource_manager.read_resource("ghidra://nonexistent-resource")
        
        assert "Unknown resource" in str(exc_info.value)
        print(f"✓ Unknown resource handling: {exc_info.value}")

    @pytest.mark.asyncio
    async def test_all_resources_return_valid_json(self, resource_manager):
        """Test that all listed resources return parseable JSON."""
        resources = resource_manager.list_resources()
        
        for resource in resources:
            uri = str(resource.uri)
            print(f"\nTesting resource: {uri}")
            
            try:
                result = await resource_manager.read_resource(uri)
                data = json.loads(result)
                
                assert isinstance(data, dict), f"Resource {uri} should return JSON object"
                assert len(result) > 0, f"Resource {uri} should return non-empty content"
                
                print(f"  ✓ Valid JSON, {len(result)} bytes")
                print(f"  ✓ Top-level keys: {list(data.keys())}")
            except Exception as e:
                pytest.fail(f"Resource {uri} failed: {type(e).__name__}: {e}")


def test_resource_providers_standalone():
    """Standalone test that can be run without pytest."""
    print("=" * 70)
    print("MCP Resource Providers Integration Test")
    print("=" * 70)
    
    async def run_tests():
        manager = ResourceProviderManager()
        
        # Test 1: List resources
        print("\n[TEST 1] List Resources")
        resources = manager.list_resources()
        print(f"  Found {len(resources)} resources:")
        for r in resources:
            print(f"    - {r.uri} ({r.name})")
        assert len(resources) == 1
        
        # Test 2: Read each resource
        print("\n[TEST 2] Read All Resources (No Program Loaded)")
        for resource in resources:
            uri = str(resource.uri)
            print(f"\n  Reading: {uri}")
            try:
                result = await manager.read_resource(uri)
                data = json.loads(result)
                print(f"    ✓ Success: {len(result)} bytes, valid JSON")
                print(f"    ✓ Keys: {list(data.keys())[:5]}")
            except Exception as e:
                print(f"    ✗ FAILED: {type(e).__name__}: {e}")
                raise
        
        print("\n" + "=" * 70)
        print("ALL TESTS PASSED ✓")
        print("=" * 70)
    
    asyncio.run(run_tests())


if __name__ == "__main__":
    # Run standalone test
    test_resource_providers_standalone()
