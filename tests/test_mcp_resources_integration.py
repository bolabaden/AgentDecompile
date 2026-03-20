"""Integration tests for MCP resource providers.

Tests that all resource providers work correctly with and without a program loaded.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from agentdecompile_cli.mcp_server.resource_providers import ResourceProviderManager
from mcp import types


class TestResourceProvidersIntegration:
    """Integration tests for resource providers."""

    @pytest.fixture
    def resource_manager(self):
        """Create a ResourceProviderManager instance."""
        return ResourceProviderManager()

    @pytest.mark.asyncio
    async def test_list_resources_returns_canonical_resource(self, resource_manager: ResourceProviderManager) -> None:
        """Test that listResources advertises the canonical debug-info and tool-backed resources."""
        resources = resource_manager.list_resources()
        assert len(resources) >= 1, f"Expected at least 1 resource, got {len(resources)}"

        uris = [str(r.uri) for r in resources]
        assert "agentdecompile://debug-info" in uris
        # Tool-backed resources (agentdecompile://<tool-name>) and ghidra://analysis-dump expected
        assert any(u.startswith("agentdecompile://") for u in uris)

    @pytest.mark.asyncio
    async def test_read_programs_without_program(self, resource_manager: ResourceProviderManager) -> None:
        """Test reading programs resource without a program loaded."""
        result = await resource_manager.read_resource("ghidra://programs")

        # Should return valid JSON
        data = json.loads(result)
        assert "programs" in data
        assert isinstance(data["programs"], list)
        print(f"✓ Programs resource (no program): {len(data['programs'])} programs")

    @pytest.mark.asyncio
    async def test_read_static_analysis_without_program(self, resource_manager: ResourceProviderManager) -> None:
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
    async def test_read_debug_info_without_program(self, resource_manager: ResourceProviderManager) -> None:
        """Test reading debug info resource without a program loaded."""
        result = await resource_manager.read_resource("agentdecompile://debug-info")

        # Should return valid JSON
        data = json.loads(result)
        assert "metadata" in data, f"Expected 'metadata' in data, got {data}"
        assert "server" in data, f"Expected 'server' in data, got {data}"
        assert "program" in data, f"Expected 'program' in data, got {data}"
        assert "analysis" in data, f"Expected 'analysis' in data, got {data}"
        assert "profiling" in data, f"Expected 'profiling' in data, got {data}"

        # Check program status
        assert data["program"]["status"] == "no_program_loaded", f"Expected 'no_program_loaded' in program status, got {data['program']['status']}"
        assert data["analysis"]["status"] == "no_program", f"Expected 'no_program' in analysis status, got {data['analysis']['status']}"
        assert data["profiling"]["status"] == "available", f"Expected 'available' in profiling status, got {data['profiling']['status']}"
        print(f"✓ Debug info resource (no program): server uptime={data['server']['uptime']['seconds']}s")

    @pytest.mark.asyncio
    async def test_read_unknown_resource_fails_gracefully(self, resource_manager: ResourceProviderManager) -> None:
        """Test that reading unknown resource raises ValueError."""
        with pytest.raises(ValueError) as exc_info:
            await resource_manager.read_resource("ghidra://nonexistent-resource")

        assert "Unknown resource" in str(exc_info.value), f"Expected 'Unknown resource' in exception message, got {exc_info.value}"
        print(f"✓ Unknown resource handling: {exc_info.value}")

    @pytest.mark.asyncio
    async def test_all_resources_return_valid_json(self, resource_manager: ResourceProviderManager) -> None:
        """Test that all listed resources return valid content (JSON for application/json, non-empty for others)."""
        resources: list[types.Resource] = resource_manager.list_resources()

        for resource in resources:
            uri = str(resource.uri)
            print(f"\nTesting resource: {uri}")

            try:
                result = await resource_manager.read_resource(uri)
                assert len(result) > 0, f"Resource {uri} should return non-empty content"

                mime = getattr(resource, "mimeType", None) or ""
                if "json" in mime.lower():
                    data = json.loads(result)
                    assert isinstance(data, (dict, list)), f"Resource {uri} should return JSON object or array"
                    print(f"  ✓ Valid JSON, {len(result)} bytes")
                    print(f"  ✓ Top-level keys: {list(data.keys() if isinstance(data, dict) else data)}")
                else:
                    print(f"  ✓ Non-JSON ({mime or 'other'}), {len(result)} bytes")
            except Exception as e:
                pytest.fail(f"Resource {uri} failed: {e.__class__.__name__}: {e}")


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
        assert len(resources) >= 1
        assert any(str(r.uri) == "agentdecompile://debug-info" for r in resources)

        # Test 2: Read each resource
        print("\n[TEST 2] Read All Resources (No Program Loaded)")
        for resource in resources:
            uri = str(resource.uri)
            print(f"\n  Reading: {uri}")
            try:
                result = await manager.read_resource(uri)
                assert len(result) > 0, f"Empty result for {uri}"
                mime = getattr(resource, "mimeType", None) or ""
                if "json" in mime.lower():
                    data = json.loads(result)
                    keys = list(data.keys())[:5] if isinstance(data, dict) else type(data).__name__
                    print(f"    ✓ Success: {len(result)} bytes, valid JSON. Keys: {keys}")
                else:
                    print(f"    ✓ Success: {len(result)} bytes ({mime or 'other'})")
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
