"""Tests for the static-analysis-results MCP resource."""

import json
from unittest.mock import MagicMock

import pytest

from agentdecompile_cli.launcher import ProgramInfo
from agentdecompile_cli.mcp_server.resources.static_analysis import StaticAnalysisResultsResource


class TestStaticAnalysisResource:
    """Test suite for StaticAnalysisResultsResource."""

    @pytest.fixture
    def analysis_resource(self):
        """Create a StaticAnalysisResultsResource instance."""
        return StaticAnalysisResultsResource()

    def test_list_resources(self, analysis_resource: StaticAnalysisResultsResource):
        """Test that the resource is properly advertised."""
        resources = analysis_resource.list_resources()
        assert len(resources) == 1
        assert str(resources[0].uri) == "ghidra://static-analysis-results"
        assert resources[0].mimeType == "application/json"

    @pytest.mark.asyncio
    async def test_read_resource_without_program(self, analysis_resource: StaticAnalysisResultsResource):
        """Test reading static analysis results without a loaded program."""
        result = await analysis_resource.read_resource("ghidra://static-analysis-results")
        data = json.loads(result)

        # Verify SARIF structure
        assert data["version"] == "2.1.0"
        assert "$schema" in data
        assert "runs" in data
        assert len(data["runs"]) == 1

        run = data["runs"][0]
        assert run["tool"]["driver"]["name"] == "AgentDecompile"
        assert run["results"] == []
        assert run["artifacts"] == []

        # Verify status indicates no program
        props = run["properties"]
        assert props["status"] == "no_program_loaded"
        assert props["analysisComplete"] is False
        assert props["programPath"] is None

    @pytest.mark.asyncio
    async def test_read_resource_with_program(self, analysis_resource: StaticAnalysisResultsResource):
        """Test reading static analysis results with a loaded program."""
        # Mock ProgramInfo with a program
        mock_program = MagicMock()
        mock_program.getName.return_value = "test_binary"
        mock_program.getImageBase.return_value = MagicMock()
        mock_program.getImageBase.return_value.getOffset.return_value = 0x400000
        mock_program.getAnalysisState.return_value = MagicMock()
        mock_program.getAnalysisState.return_value.isDone.return_value = True

        # Mock various collections to return empty results
        mock_program.getReferenceManager.return_value = MagicMock()
        mock_program.getReferenceManager.return_value.getExternalReferences.return_value = []
        mock_program.getBookmarkManager.return_value = MagicMock()
        mock_program.getBookmarkManager.return_value.getBookmarksIterator.return_value = iter([])

        program_info = MagicMock(spec=ProgramInfo)
        program_info.program = mock_program
        program_info.file_path = "/path/to/binary"

        analysis_resource.set_program_info(program_info)

        result = await analysis_resource.read_resource("ghidra://static-analysis-results")
        data = json.loads(result)

        # Verify SARIF structure with program
        assert data["version"] == "2.1.0"
        run = data["runs"][0]

        # Verify artifacts include program info
        assert len(run["artifacts"]) == 1
        assert run["artifacts"][0]["uri"] == "test_binary"
        assert run["artifacts"][0]["properties"]["imageBase"] == "0x400000"

        # Verify properties reflect loaded program
        props = run["properties"]
        assert props["analysisComplete"] is True
        assert props["programPath"] == "/path/to/binary"
        assert "status" not in props or props["status"] != "no_program_loaded"

    @pytest.mark.asyncio
    async def test_read_resource_invalid_uri(self, analysis_resource: StaticAnalysisResultsResource):
        """Test reading an invalid URI raises NotImplementedError."""
        with pytest.raises(NotImplementedError):
            await analysis_resource.read_resource("ghidra://invalid-uri")

    @pytest.mark.asyncio
    async def test_sarif_schema_version(self, analysis_resource: StaticAnalysisResultsResource):
        """Test that the SARIF schema version is correct."""
        result = await analysis_resource.read_resource("ghidra://static-analysis-results")
        data = json.loads(result)

        assert data["version"] == "2.1.0"
        assert "sarif-schema-2.1.0.json" in data["$schema"]

    @pytest.mark.asyncio
    async def test_json_serializable(self, analysis_resource: StaticAnalysisResultsResource):
        """Test that the static analysis results are always valid JSON."""
        result = await analysis_resource.read_resource("ghidra://static-analysis-results")

        # Should not raise an exception
        data = json.loads(result)
        assert isinstance(data, dict)

        # Verify we can re-serialize it
        serialized_again = json.dumps(data)
        assert isinstance(serialized_again, str)
