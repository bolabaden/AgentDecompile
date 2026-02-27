"""Static Analysis Results Resource Provider - Python MCP implementation."""

from __future__ import annotations

import json

from mcp import types
from pydantic import AnyUrl

from agentdecompile_cli.mcp_server.resource_providers import ResourceProvider


class StaticAnalysisResultsResource(ResourceProvider):
    """MCP resource provider for static analysis results."""

    def list_resources(self) -> list[types.Resource]:
        """Return list of static analysis resources."""
        return [
            types.Resource(
                uri=AnyUrl(url="ghidra://static-analysis-results"),
                name="Static Analysis Results",
                description="Results from static analysis of the current program",
                mimeType="application/json",
            ),
        ]

    async def read_resource(self, uri: str) -> str:
        """Read the static analysis results resource."""
        if uri != "ghidra://static-analysis-results":
            raise NotImplementedError(f"Unknown resource: {uri}")

        # Placeholder for static analysis results
        return json.dumps(
            {
                "analysis_complete": False,
                "results": [],
                "message": "Static analysis not yet implemented",
            },
        )
