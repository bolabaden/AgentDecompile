"""Debug Info Resource Provider - Python MCP implementation."""

from __future__ import annotations

import json
import sys

from mcp import types

from ..resource_providers import ResourceProvider


class DebugInfoResource(ResourceProvider):
    """MCP resource provider for debug information."""

    def list_resources(self) -> list[types.Resource]:
        """Return list of debug info resources."""
        return [
            types.Resource(
                uri="ghidra://agentdecompile-debug-info",
                name="AgentDecompile Debug Info",
                description="Debug information for AgentDecompile",
                mimeType="application/json",
            ),
        ]

    async def read_resource(self, uri: str) -> str:
        """Read the debug info resource."""
        if uri != "ghidra://agentdecompile-debug-info":
            raise NotImplementedError(f"Unknown resource: {uri}")

        debug_info = {
            "version": "1.0.0",
            "python_version": sys.version,
            "platform": sys.platform,
            "program_info": {
                "current_program": self.program_info.current_program.getName() if self.program_info and self.program_info.current_program else None,
                "programs_loaded": len(self.program_info.programs) if self.program_info else 0,
            }
            if self.program_info
            else None,
            "server_status": "running",
        }

        return json.dumps(debug_info)
