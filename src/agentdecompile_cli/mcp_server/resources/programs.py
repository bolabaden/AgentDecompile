"""Program List Resource Provider - Python MCP resource implementation."""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from mcp import types

from agentdecompile_cli.mcp_server.session_context import (
    SESSION_CONTEXTS,
    get_current_mcp_session_id,
)

from ..resource_providers import ResourceProvider


class ProgramListResource(ResourceProvider):
    """MCP resource provider for program lists."""

    @staticmethod
    def _is_programs_uri(uri: str) -> bool:
        parsed = urlsplit(uri)
        if parsed.scheme.lower() != "ghidra":
            return False
        target = (parsed.netloc or parsed.path or "").strip().strip("/").lower()
        return target == "programs"

    def list_resources(self) -> list[types.Resource]:
        """Return list of program resources."""
        return [
            types.Resource(
                uri="ghidra://programs",
                name="Program List",
                description="List of all programs in the current project",
                mimeType="application/json",
            ),
        ]

    async def read_resource(self, uri: str) -> str:
        """Read the program list resource."""
        uri_text = str(uri)
        if not self._is_programs_uri(uri_text):
            raise NotImplementedError(f"Unknown resource: {uri}")

        session_id = get_current_mcp_session_id()
        session_binaries = SESSION_CONTEXTS.get_project_binaries(session_id, fallback_to_latest=True)
        if session_binaries:
            programs = [
                {
                    "programPath": item.get("path") or item.get("programPath") or item.get("name"),
                    "name": item.get("name"),
                    "type": item.get("type"),
                }
                for item in session_binaries
            ]
            return json.dumps({"programs": programs})

        if self.program_info is None:
            return json.dumps({"programs": []})

        programs = []
        # ProgramInfo is a single-program dataclass, not a multi-program dict.
        # List the single currently-loaded program.
        program = self.program_info.program
        if program is not None:
            try:
                domain_file = program.getDomainFile()
                program_path_str = (
                    str(domain_file.getPathname()) if domain_file else self.program_info.name
                )
                programs.append(
                    {
                        "programPath": program_path_str,
                        "name": program.getName(),
                        "language": str(program.getLanguage()),
                        "address": str(program.getMinAddress()),
                    },
                )
            except Exception:
                programs.append(
                    {
                        "programPath": self.program_info.name,
                        "name": self.program_info.name,
                    },
                )

        return json.dumps({"programs": programs})
