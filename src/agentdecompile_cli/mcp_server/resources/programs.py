"""Program List Resource Provider - ghidra://programs.

Reads the current session's project binaries (from SessionContext) and returns
a JSON list of program paths/names. Used by DebugInfoResource and by clients
that need to see open programs without calling list-project-files or get-current-program.
"""

from __future__ import annotations

import json
import logging

from typing import Any
from urllib.parse import urlsplit

from mcp import types

logger = logging.getLogger(__name__)

from agentdecompile_cli.mcp_server.session_context import (
    SESSION_CONTEXTS,
    get_current_mcp_session_id,
)

from ..resource_providers import ResourceProvider


class ProgramListResource(ResourceProvider):
    """MCP resource provider for program lists."""

    @staticmethod
    def _is_programs_uri(uri: str) -> bool:
        """Return True if URI is ghidra://programs (scheme ghidra, path/netloc 'programs')."""
        parsed = urlsplit(uri)
        if parsed.scheme.lower() != "ghidra":
            return False
        target = (parsed.netloc or parsed.path or "").strip().strip("/").lower()
        return target == "programs"

    def list_resources(self) -> list[types.Resource]:
        """Return list of program resources."""
        return [
            types.Resource(
                uri="ghidra://programs",  # pyright: ignore[reportArgumentType]
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

        logger.info("ProgramListResource: reading resource for URI %s", uri)

        try:
            session_id = get_current_mcp_session_id()
            # Session-scoped only: binaries from open-project / list-project-files in this session
            session_binaries = SESSION_CONTEXTS.get_project_binaries(session_id, fallback_to_latest=False)
            if session_binaries:
                programs = [
                    {
                        "programPath": item.get("path") or item.get("programPath") or item.get("name"),
                        "name": item.get("name"),
                        "type": item.get("type"),
                    }
                    for item in session_binaries
                ]
                result = json.dumps({"programs": programs})
                logger.info(f"ProgramListResource: found {len(programs)} programs from session context")
                return result

            ghidra_project = (
                getattr(self.tool_provider_manager, "ghidra_project", None) if self.tool_provider_manager else None
            )
            if ghidra_project is not None:
                from agentdecompile_cli.mcp_server.domain_folder_listing import list_project_tree_from_ghidra

                tree = list_project_tree_from_ghidra(ghidra_project, normalized_folder="/", max_results=500)
                programs_from_tree: list[dict[str, Any]] = []
                for item in tree:
                    if str(item.get("type", "")).strip() != "Program":
                        continue
                    pth = item.get("path") or item.get("name")
                    programs_from_tree.append(
                        {
                            "programPath": pth,
                            "name": item.get("name"),
                            "type": "Program",
                        },
                    )
                if programs_from_tree:
                    logger.info(
                        "ProgramListResource: found %s programs from local ghidra project",
                        len(programs_from_tree),
                    )
                    return json.dumps({"programs": programs_from_tree})

            if self.program_info is None:
                logger.info("ProgramListResource: no program_info, returning empty list")
                return json.dumps({"programs": []})

            programs = []
            # ProgramInfo is a single-program dataclass, not a multi-program dict.
            # List the single currently-loaded program.
            program = self.program_info.program
            if program is not None:
                try:
                    domain_file = program.getDomainFile()
                    program_path_str = str(domain_file.getPathname()) if domain_file else self.program_info.name
                    programs.append(
                        {
                            "programPath": program_path_str,
                            "name": program.getName(),
                            "language": str(program.getLanguage()),
                            "address": str(program.getMinAddress()),
                        },
                    )
                    logger.info("ProgramListResource: found 1 program from program_info")
                except Exception as e:
                    logger.warning(f"ProgramListResource: Error getting program details: {e.__class__.__name__}: {e}")
                    programs.append(
                        {
                            "programPath": self.program_info.name,
                            "name": self.program_info.name,
                        },
                    )
            else:
                logger.info("ProgramListResource: program_info.program is None, returning empty list")

            return json.dumps({"programs": programs})
        except Exception as e:
            logger.error("ProgramListResource: Error reading resource: %s", e, exc_info=True)
            # Return empty list + error message so clients get a valid JSON response instead of a raised exception
            return json.dumps({"programs": [], "error": str(e)})
