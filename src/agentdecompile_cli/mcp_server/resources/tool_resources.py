"""Tool-backed MCP resources: agentdecompile://<tool-name> for no-arg / program_path-only tools.

Each qualifying tool gets one resource at agentdecompile://<tool-name>. When the tool
requires a program (program-scoped), reading the resource returns JSON keyed by each
opened program path to that tool's output for that program. Session-scoped tools
return a single JSON payload from one tool call.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from mcp import types
from pydantic import AnyUrl

from agentdecompile_cli.mcp_server.resource_providers import ResourceProvider
from agentdecompile_cli.mcp_server.session_context import (
    SESSION_CONTEXTS,
    get_current_mcp_session_id,
)

logger = logging.getLogger(__name__)

_RESOURCE_URI_PREFIX = "agentdecompile://"

# Tools that can be called with no arguments (session/project scope). One tool call, single JSON result.
TOOLS_RESOURCE_SESSION_SCOPED: frozenset[str] = frozenset(
    {
        "list-project-files",
        "list-prompts",
        "get-current-program",
        "open",
        "sync-project",
        "list-processors",
        "import-binary",
    }
)

# Tools that accept only optional/required program_path (and optional list-mode params).
# Resource returns JSON keyed by each opened program path to that tool's output.
TOOLS_RESOURCE_PROGRAM_SCOPED: frozenset[str] = frozenset(
    {
        "analyze-program",
        "change-processor",
        "checkin-program",
        "checkout-program",
        "checkout-status",
        "export",
        "get-call-graph",
        "get-functions",
        "list-cross-references",
        "list-exports",
        "list-functions",
        "list-imports",
        "list-strings",
        "search-constants",
        "search-symbols",
        "suggest",
    }
)

# Resource URI -> (tool_name, args) mapping for tools that need intuitive names
# When called with no args or only program_path, these tools list/return data
_RESOURCE_TO_TOOL_MAP: dict[str, tuple[str, dict[str, Any]]] = {
    "bookmarks": ("manage-bookmarks", {"mode": "list"}),
    "comments": ("manage-comments", {"mode": "list"}),
    "data-types": ("manage-data-types", {"mode": "list"}),
    "function-tags": ("manage-function-tags", {"mode": "list"}),
    "symbols": ("manage-symbols", {"mode": "list"}),
    "structures": ("manage-structures", {"mode": "list"}),
}

# All resource URIs (direct tool names + mapped intuitive names)
TOOLS_ELIGIBLE_FOR_RESOURCE: frozenset[str] = TOOLS_RESOURCE_SESSION_SCOPED | TOOLS_RESOURCE_PROGRAM_SCOPED | frozenset(_RESOURCE_TO_TOOL_MAP.keys())


def _parse_tool_response(response: Any) -> Any:
    """Extract and parse tool response (list of TextContent -> JSON or raw text)."""
    logger.debug("diag.enter %s", "mcp_server/resources/tool_resources.py:_parse_tool_response")
    if not isinstance(response, list):
        return response
    text_parts: list[str] = []
    for item in response:
        text = getattr(item, "text", None)
        if isinstance(text, str):
            text_parts.append(text)
    if not text_parts:
        return []
    merged = "\n".join(text_parts)
    try:
        return json.loads(merged)
    except Exception:
        return {"rawText": merged}


class ToolOutputResource(ResourceProvider):
    """MCP resource provider for agentdecompile://<tool-name> resources.

    Exposes one resource per tool that can be called with no arguments or only
    program_path. Program-scoped tools return JSON keyed by opened program path.
    """

    def list_resources(self) -> list[types.Resource]:
        """Return one resource per qualifying tool at agentdecompile://<resource-name>."""
        logger.debug("diag.enter %s", "mcp_server/resources/tool_resources.py:ToolOutputResource.list_resources")
        resources: list[types.Resource] = []
        
        # Direct tool names (session and program scoped)
        for tool_name in sorted(TOOLS_RESOURCE_SESSION_SCOPED | TOOLS_RESOURCE_PROGRAM_SCOPED):
            # Intuitive name based on what the tool does
            if tool_name == "list-project-files":
                name = "Project Files"
                desc = "List all files in the project"
            elif tool_name == "list-prompts":
                name = "Prompts"
                desc = "List available analysis prompts"
            elif tool_name == "get-current-program":
                name = "Current Program"
                desc = "Get the currently active program"
            elif tool_name == "list-functions":
                name = "Functions"
                desc = "List all functions in each open program"
            elif tool_name == "get-functions":
                name = "Function Details"
                desc = "Get detailed function information for each open program"
            elif tool_name == "list-exports":
                name = "Exports"
                desc = "List exported symbols in each open program"
            elif tool_name == "list-imports":
                name = "Imports"
                desc = "List imported symbols in each open program"
            elif tool_name == "list-strings":
                name = "Strings"
                desc = "List all strings in each open program"
            elif tool_name == "get-call-graph":
                name = "Call Graph"
                desc = "Get call graph for each open program"
            elif tool_name == "list-cross-references":
                name = "Cross References"
                desc = "List cross-references in each open program"
            elif tool_name == "search-constants":
                name = "Constants"
                desc = "Search constants in each open program"
            elif tool_name == "search-symbols":
                name = "Symbol Search"
                desc = "Search symbols in each open program"
            elif tool_name == "checkout-status":
                name = "Checkout Status"
                desc = "Get checkout status for each open program"
            elif tool_name == "analyze-program":
                name = "Analysis Status"
                desc = "Get analysis status for each open program"
            else:
                # Default: capitalize and replace hyphens
                name = tool_name.replace("-", " ").title()
                desc = f"Output of {tool_name}"
            
            resources.append(
                types.Resource(
                    uri=AnyUrl(url=f"{_RESOURCE_URI_PREFIX}{tool_name}"),
                    name=name,
                    description=desc,
                    mimeType="application/json",
                )
            )
        
        # Mapped intuitive names (bookmarks, comments, etc.)
        for resource_name, (tool_name, _args) in sorted(_RESOURCE_TO_TOOL_MAP.items()):
            if resource_name == "bookmarks":
                name = "Bookmarks"
                desc = "List all bookmarks in each open program"
            elif resource_name == "comments":
                name = "Comments"
                desc = "List all comments in each open program"
            elif resource_name == "data-types":
                name = "Data Types"
                desc = "List all data types in each open program"
            elif resource_name == "function-tags":
                name = "Function Tags"
                desc = "List all function tags in each open program"
            elif resource_name == "symbols":
                name = "Symbols"
                desc = "List all symbols in each open program"
            elif resource_name == "structures":
                name = "Structures"
                desc = "List all structures in each open program"
            else:
                name = resource_name.replace("-", " ").title()
                desc = f"List {resource_name.replace('-', ' ')}"
            
            resources.append(
                types.Resource(
                    uri=AnyUrl(url=f"{_RESOURCE_URI_PREFIX}{resource_name}"),
                    name=name,
                    description=desc,
                    mimeType="application/json",
                )
            )
        
        return resources

    async def read_resource(self, uri: str) -> str:
        """Read agentdecompile://<resource-name> by calling the tool (once or per open program)."""
        logger.debug("diag.enter %s", "mcp_server/resources/tool_resources.py:ToolOutputResource.read_resource")
        uri_str = str(uri).strip()
        if not uri_str.lower().startswith(_RESOURCE_URI_PREFIX.lower()):
            raise NotImplementedError(f"Not a tool resource URI: {uri}")

        resource_name = uri_str[len(_RESOURCE_URI_PREFIX) :].strip()
        if not resource_name or resource_name not in TOOLS_ELIGIBLE_FOR_RESOURCE:
            raise NotImplementedError(f"Unknown or ineligible resource: {resource_name}")

        if self.tool_provider_manager is None:
            return json.dumps(
                {"success": False, "error": "tool_provider_manager unavailable", "resource": resource_name},
                indent=2,
            )

        # Check if this is a mapped resource (e.g. "bookmarks" -> "manage-bookmarks" with mode=list)
        if resource_name in _RESOURCE_TO_TOOL_MAP:
            tool_name, tool_args = _RESOURCE_TO_TOOL_MAP[resource_name]
            # Mapped resources are always program-scoped (they list data per program)
            return await self._read_program_scoped(tool_name, extra_args=tool_args)
        
        # Direct tool name
        tool_name = resource_name
        if tool_name in TOOLS_RESOURCE_SESSION_SCOPED:
            return await self._read_session_scoped(tool_name)
        return await self._read_program_scoped(tool_name)

    async def _read_session_scoped(self, tool_name: str) -> str:
        """Call tool once with minimal args; return JSON."""
        logger.debug("diag.enter %s", "mcp_server/resources/tool_resources.py:ToolOutputResource._read_session_scoped")
        args: dict[str, Any] = {"format": "json"}
        if tool_name == "manage-files":
            args.setdefault("mode", "list")
        try:
            response = await self.tool_provider_manager.call_tool(tool_name, args)
            parsed = _parse_tool_response(response)
            return json.dumps(parsed, indent=2)
        except Exception as e:
            logger.warning("ToolOutputResource: session-scoped %s failed: %s", tool_name, e)
            return json.dumps(
                {"success": False, "error": str(e), "tool": tool_name},
                indent=2,
            )

    async def _read_program_scoped(self, tool_name: str, extra_args: dict[str, Any] | None = None) -> str:
        """Call tool for each open program; return JSON keyed by program path."""
        logger.debug("diag.enter %s", "mcp_server/resources/tool_resources.py:ToolOutputResource._read_program_scoped")
        if self.tool_provider_manager is None:
            return json.dumps({"success": False, "error": "tool_provider_manager unavailable", "tool": tool_name}, indent=2)
        session_id = get_current_mcp_session_id()
        snapshot = SESSION_CONTEXTS.get_session_snapshot(session_id)
        open_keys: list[str] = list(snapshot.get("openProgramKeys") or [])

        if not open_keys:
            return json.dumps(
                {"success": True, "programs": {}, "note": "No open programs in session"},
                indent=2,
            )

        args_base: dict[str, Any] = {"format": "json"}
        if extra_args:
            args_base.update(extra_args)
        elif tool_name in (
            "manage-bookmarks",
            "manage-comments",
            "manage-data-types",
            "manage-function-tags",
            "manage-symbols",
            "manage-structures",
            "manage-strings",
            "search-constants",
        ):
            args_base.setdefault("mode", "list")

        out: dict[str, Any] = {}
        for program_path in open_keys:
            args = dict(args_base)
            args["programPath"] = program_path
            try:
                response = await self.tool_provider_manager.call_tool(tool_name, args)
                parsed = _parse_tool_response(response)
                out[program_path] = parsed
            except Exception as e:
                logger.warning(
                    "ToolOutputResource: program-scoped %s failed for %s: %s",
                    tool_name,
                    program_path,
                    e,
                )
                out[program_path] = {"success": False, "error": str(e)}

        return json.dumps(out, indent=2)
