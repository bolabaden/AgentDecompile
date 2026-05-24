"""Conflict resolution tool provider – resolve-modification-conflict.

Call only when another tool returned a conflictId because the modification would
overwrite custom data. Use resolution=overwrite to apply the change or resolution=skip to discard.
"""

from __future__ import annotations

import logging
from typing import Any

from mcp import types

from agentdecompile_cli.app_logger import redact_session_id
from agentdecompile_cli.mcp_server.conflict_store import get as conflict_get, remove as conflict_remove
from agentdecompile_cli.mcp_server.session_context import get_current_mcp_session_id
from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
    create_error_response,
    n,
)
from agentdecompile_cli.registry import Tool

logger = logging.getLogger(__name__)


class ConflictResolutionToolProvider(ToolProvider):
    HANDLERS = {"resolvemodificationconflict": "_handle"}

    def list_tools(self) -> list[types.Tool]:
        logger.debug("diag.enter %s", "mcp_server/providers/conflict_resolution.py:ConflictResolutionToolProvider.list_tools")
        return [
            types.Tool(
                name=Tool.RESOLVE_MODIFICATION_CONFLICT.value,
                description="Resolve a modification conflict reported by another tool. Call only when a tool returned a conflictId; use resolution=overwrite to apply the change or resolution=skip to discard.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "conflictId": {
                            "type": "string",
                            "description": "The GUID returned in the conflict response from the modifying tool.",
                        },
                        "resolution": {
                            "type": "string",
                            "enum": ["overwrite", "skip"],
                            "description": "overwrite = apply the stored modification; skip = discard and remove from store.",
                        },
                        "programPath": {
                            "type": "string",
                            "description": "Optional override for program context when resolving.",
                        },
                    },
                    "required": ["conflictId", "resolution"],
                },
            ),
        ]

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/conflict_resolution.py:ConflictResolutionToolProvider._handle")
        conflict_id = self._require_str(args, "conflictid", name="conflictId")
        resolution = self._get_str(args, "resolution", "action")
        if not resolution:
            raise ValueError("resolution is required (overwrite or skip)")
        resolution_norm = n(resolution)
        if resolution_norm not in ("overwrite", "skip"):
            raise ValueError("resolution must be 'overwrite' or 'skip'")

        session_id = get_current_mcp_session_id()
        pending = conflict_get(session_id, conflict_id)
        if pending is None:
            return create_error_response("Unknown or expired conflictId. It may have been used already or the session may have changed. Re-run the modifying tool to get a new conflictId if you still want to apply the change.")

        if resolution_norm == "skip":
            src_tool = pending.tool
            conflict_remove(session_id, conflict_id)
            logger.info(
                "modification_conflict_resolved resolution=skip conflict_id_prefix=%s source_tool=%s session_id=%s",
                conflict_id[:8],
                src_tool,
                redact_session_id(session_id),
            )
            return create_success_response({"resolution": "skip", "message": "Change discarded.", "conflictId": conflict_id})

        # overwrite: re-invoke the stored tool with force flag
        if self._manager is None:
            return create_error_response("Tool provider manager unavailable; cannot apply stored modification.")
        invoke_args = dict(pending.arguments)
        invoke_args["__force_apply_conflict_id"] = pending.conflict_id
        if pending.program_path and not any(n(k) == "programpath" for k in invoke_args):
            invoke_args["programPath"] = pending.program_path
        src_tool = pending.tool
        try:
            result = await self._manager.call_tool(pending.tool, invoke_args, program_info=self.program_info)
        except Exception as e:
            logger.warning(
                "resolve-modification-conflict overwrite failed exc_type=%s",
                type(e).__name__,
            )
            return create_error_response(f"Failed to apply stored modification: {e}")
        conflict_remove(session_id, conflict_id)
        logger.info(
            "modification_conflict_resolved resolution=overwrite conflict_id_prefix=%s source_tool=%s session_id=%s",
            conflict_id[:8],
            src_tool,
            redact_session_id(session_id),
        )
        if result and isinstance(result[0], types.TextContent):
            import json as _json

            try:
                data = _json.loads(result[0].text)
                return create_success_response({"resolution": "overwrite", "applied": True, "conflictId": conflict_id, "tool": pending.tool, "result": data})
            except Exception:
                pass
        return create_success_response({"resolution": "overwrite", "applied": True, "conflictId": conflict_id, "tool": pending.tool})
