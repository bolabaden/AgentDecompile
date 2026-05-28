"""Suggestion Tool Provider - get-suggestions (tool name 'suggest').

Stub tool: no-args call lists legacy suggestionType values. Typed calls raise
not-implemented — use decompile-function for context and rename-function /
manage-symbols to apply names (see AGENTS.md naming conventions).
"""

from __future__ import annotations

import logging

from typing import Any

from mcp import types

from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
    n,
)

logger = logging.getLogger(__name__)


class SuggestionToolProvider(ToolProvider):
    HANDLERS = {
        "getsuggestions": "_handle",
        "suggest": "_handle",
    }

    def list_tools(self) -> list[types.Tool]:
        logger.debug("diag.enter %s", "mcp_server/providers/suggestions.py:SuggestionToolProvider.list_tools")
        return [
            types.Tool(
                name="suggest",
                description="Reserved for future automated naming suggestions. Not implemented — use decompile-function and apply renames with rename-function / manage-symbols. No-args call lists suggestionType values for legacy clients.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The active program project."},
                        "suggestionType": {
                            "type": "string",
                            "description": "What kind of analysis suggestion to ask the automated engine for.",
                            "enum": [
                                "comment_type",
                                "comment_text",
                                "function_name",
                                "function_tags",
                                "variable_name",
                                "data_type",
                            ],
                        },
                        "addressOrSymbol": {"type": "string", "description": "The target address (hex) or symbol name defining the context for the suggestion."},
                        "functionIdentifier": {"type": "string", "description": "Alternative parameter for the target function name or address."},
                        "variableName": {"type": "string", "description": "If asking for variable_name, the current name of the local variable."},
                        "maxContext": {"type": "integer", "default": 5, "description": "How many surrounding source/decompile lines to feed into the suggestion engine."},
                        "includeCallers": {"type": "boolean", "default": False, "description": "Whether to analyze the functions that call the target."},
                        "includeCallees": {"type": "boolean", "default": False, "description": "Whether to analyze the child functions the target calls."},
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/suggestions.py:SuggestionToolProvider._handle")
        suggestion_type_raw = self._get_str(args, "suggestiontype", "type", default="")

        if not suggestion_type_raw:
            # Resource / no-args mode: return available suggestion types
            return create_success_response(
                {
                    "availableSuggestionTypes": [
                        "comment_type",
                        "comment_text",
                        "function_name",
                        "function_tags",
                        "variable_name",
                        "data_type",
                    ],
                    "note": "The suggest engine is not implemented. Use decompile-function plus rename tools. No-args call lists legacy suggestionType values.",
                }
            )

        suggestion_type = n(suggestion_type_raw)
        valid_suggestion_types: set[str] = {
            "commenttype",
            "commenttext",
            "functionname",
            "functiontags",
            "variablename",
            "datatype",
        }
        if suggestion_type not in valid_suggestion_types:
            raise ValueError(
                "Invalid suggestionType. Valid values: comment_type, comment_text, "
                "function_name, function_tags, variable_name, data_type."
            )

        raise ValueError(
            "The suggest tool is not implemented. Use decompile-function (or get-function) for "
            "pseudocode context, then apply names with rename-function, rename-variable, or "
            "manage-symbols. Follow AGENTS.md naming conventions (camelCase locals, PascalCase types)."
        )
