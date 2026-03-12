"""Suggestion Tool Provider - get-suggestions (tool name 'suggest').

- suggestionType: comment_type, comment_text, function_name, function_tags, variable_name, data_type.
- addressOrSymbol / functionIdentifier define the context; variableName used for variable_name suggestions.
- maxContext, includeCallers, includeCallees control how much surrounding context is fed to the suggestion engine. Suggestions are advisory only (no automatic edits).
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
        return [
            types.Tool(
                name="suggest",
                description="Generate smart analysis suggestions based on the immediate function code context. Note: Only supplies localized advice without executing changes.",
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
        program_path = self._require_str(args, "programpath", "program", "binary", name="program_path")
        suggestion_type_raw = self._require_str(args, "suggestiontype", "type", name="suggestion_type")

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
            raise ValueError("Invalid suggestion_type")

        addr = self._get_address_or_symbol(args)
        variable_name = self._get_str(args, "variablename", "variable", default="")
        max_context = self._get_int(args, "maxcontext", default=5)
        include_callers = self._get_bool(args, "includecallers", default=False)
        include_callees = self._get_bool(args, "includecallees", default=False)

        response_context: dict[str, Any] = {
            "programPath": program_path,
            "maxContext": max_context,
            "includeCallers": include_callers,
            "includeCallees": include_callees,
        }
        if self.program_info is None or self.program_info.program is None:
            response_context["note"] = "Context unavailable: no program loaded"

        return create_success_response(
            {
                "suggestionType": suggestion_type,
                "address": addr,
                "variableName": variable_name,
                "context": response_context,
            },
        )
