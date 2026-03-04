"""Suggestion Tool Provider - get-suggestions.

Provides analysis suggestions based on current function context.
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
                description="Get analysis suggestions for a function or address",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "Path to the target program"},
                        "suggestionType": {
                            "type": "string",
                            "description": "Category of suggestion to generate",
                            "enum": [
                                "comment_type",
                                "comment_text",
                                "function_name",
                                "function_tags",
                                "variable_name",
                                "data_type",
                            ],
                        },
                        "addressOrSymbol": {"type": "string", "description": "Target address (hex) or symbol name"},
                        "functionIdentifier": {"type": "string", "description": "Function name or address to scope suggestions"},
                        "variableName": {"type": "string", "description": "Variable name for variable-rename suggestions"},
                        "maxContext": {"type": "integer", "default": 5, "description": "Maximum number of context lines to include"},
                        "includeCallers": {"type": "boolean", "default": False, "description": "Include caller context in suggestions"},
                        "includeCallees": {"type": "boolean", "default": False, "description": "Include callee context in suggestions"},
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
