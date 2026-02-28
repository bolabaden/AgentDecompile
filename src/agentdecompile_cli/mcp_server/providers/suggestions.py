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
                        "program_path": {"type": "string"},
                        "suggestion_type": {
                            "type": "string",
                            "enum": [
                                "comment_type",
                                "comment_text",
                                "function_name",
                                "function_tags",
                                "variable_name",
                                "data_type",
                            ],
                        },
                        "address": {"type": "string"},
                        "address_or_symbol": {"type": "string"},
                        "function_identifier": {"type": "string"},
                        "variable_name": {"type": "string"},
                        "max_context": {"type": "integer", "default": 5},
                        "include_callers": {"type": "boolean", "default": False},
                        "include_callees": {"type": "boolean", "default": False},
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

        address = self._get_str(
            args,
            "addressorsymbol",
            "address",
            "functionidentifier",
            "function",
            "symbol",
            "addr",
            default="",
        )
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
                "address": address,
                "variableName": variable_name,
                "context": response_context,
            },
        )
