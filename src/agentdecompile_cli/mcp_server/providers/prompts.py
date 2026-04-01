"""Prompt tools – list-prompts.

Exposes MCP prompt definitions as a callable tool so the model can discover
available reverse-engineering workflow prompts (names and descriptions).
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

from typing import Any

from mcp import types

from agentdecompile_cli.mcp_server import prompt_providers
from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
)
from agentdecompile_cli.registry import Tool


class PromptToolProvider(ToolProvider):
    """Provider for list-prompts."""

    HANDLERS = {
        "listprompts": "_handle_list_prompts",
    }

    def list_tools(self) -> list[types.Tool]:
        logger.debug("diag.enter %s", "mcp_server/providers/prompts.py:PromptToolProvider.list_tools")
        return [
            types.Tool(
                name=Tool.LIST_PROMPTS.value,
                description="List all available MCP prompts (reverse-engineering workflows).",
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
        ]

    async def _handle_list_prompts(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/prompts.py:PromptToolProvider._handle_list_prompts")
        prompts = prompt_providers.list_prompts()
        payload: list[dict[str, Any]] = []
        for p in prompts:
            entry: dict[str, Any] = {
                "name": p.name,
                "description": p.description or "",
            }
            if p.arguments:
                entry["arguments"] = [{"name": a.name, "description": a.description, "required": a.required} for a in p.arguments]
            payload.append(entry)
        return create_success_response({"prompts": payload})
