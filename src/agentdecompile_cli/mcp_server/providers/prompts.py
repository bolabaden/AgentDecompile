"""Prompt tools – list-prompts and get-prompt-content.

Exposes MCP prompt definitions as callable tools so the model can discover prompts
and resolve prompt content (messages + description) to drive a subagent or new turn.
Use get-prompt-content with a prompt name and arguments to get the same content
that prompts/get returns; then pass that content to your host's subagent/task API.
"""

from __future__ import annotations

from typing import Any

from mcp import types

from agentdecompile_cli.mcp_server import prompt_providers
from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
    create_error_response,
    n,
)
from agentdecompile_cli.registry import Tool


class PromptToolProvider(ToolProvider):
    """Provider for list-prompts and get-prompt-content."""

    HANDLERS = {
        "listprompts": "_handle_list_prompts",
        "getpromptcontent": "_handle_get_prompt_content",
    }

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name=Tool.LIST_PROMPTS.value,
                description="List all available MCP prompts (reverse-engineering workflows). Use get-prompt-content with a prompt name to resolve messages for a subagent.",
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
            types.Tool(
                name=Tool.GET_PROMPT_CONTENT.value,
                description="Resolve a named MCP prompt with the given arguments and return the prompt messages and description. Use the returned content to start a subagent or new turn with that task (e.g. re-scout-broad-sweep, re-diver-deep-dive, re-convergence-orchestrator).",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "promptName": {
                            "type": "string",
                            "description": "MCP prompt name (e.g. re-scout-broad-sweep, re-diver-deep-dive, re-bottom-up-analyst).",
                        },
                        "arguments": {
                            "type": "object",
                            "description": "Prompt arguments as key-value strings (e.g. program_path, analysis_target, search_keywords).",
                            "additionalProperties": {"type": "string"},
                        },
                        "programPath": {
                            "type": "string",
                            "description": "Convenience: merged into arguments as program_path if arguments is not provided.",
                        },
                        "analysisTarget": {
                            "type": "string",
                            "description": "Convenience: merged into arguments as analysis_target.",
                        },
                        "searchKeywords": {
                            "type": "string",
                            "description": "Convenience: merged into arguments as search_keywords.",
                        },
                    },
                    "required": ["promptName"],
                },
            ),
        ]

    async def _handle_list_prompts(self, args: dict[str, Any]) -> list[types.TextContent]:
        prompts = prompt_providers.list_prompts()
        payload: list[dict[str, Any]] = []
        for p in prompts:
            entry: dict[str, Any] = {
                "name": p.name,
                "description": p.description or "",
            }
            if p.arguments:
                entry["arguments"] = [
                    {"name": a.name, "description": a.description, "required": a.required}
                    for a in p.arguments
                ]
            payload.append(entry)
        return create_success_response({"prompts": payload})

    async def _handle_get_prompt_content(self, args: dict[str, Any]) -> list[types.TextContent]:
        name = self._require_str(args, "promptname", name="promptName")
        # Build arguments: explicit "arguments" dict, or convenience top-level params
        raw_args = self._get(args, "arguments")
        if isinstance(raw_args, dict):
            prompt_args = {str(k): str(v) for k, v in raw_args.items()}
        else:
            prompt_args = {}
        # Merge convenience params (snake_case for prompt_providers)
        program_path = self._get_str(args, "programpath", "program_path")
        if program_path:
            prompt_args.setdefault("program_path", program_path)
        analysis_target = self._get_str(args, "analysistarget", "analysis_target")
        if analysis_target:
            prompt_args.setdefault("analysis_target", analysis_target)
        search_keywords = self._get_str(args, "searchkeywords", "search_keywords")
        if search_keywords:
            prompt_args.setdefault("search_keywords", search_keywords)
        try:
            result = prompt_providers.get_prompt(name, prompt_args or None)
        except ValueError as e:
            return create_error_response(str(e))
        # Serialize GetPromptResult to JSON-serializable dict
        messages_payload: list[dict[str, Any]] = []
        for msg in result.messages:
            text = msg.content.text if isinstance(msg.content, types.TextContent) else ""
            messages_payload.append({"role": msg.role, "content": {"type": "text", "text": text}})
        return create_success_response(
            {
                "description": result.description,
                "messages": messages_payload,
                "promptName": name,
            }
        )
