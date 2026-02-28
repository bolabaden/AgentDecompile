from __future__ import annotations

from types import SimpleNamespace
from typing import Any, ClassVar, cast

import pytest

from agentdecompile_cli.mcp_server.session_context import CURRENT_MCP_SESSION_ID, SESSION_CONTEXTS
from agentdecompile_cli.mcp_server.tool_providers import ToolProvider, ToolProviderManager, create_success_response
from mcp import types

from tests.helpers import parse_single_text_content_json


class _FakeProgram:
    def __init__(self, name: str) -> None:
        self._name: str = name

    def getName(self) -> str:
        return self._name


class _RoutingProvider(ToolProvider):
    HANDLERS: ClassVar[dict[str, str]] = {"listfunctions": "_handle"}

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="list-functions",
                description="routing test tool",
                inputSchema={"type": "object", "properties": {"binary": {"type": "string"}}, "required": []},
            )
        ]

    async def _handle(self, args: dict[str, object]) -> list[types.TextContent]:
        program_name = None
        if self.program_info is not None and getattr(self.program_info, "program", None) is not None:
            program_name = self.program_info.program.getName()
        return create_success_response({"programName": program_name})


@pytest.mark.asyncio
async def test_manager_prefers_requested_binary_from_session_context() -> None:
    session_id = "routing-requested-binary"
    token = CURRENT_MCP_SESSION_ID.set(session_id)
    try:
        manager = ToolProviderManager()
        provider = _RoutingProvider()
        manager._register(provider)

        requested_info = SimpleNamespace(program=_FakeProgram("k1_win_gog_swkotor.exe"))
        active_info = SimpleNamespace(program=_FakeProgram("other_active_program.exe"))

        SESSION_CONTEXTS.set_active_program_info(session_id, "/K1/k1_win_gog_swkotor.exe", cast(Any, requested_info))
        SESSION_CONTEXTS.set_active_program_info(session_id, "/Other/other_active_program.exe", cast(Any, active_info))

        response = await manager.call_tool("list-functions", {"binary": "k1_win_gog_swkotor.exe"})
        payload = parse_single_text_content_json(response)

        assert payload["programName"] == "k1_win_gog_swkotor.exe"
    finally:
        CURRENT_MCP_SESSION_ID.reset(token)


@pytest.mark.asyncio
async def test_manager_falls_back_to_active_program_when_requested_not_found() -> None:
    session_id = "routing-fallback-active"
    token = CURRENT_MCP_SESSION_ID.set(session_id)
    try:
        manager = ToolProviderManager()
        provider = _RoutingProvider()
        manager._register(provider)

        active_info = SimpleNamespace(program=_FakeProgram("active_program.exe"))
        SESSION_CONTEXTS.set_active_program_info(session_id, "/Active/active_program.exe", cast(Any, active_info))

        response = await manager.call_tool("list-functions", {"binary": "missing_program.exe"})
        payload = parse_single_text_content_json(response)

        assert payload["programName"] == "active_program.exe"
    finally:
        CURRENT_MCP_SESSION_ID.reset(token)
