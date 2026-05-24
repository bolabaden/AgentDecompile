"""Unit tests for ToolProviderManager pre-dispatch analysis gate."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp import types

from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    ToolProviderManager,
    create_success_response,
)
from agentdecompile_cli.mcp_utils.program_analysis import ProgramAnalysisTimeout


class _GateProbeProvider(ToolProvider):
    """Minimal provider for list-functions and list-project-files."""

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="list-functions",
                description="probe",
                inputSchema={"type": "object", "properties": {}, "required": []},
            ),
            types.Tool(
                name="list-project-files",
                description="probe",
                inputSchema={"type": "object", "properties": {}, "required": []},
            ),
        ]

    async def call_tool(self, name: str, arguments: dict):
        if name.replace("-", "").replace("_", "").lower() == "listprojectfiles":
            return create_success_response({"programs": []})
        return create_success_response({"ok": True})


@pytest.fixture
def gate_manager() -> ToolProviderManager:
    manager = ToolProviderManager()
    manager._register(_GateProbeProvider())
    return manager


@pytest.fixture
def program_info() -> SimpleNamespace:
    program = MagicMock()
    df = MagicMock()
    df.getPathname.return_value = "/repo/other.exe"
    program.getDomainFile.return_value = df
    return SimpleNamespace(program=program, ghidra_analysis_complete=False)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_analysis_gate_invoked_for_non_exempt_tool(
    gate_manager: ToolProviderManager,
    program_info: SimpleNamespace,
) -> None:
    to_thread_mock = AsyncMock(return_value=None)
    with (
        patch(
            "agentdecompile_cli.mcp_server.tool_providers.SESSION_CONTEXTS.get_program_info",
            return_value=program_info,
        ),
        patch(
            "agentdecompile_cli.mcp_server.tool_providers.SESSION_CONTEXTS.get_active_program_info",
            return_value=None,
        ),
        patch("agentdecompile_cli.mcp_server.tool_providers.SESSION_CONTEXTS.add_tool_history"),
        patch(
            "agentdecompile_cli.mcp_server.tool_providers.asyncio.to_thread",
            to_thread_mock,
        ),
    ):
        await gate_manager.call_tool("list-functions", {"programPath": "/repo/other.exe"})

    assert to_thread_mock.await_count == 1
    assert to_thread_mock.await_args.args[0].__name__ == "wait_for_program_analysis_ready"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_analysis_gate_skipped_for_exempt_list_project_files(
    gate_manager: ToolProviderManager,
) -> None:
    to_thread_mock = AsyncMock(return_value=None)
    with (
        patch("agentdecompile_cli.mcp_server.tool_providers.SESSION_CONTEXTS.add_tool_history"),
        patch(
            "agentdecompile_cli.mcp_server.tool_providers.asyncio.to_thread",
            to_thread_mock,
        ),
    ):
        await gate_manager.call_tool("list-project-files", {})

    to_thread_mock.assert_not_awaited()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_analysis_gate_skipped_for_autoprereq_invocation(
    gate_manager: ToolProviderManager,
    program_info: SimpleNamespace,
) -> None:
    to_thread_mock = AsyncMock(return_value=None)
    with (
        patch(
            "agentdecompile_cli.mcp_server.tool_providers.SESSION_CONTEXTS.get_program_info",
            return_value=program_info,
        ),
        patch(
            "agentdecompile_cli.mcp_server.tool_providers.SESSION_CONTEXTS.get_active_program_info",
            return_value=None,
        ),
        patch("agentdecompile_cli.mcp_server.tool_providers.SESSION_CONTEXTS.add_tool_history"),
        patch(
            "agentdecompile_cli.mcp_server.tool_providers.asyncio.to_thread",
            to_thread_mock,
        ),
    ):
        await gate_manager.call_tool(
            "list-functions",
            {"programPath": "/repo/other.exe", "__auto_prereq_invocation": True},
        )

    to_thread_mock.assert_not_awaited()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_analysis_timeout_returns_structured_error(
    gate_manager: ToolProviderManager,
    program_info: SimpleNamespace,
) -> None:
    async def _raise_timeout(*_args, **_kwargs):
        raise ProgramAnalysisTimeout("Ghidra analysis did not finish within 600s")

    with (
        patch(
            "agentdecompile_cli.mcp_server.tool_providers.SESSION_CONTEXTS.get_program_info",
            return_value=program_info,
        ),
        patch(
            "agentdecompile_cli.mcp_server.tool_providers.SESSION_CONTEXTS.get_active_program_info",
            return_value=None,
        ),
        patch("agentdecompile_cli.mcp_server.tool_providers.SESSION_CONTEXTS.add_tool_history"),
        patch(
            "agentdecompile_cli.mcp_server.tool_providers.asyncio.to_thread",
            side_effect=_raise_timeout,
        ),
    ):
        result = await gate_manager.call_tool(
            "list-functions",
            {"programPath": "/repo/other.exe", "responseFormat": "json"},
        )

    assert len(result) == 1
    assert "analysis-timeout" in result[0].text
    assert "600s" in result[0].text


@pytest.mark.unit
@pytest.mark.asyncio
async def test_requested_program_path_does_not_fallback_to_active_program(
    gate_manager: ToolProviderManager,
) -> None:
    active_info = SimpleNamespace(program=MagicMock(), ghidra_analysis_complete=False)
    to_thread_mock = AsyncMock(return_value=None)
    with (
        patch(
            "agentdecompile_cli.mcp_server.tool_providers.SESSION_CONTEXTS.get_program_info",
            return_value=None,
        ),
        patch(
            "agentdecompile_cli.mcp_server.tool_providers.SESSION_CONTEXTS.get_active_program_info",
            return_value=active_info,
        ),
        patch.object(gate_manager, "_activate_requested_program", AsyncMock(return_value=None)),
        patch("agentdecompile_cli.mcp_server.tool_providers.SESSION_CONTEXTS.add_tool_history"),
        patch(
            "agentdecompile_cli.mcp_server.tool_providers.asyncio.to_thread",
            to_thread_mock,
        ),
    ):
        result = await gate_manager.call_tool(
            "list-functions",
            {"programPath": "/repo/missing.exe", "responseFormat": "json"},
        )

    assert "program-resolution-failed" in result[0].text
    to_thread_mock.assert_not_awaited()
