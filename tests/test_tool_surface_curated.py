from __future__ import annotations

import pytest

from agentdecompile_cli.registry import Tool, _build_advertised_tools, get_active_tool_surface_profile


def _clear_surface_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "AGENTDECOMPILE_TOOL_SURFACE",
        "AGENT_DECOMPILE_TOOL_SURFACE",
        "AGENTDECOMPILE_ENABLE_LEGACY_TOOLS",
        "AGENTDECOMPILE_SHOW_LEGACY_TOOLS",
        "AGENTDECOMPILE_ENABLE_TOOLS",
        "AGENT_DECOMPILE_ENABLE_TOOLS",
        "AGENTDECOMPILE_DISABLE_TOOLS",
        "AGENT_DECOMPILE_DISABLE_TOOLS",
        "AGENTDECOMPILE_AUTO_CHECKIN",
        "AGENT_DECOMPILE_AUTO_CHECKIN",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.unit
def test_curated_surface_advertises_list_and_search_primitives(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_surface_env(monkeypatch)
    monkeypatch.setenv("AGENTDECOMPILE_TOOL_SURFACE", "curated")

    advertised = set(_build_advertised_tools())

    assert get_active_tool_surface_profile() == "curated"
    for tool in (
        Tool.LIST_FUNCTIONS,
        Tool.LIST_STRINGS,
        Tool.LIST_IMPORTS,
        Tool.LIST_EXPORTS,
        Tool.SEARCH_CODE,
        Tool.SEARCH_CONSTANTS,
        Tool.SEARCH_STRINGS,
        Tool.SEARCH_SYMBOLS,
    ):
        assert tool.value in advertised


@pytest.mark.unit
def test_curated_surface_hides_workflow_routers(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_surface_env(monkeypatch)
    monkeypatch.setenv("AGENTDECOMPILE_TOOL_SURFACE", "curated")

    advertised = set(_build_advertised_tools())

    assert Tool.SEARCH_EVERYTHING.value not in advertised
    assert Tool.GET_FUNCTION.value not in advertised


@pytest.mark.unit
def test_full_surface_still_advertises_workflow_routers(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_surface_env(monkeypatch)
    monkeypatch.setenv("AGENTDECOMPILE_TOOL_SURFACE", "full")

    advertised = set(_build_advertised_tools())

    assert get_active_tool_surface_profile() == "full"
    assert Tool.SEARCH_EVERYTHING.value in advertised
    assert Tool.GET_FUNCTION.value in advertised
    assert Tool.LIST_FUNCTIONS.value in advertised
