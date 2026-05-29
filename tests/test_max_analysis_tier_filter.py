"""Unit tests for runtime tools/list filter by max analysis_tier."""

from __future__ import annotations

import pytest

from agentdecompile_cli.mcp_server.session_context import (
    CURRENT_REQUEST_MAX_ANALYSIS_TIER,
)
from agentdecompile_cli.registry import (
    Tool,
    get_advertised_tools_for_list,
    get_effective_max_analysis_tier,
    get_tool_analysis_tier,
    parse_max_analysis_tier_value,
    resolve_tool_name,
)

pytestmark = pytest.mark.unit


def test_parse_max_analysis_tier_accepts_two_and_three() -> None:
    assert parse_max_analysis_tier_value("2") == 2
    assert parse_max_analysis_tier_value("3") == 3
    assert parse_max_analysis_tier_value(" 2 ") == 2


def test_parse_max_analysis_tier_rejects_invalid() -> None:
    assert parse_max_analysis_tier_value("") is None
    assert parse_max_analysis_tier_value("1") is None
    assert parse_max_analysis_tier_value("4") is None
    assert parse_max_analysis_tier_value("tier2") is None
    assert parse_max_analysis_tier_value(None) is None


def test_env_max_tier_two_excludes_tier_three_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTDECOMPILE_MAX_ANALYSIS_TIER", "2")
    monkeypatch.delenv("AGENT_DECOMPILE_MAX_ANALYSIS_TIER", raising=False)
    listed = get_advertised_tools_for_list()
    assert Tool.LIST_FUNCTIONS.value in listed
    assert Tool.DECOMPILE_FUNCTION.value not in listed
    assert all(get_tool_analysis_tier(name) <= 2 for name in listed)


def test_header_override_beats_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTDECOMPILE_MAX_ANALYSIS_TIER", "2")
    token = CURRENT_REQUEST_MAX_ANALYSIS_TIER.set("3")
    try:
        assert get_effective_max_analysis_tier() == 3
        listed = get_advertised_tools_for_list()
        assert Tool.DECOMPILE_FUNCTION.value in listed
    finally:
        CURRENT_REQUEST_MAX_ANALYSIS_TIER.reset(token)


def test_invalid_tier_env_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTDECOMPILE_MAX_ANALYSIS_TIER", "99")
    assert get_effective_max_analysis_tier() is None
    listed = get_advertised_tools_for_list()
    assert Tool.DECOMPILE_FUNCTION.value in listed


def test_legacy_env_alias_max_analysis_tier(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENTDECOMPILE_MAX_ANALYSIS_TIER", raising=False)
    monkeypatch.setenv("AGENT_DECOMPILE_MAX_ANALYSIS_TIER", "2")
    assert get_effective_max_analysis_tier() == 2
    assert Tool.DECOMPILE_FUNCTION.value not in get_advertised_tools_for_list()


def test_invalid_header_falls_back_to_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTDECOMPILE_MAX_ANALYSIS_TIER", "2")
    token = CURRENT_REQUEST_MAX_ANALYSIS_TIER.set("invalid")
    try:
        assert get_effective_max_analysis_tier() == 2
        assert Tool.DECOMPILE_FUNCTION.value not in get_advertised_tools_for_list()
    finally:
        CURRENT_REQUEST_MAX_ANALYSIS_TIER.reset(token)


def test_tools_call_resolution_unaffected_by_list_filter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTDECOMPILE_MAX_ANALYSIS_TIER", "2")
    listed = get_advertised_tools_for_list()
    assert Tool.DECOMPILE_FUNCTION.value not in listed
    assert resolve_tool_name(Tool.DECOMPILE_FUNCTION.value) == Tool.DECOMPILE_FUNCTION.value


def test_capabilities_summary_includes_max_tier_when_active(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentdecompile_cli.mcp_utils.tool_reference import build_capabilities_payload

    monkeypatch.setenv("AGENTDECOMPILE_MAX_ANALYSIS_TIER", "2")
    payload = build_capabilities_payload()
    assert payload["summary"]["max_analysis_tier"] == 2
    tool_names = {item["name"] for item in payload["tools"]}
    assert Tool.LIST_FUNCTIONS.value in tool_names
    assert Tool.DECOMPILE_FUNCTION.value not in tool_names
