"""Unit tests for MCP initialize instructions preamble."""

from __future__ import annotations

import pytest

from agentdecompile_cli.mcp_utils.tool_reference import build_initialize_instructions
from agentdecompile_cli.registry import RESOURCE_URI_CAPABILITIES

pytestmark = pytest.mark.unit


def test_build_initialize_instructions_non_empty() -> None:
    text = build_initialize_instructions()
    assert isinstance(text, str)
    assert len(text) > 200


def test_build_initialize_instructions_includes_discovery_and_bootstrap() -> None:
    text = build_initialize_instructions()
    assert RESOURCE_URI_CAPABILITIES in text
    assert "open-project" in text
    assert "run-file-triage" in text
    for tier in ("Tier 0", "Tier 1", "Tier 2", "Tier 3"):
        assert tier in text
    assert "projectContext" in text
    assert "mcp-session-id" in text
    assert "analysis gate" in text.lower()


def test_build_initialize_instructions_under_length_budget() -> None:
    text = build_initialize_instructions()
    assert len(text.encode("utf-8")) <= 2048


def test_build_initialize_instructions_respects_max_tier_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTDECOMPILE_MAX_ANALYSIS_TIER", "2")
    text = build_initialize_instructions()
    assert "Max analysis tier cap active: Tier 2" in text
