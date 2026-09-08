"""Unit test: tools/call rejects tools above max_analysis_tier."""

from __future__ import annotations

import json

import pytest

from agentdecompile_cli.mcp_server.tool_providers import ToolProviderManager
from agentdecompile_cli.registry import Tool, get_tool_analysis_tier

pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_call_tool_rejects_tier_above_max(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTDECOMPILE_MAX_ANALYSIS_TIER", "2")
    monkeypatch.delenv("AGENT_DECOMPILE_MAX_ANALYSIS_TIER", raising=False)

    tool_name = Tool.DECOMPILE_FUNCTION.value
    assert get_tool_analysis_tier(tool_name) == 3

    manager = ToolProviderManager()
    result = await manager.call_tool(tool_name, {})

    payload = json.loads(result[0].text)
    assert payload["success"] is False
    assert payload["context"]["state"] == "max-analysis-tier-exceeded"
    assert payload["context"]["maxAnalysisTier"] == 2
    assert payload["context"]["toolAnalysisTier"] == 3
