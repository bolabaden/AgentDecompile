"""Unit tests for agentdecompile://capabilities MCP resource."""

from __future__ import annotations

import json

import pytest

from agentdecompile_cli.mcp_server.resources.capabilities import CapabilitiesResource
from agentdecompile_cli.mcp_utils.tool_reference import build_capabilities_payload
from agentdecompile_cli.registry import DISABLED_GUI_ONLY_TOOLS, RESOURCE_URI_CAPABILITIES, RESOURCE_URIS, Tool, get_advertised_tools_for_list

pytestmark = pytest.mark.unit

TIER01_RUN_TOOLS: dict[str, int] = {
    "run-file-triage": 0,
    "run-external-re-scan": 0,
    "run-batch-decompile": 1,
    "run-batch-export-gzf": 1,
    "run-batch-bsim-signatures": 1,
    "run-batch-sast-scan": 1,
}


def test_resource_uris_includes_capabilities() -> None:
    assert RESOURCE_URI_CAPABILITIES in RESOURCE_URIS


def test_capabilities_resource_listed() -> None:
    provider = CapabilitiesResource()
    resources = provider.list_resources()
    assert len(resources) == 1
    assert str(resources[0].uri) == RESOURCE_URI_CAPABILITIES


@pytest.mark.asyncio
async def test_read_capabilities_returns_json_with_tiers_and_tools() -> None:
    provider = CapabilitiesResource()
    raw = await provider.read_resource(RESOURCE_URI_CAPABILITIES)
    payload = json.loads(raw)
    assert payload["resourceUri"] == RESOURCE_URI_CAPABILITIES
    assert "tiers" in payload
    assert len(payload["tiers"]) == 4
    assert "summary" in payload
    assert "tools" in payload
    assert payload["summary"]["canonical_tool_count"] > 0


def test_build_capabilities_payload_has_analysis_tier_examples(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENTDECOMPILE_MAX_ANALYSIS_TIER", raising=False)
    monkeypatch.delenv("AGENT_DECOMPILE_MAX_ANALYSIS_TIER", raising=False)
    payload = build_capabilities_payload()
    tiers = {item["metadata"]["analysis_tier"] for item in payload["tools"]}
    assert 0 in tiers
    assert 1 in tiers
    assert 2 in tiers
    assert 3 in tiers


@pytest.mark.asyncio
async def test_read_unknown_uri_raises_not_implemented() -> None:
    provider = CapabilitiesResource()
    with pytest.raises(NotImplementedError):
        await provider.read_resource("agentdecompile://unknown")


def test_capabilities_payload_includes_tier01_run_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENTDECOMPILE_MAX_ANALYSIS_TIER", raising=False)
    monkeypatch.delenv("AGENT_DECOMPILE_MAX_ANALYSIS_TIER", raising=False)
    payload = build_capabilities_payload()
    tools_by_name = {item["name"]: item for item in payload["tools"]}
    for name, expected_tier in TIER01_RUN_TOOLS.items():
        assert name in tools_by_name, f"missing {name} in capabilities tools[]"
        tool = tools_by_name[name]
        assert tool["advertised"] is True
        assert tool["metadata"]["analysis_tier"] == expected_tier


def test_capabilities_summary_counts_match_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENTDECOMPILE_MAX_ANALYSIS_TIER", raising=False)
    monkeypatch.delenv("AGENT_DECOMPILE_MAX_ANALYSIS_TIER", raising=False)
    payload = build_capabilities_payload()
    summary = payload["summary"]
    assert summary["canonical_tool_count"] == len(Tool)
    assert summary["advertised_tool_count"] == len(get_advertised_tools_for_list())
    assert summary["advertised_tool_count"] == len(Tool) - len(DISABLED_GUI_ONLY_TOOLS)


def test_capabilities_tier_routing_includes_mcp_run_tools() -> None:
    payload = build_capabilities_payload()
    tiers = {item["tier"]: item for item in payload["tiers"]}
    tier0_examples = tiers[0]["examples"]
    tier1_examples = tiers[1]["examples"]
    assert "run-file-triage" in tier0_examples
    assert "run-external-re-scan" in tier0_examples
    assert "run-batch-decompile" in tier1_examples
    assert "run-batch-sast-scan" in tier1_examples
