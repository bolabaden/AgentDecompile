"""Unit tests for agentdecompile://capabilities MCP resource."""

from __future__ import annotations

import json

import pytest

from agentdecompile_cli.mcp_server.resources.capabilities import CapabilitiesResource
from agentdecompile_cli.mcp_utils.tool_reference import build_capabilities_payload
from agentdecompile_cli.registry import RESOURCE_URI_CAPABILITIES, RESOURCE_URIS

pytestmark = pytest.mark.unit


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
    assert 2 in tiers
    assert 3 in tiers


@pytest.mark.asyncio
async def test_read_unknown_uri_raises_not_implemented() -> None:
    provider = CapabilitiesResource()
    with pytest.raises(NotImplementedError):
        await provider.read_resource("agentdecompile://unknown")
