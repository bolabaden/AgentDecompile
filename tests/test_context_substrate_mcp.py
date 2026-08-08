"""Unit tests for VISION substrate MCP tools (export-context / acquisition-query)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_cli.mcp_server.providers.context_substrate import ContextSubstrateToolProvider
from agentdecompile_cli.mcp_server.tool_providers import ToolProviderManager, n
from agentdecompile_cli.registry import Tool, get_advertised_tools_for_list, get_tool_analysis_tier
from agentdecompile_recovery.acquisition_bundle import SCHEMA as BUNDLE_SCHEMA

pytestmark = pytest.mark.unit


def test_context_substrate_tools_are_tier_zero() -> None:
    assert get_tool_analysis_tier(Tool.EXPORT_CONTEXT) == 0
    assert get_tool_analysis_tier(Tool.ACQUISITION_QUERY) == 0


def test_context_substrate_tools_advertised_on_default_surface() -> None:
    advertised = set(get_advertised_tools_for_list())
    assert Tool.EXPORT_CONTEXT.value in advertised
    assert Tool.ACQUISITION_QUERY.value in advertised


def test_manager_registers_context_substrate_tools() -> None:
    manager = ToolProviderManager()
    manager.register_all_providers()
    names = {tool.name for tool in manager.list_tools()}
    assert "export-context" in names
    assert "acquisition-query" in names
    assert "reconstruct" in names


@pytest.mark.asyncio
async def test_provider_export_context_writes_tree(tmp_path: Path) -> None:
    src = tmp_path / "app"
    src.mkdir()
    (src / "readme.txt").write_text("hello substrate\n", encoding="utf-8")
    out = tmp_path / "out"

    provider = ContextSubstrateToolProvider()
    result = await provider._handle_export_context(
        {
            n("inputPath"): str(src),
            n("outDir"): str(out),
            n("binaryAnalysis"): "light",
            n("extractContainers"): False,
            n("maxFiles"): 50,
            n("maxDepth"): 1,
        }
    )
    payload = json.loads(result[0].text)
    assert payload["tool"] == "export-context"
    assert payload["schema"] == "agentdecompile.context-export.v1"
    assert "advisory" in payload["claimBoundary"].lower() or "not" in payload["claimBoundary"].lower()
    assert (out / "manifest.json").is_file()
    assert (out / "tree.json").is_file()
    assert (out / "TREE.md").is_file()


@pytest.mark.asyncio
async def test_provider_acquisition_query_inspect(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "manifest.json").write_text(
        json.dumps(
            {
                "schema": BUNDLE_SCHEMA,
                "status": "complete",
                "target": {"preferredName": "sample.bin"},
                "targetFingerprint": "test-fp",
                "extractorConfig": {},
                "sourceCount": 0,
                "entityCount": 1,
                "conflictCount": 0,
                "sourcesJsonl": "sources.jsonl",
                "entitiesJsonl": "entities.jsonl",
                "conflictsJsonl": "conflicts.jsonl",
                "factsJsonl": "function-facts.jsonl",
            }
        ),
        encoding="utf-8",
    )
    (bundle / "sources.jsonl").write_text("", encoding="utf-8")
    (bundle / "entities.jsonl").write_text(
        json.dumps(
            {
                "kind": "function",
                "address": 4096,
                "addressSpace": "ram",
                "name": "entry",
                "sourceId": "s1",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (bundle / "conflicts.jsonl").write_text("", encoding="utf-8")
    (bundle / "function-facts.jsonl").write_text("", encoding="utf-8")

    provider = ContextSubstrateToolProvider()
    result = await provider._handle_acquisition_query(
        {n("bundleDir"): str(bundle), n("action"): "inspect"}
    )
    payload = json.loads(result[0].text)
    assert payload["tool"] == "acquisition-query"
    assert payload["schema"] == "agentdecompile.acquisition-query.v1"
    assert payload["action"] == "inspect"
    assert payload["bundle"]["entityCount"] == 1
    assert "advisory" in payload["claimBoundary"].lower()


@pytest.mark.asyncio
async def test_provider_acquisition_query_missing_bundle(tmp_path: Path) -> None:
    provider = ContextSubstrateToolProvider()
    result = await provider._handle_acquisition_query(
        {n("bundleDir"): str(tmp_path / "missing")}
    )
    payload = json.loads(result[0].text)
    assert payload.get("success") is False or "error" in payload or "not found" in json.dumps(payload).lower()
