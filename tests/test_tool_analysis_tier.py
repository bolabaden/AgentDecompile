"""Unit tests for Ghidra MCP analysis_tier metadata (tiered RE routing)."""

from __future__ import annotations

import pytest

from agentdecompile_cli.registry import Tool, get_tool_analysis_tier, get_tool_metadata

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("tool", "expected_tier"),
    [
        (Tool.LIST_FUNCTIONS, 2),
        (Tool.LIST_STRINGS, 2),
        (Tool.GET_REFERENCES, 2),
        (Tool.GET_CALL_GRAPH, 2),
        (Tool.CHECKOUT_STATUS, 2),
        (Tool.ANALYZE_PROGRAM, 2),
        (Tool.DECOMPILE_FUNCTION, 3),
        (Tool.GET_FUNCTION, 3),
        (Tool.SEARCH_EVERYTHING, 3),
        (Tool.MANAGE_COMMENTS, 3),
        (Tool.MATCH_FUNCTION, 3),
        (Tool.EXECUTE_SCRIPT, 3),
        (Tool.RUN_FILE_TRIAGE, 0),
        (Tool.RUN_EXTERNAL_RE_SCAN, 0),
        (Tool.RUN_BATCH_DECOMPILE, 1),
        (Tool.RUN_BATCH_EXPORT_GZF, 1),
        (Tool.RUN_BATCH_BSIM_SIGNATURES, 1),
        (Tool.RUN_BATCH_SAST_SCAN, 1),
    ],
)
def test_analysis_tier_examples(tool: Tool, expected_tier: int) -> None:
    assert get_tool_analysis_tier(tool) == expected_tier
    metadata = get_tool_metadata(tool)
    assert metadata is not None
    assert metadata.analysis_tier == expected_tier


def test_every_canonical_tool_has_known_analysis_tier() -> None:
    for tool in Tool:
        if tool in {Tool.GET_CURRENT_ADDRESS, Tool.GET_CURRENT_FUNCTION, Tool.OPEN_PROGRAM_IN_CODE_BROWSER, Tool.OPEN_ALL_PROGRAMS_IN_CODE_BROWSER}:
            continue
        tier = get_tool_analysis_tier(tool)
        assert tier in {0, 1, 2, 3}, f"{tool.value} has unexpected tier {tier}"


def test_metadata_analysis_tier_matches_helper() -> None:
    for tool in Tool:
        metadata = get_tool_metadata(tool)
        if metadata is None:
            continue
        assert metadata.analysis_tier == get_tool_analysis_tier(tool)
