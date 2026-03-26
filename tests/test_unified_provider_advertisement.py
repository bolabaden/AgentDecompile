"""Tests for unified MCP tool advertisement and docs parity.

This test module ensures:
- Unified MCP provider advertises snake_case tool names and argument keys.
- Advertised tool/argument sets align with tools_schema source-of-truth.
- TOOLS_LIST.md canonical index remains in sync with tools_schema.TOOLS.
"""

from __future__ import annotations

import re

from pathlib import Path

import pytest

from agentdecompile_cli.mcp_server.tool_providers import UnifiedToolProvider
from agentdecompile_cli.registry import (
    ADVERTISED_TOOLS,
    ADVERTISED_TOOL_PARAMS,
    DISABLED_GUI_ONLY_TOOLS,
    NON_ADVERTISED_TOOL_ALIASES,
    TOOLS,
    normalize_identifier,
    to_snake_case,
)
from mcp import types
from tests.helpers import assert_mapping_invariants, assert_string_invariants

pytestmark = pytest.mark.unit


def _is_snake_case(identifier: str) -> bool:
    return bool(re.fullmatch(r"[a-z][a-z0-9_]*", identifier))


def _is_canonical_tool_name(identifier: str) -> bool:
    """MCP canonical tool ids are kebab-case (hyphens); allow a-z, digits, hyphens."""
    return bool(re.fullmatch(r"[a-z][a-z0-9-]*", identifier))


def _is_advertised_property_key(key: str) -> bool:
    """Unified provider uses snake_case param keys plus camelCase ``responseFormat`` for output shape."""
    return key == "responseFormat" or _is_snake_case(key)


def _extract_canonical_tools_from_docs(markdown_text: str) -> list[str]:
    lower_text = markdown_text.lower()
    # Heading evolved: was "## Canonical Tools", now "## Canonical Tool Docs"
    marker_line_idx: int | None = None
    for i, line in enumerate(lower_text.splitlines()):
        stripped = line.strip()
        if stripped.startswith("## ") and "canonical tool" in stripped:
            marker_line_idx = i
            break
    if marker_line_idx is None:
        raise AssertionError("TOOLS_LIST.md missing a 'Canonical Tool…' section heading")

    lines_after_marker = markdown_text.splitlines()[marker_line_idx:]
    extracted: list[str] = []

    for raw_line in lines_after_marker:
        line_stripped = raw_line.strip()
        # Do not scan past the canonical docs region (later `### ...` headings exist in skills).
        if line_stripped.lower() == "## usage tips":
            break
        match: re.Match | None = re.match(r"^###\s+`([^`]+)`\s*$", line_stripped)
        if match:
            extracted.append(match.group(1))

    return extracted


class TestUnifiedProviderAdvertisement:
    """Validate unified MCP tool advertisement contracts."""

    def test_all_advertised_tool_names_are_snake_case(self):
        provider = UnifiedToolProvider()
        advertised_tools: list[types.Tool] = provider.list_tools()

        assert advertised_tools, "Expected non-empty advertised tools list"
        for tool in advertised_tools:
            assert _is_canonical_tool_name(tool.name), f"Tool {tool.name!r} should be a canonical kebab-case id"
            assert_string_invariants(tool.name)

    def test_all_advertised_tool_names_map_to_schema_tools(self):
        provider = UnifiedToolProvider()
        advertised_tools = provider.list_tools()

        expected_advertised_names = set(ADVERTISED_TOOLS)
        actual_advertised_names = {tool.name for tool in advertised_tools}

        assert actual_advertised_names == expected_advertised_names
        assert_mapping_invariants({"expected": list(expected_advertised_names), "actual": list(actual_advertised_names)})

    @pytest.mark.parametrize("tool_name", [name for name, params in ADVERTISED_TOOL_PARAMS.items() if params])
    def test_advertised_argument_keys_are_snake_case_and_cover_schema(self, tool_name: str):
        provider = UnifiedToolProvider()
        advertised_tools = provider.list_tools()

        matched = [tool for tool in advertised_tools if tool.name == tool_name]
        assert len(matched) == 1, f"Expected exactly one advertised tool for {tool_name!r}"

        tool = matched[0]
        properties = tool.inputSchema.get("properties", {})
        assert properties, f"Tool {tool_name!r} should advertise properties"

        for arg_name in properties:
            assert _is_advertised_property_key(arg_name), (
                f"Tool {tool_name!r} advertised arg {arg_name!r} should be snake_case or responseFormat"
            )
            assert_string_invariants(arg_name)

        expected_args = {to_snake_case(param_name) for param_name in ADVERTISED_TOOL_PARAMS[tool_name]}
        expected_args.add("responseFormat")
        assert set(properties.keys()) == expected_args
        assert_mapping_invariants({"expected": list(expected_args), "actual": list(properties.keys())})

    def test_advertised_names_round_trip_to_canonical_schema_names(self):
        provider = UnifiedToolProvider()
        advertised_tools = provider.list_tools()
        canonical_tools_set = set(ADVERTISED_TOOLS)

        for advertised in advertised_tools:
            matched = [canonical for canonical in canonical_tools_set if normalize_identifier(canonical) == normalize_identifier(advertised.name)]
            assert len(matched) == 1, f"Advertised tool {advertised.name!r} should map to exactly one canonical schema tool"
            assert_string_invariants(advertised.name)

    def test_aliases_are_not_advertised(self):
        provider = UnifiedToolProvider()
        advertised_names = {tool.name for tool in provider.list_tools()}

        # Only check aliases that are NOT also in the TOOLS list
        # (some tools appear in both TOOLS and NON_ADVERTISED_TOOL_ALIASES
        # because they are canonical tools that also forward to parent tools)
        tools_set = set(TOOLS)
        for alias_name in NON_ADVERTISED_TOOL_ALIASES:
            if alias_name in tools_set:
                continue  # legitimately advertised
            assert alias_name not in advertised_names

    def test_gui_only_tools_are_not_advertised(self):
        provider = UnifiedToolProvider()
        advertised_names = {tool.name for tool in provider.list_tools()}

        for gui_tool in DISABLED_GUI_ONLY_TOOLS:
            gui_tool_name = gui_tool.value
            assert gui_tool_name not in advertised_names


class TestToolsListParity:
    """Ensure TOOLS_LIST.md canonical index stays synced to tools_schema."""

    def test_tools_list_canonical_index_matches_tools_schema(self):
        repo_root = Path(__file__).resolve().parent.parent
        tools_list_path = repo_root / "TOOLS_LIST.md"
        markdown_text = tools_list_path.read_text(encoding="utf-8")

        documented = _extract_canonical_tools_from_docs(markdown_text)
        assert documented, "Expected canonical tools to be documented in TOOLS_LIST.md"

        assert documented == TOOLS
        assert_mapping_invariants({"documented": documented, "schema": TOOLS})
