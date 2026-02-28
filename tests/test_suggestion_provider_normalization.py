"""Unit tests for suggestion provider normalization behavior."""

from __future__ import annotations

import json

from typing import Any

import pytest

from agentdecompile_cli.mcp_server.providers.suggestions import SuggestionToolProvider

from tests.helpers import assert_mapping_invariants, assert_string_invariants

pytestmark = pytest.mark.unit


def _parse_text_content_payload(text_contents: list[Any]) -> Any:
    assert text_contents, "Expected non-empty MCP text content"
    assert text_contents[0].type == "text"
    payload = json.loads(text_contents[0].text)
    assert_mapping_invariants(payload)
    return payload


class TestSuggestionToolSchema:
    """Ensure advertised schema is snake_case-only."""

    def test_advertises_snake_case_tool_and_parameters(self):
        provider = SuggestionToolProvider()
        tools: list[Any] = provider.list_tools()
        assert len(tools) == 1

        tool: Any = tools[0]
        assert tool.name == "suggest"

        properties: dict[str, Any] = tool.inputSchema["properties"]
        expected_snake_case_keys: set[str] = {
            "program_path",
            "suggestion_type",
            "address",
            "address_or_symbol",
            "function_identifier",
            "variable_name",
            "max_context",
            "include_callers",
            "include_callees",
        }
        assert expected_snake_case_keys.issubset(set(properties.keys()))

        enum_values: list[str] = properties["suggestion_type"]["enum"]
        assert "comment_type" in enum_values
        assert "comment_text" in enum_values
        assert "function_name" in enum_values
        assert "function_tags" in enum_values
        assert "variable_name" in enum_values
        assert "data_type" in enum_values


class TestSuggestionToolArgumentNormalization:
    """Ensure suggest accepts vague/non-accurate argument formats."""

    @pytest.mark.asyncio
    async def test_accepts_camel_case_and_kebab_case_and_uppercase(self):
        provider = SuggestionToolProvider()

        response: list[Any] = await provider.call_tool(
            "SUGGEST",
            {
                "Program-Path": "/tmp/test.bin",
                "SuggestionType": "COMMENT-TEXT",
                "Address_Or_Symbol": "FUN_401000",
                "VariableName": "tmpVar",
                "MAX_CONTEXT": "7",
            },
        )
        payload: dict[str, Any] = _parse_text_content_payload(response)

        assert payload["suggestionType"] == "commenttext"
        assert payload["address"] == "FUN_401000"
        assert payload["variableName"] == "tmpVar"
        assert payload["context"]["programPath"] == "/tmp/test.bin"
        assert_string_invariants(payload["suggestionType"], expected="commenttext")
        assert_string_invariants(payload["address"], expected="FUN_401000")
        assert_string_invariants(payload["variableName"], expected="tmpVar")
        # No program loaded in unit test context, so provider should still respond
        assert "context unavailable" in payload["context"].get("note", "").lower()

    @pytest.mark.asyncio
    async def test_accepts_no_separator_forms_for_primary_keys(self):
        provider = SuggestionToolProvider()

        response: list[Any] = await provider.call_tool(
            "s u g g e s t",
            {
                "programpath": "/tmp/no-sep.bin",
                "suggestiontype": "function_tags",
                "functionidentifier": "entry",
                "maxcontext": 3,
            },
        )
        payload: dict[str, Any] = _parse_text_content_payload(response)

        assert payload["suggestionType"] == "functiontags"
        assert payload["address"] == "entry"
        assert payload["context"]["programPath"] == "/tmp/no-sep.bin"
        assert_string_invariants(payload["suggestionType"], expected="functiontags")
        assert_string_invariants(payload["address"], expected="entry")

    @pytest.mark.asyncio
    async def test_rejects_unknown_suggestion_type_even_with_noise(self):
        provider = SuggestionToolProvider()
        response: list[Any] = await provider.call_tool(
            "suggest",
            {
                "suggestion_type": "unknown-type",
                "program_path": "/tmp/x",
            },
        )
        payload: dict[str, Any] = _parse_text_content_payload(response)
        assert payload["success"] is False
        assert "Invalid suggestion_type" in payload["error"]
