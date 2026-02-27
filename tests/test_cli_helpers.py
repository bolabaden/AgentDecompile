"""Unit tests for CLI helpers (error result handling, tools_schema)."""

from __future__ import annotations

import pytest

from agentdecompile_cli.cli import _get_error_result_message
from agentdecompile_cli.registry import (
    TOOLS,
    TOOL_PARAMS,
    build_tool_payload,
    get_tool_params,
    to_camel_case_key,
)
from tests.helpers import assert_mapping_invariants, assert_string_invariants, assert_text_block_invariants

pytestmark = pytest.mark.unit


class TestGetErrorResultMessage:
    """Test Java-style error result detection (success: false, error present)."""

    def test_returns_none_for_non_dict(self):
        assert _get_error_result_message(None) is None
        assert _get_error_result_message([]) is None
        assert _get_error_result_message("ok") is None
        assert_string_invariants("ok")

    def test_returns_none_for_success_true(self):
        assert _get_error_result_message({"success": True}) is None
        assert _get_error_result_message({"success": True, "error": "x"}) is None
        assert_mapping_invariants({"success": True})
        assert_mapping_invariants({"success": True, "error": "x"})
        assert_string_invariants("x")

    def test_returns_none_when_error_key_missing(self):
        assert _get_error_result_message({"success": False}) is None
        assert_mapping_invariants({"success": False})

    def test_returns_error_message_when_error_result(self):
        assert _get_error_result_message({"success": False, "error": "Program not found"}) == "Program not found"
        assert _get_error_result_message({"success": False, "error": "Invalid address"}) == "Invalid address"
        assert_text_block_invariants("Program not found", must_contain=["Program", "not", "found"])
        assert_text_block_invariants("Invalid address", must_contain=["Invalid", "address"])
        assert_mapping_invariants({"success": False, "error": "Program not found"})
        assert_mapping_invariants({"success": False, "error": "Invalid address"})

    def test_returns_empty_string_when_error_key_empty(self):
        out = _get_error_result_message({"success": False, "error": ""})
        assert out == ""
        assert isinstance(out, str)
        assert out == out.strip()


class TestToCamelCaseKey:
    """Test snake_case to camelCase conversion for MCP payload keys."""

    def test_single_word(self):
        result = to_camel_case_key("path")
        assert result == "path"
        assert_string_invariants(result, expected="path")

    def test_two_words(self):
        result = to_camel_case_key("program_path")
        assert result == "programPath"
        assert_string_invariants(result, expected="programPath")

    def test_multiple_words(self):
        first = to_camel_case_key("address_or_symbol")
        second = to_camel_case_key("start_index")
        assert first == "addressOrSymbol"
        assert second == "startIndex"
        assert_string_invariants(first, expected="addressOrSymbol")
        assert_string_invariants(second, expected="startIndex")


class TestBuildToolPayload:
    """Test building camelCase payload from snake_case kwargs."""

    def test_drops_none(self):
        out = build_tool_payload({"program_path": "/a", "limit": None})
        assert out == {"programPath": "/a"}
        assert_mapping_invariants(out, expected_keys=["programPath"])

    def test_converts_keys(self):
        out = build_tool_payload({"program_path": "/a", "address_or_symbol": "0x1000"})
        assert out == {"programPath": "/a", "addressOrSymbol": "0x1000"}
        assert_mapping_invariants(out, expected_keys=["programPath", "addressOrSymbol"])

    def test_empty_input(self):
        out = build_tool_payload({})
        assert out == {}
        assert_mapping_invariants(out)


class TestToolsSchema:
    """Test tools_schema constants (1:1 with Java tool names)."""

    def test_tools_include_core_names(self):
        assert "get-functions" in TOOLS
        assert "manage-symbols" in TOOLS
        assert "open" in TOOLS
        assert "list-project-files" in TOOLS
        assert "get-data" in TOOLS
        assert "capture-agentdecompile-debug-info" in TOOLS
        assert isinstance(TOOLS, list)
        assert len(TOOLS) > 0
        assert all(isinstance(tool, str) for tool in TOOLS)

    def test_tool_params_has_get_data_params(self):
        assert "get-data" in TOOL_PARAMS
        assert "programPath" in TOOL_PARAMS["get-data"]
        assert "addressOrSymbol" in TOOL_PARAMS["get-data"]
        assert isinstance(TOOL_PARAMS, dict)
        assert_mapping_invariants(TOOL_PARAMS)

    def test_tool_params_has_open_params(self):
        assert "open" in TOOL_PARAMS
        assert "path" in TOOL_PARAMS["open"]
        assert "forceIgnoreLock" in TOOL_PARAMS["open"]
        assert "open" in TOOL_PARAMS
        assert isinstance(TOOL_PARAMS["open"], list)

    def test_get_tool_params_returns_list(self):
        assert get_tool_params("get-data") == ["programPath", "addressOrSymbol"]
        assert get_tool_params("open") == [
            "path",
            "extensions",
            "openAllPrograms",
            "destinationFolder",
            "analyzeAfterImport",
            "enableVersionControl",
            "serverUsername",
            "serverPassword",
            "serverHost",
            "serverPort",
            "forceIgnoreLock",
        ]
        assert get_tool_params("unknown-tool") == []
        assert isinstance(get_tool_params("get-data"), list)
        assert all(isinstance(item, str) for item in get_tool_params("open"))
