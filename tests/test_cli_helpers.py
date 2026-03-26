"""Unit tests for CLI helpers (error result handling, tools_schema)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from agentdecompile_cli.cli import (
    _build_svr_admin_payload,
    _get_error_result_message,
    _load_tool_seq_steps_arg,
    _tool_seq_step_succeeded,
)
from agentdecompile_cli.registry import (
    TOOLS,
    Tool,
    build_tool_payload,
    get_tool_params,
    to_camel_case_key,
)

from tests.helpers import assert_mapping_invariants, assert_string_invariants, assert_text_block_invariants

pytestmark = pytest.mark.unit


class TestLoadToolSeqStepsArg:
    def test_passes_through_plain_json(self):
        raw = '[{"name":"open","arguments":{}}]'
        assert _load_tool_seq_steps_arg(raw) == raw

    def test_reads_at_file(self, tmp_path: Path) -> None:
        p = tmp_path / "steps.json"
        content = '[{"name":"list-project-files","arguments":{}}]'
        p.write_text(content, encoding="utf-8")
        out = _load_tool_seq_steps_arg(f"@{p}")
        assert out == content


class TestToolSeqStepSucceeded:
    def test_none_fails(self):
        assert _tool_seq_step_succeeded(None) is False

    def test_iserror_true_fails(self):
        assert _tool_seq_step_succeeded({"isError": True, "content": []}) is False

    def test_nested_json_success_false_fails(self):
        payload = {
            "isError": False,
            "content": [{"type": "text", "text": '{"success": false, "error": "bad"}'}],
        }
        assert _tool_seq_step_succeeded(payload) is False

    def test_nested_json_ok_succeeds(self):
        payload = {
            "isError": False,
            "content": [{"type": "text", "text": '{"success": true, "files": []}'}],
        }
        assert _tool_seq_step_succeeded(payload) is True

    def test_markdown_error_heading_fails(self):
        payload = {
            "isError": False,
            "content": [
                {
                    "type": "text",
                    "text": "## Error\n\n> **Ghidra server not reachable**\n\n**Tool:** `open`",
                },
            ],
        }
        assert _tool_seq_step_succeeded(payload) is False

    def test_modification_conflict_markdown_fails(self):
        payload = {
            "isError": False,
            "content": [
                {
                    "type": "text",
                    "text": "## Modification conflict\n\nCreate label would conflict\n\n**conflictId:** `x`",
                },
            ],
        }
        assert _tool_seq_step_succeeded(payload) is False

    def test_checkin_success_markdown_succeeds(self):
        payload = {
            "isError": False,
            "content": [
                {
                    "type": "text",
                    "text": "## Check-in Result\n\n**Program:** sort.exe\n**Status:** Success\n",
                },
            ],
        }
        assert _tool_seq_step_succeeded(payload) is True


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
        assert isinstance(TOOLS, list)
        assert len(TOOLS) > 0
        assert all(isinstance(tool, str) for tool in TOOLS)

    def test_tool_params_has_get_data_params(self):
        assert "programPath" in get_tool_params("get-data")
        assert "addressOrSymbol" in get_tool_params("get-data")
        tool_params_str = {t.value: get_tool_params(t) for t in Tool}
        assert isinstance(tool_params_str, dict)
        assert_mapping_invariants(tool_params_str)

    def test_tool_params_has_open_params(self):
        assert "path" in get_tool_params("open")
        assert isinstance(get_tool_params("open"), list)

    def test_get_tool_params_returns_list(self):
        assert "programPath" in get_tool_params("get-data")
        assert "addressOrSymbol" in get_tool_params("get-data")
        open_params = get_tool_params("open")
        assert isinstance(open_params, list)
        required_open_params = {
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
        }
        assert required_open_params.issubset(set(open_params))
        assert get_tool_params("unknown-tool") == []
        assert isinstance(get_tool_params("get-data"), list)
        assert all(isinstance(item, str) for item in get_tool_params("open"))


class TestBuildSvrAdminPayload:
    """Test payload construction for the curated svr-admin CLI command."""

    def test_combines_explicit_and_passthrough_args(self):
        out = _build_svr_admin_payload(
            args=("-list",),
            passthrough_args=["-all", "repo"],
            command=None,
            timeout_seconds=45,
        )
        assert out == {
            "args": ["-list", "-all", "repo"],
            "timeoutSeconds": 45,
        }

    def test_includes_command_and_omits_empty_args(self):
        out = _build_svr_admin_payload(
            args=(),
            passthrough_args=[],
            command="-users",
            timeout_seconds=None,
        )
        assert out == {"command": "-users"}


class TestMigrateMetadataNoArgs:
    """migrate-metadata with no arguments must complete (default limit 50), not hang."""

    def test_migrate_metadata_no_args_exits_without_hang(self) -> None:
        """Fail fast (program validation or connection), not hang."""
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; sys.argv = ['agentdecompile-cli', '--server-url', 'http://127.0.0.1:19999', 'migrate-metadata']; from agentdecompile_cli.cli import cli_entry_point; cli_entry_point()",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert proc.returncode != 0
        out = (proc.stdout + proc.stderr).lower()
        assert (
            "connect" in out
            or "refused" in out
            or "attempt" in out
            or "program is required" in out
        )
