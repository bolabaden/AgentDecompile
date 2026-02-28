"""CLI tests using the dynamic command surface and the 'tool' passthrough.

These tests verify:
    1. Command registration and help output
    2. Regression coverage for subcommand help invocation
    3. Dynamic command dispatch through the unified executor
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch

try:
    from click.testing import CliRunner
    from agentdecompile_cli.cli import main
    _CLICK_AVAILABLE = True
except ImportError:
    _CLICK_AVAILABLE = False

from tests.helpers import assert_text_block_invariants
from agentdecompile_cli.registry import to_snake_case, tool_registry

pytestmark = pytest.mark.skipif(not _CLICK_AVAILABLE, reason="click CLI not available")

_CALL_PATH = "agentdecompile_cli.cli._call"
_SUCCESS = {"success": True, "result": "ok"}


def _runner():
    return CliRunner()


class TestCliCommandRegistration:
    """Tests that verify commands are registered on the main CLI group."""

    def test_main_help_exit_code(self):
        """main --help should exit 0."""
        result = _runner().invoke(main, ["--help"])
        assert result.exit_code == 0, result.output
        assert_text_block_invariants(result.output, must_contain=["Commands:"])
        assert "Commands:" in result.output
        assert "Usage:" in result.output
        assert "--help" in result.output

    def test_open_help_exit_code(self):
        """Regression: `open --help` must not crash with Group object TypeError."""
        result = _runner().invoke(main, ["open", "--help"])
        assert result.exit_code == 0, result.output
        assert_text_block_invariants(
            result.output,
            must_contain=["Usage:", "open [OPTIONS]", "--server-host", "--server-port", "--server-username", "--server-password"],
        )
        assert "Usage: " in result.output
        assert "open [OPTIONS]" in result.output
        assert "--server-host" in result.output
        assert "--server-port" in result.output
        assert "--server-username" in result.output
        assert "--server-password" in result.output
        assert "TypeError" not in result.output

    def test_symbols_help_exit_code(self):
        """Regression: dynamically generated command help must be invokable."""
        result = _runner().invoke(main, ["symbols", "--help"])
        assert result.exit_code == 0, result.output
        assert_text_block_invariants(result.output, must_contain=["Usage:", "symbols [OPTIONS] COMMAND"])
        assert "Usage: " in result.output
        assert "symbols [OPTIONS] COMMAND" in result.output
        assert "TypeError" not in result.output

    def test_tool_command_registered(self):
        """The 'tool' command must be registered on the main group."""
        assert "tool" in main.commands, "Expected 'tool' command in main.commands"

    def test_tool_seq_command_registered(self):
        """The 'tool-seq' command must be registered on the main group."""
        assert "tool-seq" in main.commands, "Expected 'tool-seq' command in main.commands"

    def test_callgraph_command_registered(self):
        assert "callgraph" in main.commands

    def test_symbols_command_registered(self):
        assert "symbols" in main.commands

    def test_list_functions_command_registered(self):
        assert "list-functions" in main.commands

    def test_memory_command_registered(self):
        assert "memory" in main.commands

    def test_strings_command_registered(self):
        assert "strings" in main.commands

    def test_references_command_registered(self):
        assert "references" in main.commands

    def test_dataflow_command_registered(self):
        assert "dataflow" in main.commands

    def test_vtables_command_registered(self):
        assert "vtables" in main.commands

    def test_comments_command_registered(self):
        assert "comments" in main.commands

    def test_bookmarks_command_registered(self):
        assert "bookmarks" in main.commands

    def test_structures_command_registered(self):
        assert "structures" in main.commands

    def test_data_command_registered(self):
        assert "data" in main.commands

    def test_constants_command_registered(self):
        assert "constants" in main.commands

    def test_functions_command_registered(self):
        assert "functions" in main.commands

    def test_missing_required_option_prints_subcommand_help(self):
        """Missing required args should print contextual subcommand help."""
        result = _runner().invoke(
            main,
            [
                "references",
                "to",
                "--binary",
                "/K1/k1_win_gog_swkotor.exe",
                "--limit",
                "25",
            ],
        )

        assert result.exit_code != 0
        assert "Error: Missing option '--target'" in result.output
        assert "Usage: main references to [OPTIONS]" in result.output
        assert "--target" in result.output


class TestCliToolCommandObject:
    """Test the 'tool' command object structure without invoking."""

    def test_tool_command_has_name_param(self):
        """The 'tool' command should have a 'name' argument."""
        tool_cmd = main.commands["tool"]
        param_names = [p.name for p in tool_cmd.params]
        assert "name" in param_names, f"Expected 'name' param, got: {param_names}"

    def test_tool_command_has_arguments_param(self):
        tool_cmd = main.commands["tool"]
        param_names = [p.name for p in tool_cmd.params]
        assert "arguments" in param_names, f"Expected 'arguments' param, got: {param_names}"

    def test_tool_command_has_list_tools_option(self):
        tool_cmd = main.commands["tool"]
        param_names = [p.name for p in tool_cmd.params]
        assert "list_tools" in param_names or "list-tools" in param_names, (
            f"Expected 'list_tools' option, got: {param_names}"
        )

    def test_main_has_at_least_20_commands(self):
        """The CLI should register all major commands."""
        assert len(main.commands) >= 20, f"Expected 20+ commands, got {len(main.commands)}"


class TestCliGenericToolJsonValidation:
    def test_tool_rejects_non_object_json_arguments(self):
        result = _runner().invoke(main, ["tool", "open", "[]"])
        assert result.exit_code != 0
        assert "Arguments must be a JSON object" in result.output

    def test_tool_seq_rejects_non_array_json(self):
        result = _runner().invoke(main, ["tool-seq", "{}"])
        assert result.exit_code != 0
        assert "Steps must be a JSON array of objects" in result.output


class TestCliToolSequence:
    @patch("agentdecompile_cli.cli._call_raw", new_callable=AsyncMock)
    def test_tool_seq_runs_multiple_steps(self, mocked_call_raw):
        mocked_call_raw.side_effect = [
            {"success": True, "repository": "Odyssey"},
            {"success": True, "count": 12345},
        ]

        steps = (
            '[{"name":"open","arguments":{"path":"Odyssey"}},'
            '{"name":"list-functions","arguments":{"mode":"count"}}]'
        )
        result = _runner().invoke(main, ["-f", "json", "tool-seq", steps])

        assert result.exit_code == 0, result.output
        assert '"success": true' in result.output.lower()
        assert '"name": "open"' in result.output
        assert '"name": "list-functions"' in result.output

    @patch("agentdecompile_cli.cli._call_raw", new_callable=AsyncMock)
    def test_tool_seq_stops_on_error_by_default(self, mocked_call_raw):
        mocked_call_raw.side_effect = [
            {"success": False, "error": "checkout failed"},
            {"success": True, "count": 12345},
        ]

        steps = (
            '[{"name":"manage-files","arguments":{"operation":"checkout","path":"/K1/k1_win_gog_swkotor.exe"}},'
            '{"name":"list-functions","arguments":{"mode":"count"}}]'
        )
        result = _runner().invoke(main, ["-f", "json", "tool-seq", steps])

        assert result.exit_code != 0
        assert mocked_call_raw.await_count == 1


class TestCliToolListIntegration:
    """Test the tool list functionality."""

    def test_tool_list_shows_canonical_names(self):
        """main tool --list-tools should list canonical tool names."""
        # Invoke just `main --help` to verify the group is working
        result = _runner().invoke(main, ["--help"])
        assert result.exit_code == 0
        output = result.output
        assert_text_block_invariants(output, must_contain=["tool", "callgraph", "symbols", "memory", "dataflow"])
        # Verify major commands are shown in help
        expected = ["tool", "callgraph", "symbols", "memory", "dataflow"]
        missing = [c for c in expected if c not in output]
        assert not missing, f"Commands missing from help output: {missing}"

    def test_tool_registry_integration(self):
        """The tool registry should know about canonical tools."""
        tools = tool_registry.get_tools()
        assert "manage-symbols" in tools
        assert "list-functions" in tools
        assert "get-call-graph" in tools
        assert "inspect-memory" in tools
        assert "manage-strings" in tools

    def test_all_canonical_tools_have_direct_cli_commands(self):
        """Every canonical tool should be available as a direct CLI command."""
        missing = []
        for tool_name in tool_registry.get_tools():
            snake_name = to_snake_case(tool_name)
            if snake_name not in main.commands:
                missing.append(snake_name)
            if tool_name != snake_name and tool_name not in main.commands:
                missing.append(tool_name)

        assert not missing, f"Missing direct CLI commands for tools: {sorted(set(missing))}"
        


class TestCliDynamicDispatch:
    """Ensure dynamic subcommands resolve and dispatch the intended canonical tool."""

    @patch(_CALL_PATH, new_callable=AsyncMock)
    def test_symbols_dispatches_manage_symbols(self, mocked_call: AsyncMock):
        mocked_call.return_value = _SUCCESS
        result = _runner().invoke(
            main,
            [
                "symbols",
                "run",
                "--binary",
                "dummy_program",
                "--mode",
                "classes",
            ],
        )

        assert result.exit_code == 0, result.output
        mocked_call.assert_awaited_once()

        assert mocked_call.await_args is not None, "Expected _call to be awaited with arguments"
        called_tool_name = mocked_call.await_args.args[1]
        called_payload = mocked_call.await_args.kwargs

        assert called_tool_name == "manage-symbols"
        assert called_payload["programPath"] == "dummy_program"
        assert called_payload["mode"] == "classes"

    @patch(_CALL_PATH, new_callable=AsyncMock)
    def test_open_dispatches_shared_server_payload(self, mocked_call: AsyncMock):
        mocked_call.return_value = _SUCCESS
        result = _runner().invoke(
            main,
            [
                "open",
                "Odyssey",
                "--server-host",
                "170.9.241.140",
                "--server-port",
                "13100",
                "--server-username",
                "OpenKotOR",
                "--server-password",
                "MuchaShakaPaka",
            ],
        )

        assert result.exit_code == 0, result.output
        mocked_call.assert_awaited_once()

        assert mocked_call.await_args is not None, "Expected _call to be awaited with arguments"
        called_tool_name = mocked_call.await_args.args[1]
        called_payload = mocked_call.await_args.kwargs

        assert called_tool_name == "open"
        assert called_payload["path"] == "Odyssey"
        assert called_payload["serverHost"] == "170.9.241.140"
        assert called_payload["serverPort"] == 13100
        assert called_payload["serverUsername"] == "OpenKotOR"
        assert called_payload["serverPassword"] == "MuchaShakaPaka"

    @patch(_CALL_PATH, new_callable=AsyncMock)
    def test_dynamic_canonical_alias_dispatches(self, mocked_call: AsyncMock):
        mocked_call.return_value = _SUCCESS

        result = _runner().invoke(
            main,
            [
                "capture-agentdecompile-debug-info",
                "--message",
                "hello",
            ],
        )

        assert result.exit_code == 0, result.output
        mocked_call.assert_awaited_once()
        assert mocked_call.await_args is not None
        called_tool_name = mocked_call.await_args.args[1]
        called_payload = mocked_call.await_args.kwargs

        assert called_tool_name == "capture-agentdecompile-debug-info"
        assert called_payload["message"] == "hello"

    @patch(_CALL_PATH, new_callable=AsyncMock)
    def test_references_alias_max_results_maps_to_limit(self, mocked_call: AsyncMock):
        mocked_call.return_value = _SUCCESS

        result = _runner().invoke(
            main,
            [
                "references",
                "to",
                "--binary",
                "dummy_program",
                "--target",
                "main",
                "--max-results",
                "25",
            ],
        )

        assert result.exit_code == 0, result.output
        mocked_call.assert_awaited_once()
        assert mocked_call.await_args is not None
        called_tool_name = mocked_call.await_args.args[1]
        called_payload = mocked_call.await_args.kwargs

        assert called_tool_name == "get-references"
        assert called_payload["limit"] == 25
        assert "maxResults" not in called_payload

    @patch(_CALL_PATH, new_callable=AsyncMock)
    def test_strings_alias_max_results_maps_to_limit(self, mocked_call: AsyncMock):
        mocked_call.return_value = _SUCCESS

        result = _runner().invoke(
            main,
            [
                "strings",
                "list",
                "--binary",
                "dummy_program",
                "--max-results",
                "10",
            ],
        )

        assert result.exit_code == 0, result.output
        mocked_call.assert_awaited_once()
        assert mocked_call.await_args is not None
        called_tool_name = mocked_call.await_args.args[1]
        called_payload = mocked_call.await_args.kwargs

        assert called_tool_name == "manage-strings"
        assert called_payload["limit"] == 10
        assert "maxResults" not in called_payload
