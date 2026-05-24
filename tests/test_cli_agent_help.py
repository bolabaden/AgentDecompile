from __future__ import annotations

import json
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import click
import pytest

from agentdecompile_cli.cli_agent_help import (
    TOOL_MISSING_NAME_USAGE,
    format_tool_list_output,
    resolve_tool_seq_steps,
    tool_seq_json_error_message,
)

try:
    from agentdecompile_cli.cli import main
    from click.testing import CliRunner

    _CLICK_AVAILABLE = True
except ImportError:
    _CLICK_AVAILABLE = False

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(not _CLICK_AVAILABLE, reason="click CLI not available"),
]


class TestFormatToolListOutput:
    def test_text_format(self) -> None:
        out = format_tool_list_output(["b-tool", "a-tool"], "text")
        assert "Valid tool names:" in out
        assert "  a-tool" in out
        assert "  b-tool" in out

    def test_json_format(self) -> None:
        out = format_tool_list_output(["z", "a"], "json")
        parsed = json.loads(out)
        assert parsed == {"tools": ["a", "z"], "count": 2}


class TestResolveToolSeqSteps:
    def test_inline_json(self) -> None:
        assert resolve_tool_seq_steps(steps='[{"name":"x"}]', use_stdin=False) == '[{"name":"x"}]'

    def test_at_file(self, tmp_path: Path) -> None:
        steps_file = tmp_path / "steps.json"
        steps_file.write_text('[{"name":"from-file"}]', encoding="utf-8")
        loaded = resolve_tool_seq_steps(steps=f"@{steps_file}", use_stdin=False)
        assert loaded == '[{"name":"from-file"}]'

    def test_stdin_flag(self) -> None:
        with patch("sys.stdin", StringIO('[{"name":"stdin"}]')):
            loaded = resolve_tool_seq_steps(steps=None, use_stdin=True)
        assert loaded == '[{"name":"stdin"}]'

    def test_dash_argument(self) -> None:
        with patch("sys.stdin", StringIO('[{"name":"dash"}]')):
            loaded = resolve_tool_seq_steps(steps="-", use_stdin=False)
        assert loaded == '[{"name":"dash"}]'

    def test_missing_steps_raises_usage(self) -> None:
        with pytest.raises(click.UsageError) as exc:
            resolve_tool_seq_steps(steps=None, use_stdin=False)
        assert "Missing STEPS" in str(exc.value)


class TestToolSeqJsonErrorMessage:
    def test_includes_examples(self) -> None:
        msg = tool_seq_json_error_message(json.JSONDecodeError("msg", "doc", 0))
        assert "Examples:" in msg
        assert "Parse error:" in msg


class TestCliAgentHelpIntegration:
    def test_tool_missing_name_shows_examples(self) -> None:
        result = CliRunner().invoke(main, ["tool"])
        assert result.exit_code != 0
        assert "Examples:" in result.output
        assert TOOL_MISSING_NAME_USAGE.splitlines()[0] in result.output

    def test_tool_list_tools_json(self) -> None:
        result = CliRunner().invoke(main, ["-f", "json", "tool", "--list-tools"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert "tools" in parsed
        assert isinstance(parsed["tools"], list)
        assert parsed["count"] == len(parsed["tools"])
        assert len(parsed["tools"]) > 0

    def test_tool_seq_stdin(self) -> None:
        steps = '[{"name":"list-project-files","arguments":{}}]'
        result = CliRunner().invoke(
            main,
            ["--server-url", "http://127.0.0.1:9", "tool-seq", "--stdin"],
            input=steps,
        )
        # Fails to connect, but should parse stdin before backend errors
        assert "Missing STEPS" not in result.output
        assert "Invalid JSON for tool-seq steps" not in result.output.split("Examples:")[0]

    def test_tool_seq_help_includes_examples(self) -> None:
        result = CliRunner().invoke(main, ["tool-seq", "--help"])
        assert result.exit_code == 0
        assert "Examples:" in result.output
        assert "tool-seq --stdin" in result.output
