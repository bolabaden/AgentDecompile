"""Agent-oriented help text and CLI utilities for tool / tool-seq commands."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import click

if TYPE_CHECKING:
    from collections.abc import Sequence

MAIN_AGENT_EPILOG = """
Agent-oriented entry points (see subcommand --help for more):

Examples:
  agentdecompile-cli --server-url http://127.0.0.1:8080 tool --list-tools
  agentdecompile-cli -f json tool --list-tools
  agentdecompile-cli tool list-functions '{"programPath":"/path/to/binary","limit":5}'
  agentdecompile-cli tool-seq '[{"name":"open-project","arguments":{"path":"/path/to/binary"}}]'
  echo '[{"name":"list-project-files","arguments":{}}]' | agentdecompile-cli tool-seq --stdin
""".strip()

TOOL_AGENT_EPILOG = """
Examples:
  agentdecompile-cli --server-url http://127.0.0.1:8080 tool --list-tools
  agentdecompile-cli -f json tool --list-tools
  agentdecompile-cli tool list-functions '{"programPath":"/path/to/binary","limit":10}'
  agentdecompile-cli -b /path/to/binary tool decompile-function '{"addressOrSymbol":"main"}'
""".strip()

TOOL_SEQ_AGENT_EPILOG = """
Examples:
  agentdecompile-cli tool-seq '[{"name":"list-project-files","arguments":{}}]'
  agentdecompile-cli tool-seq @/tmp/steps.json
  echo '[{"name":"list-project-files","arguments":{}}]' | agentdecompile-cli tool-seq -
  echo '[{"name":"list-project-files","arguments":{}}]' | agentdecompile-cli tool-seq --stdin
  agentdecompile-cli tool-seq-file /tmp/steps.json
""".strip()

TOOL_MISSING_NAME_USAGE = (
    "Missing argument 'NAME'.\n"
    "Examples:\n"
    "  agentdecompile-cli tool --list-tools\n"
    "  agentdecompile-cli -f json tool --list-tools\n"
    '  agentdecompile-cli tool list-functions \'{"programPath":"/path/to/binary","limit":5}\''
)

TOOL_SEQ_MISSING_STEPS_USAGE = (
    "Missing STEPS: pass inline JSON, a file (@path), stdin (-), or use --stdin.\n"
    "Examples:\n"
    '  agentdecompile-cli tool-seq \'[{"name":"list-project-files","arguments":{}}]\'\n'
    "  agentdecompile-cli tool-seq @/tmp/steps.json\n"
    "  echo '[{\"name\":\"list-project-files\",\"arguments\":{}}]' | agentdecompile-cli tool-seq --stdin"
)

INVALID_TOOL_SEQ_JSON_USAGE = (
    "Invalid JSON for tool-seq steps.\n"
    "Examples:\n"
    '  agentdecompile-cli tool-seq \'[{"name":"list-project-files","arguments":{}}]\'\n'
    "  agentdecompile-cli tool-seq @/tmp/steps.json"
)


def format_tool_list_output(tool_names: Sequence[str], output_format: str) -> str:
    """Format tool names for agents (plain list or JSON object)."""
    sorted_names = sorted(tool_names)
    if output_format == "json":
        return json.dumps({"tools": sorted_names, "count": len(sorted_names)}, indent=2)
    lines = ["Valid tool names:"]
    lines.extend(f"  {name}" for name in sorted_names)
    return "\n".join(lines)


def resolve_tool_seq_steps(*, steps: str | None, use_stdin: bool) -> str:
    """Resolve tool-seq step JSON from inline text, @file, stdin (-), or --stdin."""
    if use_stdin:
        return sys.stdin.read()

    raw = (steps or "").strip()
    if not raw:
        raise click.UsageError(TOOL_SEQ_MISSING_STEPS_USAGE)

    if raw == "-":
        return sys.stdin.read()

    if raw.startswith("@"):
        path_str = raw[1:].strip().strip('"').strip("'")
        if not path_str:
            raise click.UsageError(TOOL_SEQ_MISSING_STEPS_USAGE)
        path = Path(path_str).expanduser()
        if not path.is_file():
            click.echo(f"tool-seq: steps file not found: {path}", err=True)
            raise SystemExit(1)
        return path.read_text(encoding="utf-8")

    return steps or ""


def tool_seq_json_error_message(exc: json.JSONDecodeError) -> str:
    """Actionable JSON parse failure for tool-seq."""
    return f"{INVALID_TOOL_SEQ_JSON_USAGE}\nParse error: {exc}"
