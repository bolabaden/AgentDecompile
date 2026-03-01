#!/usr/bin/env python
"""Test NL tool call parsing fresh."""
from __future__ import annotations

from agentdecompile_cli.registry import ToolRegistry

reg = ToolRegistry()
text = "list functions in program /tmp/test"
tool, args = reg.parse_natural_language_tool_call(text)
print(f"Tool: {tool}")
print(f"Args: {args}")
