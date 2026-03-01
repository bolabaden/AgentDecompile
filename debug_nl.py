"""Debug NL tool call parsing."""

from __future__ import annotations

from agentdecompile_cli.registry import tool_registry

text = "list functions in program /path/to/binary"
print(f"Original text: {text}")

# Get tool name and remaining text
tool_name, args = tool_registry.parse_natural_language_tool_call(text)
print(f"Tool: {tool_name}")
print(f"Args: {args}")

# Try the preprocessing manually
remaining = "in program /path/to/binary"
processed = tool_registry._preprocess_nl_phrases(remaining)
print(f"\nRemaining text: {remaining}")
print(f"After preprocessing: {processed}")

# Try extraction manually
expected_params = tool_registry.get_tool_params("list-functions")
print(f"\nExpected params: {expected_params}")
alias_map = tool_registry._build_natural_language_alias_map("list-functions", expected_params)
print(f"Alias map keys (normalized): {list(alias_map.keys())[:20]}")
extracted = tool_registry._extract_natural_language_pairs(processed, alias_map)
print(f"Extracted args: {extracted}")
