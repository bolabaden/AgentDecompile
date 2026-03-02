from __future__ import annotations

import pytest

from agentdecompile_cli.registry import tool_registry


@pytest.mark.parametrize(
    "text",
    [
        "list functions in program /path/to/binary",
        "manage symbols with program path '/tmp/a.bin' and mode list",
        "search strings in program /tmp/test with pattern http and max results 10",
        "list_functions in program /tmp/test",
        "get-data at 0xDEADBEEF in program /tmp/test",
    ],
)
def test_debug_nl_examples_parse(text: str) -> None:
    tool_name, arguments = tool_registry.parse_natural_language_tool_call(text)
    assert tool_name is None or isinstance(tool_name, str)
    assert isinstance(arguments, dict)


def test_debug_nl_examples_are_repeatable() -> None:
    text = "search strings in program /tmp/test with pattern http and max results 10"
    first = tool_registry.parse_natural_language_tool_call(text)
    second = tool_registry.parse_natural_language_tool_call(text)
    assert first == second
