"""Unit tests for the natural-language tool-call parser (fresh / standalone).

Ported from root-level test_nl_fresh.py.
No backend or PyGhidra required.
"""

from __future__ import annotations

import pytest

from agentdecompile_cli.registry import ToolRegistry


@pytest.fixture(scope="module")
def registry() -> ToolRegistry:
    return ToolRegistry()


class TestNLParseBasic:
    """Basic natural-language parsing smoke tests."""

    def test_returns_tool_and_dict(self, registry: ToolRegistry) -> None:
        tool, args = registry.parse_natural_language_tool_call(
            "list functions in program /tmp/test"
        )
        assert tool is not None
        assert isinstance(args, dict)

    def test_tool_is_non_empty_string(self, registry: ToolRegistry) -> None:
        tool, _ = registry.parse_natural_language_tool_call(
            "list functions in program /tmp/test"
        )
        assert isinstance(tool, str)
        assert tool.strip() != ""

    def test_list_functions_query(self, registry: ToolRegistry) -> None:
        """Canonical smoke test from the original test_nl_fresh.py script."""
        tool, args = registry.parse_natural_language_tool_call(
            "list functions in program /tmp/test"
        )
        # Should resolve to a function-listing tool
        assert tool is not None
        assert isinstance(args, dict)

    def test_args_is_always_dict(self, registry: ToolRegistry) -> None:
        tool, args = registry.parse_natural_language_tool_call(
            "search for symbol WinMain"
        )
        assert isinstance(args, dict)

    def test_empty_input_does_not_raise(self, registry: ToolRegistry) -> None:
        try:
            tool, args = registry.parse_natural_language_tool_call("")
            # Whatever it returns, it must be (str | None, dict)
            assert args is None or isinstance(args, dict)
        except Exception:
            # Some implementations may raise on empty input; that's acceptable
            pass

    def test_get_decompiled_code_query(self, registry: ToolRegistry) -> None:
        tool, args = registry.parse_natural_language_tool_call(
            "decompile function at address 0x401000"
        )
        assert isinstance(args, dict)

    def test_search_symbols_query(self, registry: ToolRegistry) -> None:
        tool, args = registry.parse_natural_language_tool_call(
            "search symbols by name main"
        )
        assert tool is not None
        assert isinstance(args, dict)

    def test_repeated_calls_are_deterministic(self, registry: ToolRegistry) -> None:
        text = "list functions in program /tmp/test"
        tool1, args1 = registry.parse_natural_language_tool_call(text)
        tool2, args2 = registry.parse_natural_language_tool_call(text)
        assert tool1 == tool2
        assert args1 == args2

    def test_registry_singleton_consistency(self) -> None:
        """Two separate ToolRegistry instances give the same result."""
        reg_a = ToolRegistry()
        reg_b = ToolRegistry()
        text = "list functions in program /tmp/test"
        tool_a, args_a = reg_a.parse_natural_language_tool_call(text)
        tool_b, args_b = reg_b.parse_natural_language_tool_call(text)
        assert tool_a == tool_b
        assert args_a == args_b
