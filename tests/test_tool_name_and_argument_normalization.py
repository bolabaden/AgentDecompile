"""Comprehensive normalization tests for tool names and argument keys.

These tests verify that tool and argument matching works case-insensitively,
separator-insensitively, and with alphabet-only canonicalization across the
entire schema in ``tools_schema``.
"""

from __future__ import annotations

import itertools

import pytest

from agentdecompile_cli.executor import DynamicToolExecutor
from agentdecompile_cli.registry import (
    TOOLS,
    Tool,
    ToolRegistry,
    get_tool_params,
    normalize_identifier,
    resolve_tool_name_enum,
)
from tests.helpers import assert_mapping_invariants, assert_string_invariants

pytestmark = pytest.mark.unit

_TOOLS_WITH_PARAMS: list[str] = [t.value for t in Tool if get_tool_params(t)]


def _tool_variants(name: str) -> list[str]:
    """Generate representative name variants for a canonical tool name."""
    dehyphen = name.replace("-", "")
    snake = name.replace("-", "_")
    spaced = name.replace("-", " ")
    return [
        name,
        name.upper(),
        snake,
        snake.upper(),
        dehyphen,
        dehyphen.upper(),
        f"  {name}  ",
        spaced,
    ]


def _param_variants(param_name: str) -> list[str]:
    """Generate representative argument-key variants for a parameter name."""
    lowered = param_name.lower()
    snake = []
    for index, char in enumerate(param_name):
        if char.isupper() and index > 0:
            snake.append("_")
        snake.append(char.lower())
    snake_case = "".join(snake)
    kebab_case = snake_case.replace("_", "-")
    no_sep = "".join(c for c in param_name if c.isalpha()).lower()
    spaced = snake_case.replace("_", " ")
    return [
        param_name,
        lowered,
        snake_case,
        kebab_case,
        no_sep,
        spaced,
        f" {snake_case} ",
    ]


class TestNormalizeIdentifier:
    """Test low-level normalization contract."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("manage-comments", "managecomments"),
            ("Manage_Comments", "managecomments"),
            ("  MANAGE comments  ", "managecomments"),
            ("programPath", "programpath"),
            ("program_path", "programpath"),
            ("PROGRAM-PATH", "programpath"),
            ("include_callers", "includecallers"),
            ("includeCallers", "includecallers"),
            ("", ""),
        ],
    )
    def test_normalize_identifier(self, raw: str, expected: str):
        result = normalize_identifier(raw)
        assert result == expected
        assert_string_invariants(result, expected=expected, allow_empty=(expected == ""))


class TestToolRegistryNameMatching:
    """Test registry tool-name matching with fuzzy input variants."""

    @pytest.mark.parametrize("tool_name", TOOLS)
    def test_is_valid_tool_accepts_common_variants(self, tool_name: str):
        registry = ToolRegistry()
        for variant in _tool_variants(tool_name):
            assert registry.is_valid_tool(variant), f"Variant {variant!r} should match {tool_name!r}"
            assert_string_invariants(normalize_identifier(variant), expected=normalize_identifier(tool_name))

    @pytest.mark.parametrize("tool_name", TOOLS)
    def test_match_tool_name_accepts_common_variants(self, tool_name: str):
        registry = ToolRegistry()
        for variant in _tool_variants(tool_name):
            assert registry.match_tool_name(variant, tool_name), f"Variant {variant!r} should match canonical {tool_name!r}"
            assert_string_invariants(normalize_identifier(variant), expected=normalize_identifier(tool_name))


class TestToolRegistryArgumentParsing:
    """Test argument parsing accepts noisy/non-accurate key formats."""

    @pytest.mark.parametrize("tool_name", _TOOLS_WITH_PARAMS)
    def test_parse_arguments_accepts_variant_for_each_parameter(self, tool_name: str):
        registry = ToolRegistry()
        canonical_params = get_tool_params(tool_name)

        for param_name in canonical_params:
            for variant in _param_variants(param_name):
                raw_arguments = {variant: "value"}
                parsed = registry.parse_arguments(raw_arguments, tool_name)
                assert param_name in parsed, f"Tool {tool_name!r} param {param_name!r} should parse from variant {variant!r}"
                assert parsed[param_name] == "value"
                assert_mapping_invariants(parsed)

    @pytest.mark.parametrize("tool_name", _TOOLS_WITH_PARAMS)
    def test_parse_arguments_handles_mixed_argument_styles_in_single_call(self, tool_name: str):
        registry = ToolRegistry()
        params = get_tool_params(tool_name)

        selected = list(itertools.islice(params, 0, min(3, len(params))))
        raw_arguments: dict[str, str] = {}
        for index, param_name in enumerate(selected):
            variant_pool = _param_variants(param_name)
            raw_arguments[variant_pool[index % len(variant_pool)]] = f"v{index}"

        parsed = registry.parse_arguments(raw_arguments, tool_name)

        for index, param_name in enumerate(selected):
            assert parsed.get(param_name) == f"v{index}"
        assert_mapping_invariants(parsed)


class TestDynamicExecutorResolution:
    """Test dynamic executor resolves tool names and arguments robustly."""

    @pytest.mark.parametrize("tool_name", TOOLS)
    def test_resolve_tool_name_accepts_common_variants(self, tool_name: str):
        executor = DynamicToolExecutor()
        for variant in _tool_variants(tool_name):
            resolved = executor._resolve_tool_name(variant)
            assert resolved == tool_name
            assert_string_invariants(normalize_identifier(resolved), expected=normalize_identifier(tool_name))

    @pytest.mark.parametrize("tool_name", _TOOLS_WITH_PARAMS)
    def test_parse_arguments_dynamically_accepts_non_alphabet_noise(self, tool_name: str):
        executor = DynamicToolExecutor()
        canonical_params = get_tool_params(tool_name)

        param_name = canonical_params[0]
        noisy_key = f"__{param_name}__".replace("Path", "-Path").replace("Or", "_Or_")
        parsed = executor._parse_arguments_dynamically(tool_name, {noisy_key: "x"})
        assert parsed.get(param_name) == "x"
        assert_mapping_invariants(parsed)


class TestDynamicExecutorRequiredValidation:
    def test_required_validation_accepts_normalized_key_equivalence(self):
        executor = DynamicToolExecutor()

        parsed_args = {"programPath": "dummy_program", "addressOrSymbol": "0x401000"}

        executor._validate_arguments_dynamically("get-data", parsed_args)

    def test_required_validation_rejects_missing_after_normalization(self):
        executor = DynamicToolExecutor()

        with pytest.raises(ValueError, match="Required parameter 'programpath' is missing"):
            executor._validate_arguments_dynamically("get-data", {"addressOrSymbol": "0x401000"})


class TestToolEnum:
    """Test Tool enum and resolve_tool_name_enum."""

    def test_tools_derived_from_enum(self):
        """TOOLS list should match Tool enum values."""
        assert TOOLS == [t.value for t in Tool]
        assert len(TOOLS) == len(list(Tool))

    def test_resolve_tool_name_enum_canonical(self):
        """resolve_tool_name_enum returns enum for canonical kebab-case names."""
        assert resolve_tool_name_enum("open") == Tool.OPEN
        assert resolve_tool_name_enum("get-functions") == Tool.GET_FUNCTIONS
        assert resolve_tool_name_enum("manage-bookmarks") == Tool.MANAGE_BOOKMARKS

    def test_resolve_tool_name_enum_aliases(self):
        """resolve_tool_name_enum returns enum for known aliases (alias -> canonical)."""
        assert resolve_tool_name_enum("get-symbols") == Tool.MANAGE_SYMBOLS
        assert resolve_tool_name_enum("get-bookmarks") == Tool.MANAGE_BOOKMARKS
        # get-call-tree is an alias for get-call-graph (not a canonical tool name)
        assert resolve_tool_name_enum("get-call-tree") == Tool.GET_CALL_GRAPH

    def test_resolve_tool_name_enum_variants(self):
        """resolve_tool_name_enum accepts case/separator variants."""
        assert resolve_tool_name_enum("Open_Project") == Tool.OPEN
        assert resolve_tool_name_enum("GETFUNCTIONS") == Tool.GET_FUNCTIONS

    def test_resolve_tool_name_enum_unknown_returns_none(self):
        """resolve_tool_name_enum returns None for unknown tool names."""
        assert resolve_tool_name_enum("unknown-tool") is None
        assert resolve_tool_name_enum("") is None

    def test_get_tool_params_accepts_enum(self):
        """get_tool_params accepts Tool enum."""
        assert "programPath" in get_tool_params(Tool.GET_DATA)
        assert "path" in get_tool_params(Tool.OPEN)

    def test_tool_from_string(self):
        """Tool.from_string matches resolve_tool_name_enum."""
        assert Tool.from_string("open") == Tool.OPEN
        assert Tool.from_string("get-symbols") == Tool.MANAGE_SYMBOLS
        assert Tool.from_string("unknown-tool") is None

    def test_tool_params_property(self):
        """Tool.params returns same as get_tool_params(tool)."""
        assert "programPath" in Tool.GET_DATA.params
        assert "path" in Tool.OPEN.params

    def test_tool_normalized_property(self):
        """Tool.normalized is alpha-only lowercase."""
        assert Tool.OPEN.normalized == "open"
        assert Tool.GET_FUNCTIONS.normalized == "getfunctions"

    def test_tool_is_gui_only_disabled(self):
        """GUI-only disabled tools have is_gui_only_disabled True."""
        # At least one known GUI-only tool should be disabled
        from agentdecompile_cli.registry import DISABLED_GUI_ONLY_TOOLS

        for t in Tool:
            assert t.is_gui_only_disabled == (t in DISABLED_GUI_ONLY_TOOLS)
