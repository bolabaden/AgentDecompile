"""Comprehensive normalization tests for tool names and argument keys.

These tests verify that tool and argument matching works case-insensitively,
separator-insensitively, and with alphabet-only canonicalization across the
entire schema in ``tools_schema``.
"""

from __future__ import annotations

import itertools

import pytest

from agentdecompile_cli.executor import DynamicToolExecutor
from agentdecompile_cli.registry import ToolRegistry, normalize_identifier
from agentdecompile_cli.registry import TOOLS, TOOL_PARAMS
from tests.helpers import assert_mapping_invariants, assert_string_invariants

pytestmark = pytest.mark.unit


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

    @pytest.mark.parametrize("tool_name", [name for name, params in TOOL_PARAMS.items() if params])
    def test_parse_arguments_accepts_variant_for_each_parameter(self, tool_name: str):
        registry = ToolRegistry()
        canonical_params = TOOL_PARAMS[tool_name]

        for param_name in canonical_params:
            for variant in _param_variants(param_name):
                raw_arguments = {variant: "value"}
                parsed = registry.parse_arguments(raw_arguments, tool_name)
                assert param_name in parsed, f"Tool {tool_name!r} param {param_name!r} should parse from variant {variant!r}"
                assert parsed[param_name] == "value"
                assert_mapping_invariants(parsed)

    @pytest.mark.parametrize("tool_name", [name for name, params in TOOL_PARAMS.items() if params])
    def test_parse_arguments_handles_mixed_argument_styles_in_single_call(self, tool_name: str):
        registry = ToolRegistry()
        params = TOOL_PARAMS[tool_name]

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
            assert resolved == normalize_identifier(tool_name)
            assert_string_invariants(resolved, expected=normalize_identifier(tool_name))

    @pytest.mark.parametrize("tool_name", [name for name, params in TOOL_PARAMS.items() if params])
    def test_parse_arguments_dynamically_accepts_non_alphabet_noise(self, tool_name: str):
        executor = DynamicToolExecutor()
        canonical_params = TOOL_PARAMS[tool_name]

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
