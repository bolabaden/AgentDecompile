"""Deterministic combinatorial normalization coverage for tools and arguments.

This suite adds broader, schema-driven stress tests that mix casing,
separators, and non-alphabetic noise while keeping runtime predictable.
"""

from __future__ import annotations

import random
import re

import pytest

from agentdecompile_cli.executor import DynamicToolExecutor
from agentdecompile_cli.registry import ToolRegistry
from agentdecompile_cli.registry import TOOLS, TOOL_PARAMS
from tests.helpers import assert_mapping_invariants, assert_string_invariants

pytestmark = pytest.mark.unit


def _camel_to_snake(name: str) -> str:
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()


def _noisy_param_variants(param_name: str) -> list[str]:
    snake = _camel_to_snake(param_name)
    kebab = snake.replace("_", "-")
    compact = "".join(ch for ch in param_name if ch.isalpha()).lower()
    spaced = snake.replace("_", " ")
    dotted = snake.replace("_", ".")
    return [
        param_name,
        param_name.upper(),
        snake,
        kebab,
        compact,
        spaced,
        dotted,
        f"__{snake}__",
        f"@@{kebab}@@",
        f"  {param_name}  ",
    ]


def _noisy_tool_variants(tool_name: str) -> list[str]:
    snake = tool_name.replace("-", "_")
    compact = tool_name.replace("-", "")
    spaced = tool_name.replace("-", " ")
    return [
        tool_name,
        tool_name.upper(),
        snake,
        snake.upper(),
        compact,
        compact.upper(),
        spaced,
        f"__{snake}__",
        f"@@{tool_name}@@",
        f"  {tool_name}  ",
    ]


def _pick_param_subset(
    params: list[str],
    seed: int,
    max_items: int = 3,
) -> list[str]:
    if not params:
        return []
    rng = random.Random(seed)
    count = min(max_items, len(params))
    return rng.sample(params, k=count)


class TestCombinatorialToolNameResolution:
    @pytest.mark.parametrize("tool_name", TOOLS)
    def test_dynamic_resolve_accepts_noisy_tool_variants(self, tool_name: str):
        executor = DynamicToolExecutor()

        for variant in _noisy_tool_variants(tool_name):
            resolved = executor._resolve_tool_name(variant)
            assert resolved is not None, f"Expected to resolve {variant!r} to {tool_name!r} but got None"
            assert resolved == tool_name, f"Expected to resolve {variant!r} to {tool_name!r} but got {resolved!r}"
            assert_string_invariants(resolved, expected=tool_name)


class TestCombinatorialArgumentParsing:
    @pytest.mark.parametrize("tool_name", [name for name, params in TOOL_PARAMS.items() if params])
    def test_registry_parses_mixed_noisy_argument_variants(self, tool_name: str):
        registry = ToolRegistry()
        params: list[str] = TOOL_PARAMS[tool_name]
        selected: list[str] = _pick_param_subset(params, seed=len(tool_name), max_items=3)

        raw_arguments: dict[str, str] = {}
        for index, param in enumerate(selected):
            variants: list[str] = _noisy_param_variants(param)
            chosen: str = variants[(len(param) + index) % len(variants)]
            raw_arguments[chosen] = f"value_{index}"

        parsed: dict[str, str] = registry.parse_arguments(raw_arguments, tool_name)

        for index, param in enumerate(selected):
            assert parsed.get(param) == f"value_{index}", (
                f"Expected param {param!r} to parse as 'value_{index}' for tool {tool_name!r} from raw arguments with variant {chosen!r}"
            )
        assert_mapping_invariants(parsed)

    @pytest.mark.parametrize("tool_name", [name for name, params in TOOL_PARAMS.items() if params])
    def test_dynamic_executor_parses_mixed_noisy_argument_variants(self, tool_name: str):
        executor = DynamicToolExecutor()
        params: list[str] = TOOL_PARAMS[tool_name]
        selected: list[str] = _pick_param_subset(params, seed=len(tool_name) * 17, max_items=3)

        raw_arguments: dict[str, str] = {}
        for index, param in enumerate(selected):
            variants: list[str] = _noisy_param_variants(param)
            chosen: str = variants[(index * 3 + len(param)) % len(variants)]
            raw_arguments[chosen] = f"token_{index}"

        parsed: dict[str, str] = executor._parse_arguments_dynamically(tool_name, raw_arguments)

        for param in selected:
            assert param in parsed, f"Expected param {param!r} in parsed arguments for tool {tool_name!r}"
            assert parsed[param].startswith("token_"), f"Expected value starting with 'token_' for param {param!r} in parsed arguments for tool {tool_name!r}"
        assert_mapping_invariants(parsed)


# Full cross-product: every tool with every noisy tool name and every noisy argument variant
class TestFullCrossProductNormalization:
    @pytest.mark.parametrize("tool_name", [name for name, params in TOOL_PARAMS.items() if params])
    def test_registry_cross_product_tool_and_argument_variants(self, tool_name: str):
        registry = ToolRegistry()
        params: list[str] = TOOL_PARAMS[tool_name]
        # For each noisy tool name variant
        for tool_variant in _noisy_tool_variants(tool_name):
            # For each argument, try all noisy variants
            for param in params:
                for arg_variant in _noisy_param_variants(param):
                    raw_arguments: dict[str, str] = {arg_variant: "crossprod"}
                    parsed: dict[str, str] = registry.parse_arguments(raw_arguments, tool_variant)
                    assert param in parsed, f"Expected param {param!r} in parsed arguments for tool variant {tool_variant!r} and arg variant {arg_variant!r}"
                    assert parsed[param] == "crossprod", (
                        f"Expected value 'crossprod' for param {param!r} in parsed arguments for tool variant {tool_variant!r} and arg variant {arg_variant!r}"
                    )
                    assert_mapping_invariants(parsed)

    @pytest.mark.parametrize("tool_name", [name for name, params in TOOL_PARAMS.items() if params])
    def test_dynamic_executor_cross_product_tool_and_argument_variants(self, tool_name: str):
        executor = DynamicToolExecutor()
        params: list[str] = TOOL_PARAMS[tool_name]
        for tool_variant in _noisy_tool_variants(tool_name):
            for param in params:
                for arg_variant in _noisy_param_variants(param):
                    raw_arguments: dict[str, str] = {arg_variant: "crossprod"}
                    parsed: dict[str, str] = executor._parse_arguments_dynamically(tool_variant, raw_arguments)
                    assert param in parsed, f"Expected param {param!r} in parsed arguments for tool variant {tool_variant!r} and arg variant {arg_variant!r}"
                    assert parsed[param] == "crossprod", (
                        f"Expected value 'crossprod' for param {param!r} in parsed arguments for tool variant {tool_variant!r} and arg variant {arg_variant!r}"
                    )
                    assert_mapping_invariants(parsed)
