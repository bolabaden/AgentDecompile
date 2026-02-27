"""Migrated and extended tests for DynamicToolExecutor (executor.py).

Migrated from src/test/python/test_dynamic_tool_executor.py and extended
with additional coverage for the Python-authoritative implementation.

Tests cover:
- Tool name resolution (normalize → canonical kebab-case name)
- Argument parsing with camelCase / snake_case / kebab-case variations
- Dynamic type coercion (bool, int, list, str)
- Argument validation for required parameters
- Per-tool execution dispatch (mocked)
- Backward compatibility
"""
from __future__ import annotations

import json
from unittest.mock import Mock, MagicMock, patch

import pytest

from agentdecompile_cli.registry import (
    normalize_identifier,
    tool_registry,
    TOOLS,
)
from agentdecompile_cli.executor import (
    DynamicToolExecutor,
    create_success_response,
    create_error_response,
)
from tests.helpers import assert_mapping_invariants, assert_string_invariants, parse_single_text_content_json


# ---------------------------------------------------------------------------
# normalize_identifier tests
# ---------------------------------------------------------------------------


class TestNormalizeIdentifier:
    def _assert_normalized(self, raw: str, expected: str) -> None:
        result = normalize_identifier(raw)
        assert result == expected
        assert_string_invariants(result, expected=expected, allow_empty=(expected == ""))

    def test_strips_hyphens(self):
        self._assert_normalized("get-data", "getdata")

    def test_strips_underscores(self):
        self._assert_normalized("get_data", "getdata")

    def test_lowercases(self):
        self._assert_normalized("GetData", "getdata")

    def test_strips_numbers(self):
        self._assert_normalized("get-data-2", "getdata")

    def test_strips_spaces(self):
        self._assert_normalized("  get data  ", "getdata")

    def test_camelcase_stripped(self):
        self._assert_normalized("addressOrSymbol", "addressorsymbol")

    def test_all_lowercase_alpha_unchanged(self):
        s = "getdata"
        self._assert_normalized(s, s)

    def test_empty_string(self):
        self._assert_normalized("", "")

    def test_numbers_only(self):
        self._assert_normalized("12345", "")

    def test_mixed_separators(self):
        self._assert_normalized("get_call-graph", "getcallgraph")

    def test_all_caps(self):
        self._assert_normalized("GETDATA", "getdata")


# ---------------------------------------------------------------------------
# ToolRegistry tests
# ---------------------------------------------------------------------------


class TestToolRegistry:
    def test_registry_has_tools(self):
        tools = tool_registry.get_tools()
        assert len(tools) > 0

    def test_registry_contains_canonical_tools(self):
        """Key canonical tools from TOOLS list must be in the registry."""
        expected_names = [
            "manage-symbols",
            "list-functions",
            "get-call-graph",
            "inspect-memory",
            "manage-strings",
            "manage-comments",
            "manage-bookmarks",
            "get-references",
            "search-constants",
            "analyze-vtables",
            "manage-function",
            "manage-function-tags",
            "match-function",
            "decompile-function",
            "analyze-data-flow",
            "manage-structures",
            "manage-data-types",
        ]
        # get_tools() returns list of normalized tool name strings
        registered_names = set(tool_registry.get_tools())
        for name in expected_names:
            assert name in registered_names, f"Tool '{name}' missing from registry"

    def test_tools_list_has_expected_count(self):
        """TOOLS list should have ~49+ canonical tool names."""
        assert len(TOOLS) >= 40


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------


class TestResponseHelpers:
    def test_create_success_response_structure(self):
        resp = create_success_response({"count": 5, "results": []})
        assert len(resp) == 1
        data = parse_single_text_content_json(resp)
        assert_mapping_invariants(data)
        assert data["count"] == 5
        assert data["results"] == []

    def test_create_error_response_structure(self):
        resp = create_error_response("Something went wrong")
        assert len(resp) == 1
        data = parse_single_text_content_json(resp)
        assert_mapping_invariants(data)
        assert data["success"] is False
        assert "Something went wrong" in data["error"]

    def test_create_error_response_from_exception(self):
        resp = create_error_response(ValueError("Bad value"))
        data = parse_single_text_content_json(resp)
        assert_mapping_invariants(data)
        assert "Bad value" in data["error"]

    def test_success_response_serializes_nested(self):
        resp = create_success_response({"nested": {"a": 1, "b": [1, 2, 3]}})
        data = parse_single_text_content_json(resp)
        assert_mapping_invariants(data)
        assert data["nested"]["b"] == [1, 2, 3]


# ---------------------------------------------------------------------------
# Tool provider base class helpers
# ---------------------------------------------------------------------------


class TestToolProviderHelpers:
    """Tests for ToolProvider._get_*, _coerce_* helpers."""

    def _tp(self):
        from agentdecompile_cli.mcp_server.tool_providers import ToolProvider
        return ToolProvider

    def test_get_str_first_key_wins(self):
        TP = self._tp()
        args = {"query": "main", "namepattern": "ignored"}
        assert TP._get_str(args, "query", "namepattern") == "main"

    def test_get_str_skips_none(self):
        TP = self._tp()
        args = {"namepattern": "test"}
        assert TP._get_str(args, "query", "namepattern") == "test"

    def test_get_int_string_coerced(self):
        TP = self._tp()
        args = {"maxresults": "75"}
        assert TP._get_int(args, "maxresults") == 75

    def test_get_int_float_coerced(self):
        TP = self._tp()
        args = {"timeout": 30.9}
        assert TP._get_int(args, "timeout") == 30

    def test_get_bool_true_variants(self):
        TP = self._tp()
        for val in ["true", "1", "yes", "on", "enabled", True, 1]:
            args = {"flag": val}
            assert TP._get_bool(args, "flag") is True

    def test_get_bool_false_variants(self):
        TP = self._tp()
        for val in ["false", "0", "no", "off", "disabled", False, 0]:
            args = {"flag": val}
            assert TP._get_bool(args, "flag") is False

    def test_get_list_from_list(self):
        TP = self._tp()
        args = {"items": [1, 2, 3]}
        assert TP._get_list(args, "items") == [1, 2, 3]

    def test_get_list_from_csv_string(self):
        TP = self._tp()
        args = {"items": "a,b,c"}
        assert TP._get_list(args, "items") == ["a", "b", "c"]

    def test_get_list_from_scalar(self):
        TP = self._tp()
        args = {"items": "single"}
        assert TP._get_list(args, "items") == ["single"]

    def test_get_returns_none_for_missing(self):
        TP = self._tp()
        args = {}
        assert TP._get(args, "missing") is None

    def test_get_returns_default(self):
        TP = self._tp()
        args = {}
        assert TP._get(args, "missing", default=42) == 42


# ---------------------------------------------------------------------------
# Per-provider HANDLERS completeness
# ---------------------------------------------------------------------------


class TestAllHandlersNormalized:
    """All HANDLERS keys in every provider must be normalize_identifier-clean."""

    def _all_providers(self):
        from agentdecompile_cli.mcp_server.providers.symbols import SymbolToolProvider
        from agentdecompile_cli.mcp_server.providers.functions import FunctionToolProvider
        from agentdecompile_cli.mcp_server.providers.decompiler import DecompilerToolProvider
        from agentdecompile_cli.mcp_server.providers.callgraph import CallGraphToolProvider
        from agentdecompile_cli.mcp_server.providers.xrefs import CrossReferencesToolProvider
        from agentdecompile_cli.mcp_server.providers.memory import MemoryToolProvider
        from agentdecompile_cli.mcp_server.providers.strings import StringToolProvider
        from agentdecompile_cli.mcp_server.providers.comments import CommentToolProvider
        from agentdecompile_cli.mcp_server.providers.bookmarks import BookmarkToolProvider
        from agentdecompile_cli.mcp_server.providers.constants import ConstantSearchToolProvider
        from agentdecompile_cli.mcp_server.providers.vtable import VtableToolProvider
        from agentdecompile_cli.mcp_server.providers.getfunction import GetFunctionToolProvider
        from agentdecompile_cli.mcp_server.providers.project import ProjectToolProvider
        from agentdecompile_cli.mcp_server.providers.import_export import ImportExportToolProvider
        from agentdecompile_cli.mcp_server.providers.structures import StructureToolProvider
        from agentdecompile_cli.mcp_server.providers.datatypes import DataTypeToolProvider
        from agentdecompile_cli.mcp_server.providers.data import DataToolProvider
        from agentdecompile_cli.mcp_server.providers.dataflow import DataFlowToolProvider
        return [
            SymbolToolProvider, FunctionToolProvider, DecompilerToolProvider,
            CallGraphToolProvider, CrossReferencesToolProvider, MemoryToolProvider,
            StringToolProvider, CommentToolProvider, BookmarkToolProvider,
            ConstantSearchToolProvider, VtableToolProvider, GetFunctionToolProvider,
            ProjectToolProvider, ImportExportToolProvider, StructureToolProvider,
            DataTypeToolProvider, DataToolProvider, DataFlowToolProvider,
        ]

    @pytest.mark.parametrize("provider_class", [
        "SymbolToolProvider", "FunctionToolProvider", "DecompilerToolProvider",
        "CallGraphToolProvider", "CrossReferencesToolProvider", "MemoryToolProvider",
        "StringToolProvider", "CommentToolProvider", "BookmarkToolProvider",
        "ConstantSearchToolProvider", "VtableToolProvider", "GetFunctionToolProvider",
        "ProjectToolProvider", "ImportExportToolProvider", "StructureToolProvider",
        "DataTypeToolProvider", "DataToolProvider", "DataFlowToolProvider",
    ])
    def test_handlers_keys_all_normalized(self, provider_class):
        providers = self._all_providers()
        cls = next(p for p in providers if p.__name__ == provider_class)
        for key in cls.HANDLERS:
            assert key == normalize_identifier(key), (
                f"{provider_class}.HANDLERS['{key}'] is not normalized. "
                f"Expected '{normalize_identifier(key)}'"
            )

    @pytest.mark.parametrize("provider_class", [
        "SymbolToolProvider", "FunctionToolProvider", "DecompilerToolProvider",
        "CallGraphToolProvider", "CrossReferencesToolProvider", "MemoryToolProvider",
        "StringToolProvider", "CommentToolProvider", "BookmarkToolProvider",
        "ConstantSearchToolProvider", "VtableToolProvider", "GetFunctionToolProvider",
        "ProjectToolProvider", "ImportExportToolProvider", "StructureToolProvider",
        "DataTypeToolProvider", "DataToolProvider", "DataFlowToolProvider",
    ])
    def test_all_handlers_methods_exist(self, provider_class):
        """Each HANDLERS method name must exist as an actual method on the class."""
        providers = self._all_providers()
        cls = next(p for p in providers if p.__name__ == provider_class)
        instance = cls(program_info=None)
        for key, method_name in cls.HANDLERS.items():
            assert hasattr(instance, method_name), (
                f"{provider_class}.HANDLERS['{key}'] = '{method_name}' "
                f"but method does not exist"
            )


# ---------------------------------------------------------------------------
# Tool advertisement completeness
# ---------------------------------------------------------------------------


class TestToolAdvertisementCompleteness:
    """All providers combined should advertise at least the canonical tools."""

    def _collect_all_tool_names(self) -> set[str]:
        from agentdecompile_cli.mcp_server.providers.symbols import SymbolToolProvider
        from agentdecompile_cli.mcp_server.providers.functions import FunctionToolProvider
        from agentdecompile_cli.mcp_server.providers.decompiler import DecompilerToolProvider
        from agentdecompile_cli.mcp_server.providers.callgraph import CallGraphToolProvider
        from agentdecompile_cli.mcp_server.providers.xrefs import CrossReferencesToolProvider
        from agentdecompile_cli.mcp_server.providers.memory import MemoryToolProvider
        from agentdecompile_cli.mcp_server.providers.strings import StringToolProvider
        from agentdecompile_cli.mcp_server.providers.comments import CommentToolProvider
        from agentdecompile_cli.mcp_server.providers.bookmarks import BookmarkToolProvider
        from agentdecompile_cli.mcp_server.providers.constants import ConstantSearchToolProvider
        from agentdecompile_cli.mcp_server.providers.vtable import VtableToolProvider
        from agentdecompile_cli.mcp_server.providers.getfunction import GetFunctionToolProvider
        from agentdecompile_cli.mcp_server.providers.project import ProjectToolProvider
        from agentdecompile_cli.mcp_server.providers.import_export import ImportExportToolProvider
        from agentdecompile_cli.mcp_server.providers.structures import StructureToolProvider
        from agentdecompile_cli.mcp_server.providers.datatypes import DataTypeToolProvider
        from agentdecompile_cli.mcp_server.providers.data import DataToolProvider
        from agentdecompile_cli.mcp_server.providers.dataflow import DataFlowToolProvider

        all_names = set()
        for cls in [
            SymbolToolProvider, FunctionToolProvider, DecompilerToolProvider,
            CallGraphToolProvider, CrossReferencesToolProvider, MemoryToolProvider,
            StringToolProvider, CommentToolProvider, BookmarkToolProvider,
            ConstantSearchToolProvider, VtableToolProvider, GetFunctionToolProvider,
            ProjectToolProvider, ImportExportToolProvider, StructureToolProvider,
            DataTypeToolProvider, DataToolProvider, DataFlowToolProvider,
        ]:
            instance = cls(program_info=None)
            for t in instance.list_tools():
                all_names.add(t.name)
        return all_names

    @pytest.mark.parametrize("tool_name", [
        "manage-symbols",
        "search-symbols-by-name",
        "list-functions",
        "decompile-function",
        "get-call-graph",
        "gen-callgraph",
        "get-references",
        "inspect-memory",
        "manage-strings",
        "list-strings",
        "manage-comments",
        "manage-bookmarks",
        "search-constants",
        "analyze-vtables",
        "manage-function",
        "manage-function-tags",
        "match-function",
        "manage-structures",
        "manage-data-types",
        "get-data",
        "apply-data-type",
        "analyze-data-flow",
        "import-binary",
        "export",
        "analyze-program",
        "open",
        "list-project-files",
    ])
    def test_tool_is_advertised(self, tool_name):
        tools = self._collect_all_tool_names()
        assert tool_name in tools, f"Tool '{tool_name}' not advertised by any provider"


class TestDynamicExecutorOpenValidation:
    def test_open_does_not_require_programpath_for_shared_server(self):
        executor = DynamicToolExecutor()
        parsed_args = {
            "serverHost": "170.9.241.140",
            "serverPort": 13100,
            "serverUsername": "OpenKotOR",
            "serverPassword": "MuchaShakaPaka",
            "path": "Odyssey",
        }

        executor._validate_arguments_dynamically("open", parsed_args)
