"""Unit tests for SymbolToolProvider.

Covers:
- Tool schema (list_tools)
- HANDLERS keys (alias routing)
- Mode enum validation
- Required argument checks
- Argument normalization (camelCase / snake_case / kebab-case)
- Vendor alias routing (listimports, listexports, createlabel, searchsymbolsbyname)

These tests do NOT require a live Ghidra/PyGhidra instance; program_info is
mocked so the tests run fast on any platform.
"""
from __future__ import annotations

from unittest.mock import MagicMock, AsyncMock, patch

import pytest

from agentdecompile_cli.mcp_server.providers.symbols import SymbolToolProvider
from agentdecompile_cli.registry import normalize_identifier as n
from tests.helpers import assert_tool_schema_invariants, parse_single_text_content_json


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_provider(with_program: bool = False) -> SymbolToolProvider:
    """Return a provider, optionally with a mocked program."""
    if not with_program:
        return SymbolToolProvider(program_info=None)
    pi = MagicMock()
    pi.program = MagicMock()
    pi.program.getSymbolTable = MagicMock(return_value=MagicMock())
    pi.program.getExternalManager = MagicMock(return_value=MagicMock())
    return SymbolToolProvider(program_info=pi)


def _parse(resp) -> dict:
    return parse_single_text_content_json(resp)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


class TestSymbolProviderSchema:
    def test_list_tools_returns_tools(self):
        p = _make_provider()
        tools = p.list_tools()
        for tool in tools:
            assert_tool_schema_invariants(tool)
        assert len(tools) >= 3, "Expected at least manage-symbols + search-symbols-by-name + search-symbols"

    def test_tool_names(self):
        p = _make_provider()
        names = {t.name for t in p.list_tools()}
        assert "manage-symbols" in names
        assert "search-symbols-by-name" in names
        assert "search-symbols" in names

    def test_manage_symbols_mode_enum(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "manage-symbols")
        assert_tool_schema_invariants(tool, expected_name="manage-symbols")
        schema = tool.inputSchema
        modes = schema["properties"]["mode"]["enum"]
        for expected in ("symbols", "classes", "namespaces", "imports", "exports",
                         "create_label", "count", "rename_data", "demangle"):
            assert expected in modes, f"Missing mode '{expected}' from enum"

    def test_manage_symbols_has_expected_properties(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "manage-symbols")
        assert_tool_schema_invariants(tool, expected_name="manage-symbols")
        schema = tool.inputSchema
        props = schema["properties"]
        for key in ("programPath", "mode", "query", "addressOrSymbol", "labelName", "newName"):
            assert key in props, f"Missing property '{key}'"

    def test_search_symbols_schema(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "search-symbols-by-name")
        assert_tool_schema_invariants(tool, expected_name="search-symbols-by-name")
        props = tool.inputSchema["properties"]
        assert "query" in props
        assert "maxResults" in props


# ---------------------------------------------------------------------------
# HANDLERS / alias routing
# ---------------------------------------------------------------------------


class TestSymbolProviderHandlers:
    def test_handler_keys_are_normalized(self):
        """HANDLERS keys must only contain lowercase a-z (no hyphens/underscores)."""
        for key in SymbolToolProvider.HANDLERS:
            assert key == n(key), f"Handler key '{key}' not normalized"

    def test_has_managesymbols_handler(self):
        assert "managesymbols" in SymbolToolProvider.HANDLERS

    def test_has_searchsymbolsbyname_handler(self):
        assert "searchsymbolsbyname" in SymbolToolProvider.HANDLERS

    def test_has_searchsymbols_handler(self):
        assert "searchsymbols" in SymbolToolProvider.HANDLERS

    def test_has_listimports_alias(self):
        assert "listimports" in SymbolToolProvider.HANDLERS

    def test_has_listexports_alias(self):
        assert "listexports" in SymbolToolProvider.HANDLERS

    def test_has_createlabel_alias(self):
        assert "createlabel" in SymbolToolProvider.HANDLERS

    def test_searchsymbolsbyname_routes_to_search_method(self):
        """search-symbols-by-name and search-symbols go to the same handler."""
        assert SymbolToolProvider.HANDLERS["searchsymbolsbyname"] == SymbolToolProvider.HANDLERS["searchsymbols"]

    def test_listimports_routes_to_import_method(self):
        method = SymbolToolProvider.HANDLERS["listimports"]
        assert "import" in method.lower() or method == "_handle_list_imports_alias"

    def test_listexports_routes_to_export_method(self):
        method = SymbolToolProvider.HANDLERS["listexports"]
        assert "export" in method.lower() or method == "_handle_list_exports_alias"


# ---------------------------------------------------------------------------
# Tool dispatch via call_tool (validation layer)
# ---------------------------------------------------------------------------


class TestSymbolProviderValidation:
    """Validation tests that require no real Ghidra but DO touch handler dispatch."""

    @pytest.mark.asyncio
    async def test_no_program_returns_error(self):
        p = _make_provider(with_program=False)
        resp = await p.call_tool("manage-symbols", {"mode": "symbols"})
        result = _parse(resp)
        assert result.get("success") is False or "error" in result

    @pytest.mark.asyncio
    async def test_invalid_mode_returns_error(self):
        p = _make_provider(with_program=True)
        # Patch _require_program so it doesn't fail
        p._require_program = MagicMock()
        # Patch mode dispatch so it hits the unknown path
        with patch.object(p, "_handle", wraps=p._handle):
            resp = await p.call_tool("manage-symbols", {"mode": "invalid_mode_xyz"})
        result = _parse(resp)
        # Should return error about unknown mode
        assert "error" in result or result.get("success") is False

    @pytest.mark.asyncio
    async def test_create_label_alias_dispatches(self):
        """Calling 'create-label' tool routes to _handle_create_label_alias."""
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        called = []

        async def fake_create_label(args):
            called.append(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_success_response
            return create_success_response({"action": "create_label", "success": True})

        p._handle_create_label_alias = fake_create_label
        resp = await p.call_tool("create-label", {"addressOrSymbol": "0x401000", "labelName": "my_label"})
        assert len(called) == 1

    @pytest.mark.asyncio
    async def test_list_imports_alias_dispatches(self):
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        called = []

        async def fake(args):
            called.append(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_success_response
            return create_success_response({"imports": []})

        p._handle_list_imports_alias = fake
        await p.call_tool("list-imports", {})
        assert len(called) == 1


# ---------------------------------------------------------------------------
# Argument normalization
# ---------------------------------------------------------------------------


class TestSymbolProviderArgumentNormalization:
    """Verify argument keys are normalized before reaching handlers."""

    @pytest.mark.asyncio
    async def test_camelcase_args_normalized(self):
        """camelCase arg keys should be accessible via normalized form."""
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()

        received_args = {}

        async def capture(args):
            received_args.update(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_success_response
            return create_success_response({})

        # Force search handler
        p._handle_search = capture

        await p.call_tool("search-symbols-by-name", {"namePattern": "main", "maxResults": 50})
        # After normalization "namePattern" → "namepattern"
        assert "namepattern" in received_args

    @pytest.mark.asyncio
    async def test_snake_case_args_normalized(self):
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        received_args = {}

        async def capture(args):
            received_args.update(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_success_response
            return create_success_response({})

        p._handle_search = capture
        await p.call_tool("search-symbols", {"name_pattern": "foo", "max_results": 10})
        assert "namepattern" in received_args
        assert "maxresults" in received_args

    def test_get_str_accepts_multiple_keys(self):
        from agentdecompile_cli.mcp_server.tool_providers import ToolProvider
        args = {"namepattern": "test"}
        result = ToolProvider._get_str(args, "query", "namepattern", "pattern")
        assert result == "test"

    def test_get_str_returns_default_if_missing(self):
        from agentdecompile_cli.mcp_server.tool_providers import ToolProvider
        args = {}
        result = ToolProvider._get_str(args, "query", default="DEFAULT")
        assert result == "DEFAULT"

    def test_get_int_coercion(self):
        from agentdecompile_cli.mcp_server.tool_providers import ToolProvider
        args = {"maxresults": "42"}
        result = ToolProvider._get_int(args, "maxresults", default=100)
        assert result == 42

    def test_get_bool_string_true(self):
        from agentdecompile_cli.mcp_server.tool_providers import ToolProvider
        args = {"filterdefaultnames": "true"}
        result = ToolProvider._get_bool(args, "filterdefaultnames", default=False)
        assert result is True

    def test_get_bool_string_false(self):
        from agentdecompile_cli.mcp_server.tool_providers import ToolProvider
        args = {"filterdefaultnames": "false"}
        result = ToolProvider._get_bool(args, "filterdefaultnames", default=True)
        assert result is False


# ---------------------------------------------------------------------------
# mode / action alias interchangeability
# ---------------------------------------------------------------------------


class TestSymbolProviderModeActionAlias:
    """Verify that 'action' is accepted as an alias for 'mode' in manage-symbols."""

    def test_schema_advertises_action_property(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "manage-symbols")
        props = tool.inputSchema["properties"]
        assert "action" in props, "manage-symbols schema must advertise 'action' property"
        assert "alias" in props["action"].get("description", "").lower(), \
            "action description should mention it's an alias"

    def test_schema_advertises_mode_as_primary(self):
        p = _make_provider()
        tool = next(t for t in p.list_tools() if t.name == "manage-symbols")
        props = tool.inputSchema["properties"]
        assert "mode" in props
        assert "enum" in props["mode"], "mode must remain the primary with enum values"

    @pytest.mark.asyncio
    async def test_action_dispatches_same_as_mode(self):
        """Calling with action='classes' should behave identically to mode='classes'."""
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()

        captured_mode = []
        captured_action = []

        async def capture_handler(args, *, _store):
            _store.append(args)
            from agentdecompile_cli.mcp_server.tool_providers import create_success_response
            return create_success_response({"classes": []})

        # Patch _handle to record args
        import functools
        original_handle = p._handle

        async def intercept_mode(args):
            captured_mode.append(dict(args))
            from agentdecompile_cli.mcp_server.tool_providers import create_success_response
            return create_success_response({"intercepted": True})

        async def intercept_action(args):
            captured_action.append(dict(args))
            from agentdecompile_cli.mcp_server.tool_providers import create_success_response
            return create_success_response({"intercepted": True})

        # Test with mode=
        p._handle = intercept_mode
        await p.call_tool("manage-symbols", {"mode": "classes"})
        assert len(captured_mode) == 1

        # Test with action=
        p._handle = intercept_action
        await p.call_tool("manage-symbols", {"action": "classes"})
        assert len(captured_action) == 1

    @pytest.mark.asyncio
    async def test_action_classes_reaches_handler(self):
        """action='classes' should pass through to the actual _handle method."""
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()

        # The real handler will try to invoke program APIs.
        # We just confirm no ValueError about unknown mode.
        resp = await p.call_tool("manage-symbols", {"action": "classes"})
        result = _parse(resp)
        # Should NOT be "unknown mode" error
        assert result.get("error", "").find("Unknown mode") == -1 or "error" not in result

    @pytest.mark.asyncio
    async def test_action_symbols_is_default_mode(self):
        """action='symbols' should work the same as mode='symbols' (the default)."""
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        resp = await p.call_tool("manage-symbols", {"action": "symbols"})
        result = _parse(resp)
        assert result.get("error", "").find("Unknown mode") == -1 or "error" not in result

    @pytest.mark.asyncio
    async def test_mode_takes_precedence_over_action(self):
        """If both mode and action are supplied, mode should win (first key in _get_str)."""
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()

        received = {}

        async def capture(args):
            received.update(args)
            # Read mode via the same _get_str logic the real handler uses
            mode_val = p._get_str(args, "mode", "action", default="symbols")
            received["_resolved_mode"] = mode_val
            from agentdecompile_cli.mcp_server.tool_providers import create_success_response
            return create_success_response({"resolved": mode_val})

        p._handle = capture
        await p.call_tool("manage-symbols", {"mode": "imports", "action": "exports"})
        # mode is listed first in _get_str, so it should win
        assert received["_resolved_mode"] == "imports"
