"""Unit tests for BookmarkToolProvider.

Covers:
- manage-bookmarks schema and action enum
- Type enum: Note, Warning, TODO, Bug, Analysis
- HANDLERS normalization
- set/add requires addressOrSymbol
- Search, list, get actions
- Batch bookmarks via array
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from agentdecompile_cli.mcp_server.providers.bookmarks import BookmarkToolProvider
from agentdecompile_cli.registry import normalize_identifier as n
from tests.helpers import assert_tool_schema_invariants, parse_single_text_content_json


def _make_provider(with_program: bool = False) -> BookmarkToolProvider:
    if not with_program:
        return BookmarkToolProvider(program_info=None)
    pi = MagicMock()
    pi.program = MagicMock()
    bm_mgr = MagicMock()
    bm_mgr.getBookmarks = MagicMock(return_value=iter([]))
    bm_mgr.getBookmarksIterator = MagicMock(return_value=iter([]))
    pi.program.getBookmarkManager = MagicMock(return_value=bm_mgr)
    pi.program.startTransaction = MagicMock(return_value=1)
    pi.program.endTransaction = MagicMock()
    return BookmarkToolProvider(program_info=pi)


def _parse(resp) -> dict:
    return parse_single_text_content_json(resp)


class TestBookmarkProviderSchema:
    def test_manage_bookmarks_tool_present(self):
        p = _make_provider()
        names = {t.name for t in p.list_tools()}
        for tool in p.list_tools():
            assert_tool_schema_invariants(tool)
        assert "manage-bookmarks" in names

    def test_action_enum(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        assert_tool_schema_invariants(tool, expected_name="manage-bookmarks")
        actions = tool.inputSchema["properties"]["action"]["enum"]
        for a in ("set", "get", "search", "remove", "remove_all", "categories"):
            assert a in actions

    def test_type_enum(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        assert_tool_schema_invariants(tool, expected_name="manage-bookmarks")
        types_enum = tool.inputSchema["properties"]["type"]["enum"]
        for t in ("Note", "Warning", "TODO", "Bug", "Analysis"):
            assert t in types_enum

    def test_address_or_symbol_param(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        assert_tool_schema_invariants(tool, expected_name="manage-bookmarks")
        props = tool.inputSchema["properties"]
        assert "addressOrSymbol" in props

    def test_category_param(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        assert_tool_schema_invariants(tool, expected_name="manage-bookmarks")
        assert "category" in tool.inputSchema["properties"]

    def test_comment_param(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        assert_tool_schema_invariants(tool, expected_name="manage-bookmarks")
        assert "comment" in tool.inputSchema["properties"]

    def test_batch_bookmarks_param(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        assert_tool_schema_invariants(tool, expected_name="manage-bookmarks")
        assert "bookmarks" in tool.inputSchema["properties"]

    def test_pagination_params(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        assert_tool_schema_invariants(tool, expected_name="manage-bookmarks")
        props = tool.inputSchema["properties"]
        assert "maxResults" in props
        assert "offset" in props


class TestBookmarkProviderHandlers:
    def test_handler_keys_normalized(self):
        for key in BookmarkToolProvider.HANDLERS:
            assert key == n(key)

    def test_managebookmarks_present(self):
        assert "managebookmarks" in BookmarkToolProvider.HANDLERS


class TestBookmarkProviderValidation:
    @pytest.mark.asyncio
    async def test_no_program_returns_error(self):
        p = _make_provider(with_program=False)
        resp = await p.call_tool("manage-bookmarks", {"action": "get"})
        result = _parse(resp)
        assert result.get("success") is False or "error" in result

    @pytest.mark.asyncio
    async def test_missing_action_returns_error(self):
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        # With empty action the handler should raise
        resp = await p.call_tool("manage-bookmarks", {})
        result = _parse(resp)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_invalid_action_returns_error(self):
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        resp = await p.call_tool("manage-bookmarks", {"action": "invalid_xyz123"})
        result = _parse(resp)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_set_requires_address(self):
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        resp = await p.call_tool("manage-bookmarks", {"action": "set", "type": "Note", "category": "Test"})
        result = _parse(resp)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_add_alias_routes_to_set(self):
        """'add' is an alias for 'set'."""
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        called = []

        async def fake_add(args):
            called.append(True)
            from agentdecompile_cli.mcp_server.tool_providers import create_success_response
            return create_success_response({"action": "set"})

        p._add = fake_add
        await p.call_tool("manage-bookmarks", {"action": "add", "programPath": "/test/binary", "addressOrSymbol": "0x1000"})
        assert len(called) == 1

    @pytest.mark.asyncio
    async def test_categories_action(self):
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        called = []

        async def fake_categories(args):
            called.append(True)
            from agentdecompile_cli.mcp_server.tool_providers import create_success_response
            return create_success_response({"categories": []})

        p._categories = fake_categories
        await p.call_tool("manage-bookmarks", {"action": "categories", "programPath": "/test/binary"})
        assert len(called) == 1

    @pytest.mark.asyncio
    async def test_remove_all_action(self):
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        called = []

        async def fake_remove_all(args):
            called.append(True)
            from agentdecompile_cli.mcp_server.tool_providers import create_success_response
            return create_success_response({"removed": 0})

        p._remove_all = fake_remove_all
        await p.call_tool("manage-bookmarks", {"action": "removeall", "programPath": "/test/binary"})
        assert len(called) == 1


class TestBookmarkProviderModeActionAlias:
    """Verify that 'mode' is accepted as an alias for 'action' in manage-bookmarks."""

    @pytest.mark.asyncio
    async def test_mode_dispatches_same_as_action(self):
        """Calling with mode='list' should behave identically to action='list'."""
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        called = []

        async def fake_list(args):
            called.append(True)
            from agentdecompile_cli.mcp_server.tool_providers import create_success_response
            return create_success_response({"bookmarks": []})

        p._list = fake_list
        await p.call_tool("manage-bookmarks", {"mode": "list", "programPath": "/test/binary"})
        assert len(called) == 1

    @pytest.mark.asyncio
    async def test_mode_set_dispatches_to_add(self):
        """mode='set' should route to the add/set handler."""
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        called = []

        async def fake_add(args):
            called.append(True)
            from agentdecompile_cli.mcp_server.tool_providers import create_success_response
            return create_success_response({"action": "set"})

        p._add = fake_add
        await p.call_tool("manage-bookmarks", {"mode": "set", "programPath": "/test/binary", "addressOrSymbol": "0x1000"})
        assert len(called) == 1

    @pytest.mark.asyncio
    async def test_mode_categories_dispatches(self):
        """mode='categories' should route to categories handler."""
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        called = []

        async def fake_categories(args):
            called.append(True)
            from agentdecompile_cli.mcp_server.tool_providers import create_success_response
            return create_success_response({"categories": []})

        p._categories = fake_categories
        await p.call_tool("manage-bookmarks", {"mode": "categories", "programPath": "/test/binary"})
        assert len(called) == 1

    @pytest.mark.asyncio
    async def test_action_takes_precedence_over_mode(self):
        """If both action and mode supplied, action wins (first key in _get_str)."""
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        list_called = []
        cat_called = []

        async def fake_list(args):
            list_called.append(True)
            from agentdecompile_cli.mcp_server.tool_providers import create_success_response
            return create_success_response({"bookmarks": []})

        async def fake_categories(args):
            cat_called.append(True)
            from agentdecompile_cli.mcp_server.tool_providers import create_success_response
            return create_success_response({"categories": []})

        p._list = fake_list
        p._categories = fake_categories
        # action=list should win over mode=categories since action is listed first in _get_str
        await p.call_tool("manage-bookmarks", {"action": "list", "mode": "categories", "programPath": "/test/binary"})
        assert len(list_called) == 1
        assert len(cat_called) == 0
