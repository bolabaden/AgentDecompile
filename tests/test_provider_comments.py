"""Unit tests for CommentToolProvider.

Covers:
- manage-comments schema and action enum
- Comment type enum: eol, pre, post, plate, repeatable
- HANDLERS normalization
- set action requires addressOrSymbol + comment
- Batch comments via array
- Comment type constant mapping (eol=0, pre=1, post=2, plate=3, repeatable=4)
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from agentdecompile_cli.mcp_server.providers.comments import (
    CommentToolProvider,
    _COMMENT_TYPES,
)
from agentdecompile_cli.registry import normalize_identifier as n
from tests.helpers import assert_tool_schema_invariants, parse_single_text_content_json


def _make_provider(with_program: bool = False) -> CommentToolProvider:
    if not with_program:
        return CommentToolProvider(program_info=None)
    pi = MagicMock()
    pi.program = MagicMock()
    pi.program.getListing = MagicMock(return_value=MagicMock())
    pi.program.startTransaction = MagicMock(return_value=1)
    pi.program.endTransaction = MagicMock()
    return CommentToolProvider(program_info=pi)


def _parse(resp) -> dict:
    return parse_single_text_content_json(resp)


class TestCommentProviderSchema:
    def test_manage_comments_tool_present(self):
        p = _make_provider()
        names = {t.name for t in p.list_tools()}
        for tool in p.list_tools():
            assert_tool_schema_invariants(tool)
        assert "manage-comments" in names

    def test_action_enum(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        assert_tool_schema_invariants(tool, expected_name="manage-comments")
        actions = tool.inputSchema["properties"]["action"]["enum"]
        for a in ("set", "get", "remove", "search", "search_decomp"):
            assert a in actions

    def test_comment_type_enum(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        assert_tool_schema_invariants(tool, expected_name="manage-comments")
        types_enum = tool.inputSchema["properties"]["type"]["enum"]
        for t in ("eol", "pre", "post", "plate", "repeatable"):
            assert t in types_enum

    def test_comment_type_default_eol(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        assert_tool_schema_invariants(tool, expected_name="manage-comments")
        assert tool.inputSchema["properties"]["type"].get("default") == "eol"

    def test_batch_comments_array_param(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        assert_tool_schema_invariants(tool, expected_name="manage-comments")
        assert "comments" in tool.inputSchema["properties"]

    def test_search_text_param(self):
        p = _make_provider()
        tool = p.list_tools()[0]
        assert_tool_schema_invariants(tool, expected_name="manage-comments")
        assert "searchText" in tool.inputSchema["properties"]


class TestCommentProviderHandlers:
    def test_handler_keys_normalized(self):
        for key in CommentToolProvider.HANDLERS:
            assert key == n(key)

    def test_managecomments_present(self):
        assert "managecomments" in CommentToolProvider.HANDLERS


class TestCommentTypeConstants:
    def test_eol_is_zero(self):
        assert _COMMENT_TYPES["eol"] == 0

    def test_pre_is_one(self):
        assert _COMMENT_TYPES["pre"] == 1

    def test_post_is_two(self):
        assert _COMMENT_TYPES["post"] == 2

    def test_plate_is_three(self):
        assert _COMMENT_TYPES["plate"] == 3

    def test_repeatable_is_four(self):
        assert _COMMENT_TYPES["repeatable"] == 4

    def test_resolve_comment_type_eol(self):
        p = _make_provider()
        assert p._resolve_comment_type("eol") == 0

    def test_resolve_comment_type_plate(self):
        p = _make_provider()
        assert p._resolve_comment_type("plate") == 3

    def test_resolve_comment_type_case_insensitive(self):
        p = _make_provider()
        assert p._resolve_comment_type("EOL") == 0
        assert p._resolve_comment_type("PRE") == 1

    def test_resolve_unknown_defaults_to_eol(self):
        p = _make_provider()
        assert p._resolve_comment_type("unknown_type") == 0


class TestCommentProviderValidation:
    @pytest.mark.asyncio
    async def test_no_program_returns_error(self):
        p = _make_provider(with_program=False)
        resp = await p.call_tool("manage-comments", {"action": "get"})
        result = _parse(resp)
        assert result.get("success") is False or "error" in result

    @pytest.mark.asyncio
    async def test_invalid_action_returns_error(self):
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        resp = await p.call_tool("manage-comments", {"action": "invalid_xyz"})
        result = _parse(resp)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_set_requires_address(self):
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        resp = await p.call_tool("manage-comments", {"action": "set", "comment": "hello"})
        result = _parse(resp)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_set_requires_comment(self):
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        resp = await p.call_tool("manage-comments", {"action": "set", "addressOrSymbol": "0x1000"})
        result = _parse(resp)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_add_action_alias_for_set(self):
        """'add' is an alias for 'set'."""
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        called = []

        async def fake_set(args):
            called.append(True)
            from agentdecompile_cli.mcp_server.tool_providers import create_success_response
            return create_success_response({"action": "set"})

        p._set = fake_set
        await p.call_tool("manage-comments", {"action": "add", "addressOrSymbol": "0x1000", "comment": "test"})
        assert len(called) == 1

    @pytest.mark.asyncio
    async def test_delete_action_alias_for_remove(self):
        """'delete' is an alias for 'remove'."""
        p = _make_provider(with_program=True)
        p._require_program = MagicMock()
        called = []

        async def fake_remove(args):
            called.append(True)
            from agentdecompile_cli.mcp_server.tool_providers import create_success_response
            return create_success_response({"action": "remove"})

        p._remove = fake_remove
        await p.call_tool("manage-comments", {"action": "delete", "addressOrSymbol": "0x1000"})
        assert len(called) == 1
