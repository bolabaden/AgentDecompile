"""Unit tests for the two-step modification conflict system.

Covers conflict_store (store/get/remove) and resolve-modification-conflict
(skip, unknown conflictId, overwrite re-invokes tool and removes pending).
"""

from __future__ import annotations

from typing import Any

import pytest

from agentdecompile_cli.mcp_server.conflict_store import (
    get as conflict_get,
    remove as conflict_remove,
    store as conflict_store_store,
)
from agentdecompile_cli.mcp_server.providers.conflict_resolution import ConflictResolutionToolProvider
from mcp import types

from tests.helpers import parse_single_text_content_json


# ---------------------------------------------------------------------------
# Conflict store
# ---------------------------------------------------------------------------


def test_conflict_store_store_and_get() -> None:
    session_id = "test-conflict-store-1"
    conflict_id = "cid-001"
    conflict_store_store(
        session_id,
        conflict_id,
        tool="manage-symbols",
        arguments={"mode": "rename_data", "addressOrSymbol": "0x1000", "newName": "foo"},
        program_path="/bin.exe",
        summary="Rename would overwrite custom name",
    )
    pending = conflict_get(session_id, conflict_id)
    assert pending is not None
    assert pending.tool == "manage-symbols"
    assert pending.arguments.get("newName") == "foo"
    assert pending.program_path == "/bin.exe"
    conflict_remove(session_id, conflict_id)


def test_conflict_store_get_unknown_returns_none() -> None:
    session_id = "test-conflict-unknown"
    assert conflict_get(session_id, "nonexistent-id") is None


def test_conflict_store_remove_returns_true_when_present() -> None:
    session_id = "test-conflict-remove"
    conflict_id = "cid-remove"
    conflict_store_store(session_id, conflict_id, tool="manage-symbols", arguments={})
    assert conflict_remove(session_id, conflict_id) is True
    assert conflict_get(session_id, conflict_id) is None
    assert conflict_remove(session_id, conflict_id) is False


# ---------------------------------------------------------------------------
# resolve-modification-conflict provider (skip, unknown, overwrite)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resolve_skip_discards_and_returns_success() -> None:
    session_id = "test-resolve-skip"
    conflict_id = "cid-skip"
    conflict_store_store(
        session_id,
        conflict_id,
        tool="manage-symbols",
        arguments={"mode": "rename_data", "newName": "bar"},
    )
    from agentdecompile_cli.mcp_server.session_context import CURRENT_MCP_SESSION_ID

    token = CURRENT_MCP_SESSION_ID.set(session_id)
    try:
        provider = ConflictResolutionToolProvider()
        result = await provider.call_tool(
            "resolve-modification-conflict",
            {"conflictId": conflict_id, "resolution": "skip"},
        )
        payload = parse_single_text_content_json(result)
        assert payload.get("resolution") == "skip"
        assert payload.get("message") == "Change discarded."
        assert conflict_get(session_id, conflict_id) is None
    finally:
        CURRENT_MCP_SESSION_ID.reset(token)


@pytest.mark.asyncio
async def test_resolve_unknown_conflict_id_returns_error() -> None:
    session_id = "test-resolve-unknown"
    from agentdecompile_cli.mcp_server.session_context import CURRENT_MCP_SESSION_ID

    token = CURRENT_MCP_SESSION_ID.set(session_id)
    try:
        provider = ConflictResolutionToolProvider()
        result = await provider.call_tool(
            "resolve-modification-conflict",
            {"conflictId": "unknown-uuid-12345", "resolution": "overwrite"},
        )
        payload = parse_single_text_content_json(result)
        assert payload.get("success") is False
        assert "Unknown or expired" in (payload.get("error") or "")
    finally:
        CURRENT_MCP_SESSION_ID.reset(token)


@pytest.mark.asyncio
async def test_resolve_overwrite_calls_manager_and_removes() -> None:
    session_id = "test-resolve-overwrite"
    conflict_id = "cid-overwrite"
    conflict_store_store(
        session_id,
        conflict_id,
        tool="manage-symbols",
        arguments={"mode": "rename_data", "addressOrSymbol": "0x2000", "newName": "baz"},
        program_path="/other.exe",
    )
    from agentdecompile_cli.mcp_server.session_context import CURRENT_MCP_SESSION_ID

    token = CURRENT_MCP_SESSION_ID.set(session_id)
    try:
        provider = ConflictResolutionToolProvider()
        call_record: list[tuple[str, dict]] = []

        async def fake_call_tool(self: Any, name: str, arguments: dict[str, Any], **kwargs: Any) -> list[types.TextContent]:
            call_record.append((name, dict(arguments)))
            from agentdecompile_cli.mcp_server.tool_providers import create_success_response
            return create_success_response({"mode": "rename_data", "success": True})

        provider._manager = type("Manager", (), {"call_tool": fake_call_tool})()  # pyright: ignore[reportAttributeAccessIssue]
        result = await provider.call_tool(
            "resolve-modification-conflict",
            {"conflictId": conflict_id, "resolution": "overwrite"},
        )
        payload = parse_single_text_content_json(result)
        assert payload.get("resolution") == "overwrite"
        assert payload.get("applied") is True
        assert len(call_record) == 1
        assert call_record[0][0] == "manage-symbols"
        assert call_record[0][1].get("newName") == "baz" or call_record[0][1].get("newname") == "baz"
        assert "__force_apply_conflict_id" in call_record[0][1] or any(
            "force" in str(k).lower()
            and "conflict" in str(k).lower()
            for k in call_record[0][1]
        )
        assert conflict_get(session_id, conflict_id) is None
    finally:
        CURRENT_MCP_SESSION_ID.reset(token)
