"""Tests that verify the shared project flow: create/open shared repo and use tools with it.

These tests ensure that when the session is in shared-server mode, list-project-files
returns source=shared-server-session and that shared mode is recognized consistently
(mode \"shared-server\" or \"sharedserver\"). No live Ghidra server or Docker required.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from agentdecompile_cli.mcp_server.providers import project as project_provider_module
from agentdecompile_cli.mcp_server.providers.project import ProjectToolProvider
from agentdecompile_cli.mcp_server.session_context import (
    SESSION_CONTEXTS,
    get_current_mcp_session_id,
    is_shared_server_handle,
)


# -----------------------------------------------------------------------------
# is_shared_server_handle (canonical shared-mode check)
# -----------------------------------------------------------------------------


def test_is_shared_server_handle_accepts_shared_server() -> None:
    """Session stores mode 'shared-server'; must be recognized as shared."""
    assert is_shared_server_handle({"mode": "shared-server", "repository_name": "agentrepo"}) is True


def test_is_shared_server_handle_accepts_sharedserver() -> None:
    """Legacy 'sharedserver' (no hyphen) must still be recognized."""
    assert is_shared_server_handle({"mode": "sharedserver"}) is True


def test_is_shared_server_handle_rejects_local_and_empty() -> None:
    """Local or missing handle must not be treated as shared."""
    assert is_shared_server_handle(None) is False
    assert is_shared_server_handle({}) is False
    assert is_shared_server_handle({"mode": "local-gpr"}) is False
    assert is_shared_server_handle({"mode": "local"}) is False


# -----------------------------------------------------------------------------
# list-project-files returns source=shared-server-session when session is shared
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_project_files_returns_shared_server_session_when_handle_is_shared(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With session in shared-server mode and binaries set, list-project-files returns source=shared-server-session."""
    session_id = "test-shared-flow-list"
    provider = ProjectToolProvider()

    monkeypatch.setattr(project_provider_module, "get_current_mcp_session_id", lambda: session_id)

    # Simulate a completed open(shared): handle + binaries
    SESSION_CONTEXTS.set_project_handle(
        session_id,
        {
            "mode": "shared-server",
            "server_host": "ghidra",
            "server_port": 13100,
            "repository_name": "agentrepo",
        },
    )
    SESSION_CONTEXTS.set_project_binaries(
        session_id,
        [
            {"name": "ls", "path": "/ls", "type": "Program"},
            {"name": "test_x86_64", "path": "/test_x86_64", "type": "Program"},
        ],
    )

    try:
        response = await provider._handle_list({})
        payload = json.loads(response[0].text)
        assert payload.get("source") == "shared-server-session"
        assert payload.get("count") == 2
        assert payload.get("folder") == "/"
        paths = [f["path"] for f in payload.get("files", [])]
        assert "/ls" in paths
        assert "/test_x86_64" in paths
    finally:
        SESSION_CONTEXTS.set_project_handle(session_id, None)
        SESSION_CONTEXTS.set_project_binaries(session_id, [])


@pytest.mark.asyncio
async def test_list_project_files_shared_mode_empty_repo_returns_shared_server_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When session is shared but repo has no binaries, list-project-files still returns source=shared-server-session."""
    session_id = "test-shared-flow-empty"
    provider = ProjectToolProvider()

    monkeypatch.setattr(project_provider_module, "get_current_mcp_session_id", lambda: session_id)
    SESSION_CONTEXTS.set_project_handle(
        session_id,
        {"mode": "shared-server", "server_host": "127.0.0.1", "repository_name": "agentrepo"},
    )
    SESSION_CONTEXTS.set_project_binaries(session_id, [])

    try:
        response = await provider._handle_list({})
        payload = json.loads(response[0].text)
        assert payload.get("source") == "shared-server-session"
        assert payload.get("count") == 0
        assert "note" in payload
    finally:
        SESSION_CONTEXTS.set_project_handle(session_id, None)
        SESSION_CONTEXTS.set_project_binaries(session_id, [])


# -----------------------------------------------------------------------------
# open(shared) routes to connect-shared and sets shared session
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_open_with_shared_and_server_host_routes_to_connect_shared(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """open(shared=true, serverHost=...) must route to _handle_connect_shared_project, not local open."""
    provider = ProjectToolProvider()
    connect_called: list[dict[str, Any]] = []

    async def _fake_connect(args: dict[str, Any]) -> list[Any]:
        connect_called.append(dict(args))
        return project_provider_module.create_success_response(
            {
                "action": "connect-shared-project",
                "mode": "shared-server",
                "repository": args.get("path") or "agentrepo",
                "programCount": 0,
            }
        )

    monkeypatch.setattr(provider, "_handle_connect_shared_project", _fake_connect)

    response = await provider._handle_open_project(
        {
            "shared": True,
            "path": "agentrepo",
            "serverHost": "ghidra",
            "serverPort": 13100,
            "serverUsername": "ghidra",
            "serverPassword": "admin",
        }
    )
    payload = json.loads(response[0].text)

    assert len(connect_called) == 1
    # Args may be camelCase (direct call) or normalized (via call_tool)
    connect_args = connect_called[0]
    assert (connect_args.get("serverHost") or connect_args.get("serverhost")) == "ghidra"
    assert (connect_args.get("path")) == "agentrepo"
    assert payload.get("mode") == "shared-server"
    assert payload.get("action") == "connect-shared-project"
