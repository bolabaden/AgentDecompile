from __future__ import annotations

from agentdecompile_cli.mcp_server.session_context import SessionContextStore


def test_get_project_binaries_returns_session_specific_first() -> None:
    store = SessionContextStore()
    store.set_project_binaries("session-a", [{"name": "A", "path": "/A"}])
    store.set_project_binaries("session-b", [{"name": "B", "path": "/B"}])

    binaries = store.get_project_binaries("session-a", fallback_to_latest=True)

    assert binaries == [{"name": "A", "path": "/A"}]


def test_get_project_binaries_falls_back_to_latest_when_enabled() -> None:
    store = SessionContextStore()
    store.set_project_binaries("session-open", [{"name": "prog", "path": "/prog"}])

    binaries = store.get_project_binaries("session-list", fallback_to_latest=True)

    assert binaries == [{"name": "prog", "path": "/prog"}]


def test_get_project_binaries_does_not_fallback_by_default() -> None:
    store = SessionContextStore()
    store.set_project_binaries("session-open", [{"name": "prog", "path": "/prog"}])

    binaries = store.get_project_binaries("session-list")

    assert binaries == []
