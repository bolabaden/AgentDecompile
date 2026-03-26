from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

from agentdecompile_cli.mcp_server.session_context import (
    CURRENT_MCP_SESSION_ID,
    SessionContextStore,
    get_current_mcp_session_id,
)


def test_get_project_binaries_returns_session_specific_first() -> None:
    store = SessionContextStore()
    store.set_project_binaries("session-a", [{"name": "A", "path": "/A"}])
    store.set_project_binaries("session-b", [{"name": "B", "path": "/B"}])

    binaries = store.get_project_binaries("session-a", fallback_to_latest=True)

    assert binaries == [{"name": "A", "path": "/A"}]


def test_get_project_binaries_ignores_fallback_for_session_isolation() -> None:
    store = SessionContextStore()
    store.set_project_binaries("session-open", [{"name": "prog", "path": "/prog"}])

    binaries = store.get_project_binaries("default", fallback_to_latest=True)

    assert binaries == []


def test_get_project_binaries_does_not_fallback_by_default() -> None:
    store = SessionContextStore()
    store.set_project_binaries("session-open", [{"name": "prog", "path": "/prog"}])

    binaries = store.get_project_binaries("session-list")

    assert binaries == []


class _FakeProgram:
    def __init__(self, name: str) -> None:
        self._name = name

    def getName(self) -> str:
        return self._name


def test_get_program_info_matches_exact_key() -> None:
    store = SessionContextStore()
    info = SimpleNamespace(program=_FakeProgram("k1_win_gog_swkotor.exe"))
    store.set_active_program_info("session-a", "/K1/k1_win_gog_swkotor.exe", cast(Any, info))

    resolved = store.get_program_info("session-a", "/K1/k1_win_gog_swkotor.exe")

    assert resolved is info


def test_get_program_info_matches_key_ignoring_leading_slash_and_case() -> None:
    store = SessionContextStore()
    info = SimpleNamespace(program=_FakeProgram("k1_win_gog_swkotor.exe"))
    store.set_active_program_info("session-a", "/K1/k1_win_gog_swkotor.exe", cast(Any, info))

    resolved = store.get_program_info("session-a", "k1/k1_WIN_GOG_SWKOTOR.exe")

    assert resolved is info


def test_get_program_info_matches_by_program_name() -> None:
    store = SessionContextStore()
    info = SimpleNamespace(program=_FakeProgram("k1_win_gog_swkotor.exe"))
    store.set_active_program_info("session-a", "/K1/k1_win_gog_swkotor.exe", cast(Any, info))

    resolved = store.get_program_info("session-a", "k1_win_gog_swkotor.exe")

    assert resolved is info


def test_get_or_create_rebinds_default_to_sdk_session_id() -> None:
    store = SessionContextStore()
    store.set_project_binaries("default", [{"name": "p.exe", "path": "/p.exe"}])
    ctx = store.get_or_create("550e8400-e29b-41d4-a716-446655440000")
    assert ctx.session_id == "550e8400-e29b-41d4-a716-446655440000"
    assert store.get_project_binaries("550e8400-e29b-41d4-a716-446655440000") == [
        {"name": "p.exe", "path": "/p.exe"},
    ]
    assert store.get_project_binaries("default", fallback_to_latest=False) == []


def test_get_current_mcp_session_id_returns_default_when_middleware_set_default() -> None:
    """Stable anonymous session: tools must not use sdk-session:object-id (breaks CLI persistence)."""
    token = CURRENT_MCP_SESSION_ID.set("default")
    try:
        assert get_current_mcp_session_id() == "default"
    finally:
        CURRENT_MCP_SESSION_ID.reset(token)


def test_canonicalize_program_path_matches_listing_case_insensitively() -> None:
    store = SessionContextStore()
    store.set_project_binaries(
        "s1",
        [{"name": "HOSTNAME.EXE", "path": "/HOSTNAME.EXE", "type": "Program"}],
    )
    assert store.canonicalize_program_path("s1", "/hostname.exe") == "/HOSTNAME.EXE"
    assert store.canonicalize_program_path("s1", "hostname.exe") == "/HOSTNAME.EXE"
