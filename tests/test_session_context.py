from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

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
