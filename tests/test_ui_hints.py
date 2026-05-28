from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import agentdecompile_cli.mcp_server.program_metadata as program_metadata


def _patch_session(monkeypatch: pytest.MonkeyPatch, fake_session: SimpleNamespace, *, shared: bool = False) -> None:
    monkeypatch.setattr(program_metadata.SESSION_CONTEXTS, "get_or_create", lambda _session_id: fake_session)
    monkeypatch.setattr(program_metadata, "is_shared_server_handle", lambda handle: shared and bool(handle))


@pytest.mark.unit
def test_attach_ui_hints_on_successful_mutating_tool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_session = SimpleNamespace(
        project_handle={"mode": "local", "path": "/tmp/proj.gpr"},
        open_programs={},
        active_program_key=None,
        project_binaries=[],
    )
    _patch_session(monkeypatch, fake_session)
    payload: dict = {"action": "set", "success": True}

    program_metadata.attach_ui_hints_to_payload(
        payload,
        "session-1",
        tool_name_normalized="managecomments",
        auto_checkin_enabled=False,
    )

    assert payload["uiVisibility"]["liveInCodeBrowser"] is False
    assert payload["uiVisibility"]["persistence"] == "local-save"
    assert "CodeBrowser" in payload["guiHint"]
    assert "checkin-program" in payload["guiHint"]


@pytest.mark.unit
def test_attach_ui_hints_uses_shared_persistence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_session = SimpleNamespace(
        project_handle={"mode": "shared-server", "server_host": "127.0.0.1"},
        open_programs={},
        active_program_key=None,
        project_binaries=[],
    )
    _patch_session(monkeypatch, fake_session, shared=True)
    payload: dict = {"success": True}

    program_metadata.attach_ui_hints_to_payload(
        payload,
        "session-1",
        tool_name_normalized="managesymbols",
        auto_checkin_enabled=True,
    )

    assert payload["uiVisibility"]["persistence"] == "shared-checkin"
    assert payload["uiVisibility"]["autoCheckinEnabled"] is True
    assert "Auto-checkin is enabled" in payload["guiHint"]


@pytest.mark.unit
def test_attach_ui_hints_skips_read_only_tool() -> None:
    payload: dict = {"functions": [], "count": 0}

    program_metadata.attach_ui_hints_to_payload(
        payload,
        "session-1",
        tool_name_normalized="listfunctions",
    )

    assert "uiVisibility" not in payload
    assert "guiHint" not in payload


@pytest.mark.unit
def test_attach_ui_hints_skips_modification_conflict() -> None:
    payload: dict = {"success": False, "modificationConflict": True, "conflictId": "abc"}

    program_metadata.attach_ui_hints_to_payload(
        payload,
        "session-1",
        tool_name_normalized="managecomments",
    )

    assert "uiVisibility" not in payload


@pytest.mark.unit
def test_inject_ui_hints_round_trip() -> None:
    original = json.dumps({"action": "rename", "success": True})
    injected = program_metadata.inject_ui_hints(
        original,
        "session-1",
        tool_name_normalized="managefunction",
        auto_checkin_enabled=False,
    )

    data = json.loads(injected)
    assert "uiVisibility" in data
    assert "guiHint" in data


@pytest.mark.unit
def test_attach_ui_hints_skips_enum_list_action() -> None:
    payload: dict = {"action": "list", "enums": [], "count": 0}

    program_metadata.attach_ui_hints_to_payload(
        payload,
        "session-1",
        tool_name_normalized="manageenums",
    )

    assert "uiVisibility" not in payload
    assert "guiHint" not in payload


@pytest.mark.unit
def test_attach_ui_hints_on_enum_create_action(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_session = SimpleNamespace(
        project_handle={"mode": "local", "path": "/tmp/proj.gpr"},
        open_programs={},
        active_program_key=None,
        project_binaries=[],
    )
    _patch_session(monkeypatch, fake_session)
    payload: dict = {"action": "create", "success": True}

    program_metadata.attach_ui_hints_to_payload(
        payload,
        "session-1",
        tool_name_normalized="manageenums",
    )

    assert "uiVisibility" in payload
    assert "guiHint" in payload


@pytest.mark.unit
def test_payload_has_mutating_action_enum_list() -> None:
    assert program_metadata.payload_has_mutating_action("manageenums", {"action": "list"}) is False
    assert program_metadata.payload_has_mutating_action("manageenums", {"action": "create"}) is True


@pytest.mark.unit
def test_inject_ui_hints_leaves_non_json_unchanged() -> None:
    text = "not json"
    assert program_metadata.inject_ui_hints(text, "session-1", tool_name_normalized="managecomments") == text
