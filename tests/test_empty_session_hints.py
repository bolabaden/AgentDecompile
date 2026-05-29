from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, cast

import pytest

from agentdecompile_cli.mcp_server.providers.project import ProjectToolProvider
from agentdecompile_cli.mcp_server.response_formatter import (
    enrich_empty_session_payload,
    payload_indicates_empty_session,
    render_tool_response,
)


@pytest.mark.unit
def test_payload_indicates_empty_session_for_no_project_loaded_note() -> None:
    payload = {"action": "list", "files": [], "count": 0, "note": "No project loaded"}
    assert payload_indicates_empty_session(payload) is True


@pytest.mark.unit
def test_payload_indicates_empty_session_for_get_current_program() -> None:
    payload = {"loaded": False, "availablePrograms": [], "availableCount": 0}
    assert payload_indicates_empty_session(payload) is True


@pytest.mark.unit
def test_payload_indicates_empty_session_false_when_programs_available() -> None:
    payload = {"loaded": False, "availablePrograms": ["/repo/a.exe"], "availableCount": 1}
    assert payload_indicates_empty_session(payload) is False


@pytest.mark.unit
def test_enrich_empty_session_payload_adds_bootstrap_fields() -> None:
    payload = enrich_empty_session_payload(
        {"action": "list", "files": [], "count": 0, "note": "No project loaded"},
    )
    assert payload["sessionEmpty"] is True
    assert "sessionHint" in payload
    assert len(payload["nextSteps"]) >= 4
    assert any("import-binary" in step for step in payload["nextSteps"])


@pytest.mark.unit
def test_render_tool_response_includes_bootstrap_next_steps_for_empty_list() -> None:
    payload = enrich_empty_session_payload(
        {"action": "list", "files": [], "count": 0, "note": "No project loaded"},
    )
    rendered = render_tool_response("listprojectfiles", payload)
    assert "### Suggested Next Steps" in rendered
    assert "import-binary" in rendered
    assert "connect-shared-project" in rendered


@pytest.mark.unit
@pytest.mark.asyncio
async def test_list_project_files_empty_session_includes_bootstrap(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = ProjectToolProvider()
    provider._manager = cast(Any, SimpleNamespace(ghidra_project=None))
    provider.program_info = None

    async def _noop_ensure(_args: dict[str, Any]) -> None:
        return None

    monkeypatch.setattr(provider, "_ensure_program_loaded_for_stateless_request", _noop_ensure)
    monkeypatch.setattr(
        "agentdecompile_cli.mcp_server.providers.project.SESSION_CONTEXTS.get_project_binaries",
        lambda _sid, fallback_to_latest=False: [],
    )
    monkeypatch.setattr(
        "agentdecompile_cli.mcp_server.providers.project.SESSION_CONTEXTS.get_project_handle",
        lambda _sid: None,
    )

    result = await provider._handle_list({})
    payload = json.loads(result[0].text)

    assert payload.get("count") == 0
    assert payload.get("sessionEmpty") is True
    assert payload.get("nextSteps")
    assert any("open path=" in step or "import-binary" in step for step in payload["nextSteps"])


@pytest.mark.unit
@pytest.mark.asyncio
async def test_get_current_program_empty_session_includes_bootstrap(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = ProjectToolProvider()
    provider._manager = cast(Any, SimpleNamespace(ghidra_project=None))
    provider.program_info = None

    async def _noop_ensure(_args: dict[str, Any]) -> None:
        return None

    monkeypatch.setattr(provider, "_ensure_program_loaded_for_stateless_request", _noop_ensure)
    monkeypatch.setattr(
        "agentdecompile_cli.mcp_server.providers.project.SESSION_CONTEXTS.get_project_binaries",
        lambda _sid, fallback_to_latest=True: [],
    )

    result = await provider._handle_get_current_program({})
    payload = json.loads(result[0].text)

    assert payload.get("loaded") is False
    assert payload.get("sessionEmpty") is True
    assert payload.get("sessionHint")
    assert any("analyze-program" in step for step in payload.get("nextSteps", []))
