from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import agentdecompile_cli.mcp_server.program_metadata as program_metadata

from agentdecompile_cli.mcp_server.response_formatter import render_tool_response
from agentdecompile_cli.mcp_server.tool_providers import create_error_response


def _patch_collect_context_session(
    monkeypatch: pytest.MonkeyPatch,
    fake_session: SimpleNamespace,
    *,
    shared: bool = False,
) -> None:
    monkeypatch.setattr(program_metadata.SESSION_CONTEXTS, "get_or_create", lambda _session_id: fake_session)
    monkeypatch.setattr(program_metadata, "is_shared_server_handle", lambda handle: shared and bool(handle))


@pytest.mark.unit
def test_collect_project_context_includes_analysis_complete_for_active_program(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_session = SimpleNamespace(
        project_handle={"mode": "local", "path": "/tmp/proj.gpr"},
        open_programs={
            "/bin/a.exe": SimpleNamespace(ghidra_analysis_complete=True),
            "/bin/b.exe": SimpleNamespace(ghidra_analysis_complete=False),
        },
        active_program_key="/bin/a.exe",
        project_binaries=[],
    )
    _patch_collect_context_session(monkeypatch, fake_session)

    context = program_metadata.collect_project_context("session-1")

    assert context is not None
    assert context["analysisComplete"] is True
    assert context["analysisByProgram"] == {
        "/bin/a.exe": True,
        "/bin/b.exe": False,
    }


@pytest.mark.unit
def test_collect_project_context_includes_checkout_summary_in_shared_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checked_out_df = SimpleNamespace(
        isCheckedOut=lambda: True,
        modifiedSinceCheckout=lambda: True,
        canCheckin=lambda: True,
    )
    read_only_df = SimpleNamespace(
        isCheckedOut=lambda: False,
        modifiedSinceCheckout=lambda: False,
        canCheckin=lambda: False,
    )
    fake_session = SimpleNamespace(
        project_handle={
            "mode": "shared-server",
            "server_host": "127.0.0.1",
            "server_port": 13100,
            "repository_name": "Repo",
        },
        open_programs={
            "/repo/a.exe": SimpleNamespace(domain_file=checked_out_df),
            "/repo/b.exe": SimpleNamespace(domain_file=read_only_df),
        },
        active_program_key="/repo/a.exe",
        project_binaries=[],
    )
    _patch_collect_context_session(monkeypatch, fake_session, shared=True)

    context = program_metadata.collect_project_context("session-1")

    assert context is not None
    assert context["checkoutSummary"] == {
        "checkedOutCount": 1,
        "modifiedCount": 1,
        "canCheckinCount": 1,
        "programs": [
            {
                "program": "/repo/a.exe",
                "isCheckedOut": True,
                "modifiedSinceCheckout": True,
                "canCheckin": True,
            },
        ],
    }


@pytest.mark.unit
def test_create_error_response_includes_project_context_when_programs_loaded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_session = SimpleNamespace(
        project_handle={"mode": "local", "path": "/tmp/proj.gpr"},
        open_programs={
            "/bin/a.exe": SimpleNamespace(ghidra_analysis_complete=True),
        },
        active_program_key="/bin/a.exe",
        project_binaries=[],
    )
    _patch_collect_context_session(monkeypatch, fake_session)

    response = create_error_response("Program not found", session_id="session-err")
    payload = json.loads(response[0].text)

    assert payload["success"] is False
    assert payload["error"] == "Program not found"
    assert payload["projectContext"]["activeProgram"] == "/bin/a.exe"
    assert payload["projectContext"]["analysisComplete"] is True


@pytest.mark.unit
def test_create_error_response_omits_project_context_when_session_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    empty_session = SimpleNamespace(
        project_handle=None,
        open_programs={},
        active_program_key=None,
        project_binaries=[],
    )
    _patch_collect_context_session(monkeypatch, empty_session)

    payload = json.loads(create_error_response("Unknown tool", session_id="empty")[0].text)

    assert payload["success"] is False
    assert "projectContext" not in payload


@pytest.mark.unit
def test_create_error_response_skips_project_context_for_debuginfo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_session = SimpleNamespace(
        project_handle={"mode": "local", "path": "/tmp/proj.gpr"},
        open_programs={
            "/bin/a.exe": SimpleNamespace(ghidra_analysis_complete=True),
        },
        active_program_key="/bin/a.exe",
        project_binaries=[],
    )
    _patch_collect_context_session(monkeypatch, fake_session)

    payload = json.loads(
        create_error_response(
            "debug failed",
            session_id="session-err",
            tool_name_normalized="debuginfo",
        )[0].text,
    )

    assert "projectContext" not in payload


@pytest.mark.unit
def test_collect_project_context_uses_project_inventory_over_open_programs(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_session = SimpleNamespace(
        project_handle={
            "mode": "shared-server",
            "server_host": "170.9.241.140",
            "server_port": 13100,
            "repository_name": "Odyssey",
        },
        open_programs={
            "/Other BioWare Engines/Aurora/nwmain.exe": object(),
            "/Other BioWare Engines/Aurora/nwserver.exe": object(),
            "/Other BioWare Engines/Aurora/toolset.exe": object(),
        },
        active_program_key="/Other BioWare Engines/Aurora/nwmain.exe",
        project_binaries=[
            {"path": f"/repo/program_{index}.exe"}
            for index in range(13)
        ],
    )

    _patch_collect_context_session(monkeypatch, fake_session, shared=True)

    context = program_metadata.collect_project_context("session-1")

    assert context is not None
    assert context["programCount"] == 13
    assert context["projectProgramCount"] == 13
    assert context["openProgramCount"] == 3
    assert context["openPrograms"] == [
        "/Other BioWare Engines/Aurora/nwmain.exe",
        "/Other BioWare Engines/Aurora/nwserver.exe",
        "/Other BioWare Engines/Aurora/toolset.exe",
    ]


@pytest.mark.unit
def test_render_tool_response_shows_project_open_and_search_coverage() -> None:
    rendered = render_tool_response(
        "searcheverything",
        {
            "count": 0,
            "total": 0,
            "offset": 0,
            "hasMore": False,
            "queries": ["aurora"],
            "searchMode": "literal",
            "scopes": ["functions"],
            "targetProgramCount": 3,
            "projectProgramCount": 13,
            "targetPrograms": [
                "/Other BioWare Engines/Aurora/nwmain.exe",
                "/Other BioWare Engines/Aurora/nwserver.exe",
                "/Other BioWare Engines/Aurora/toolset.exe",
            ],
            "skippedPrograms": [
                {"program": "/Other BioWare Engines/Aurora/nwhak.exe", "reason": "checkout failed"},
            ],
            "warnings": ["program '/Other BioWare Engines/Aurora/nwhak.exe': checkout failed"],
            "results": [],
            "projectContext": {
                "mode": "shared-server",
                "activeProgram": "/Other BioWare Engines/Aurora/nwmain.exe",
                "projectProgramCount": 13,
                "openProgramCount": 3,
                "serverHost": "170.9.241.140",
                "serverPort": 13100,
                "repository": "Odyssey",
            },
        },
    )

    assert "**Programs:** 3 searched / 13 in project" in rendered
    assert "### Skipped Programs" in rendered
    assert "/Other BioWare Engines/Aurora/nwhak.exe: checkout failed" in rendered
    assert "### Warnings" in rendered
    assert "shared-server | active: `/Other BioWare Engines/Aurora/nwmain.exe` | 13 in project | 3 open | shared: 170.9.241.140:13100/Odyssey" in rendered


@pytest.mark.unit
def test_render_tool_response_search_everything_shows_detailed_result_context() -> None:
    rendered = render_tool_response(
        "searcheverything",
        {
            "count": 2,
            "total": 2,
            "offset": 0,
            "hasMore": False,
            "queries": ["CResTGA", "CResDDS"],
            "searchMode": "auto",
            "scopes": ["classes", "structures"],
            "targetProgramCount": 1,
            "projectProgramCount": 13,
            "targetPrograms": ["[REDACTED]"],
            "results": [
                {
                    "resultType": "structure",
                    "name": "CResTGA",
                    "program": "[REDACTED]",
                    "query": "CResTGA",
                    "matchType": "literal",
                    "score": 1.0,
                    "categoryPath": "/Res",
                    "length": 64,
                    "fieldCount": 3,
                    "fieldPreviewText": "width@0x0:uint32, height@0x4:uint32, format@0x8:uint32",
                    "addressNote": "Data type definition only; no concrete memory address for the type itself",
                    "referenceCount": 2,
                    "referencesPreview": [{"fromAddress": "0x402000", "function": "LoadTexture", "type": "DATA"}],
                    "relatedClasses": ["CResTGA"],
                    "nextTools": [{"tool": "manage-structures", "args": {"mode": "info", "name": "CResTGA"}}],
                },
                {
                    "resultType": "class",
                    "name": "CResDDS",
                    "program": "[REDACTED]",
                    "query": "CResDDS",
                    "matchType": "literal",
                    "score": 1.0,
                    "address": "0x405000",
                    "namespace": "global",
                    "source": "ANALYSIS",
                    "relatedStructure": "CResDDS",
                    "relatedStructureLength": 80,
                    "relatedStructureFieldCount": 2,
                    "relatedStructureFieldPreviewText": "header@0x0:DDSHeader, pixels@0x4:byte *",
                    "referenceCount": 1,
                    "referencesPreview": [{"fromAddress": "0x406000", "function": "CreateDDS", "type": "CALL"}],
                    "nextTools": [{"tool": "get-references", "args": {"address": "0x405000", "mode": "to"}}],
                },
            ],
        },
    )

    assert "**Breakdown:** 1 class, 1 structure" in rendered
    assert "#### 1. structure CResTGA" in rendered
    assert "**Where:** Data type definition only; no concrete memory address for the type itself | program `[REDACTED]` | category `/Res`" in rendered
    assert "**Fields:** width@0x0:uint32, height@0x4:uint32, format@0x8:uint32" in rendered
    assert "**Used By:** 2 inbound reference(s) | 0x402000 in LoadTexture (DATA)" in rendered
    assert "#### 2. class CResDDS" in rendered
    assert "**What:** source ANALYSIS | mirrors structure `CResDDS` (80 bytes, 2 fields)" in rendered
    assert "**Follow Up:** `get-references address=0x405000 mode=to`" in rendered
