from __future__ import annotations

from types import SimpleNamespace

import pytest

import agentdecompile_cli.mcp_server.program_metadata as program_metadata

from agentdecompile_cli.mcp_server.response_formatter import render_tool_response


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

    monkeypatch.setattr(program_metadata.SESSION_CONTEXTS, "get_or_create", lambda _session_id: fake_session)
    monkeypatch.setattr(program_metadata, "is_shared_server_handle", lambda handle: bool(handle))

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
            "targetPrograms": ["/K1/k1_win_gog_swkotor.exe"],
            "results": [
                {
                    "resultType": "structure",
                    "name": "CResTGA",
                    "program": "/K1/k1_win_gog_swkotor.exe",
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
                    "program": "/K1/k1_win_gog_swkotor.exe",
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
    assert "**Where:** Data type definition only; no concrete memory address for the type itself | program `/K1/k1_win_gog_swkotor.exe` | category `/Res`" in rendered
    assert "**Fields:** width@0x0:uint32, height@0x4:uint32, format@0x8:uint32" in rendered
    assert "**Used By:** 2 inbound reference(s) | 0x402000 in LoadTexture (DATA)" in rendered
    assert "#### 2. class CResDDS" in rendered
    assert "**What:** source ANALYSIS | mirrors structure `CResDDS` (80 bytes, 2 fields)" in rendered
    assert "**Follow Up:** `get-references address=0x405000 mode=to`" in rendered