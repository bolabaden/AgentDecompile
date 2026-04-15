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