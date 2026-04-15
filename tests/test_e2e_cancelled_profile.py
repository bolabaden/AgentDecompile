from __future__ import annotations

import asyncio
import json
import httpx

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest

from tests.e2e_project_lifecycle_helpers import JsonRpcMcpSession, dump_jfr_recording, extract_jfr_jcmd_pid


pytestmark = [
    pytest.mark.e2e,
    pytest.mark.slow,
    pytest.mark.timeout(300),
]


def _tool_names(session: JsonRpcMcpSession) -> set[str]:
    return {str(tool.get("name", "")) for tool in session.list_tools()}


def _import_tool_name(session: JsonRpcMcpSession) -> str:
    tool_names = _tool_names(session)
    if "import-binary" in tool_names:
        return "import-binary"
    if "open" in tool_names:
        return "open"
    raise AssertionError(f"Expected import tool in advertised surface, got: {sorted(tool_names)}")


def _extract_project_file_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("files", "projectFiles", "items", "entries", "results"):
        value = payload.get(key)
        if isinstance(value, list):
            return [row for row in value if isinstance(row, dict)]
    return []


def _search_args() -> dict[str, Any]:
    return {
        "query": "cancelled_profile_probe_no_match",
        "scopes": ["functions", "symbols", "strings", "decompilation", "disassembly"],
        "limit": 5000,
        "perScopeLimit": 5000,
        "maxFunctionsScan": 5000,
        "maxInstructionsScan": 500000,
        "decompileTimeout": 1,
        "groupByFunction": False,
    }


def _profile_artifacts(profiled_live_artifacts: dict[str, Path]) -> dict[str, list[Path] | Path]:
    profile_dir = profiled_live_artifacts["profile_dir"]
    return {
        "prof": sorted(profile_dir.glob("*.prof")),
        "analysis_txt": sorted(profile_dir.glob("*.analysis.txt")),
        "analysis_json": sorted(profile_dir.glob("*.analysis.json")),
        "server_log": profiled_live_artifacts["server_log"],
        "jfr": profiled_live_artifacts["jfr_path"],
        "jfr_dump": profiled_live_artifacts["jfr_dump_path"],
    }


@asynccontextmanager
async def _async_mcp_session(base_url: str):
    from mcp.client.session import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    url = base_url.rstrip("/") + "/mcp/message"
    http_client = httpx.AsyncClient(timeout=300.0)
    async with streamable_http_client(url, http_client=http_client) as (read_stream, write_stream, _get_session_id):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            yield session


@pytest.fixture(scope="module")
def imported_stress_project(
    profiled_http_session: JsonRpcMcpSession,
    stress_binary_corpus: list[Path],
) -> dict[str, Any]:
    importer = _import_tool_name(profiled_http_session)
    imported_paths: list[str] = []
    for binary_path in stress_binary_corpus:
        profiled_http_session.call_tool_json(importer, {"path": str(binary_path)})
        imported_paths.append(str(binary_path))

    listing = profiled_http_session.call_tool_json("list-project-files", {})
    rows = _extract_project_file_rows(listing)
    return {
        "importer": importer,
        "imported_paths": imported_paths,
        "listing": listing,
        "rows": rows,
    }


def test_imports_predetermined_stress_corpus(imported_stress_project: dict[str, Any]) -> None:
    rows = imported_stress_project["rows"]
    assert imported_stress_project["importer"] in {"import-binary", "open"}
    assert len(imported_stress_project["imported_paths"]) >= 12
    visible_names = {str(row.get("name", "")) for row in rows}
    matched = 0
    for imported_path in imported_stress_project["imported_paths"]:
        if Path(imported_path).name in visible_names:
            matched += 1
    assert matched >= 6, json.dumps(imported_stress_project["listing"], indent=2, default=str)


@pytest.mark.asyncio
async def test_search_everything_client_cancellation_surfaces_cancelled(
    profiled_server_base_url: str,
    imported_stress_project: dict[str, Any],
) -> None:
    assert imported_stress_project["imported_paths"]
    async with _async_mcp_session(profiled_server_base_url) as session:
        task = asyncio.create_task(session.call_tool("search-everything", _search_args()))
        await asyncio.sleep(0.1)
        if task.done():
            pytest.fail("The heavy search completed before cancellation; increase corpus size or scope cost.")
        task.cancel()

        cancelled_message = ""
        try:
            await task
        except asyncio.CancelledError as exc:
            cancelled_message = str(exc) or exc.__class__.__name__
        except RuntimeError as exc:
            if "cancel" not in str(exc).lower():
                raise
            cancelled_message = str(exc)
        else:
            pytest.fail("Expected the in-flight search task to surface cancellation")

    assert "cancel" in cancelled_message.lower() or cancelled_message == "CancelledError"


def test_search_everything_emits_profile_and_jfr_artifacts(
    profiled_http_session: JsonRpcMcpSession,
    profiled_live_artifacts: dict[str, Path],
    imported_stress_project: dict[str, Any],
) -> None:
    assert imported_stress_project["imported_paths"]
    payload = profiled_http_session.call_tool_json("search-everything", _search_args())
    diagnostics = payload.get("scopeDiagnostics")
    assert isinstance(diagnostics, list) and diagnostics, json.dumps(payload, indent=2, default=str)
    decomp_diag = next((item for item in diagnostics if item.get("scope") == "decompilation"), None)
    assert decomp_diag is not None, json.dumps(payload, indent=2, default=str)
    assert int(decomp_diag.get("scannedFunctions", 0) or 0) > 0, json.dumps(payload, indent=2, default=str)

    artifacts = _profile_artifacts(profiled_live_artifacts)
    assert artifacts["server_log"].exists(), f"Missing server log at {artifacts['server_log']}"
    assert artifacts["prof"], f"Expected at least one .prof artifact in {profiled_live_artifacts['profile_dir']}"
    assert artifacts["analysis_txt"], f"Expected at least one .analysis.txt artifact in {profiled_live_artifacts['profile_dir']}"
    assert artifacts["analysis_json"], f"Expected at least one .analysis.json artifact in {profiled_live_artifacts['profile_dir']}"
    jfr_pid = extract_jfr_jcmd_pid(artifacts["server_log"])
    jfr_dump = dump_jfr_recording(jfr_pid, artifacts["jfr_dump"])
    assert jfr_dump.exists(), f"Expected JFR dump at {jfr_dump}"
    assert jfr_dump.stat().st_size > 0, f"Expected non-empty JFR dump at {jfr_dump}"