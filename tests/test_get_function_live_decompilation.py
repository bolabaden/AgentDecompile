from __future__ import annotations

import json
import os

from pathlib import Path
from typing import Any, Generator

import pytest

from tests.e2e_project_lifecycle_helpers import JsonRpcMcpSession, LocalServerPool, find_project_file


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


def _find_imported_program_path(session: JsonRpcMcpSession, binary_path: Path) -> str:
    listing = session.call_tool_json("list-project-files", {})
    rows = _extract_project_file_rows(listing)
    row = find_project_file(rows, name=binary_path.name)
    assert row is not None, json.dumps(listing, indent=2, default=str)
    program_path = str(row.get("path") or "")
    assert program_path, json.dumps(row, indent=2, default=str)
    return program_path


def _analyze_if_available(session: JsonRpcMcpSession, program_path: str) -> None:
    if "analyze-program" not in _tool_names(session):
        return
    session.call_tool_json("analyze-program", {"programPath": program_path})


@pytest.fixture(scope="module")
def live_get_function_server(
    request: pytest.FixtureRequest,
    tmp_path_factory: pytest.TempPathFactory,
    local_live_server_pool: LocalServerPool,
) -> Generator[str, None, None]:
    external = os.environ.get("AGENTDECOMPILE_TEST_SERVER_URL", "").strip()
    if external:
        yield external
        return

    module_name = request.module.__name__.rsplit(".", 1)[-1].replace("_", "-")
    workspace = tmp_path_factory.mktemp(f"{module_name}-workspace")
    project_path = workspace / "runtime_project"
    log_path = workspace / "live-server.log"
    handle = local_live_server_pool.get_or_start(
        f"{module_name}-extended-timeout",
        project_path=project_path,
        project_name=module_name,
        timeout=240.0,
        log_path=log_path,
    )
    yield handle.base_url


@pytest.fixture(scope="module")
def live_get_function_session(live_get_function_server: str) -> Generator[JsonRpcMcpSession, None, None]:
    with JsonRpcMcpSession(live_get_function_server, timeout=180.0) as session:
        yield session


@pytest.fixture
def hello_world_binary(isolated_workspace: Path) -> Path:
    from tests.helpers import _build_sourcedennis_x64_binary

    binary_path = isolated_workspace / "sourcedennis_small_hello_world_x64"
    binary_path.write_bytes(_build_sourcedennis_x64_binary())
    binary_path.chmod(0o755)
    return binary_path


def test_get_function_live_decompilation_uses_working_decompiler(
    live_get_function_session: JsonRpcMcpSession,
    hello_world_binary: Path,
) -> None:
    importer = _import_tool_name(live_get_function_session)
    live_get_function_session.call_tool_json(importer, {"path": str(hello_world_binary)})

    program_path = _find_imported_program_path(live_get_function_session, hello_world_binary)
    _analyze_if_available(live_get_function_session, program_path)

    probe = live_get_function_session.call_tool_json(
        "execute-script",
        {
            "programPath": program_path,
            "code": (
                "import json\n"
                "selected = None\n"
                "fallback = None\n"
                "for func in currentProgram.getFunctionManager().getFunctions(True):\n"
                "    entry = str(func.getEntryPoint())\n"
                "    size = int(func.getBody().getNumAddresses())\n"
                "    candidate = {'entry': entry, 'name': func.getName(), 'size': size}\n"
                "    if fallback is None:\n"
                "        fallback = candidate\n"
                "    if size > 1:\n"
                "        selected = candidate\n"
                "        break\n"
                "if selected is None:\n"
                "    selected = fallback\n"
                "__result__ = json.dumps(selected)\n"
            ),
        },
    )

    function_info = probe.get("result")
    if isinstance(function_info, str):
        function_info = json.loads(function_info)
    assert isinstance(function_info, dict), json.dumps(probe, indent=2, default=str)
    function_entry = str(function_info.get("entry") or "")
    assert function_entry, json.dumps(function_info, indent=2, default=str)

    payload = live_get_function_session.call_tool_json(
        "get-function",
        {
            "programPath": program_path,
            "addressOrSymbol": function_entry,
        },
    )

    decompilation = str(payload.get("decompilation") or "")
    assert decompilation, json.dumps(payload, indent=2, default=str)
    assert "[decompilation unavailable:" not in decompilation, json.dumps(payload, indent=2, default=str)
    assert "Failed to open DecompInterface" not in decompilation, json.dumps(payload, indent=2, default=str)
    assert str(payload.get("address") or "") == function_entry