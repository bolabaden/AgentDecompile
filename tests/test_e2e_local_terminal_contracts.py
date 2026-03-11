from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

from pathlib import Path
from collections.abc import Generator
from typing import Any

import pytest

from tests.e2e_project_lifecycle_helpers import (
    JsonRpcMcpSession,
    build_local_server_env,
    extract_text_content,
    find_free_port,
    wait_for_server,
)


_EXPERIMENTAL_LOCAL_CONTRACTS_ENABLED = os.environ.get(
    "AGENTDECOMPILE_ENABLE_EXPERIMENTAL_LOCAL_CONTRACTS",
    "",
).strip().lower() in {"1", "true", "yes", "on"}

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.slow,
    pytest.mark.skipif(
        not _EXPERIMENTAL_LOCAL_CONTRACTS_ENABLED,
        reason=(
            "Experimental terminal-validated local contract suite is disabled by default. "
            "Enable with AGENTDECOMPILE_ENABLE_EXPERIMENTAL_LOCAL_CONTRACTS=1."
        ),
    ),
]

KNOWN_FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "test_x86_64"
KNOWN_FIXTURE_NAME = KNOWN_FIXTURE_PATH.name
KNOWN_ENTRY_ADDRESS = "1000004b0"
DEFAULT_HTTP_ADVERTISED_TOOLS = [
    "analyze_data_flow",
    "analyze_program",
    "analyze_vtables",
    "apply_data_type",
    "change_processor",
    "checkin_program",
    "checkout_program",
    "checkout_status",
    "create_label",
    "decompile_function",
    "sync_project",
    "export",
    "get_call_graph",
    "remove_program_binary",
    "get_current_program",
    "get_data",
    "get_references",
    "import_binary",
    "inspect_memory",
    "list_cross_references",
    "list_exports",
    "list_functions",
    "list_imports",
    "list_project_files",
    "list_processors",
    "list_strings",
    "manage_function_tags",
    "match_function",
    "execute_script",
    "open_project",
    "read_bytes",
    "search_code",
    "search_constants",
    "search_everything",
    "search_strings",
    "search_symbols",
]


@pytest.fixture(scope="module")
def terminal_style_local_server(tmp_path_factory: pytest.TempPathFactory) -> Generator[str, None, None]:
    workspace = tmp_path_factory.mktemp("terminal-style-local-server")
    project_path = workspace / "runtime_project"
    project_path.mkdir(parents=True, exist_ok=True)
    port = find_free_port()
    server_executable = shutil.which("agentdecompile-server") or shutil.which("agentdecompile-server.exe")

    env = build_local_server_env(project_path)
    for key in [
        "AGENT_DECOMPILE_BACKEND_URL",
        "AGENT_DECOMPILE_MCP_SERVER_URL",
        "AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME",
        "AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD",
        "AGENT_DECOMPILE_GHIDRA_SERVER_HOST",
        "AGENT_DECOMPILE_GHIDRA_SERVER_PORT",
        "AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY",
    ]:
        env.pop(key, None)

    if server_executable:
        command = [
            server_executable,
            "-t",
            "streamable-http",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--project-path",
            str(project_path),
            "--project-name",
            "terminal_contracts",
        ]
    else:
        command = [
            sys.executable,
            "-m",
            "agentdecompile_cli.server",
            "-t",
            "streamable-http",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--project-path",
            str(project_path),
            "--project-name",
            "terminal_contracts",
        ]

    process = subprocess.Popen(
        command,
        cwd=str(Path(__file__).resolve().parents[1]),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    base_url = f"http://127.0.0.1:{port}"
    wait_for_server(base_url, process, timeout=120.0)

    yield base_url

    process.terminate()
    try:
        process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=10)


@pytest.fixture(scope="module")
def local_contract_snapshot(
    terminal_style_local_server: str,
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[str, Any]:
    export_path = tmp_path_factory.mktemp("local-contract-export") / "test_program.html"

    with JsonRpcMcpSession(terminal_style_local_server, timeout=120.0) as session:
        tools = session.list_tools()
        open_payload = session.call_tool_json("open-project", {"path": str(KNOWN_FIXTURE_PATH)})
        switch_payload = session.call_tool_json("switch-project", {"path": str(KNOWN_FIXTURE_PATH)})
        import_payload = session.call_tool_json("import-binary", {"path": str(KNOWN_FIXTURE_PATH)})
        listing_payload = session.call_tool_json("list-project-files", {})
        current_payload = session.call_tool_json("get-current-program", {})
        checkout_payload = session.call_tool_json("checkout-status", {})
        comment_get_before = session.call_tool_json(
            "manage-comments",
            {"mode": "get", "addressOrSymbol": KNOWN_ENTRY_ADDRESS},
        )
        comment_set = session.call_tool_json(
            "manage-comments",
            {
                "mode": "set",
                "addressOrSymbol": KNOWN_ENTRY_ADDRESS,
                "type": "plate",
                "comment": "terminal plate comment",
            },
        )
        comment_get_after_set = session.call_tool_json(
            "manage-comments",
            {"mode": "get", "addressOrSymbol": KNOWN_ENTRY_ADDRESS},
        )
        comment_search = session.call_tool_json(
            "manage-comments",
            {"mode": "search", "query": "terminal plate"},
        )
        script_read_after_set = session.call_tool_json(
            "execute-script",
            {
                "code": (
                    "f = currentProgram.getFunctionManager().getFunctionAt(toAddr('1000004b0'))\n"
                    "__result__ = f.getComment()"
                )
            },
        )
        comment_remove = session.call_tool_json(
            "manage-comments",
            {"mode": "remove", "addressOrSymbol": KNOWN_ENTRY_ADDRESS, "type": "plate"},
        )
        comment_get_after_remove = session.call_tool_json(
            "manage-comments",
            {"mode": "get", "addressOrSymbol": KNOWN_ENTRY_ADDRESS},
        )
        script_read_after_remove = session.call_tool_json(
            "execute-script",
            {
                "code": (
                    "f = currentProgram.getFunctionManager().getFunctionAt(toAddr('1000004b0'))\n"
                    "__result__ = f.getComment()"
                )
            },
        )
        export_text = _tool_text(
            session,
            "export",
            {"format": "html", "outputPath": str(export_path)},
        )

    return {
        "tool_names": [tool["name"] for tool in tools],
        "open_payload": open_payload,
        "switch_payload": switch_payload,
        "import_payload": import_payload,
        "listing_payload": listing_payload,
        "current_payload": current_payload,
        "checkout_payload": checkout_payload,
        "comment_get_before": comment_get_before,
        "comment_set": comment_set,
        "comment_get_after_set": comment_get_after_set,
        "comment_search": comment_search,
        "script_read_after_set": script_read_after_set,
        "comment_remove": comment_remove,
        "comment_get_after_remove": comment_get_after_remove,
        "script_read_after_remove": script_read_after_remove,
        "export_text": export_text,
        "export_path": export_path,
    }


def _normalize_text(text: str) -> str:
    return text.replace("\r\n", "\n").strip()


def _tool_text(session: JsonRpcMcpSession, name: str, arguments: dict[str, object]) -> str:
    return _normalize_text(extract_text_content(session.call_tool(name, arguments)))


def _open_known_fixture(session: JsonRpcMcpSession) -> dict[str, object]:
    return session.call_tool_json("open-project", {"path": str(KNOWN_FIXTURE_PATH)})


def test_live_local_default_advertised_tool_surface_matches_terminal_contract(
    local_contract_snapshot: dict[str, Any],
) -> None:
    tool_names = local_contract_snapshot["tool_names"]

    assert tool_names == DEFAULT_HTTP_ADVERTISED_TOOLS
    assert len(tool_names) == 36
    assert "manage-comments" not in tool_names
    assert "switch-project" not in tool_names
    assert "open_project" in tool_names
    assert "import_binary" in tool_names
    assert "sync_project" in tool_names
    assert "change_processor" in tool_names


def test_live_local_open_switch_import_and_listing_contracts(
    local_contract_snapshot: dict[str, Any],
) -> None:
    open_payload = local_contract_snapshot["open_payload"]
    switch_payload = local_contract_snapshot["switch_payload"]
    import_payload = local_contract_snapshot["import_payload"]
    listing_payload = local_contract_snapshot["listing_payload"]
    current_payload = local_contract_snapshot["current_payload"]

    expected_open = {
        "operation": "import",
        "importedFrom": str(KNOWN_FIXTURE_PATH),
        "filesDiscovered": 1,
        "filesImported": 1,
        "importedPrograms": [{"path": str(KNOWN_FIXTURE_PATH), "programName": KNOWN_FIXTURE_NAME}],
        "groupsCreated": 0,
        "maxDepthUsed": 16,
        "wasRecursive": False,
        "analysisRequested": False,
        "errors": [],
    }
    expected_import = {
        "action": "import",
        "importedFrom": str(KNOWN_FIXTURE_PATH),
        "filesDiscovered": 1,
        "filesImported": 1,
        "importedPrograms": [{"sourcePath": str(KNOWN_FIXTURE_PATH), "programName": KNOWN_FIXTURE_NAME}],
        "groupsCreated": 0,
        "maxDepthUsed": 16,
        "wasRecursive": False,
        "analysisRequested": False,
        "language": None,
        "compiler": None,
        "success": True,
        "errors": [],
    }

    assert open_payload == expected_open
    assert switch_payload == expected_open
    assert import_payload == expected_import
    assert listing_payload == {
        "folder": "/",
        "files": [
            {
                "name": KNOWN_FIXTURE_NAME,
                "path": f"/{KNOWN_FIXTURE_NAME}",
                "isDirectory": False,
                "type": "Program",
            }
        ],
        "count": 1,
        "source": "session-binaries",
    }
    assert current_payload == {
        "loaded": True,
        "name": KNOWN_FIXTURE_NAME,
        "programPath": f"/{KNOWN_FIXTURE_NAME}",
        "language": "x86:LE:64:default",
        "compiler": "gcc",
        "functionCount": 3,
    }


def test_live_local_manage_comments_round_trip_and_export_contracts(
    local_contract_snapshot: dict[str, Any],
) -> None:
    checkout_payload = local_contract_snapshot["checkout_payload"]
    comment_get_before = local_contract_snapshot["comment_get_before"]
    comment_set = local_contract_snapshot["comment_set"]
    comment_get_after_set = local_contract_snapshot["comment_get_after_set"]
    comment_search = local_contract_snapshot["comment_search"]
    script_read_after_set = local_contract_snapshot["script_read_after_set"]
    comment_remove = local_contract_snapshot["comment_remove"]
    comment_get_after_remove = local_contract_snapshot["comment_get_after_remove"]
    script_read_after_remove = local_contract_snapshot["script_read_after_remove"]
    export_text = local_contract_snapshot["export_text"]
    export_path = local_contract_snapshot["export_path"]

    expected_export_text = _normalize_text(
        (
            "## Export Results\n\n"
            "**Format:** html\n"
            f"**Output Path:** `{export_path}`\n"
            "**Status:** Success\n\n"
            "### About This Tool\n\n"
            "Exports analysis results in various formats (C/C++, GZF, SARIF, XML, HTML).\n\n"
            "### Suggested Next Steps\n\n"
            "1. Export complete. The file is saved to the specified output path."
        )
    )

    assert checkout_payload == {
        "action": "checkout_status",
        "program": KNOWN_FIXTURE_NAME,
        "is_versioned": False,
        "is_checked_out": False,
        "is_exclusive": False,
        "modified_since_checkout": False,
        "can_checkout": False,
        "can_checkin": False,
        "latest_version": None,
        "current_version": None,
        "checkout_status": None,
        "versionControlEnabled": False,
        "note": "Program is local-only. Shared checkout/checkin is unavailable until the program exists in a shared Ghidra repository.",
    }
    assert comment_get_before == {"action": "get", "address": KNOWN_ENTRY_ADDRESS, "comments": {}}
    assert comment_set == {
        "action": "set",
        "address": KNOWN_ENTRY_ADDRESS,
        "type": "plate",
        "comment": "terminal plate comment",
        "success": True,
    }
    assert comment_get_after_set == {
        "action": "get",
        "address": KNOWN_ENTRY_ADDRESS,
        "comments": {"plate": "terminal plate comment"},
    }
    assert comment_search == {
        "results": [{"address": KNOWN_ENTRY_ADDRESS, "type": "plate", "comment": "terminal plate comment"}],
        "count": 1,
        "total": 1,
        "hasMore": False,
        "offset": 0,
        "limit": 100,
        "query": "terminal plate",
        "mode": "search",
    }
    assert script_read_after_set == {"success": True, "result": "terminal plate comment"}
    assert comment_remove == {
        "action": "remove",
        "address": KNOWN_ENTRY_ADDRESS,
        "type": "plate",
        "success": True,
    }
    assert comment_get_after_remove == {"action": "get", "address": KNOWN_ENTRY_ADDRESS, "comments": {}}
    assert script_read_after_remove == {"success": True, "result": "None"}
    assert export_text == expected_export_text
    assert export_path.exists()
    assert json.loads(export_path.read_text(encoding="utf-8")) == {
        "name": KNOWN_FIXTURE_NAME,
        "address": "100000000",
        "language": "x86:LE:64:default",
        "compiler": "gcc",
        "functionCount": 3,
        "format": "html",
    }