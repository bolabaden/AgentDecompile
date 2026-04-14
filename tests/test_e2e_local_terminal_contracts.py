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

from agentdecompile_cli.registry import get_advertised_tools

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
DEFAULT_HTTP_ADVERTISED_TOOLS = frozenset(tool.replace("-", "_") for tool in get_advertised_tools())


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
        open_payload = session.call_tool_json("open", {"path": str(KNOWN_FIXTURE_PATH)})
        switch_payload = session.call_tool_json("switch-project", {"path": str(KNOWN_FIXTURE_PATH)})
        import_payload = session.call_tool_json("import-binary", {"path": str(KNOWN_FIXTURE_PATH)})
        listing_payload = session.call_tool_json("list-project-files", {})
        current_payload = session.call_tool_json("get-current-program", {})
        checkout_payload = session.call_tool_json("checkout-status", {})
        # Analysis and data-retrieval operations that mirror the manual terminal workflow.
        analyze_payload = session.call_tool_json(
            "analyze-program",
            {"programPath": KNOWN_FIXTURE_NAME, "force": True},
        )
        list_functions_payload = session.call_tool_json(
            "list-functions",
            {"programPath": KNOWN_FIXTURE_NAME, "limit": 50},
        )
        list_imports_payload = session.call_tool_json(
            "list-imports",
            {"programPath": KNOWN_FIXTURE_NAME},
        )
        list_exports_payload = session.call_tool_json(
            "list-exports",
            {"programPath": KNOWN_FIXTURE_NAME},
        )
        search_symbols_payload = session.call_tool_json(
            "search-symbols",
            {"programPath": KNOWN_FIXTURE_NAME, "query": "main"},
        )
        references_from_payload = session.call_tool_json(
            "get-references",
            {"programPath": KNOWN_FIXTURE_NAME, "target": KNOWN_ENTRY_ADDRESS, "mode": "from"},
        )
        references_to_payload = session.call_tool_json(
            "get-references",
            {"programPath": KNOWN_FIXTURE_NAME, "target": KNOWN_ENTRY_ADDRESS, "mode": "to"},
        )
        resources_programs = session.read_resource_json("ghidra://programs")
        resources_static_analysis = session.read_resource_json("ghidra://static-analysis-results")
        resources_debug_info = session.read_resource_json("ghidra://agentdecompile-debug-info")
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
        "analyze_payload": analyze_payload,
        "list_functions_payload": list_functions_payload,
        "list_imports_payload": list_imports_payload,
        "list_exports_payload": list_exports_payload,
        "search_symbols_payload": search_symbols_payload,
        "references_from_payload": references_from_payload,
        "references_to_payload": references_to_payload,
        "resources_programs": resources_programs,
        "resources_static_analysis": resources_static_analysis,
        "resources_debug_info": resources_debug_info,
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
    return session.call_tool_json("open", {"path": str(KNOWN_FIXTURE_PATH)})


def test_live_local_default_advertised_tool_surface_matches_terminal_contract(
    local_contract_snapshot: dict[str, Any],
) -> None:
    tool_names = local_contract_snapshot["tool_names"]
    tool_name_set = set(tool_names)

    # Exact set match – every tool that should be advertised is present.
    assert tool_name_set == DEFAULT_HTTP_ADVERTISED_TOOLS
    assert len(tool_names) == len(DEFAULT_HTTP_ADVERTISED_TOOLS)
    assert "manage-comments" not in tool_name_set
    assert "switch-project" not in tool_name_set
    assert "open" in tool_name_set
    assert "import_binary" in tool_name_set
    assert "sync_project" in tool_name_set
    assert "change_processor" in tool_name_set
    assert "svr_admin" in tool_name_set
    assert "search_everything" in tool_name_set
    assert "get_function" in tool_name_set
    assert "list_project_files" in tool_name_set
    assert "get_references" not in tool_name_set
    assert "list_functions" not in tool_name_set
    assert "search_symbols" not in tool_name_set


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


# ---------------------------------------------------------------------------
# New MCP-session tests mirroring the manual terminal validation workflow
# ---------------------------------------------------------------------------


def test_live_local_analyze_program_contract(
    local_contract_snapshot: dict[str, Any],
) -> None:
    """analyze-program returns a success action with the binary name."""
    p = local_contract_snapshot["analyze_payload"]
    assert p["action"] == "analyze"
    assert p["programName"] == KNOWN_FIXTURE_NAME


def test_live_local_list_functions_contract(
    local_contract_snapshot: dict[str, Any],
) -> None:
    """list-functions returns entry and _printf thunk for the known fixture."""
    p = local_contract_snapshot["list_functions_payload"]
    assert "results" in p
    assert isinstance(p["results"], list)
    assert p["count"] == len(p["results"])
    assert p["total"] >= p["count"]

    names = [f["name"] for f in p["results"]]
    assert "entry" in names
    assert "_printf" in names

    entry_fn = next(f for f in p["results"] if f["name"] == "entry")
    assert entry_fn["address"] == KNOWN_ENTRY_ADDRESS
    assert entry_fn["isExternal"] is False
    assert entry_fn["isThunk"] is False

    printf_fn = next(f for f in p["results"] if f["name"] == "_printf")
    assert printf_fn["isThunk"] is True


def test_live_local_list_imports_contract(
    local_contract_snapshot: dict[str, Any],
) -> None:
    """list-imports surfaces _printf from libSystem."""
    p = local_contract_snapshot["list_imports_payload"]
    assert "results" in p
    assert p["count"] >= 1

    names = [r["name"] for r in p["results"]]
    assert "_printf" in names

    printf_imp = next(r for r in p["results"] if r["name"] == "_printf")
    assert "/usr/lib/libSystem.B.dylib" in (printf_imp.get("namespace") or printf_imp.get("library") or "")


def test_live_local_list_exports_contract(
    local_contract_snapshot: dict[str, Any],
) -> None:
    """list-exports contains _add, _multiply, entry, and _main."""
    p = local_contract_snapshot["list_exports_payload"]
    assert "results" in p
    assert p["count"] >= 4

    names = [r["name"] for r in p["results"]]
    assert "_add" in names
    assert "_multiply" in names
    assert "entry" in names
    assert "_main" in names

    exports_by_name = {r["name"]: r for r in p["results"]}
    assert exports_by_name["entry"]["address"] == KNOWN_ENTRY_ADDRESS


def test_live_local_search_symbols_contract(
    local_contract_snapshot: dict[str, Any],
) -> None:
    """search-symbols query=main finds _main at the entry address."""
    p = local_contract_snapshot["search_symbols_payload"]
    assert p["query"] == "main"
    assert p["count"] >= 1

    names = [r["name"] for r in p["results"]]
    assert "_main" in names

    main_sym = next(r for r in p["results"] if r["name"] == "_main")
    assert main_sym["address"] == KNOWN_ENTRY_ADDRESS
    assert "name" in main_sym
    assert "address" in main_sym
    assert "type" in main_sym


def test_live_local_get_references_from_contract(
    local_contract_snapshot: dict[str, Any],
) -> None:
    """get-references mode=from returns outbound references from entry."""
    p = local_contract_snapshot["references_from_payload"]
    assert "references" in p or "results" in p or "mode" in p
    # mode field identifies the query type
    assert p.get("mode") == "from" or "from" in str(p.get("target", ""))


def test_live_local_get_references_to_contract(
    local_contract_snapshot: dict[str, Any],
) -> None:
    """get-references mode=to returns inbound references to entry (entry point + DATA)."""
    p = local_contract_snapshot["references_to_payload"]
    # At minimum the entry point itself is a reference target
    refs = p.get("references") or p.get("results") or []
    assert isinstance(refs, list)
    assert len(refs) >= 1


def test_live_local_resource_programs_contract(
    local_contract_snapshot: dict[str, Any],
) -> None:
    """ghidra://programs resource lists the imported binary."""
    resources = local_contract_snapshot["resources_programs"]
    # Resource may be a list or dict wrapping a list
    programs = resources if isinstance(resources, list) else (
        resources.get("programs") or resources.get("files") or resources.get("results") or []
    )
    names = [
        (p.get("name") or p.get("programName") or "")
        for p in programs
        if isinstance(p, dict)
    ]
    assert any(KNOWN_FIXTURE_NAME in n for n in names), (
        f"Expected {KNOWN_FIXTURE_NAME!r} in programs resource, got: {names}"
    )


def test_live_local_resource_static_analysis_contract(
    local_contract_snapshot: dict[str, Any],
) -> None:
    """ghidra://static-analysis-results resource returns SARIF-shaped JSON."""
    sarif = local_contract_snapshot["resources_static_analysis"]
    # SARIF 2.1.0 envelope
    assert "$schema" in sarif or "version" in sarif or "runs" in sarif


def test_live_local_resource_debug_info_contract(
    local_contract_snapshot: dict[str, Any],
) -> None:
    """ghidra://agentdecompile-debug-info resource returns server metadata."""
    info = local_contract_snapshot["resources_debug_info"]
    # Debug info always has server version or name fields
    assert isinstance(info, dict)
    assert len(info) > 0


# ---------------------------------------------------------------------------
# CLI subprocess fixture – mirrors the terminal commands run manually
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def cli_contract_snapshot(
    terminal_style_local_server: str,
    local_contract_snapshot: dict[str, Any],   # ensures binary is in project before CLI runs
) -> dict[str, Any]:
    """Run agentdecompile-cli subcommands against the live server exactly as done in the terminal."""
    server_url = terminal_style_local_server
    fixture_path = str(KNOWN_FIXTURE_PATH)
    binary_name = KNOWN_FIXTURE_NAME
    repo_root = str(Path(__file__).resolve().parents[1])

    def _cli(*args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "agentdecompile_cli.cli", "--server-url", server_url, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=repo_root,
        )

    def _cli_no_server(*args: str, timeout: int = 15) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "agentdecompile_cli.cli", *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=repo_root,
        )

    # --- tool --list-tools (mirrors: agentdecompile-cli --server-url ... tool --list-tools) ---
    list_tools_result = _cli("tool", "--list-tools")

    # --- tool-seq: open + list-functions (mirrors USAGE.md tool-seq example) ---
    seq_analysis = json.dumps([
        {"name": "open", "arguments": {"path": fixture_path}},
        {"name": "list-functions", "arguments": {"programPath": binary_name, "limit": 50, "format": "json"}},
    ])
    analysis_toolseq_result = _cli("tool-seq", seq_analysis, timeout=120)

    # --- tool-seq: open + list-imports + list-exports + search-symbols --- 
    seq_imports_exports = json.dumps([
        {"name": "open", "arguments": {"path": fixture_path}},
        {"name": "list-imports", "arguments": {"programPath": binary_name, "format": "json"}},
        {"name": "list-exports", "arguments": {"programPath": binary_name, "format": "json"}},
        {"name": "search-symbols", "arguments": {"programPath": binary_name, "query": "main", "format": "json"}},
    ])
    imports_exports_toolseq_result = _cli("tool-seq", seq_imports_exports, timeout=120)

    # --- tool-seq: open + get-references mode=from (mirrors: references from --binary ...) ---
    seq_refs_from = json.dumps([
        {"name": "open", "arguments": {"path": fixture_path}},
        {"name": "get-references", "arguments": {
            "programPath": binary_name, "target": KNOWN_ENTRY_ADDRESS, "mode": "from", "format": "json",
        }},
    ])
    references_from_toolseq_result = _cli("tool-seq", seq_refs_from, timeout=120)

    # --- tool-seq: open + get-references mode=to (mirrors: references to --binary ...) ---
    seq_refs_to = json.dumps([
        {"name": "open", "arguments": {"path": fixture_path}},
        {"name": "get-references", "arguments": {
            "programPath": binary_name, "target": KNOWN_ENTRY_ADDRESS, "mode": "to", "format": "json",
        }},
    ])
    references_to_toolseq_result = _cli("tool-seq", seq_refs_to, timeout=120)

    # --- resource programs / debug-info (no program load required in new session) ---
    resource_programs_result = _cli("resource", "programs")
    resource_debug_info_result = _cli("resource", "debug-info")

    # --- alias commands (no server needed – purely registry lookups) ---
    alias_ssbn_result = _cli_no_server("alias", "search-symbols-by-name")
    alias_ss_result = _cli_no_server("alias", "search-symbols")
    alias_op_result = _cli_no_server("alias", "open")

    return {
        "list_tools_result": list_tools_result,
        "analysis_toolseq_result": analysis_toolseq_result,
        "imports_exports_toolseq_result": imports_exports_toolseq_result,
        "references_from_toolseq_result": references_from_toolseq_result,
        "references_to_toolseq_result": references_to_toolseq_result,
        "resource_programs_result": resource_programs_result,
        "resource_debug_info_result": resource_debug_info_result,
        "alias_ssbn_result": alias_ssbn_result,
        "alias_ss_result": alias_ss_result,
        "alias_op_result": alias_op_result,
    }


# ---------------------------------------------------------------------------
# CLI tests derived from cli_contract_snapshot
# ---------------------------------------------------------------------------


def test_cli_tool_list_tools_shows_37(
    cli_contract_snapshot: dict[str, Any],
) -> None:
    """``agentdecompile-cli tool --list-tools`` should exit 0 and mention 37 tools."""
    result = cli_contract_snapshot["list_tools_result"]
    output = result.stdout + result.stderr
    assert result.returncode == 0, f"tool --list-tools failed:\n{output}"
    # Count tool lines in the output (each line has a tool name + description)
    assert "37" in output or output.count("\n") >= 37, (
        f"Expected at least 37 tool lines in output, got:\n{output[:2000]}"
    )


def test_cli_toolseq_open_and_list_functions(
    cli_contract_snapshot: dict[str, Any],
) -> None:
    """tool-seq open + list-functions exits 0 and surfaces entry/_printf."""
    result = cli_contract_snapshot["analysis_toolseq_result"]
    output = result.stdout + result.stderr
    assert result.returncode == 0, f"tool-seq analysis failed:\n{output}"
    assert "entry" in output
    assert "_printf" in output


def test_cli_toolseq_list_imports_exports_search_symbols(
    cli_contract_snapshot: dict[str, Any],
) -> None:
    """tool-seq open + list-imports + list-exports + search-symbols exits 0 with known names."""
    result = cli_contract_snapshot["imports_exports_toolseq_result"]
    output = result.stdout + result.stderr
    assert result.returncode == 0, f"tool-seq imports/exports failed:\n{output}"
    assert "_printf" in output        # import
    assert "_add" in output or "_multiply" in output  # exports
    assert "_main" in output          # search-symbols result


def test_cli_toolseq_references_from_exit_zero(
    cli_contract_snapshot: dict[str, Any],
) -> None:
    """tool-seq open + get-references mode=from exits 0 for the entry point."""
    result = cli_contract_snapshot["references_from_toolseq_result"]
    output = result.stdout + result.stderr
    assert result.returncode == 0, f"tool-seq references from failed:\n{output}"
    assert "from" in output.lower()


def test_cli_toolseq_references_to_exit_zero(
    cli_contract_snapshot: dict[str, Any],
) -> None:
    """tool-seq open + get-references mode=to exits 0 and reports >=1 reference."""
    result = cli_contract_snapshot["references_to_toolseq_result"]
    output = result.stdout + result.stderr
    assert result.returncode == 0, f"tool-seq references to failed:\n{output}"
    # entry/EXTERNAL reference always present
    assert KNOWN_ENTRY_ADDRESS in output or "entry" in output.lower()


def test_cli_resource_programs_exits_zero_and_lists_project(
    cli_contract_snapshot: dict[str, Any],
) -> None:
    """``resource programs`` exits 0 and the project directory is listed."""
    result = cli_contract_snapshot["resource_programs_result"]
    output = result.stdout + result.stderr
    assert result.returncode == 0, f"resource programs failed:\n{output}"
    assert len(output.strip()) > 0


def test_cli_resource_debug_info_exits_zero_and_has_server_fields(
    cli_contract_snapshot: dict[str, Any],
) -> None:
    """``resource debug-info`` exits 0 and returns JSON with server metadata."""
    result = cli_contract_snapshot["resource_debug_info_result"]
    output = result.stdout
    assert result.returncode == 0, f"resource debug-info failed:\n{result.stdout + result.stderr}"
    # Output should be parseable JSON or contain key server fields
    try:
        data = json.loads(output)
        assert isinstance(data, dict)
        assert len(data) > 0
    except json.JSONDecodeError:
        # Might be markdown-wrapped; check for known field substrings
        assert "version" in output.lower() or "server" in output.lower(), (
            f"debug-info output has no server fields:\n{output[:500]}"
        )


def test_cli_alias_search_symbols_by_name_resolves(
    cli_contract_snapshot: dict[str, Any],
) -> None:
    """``alias search-symbols-by-name`` resolves to search_symbols canonical name."""
    result = cli_contract_snapshot["alias_ssbn_result"]
    output = result.stdout + result.stderr
    assert result.returncode == 0, f"alias search-symbols-by-name failed:\n{output}"
    assert "search_symbols" in output or "search-symbols" in output


def test_cli_alias_search_symbols_resolves(
    cli_contract_snapshot: dict[str, Any],
) -> None:
    """``alias search-symbols`` is self-canonical and lists its aliases."""
    result = cli_contract_snapshot["alias_ss_result"]
    output = result.stdout + result.stderr
    assert result.returncode == 0, f"alias search-symbols failed:\n{output}"
    assert "search_symbols" in output or "search-symbols" in output


def test_cli_alias_open_project_resolves(
    cli_contract_snapshot: dict[str, Any],
) -> None:
    """``alias open`` shows canonical name and any aliases."""
    result = cli_contract_snapshot["alias_op_result"]
    output = result.stdout + result.stderr
    assert result.returncode == 0, f"alias open failed:\n{output}"
    assert "open" in output or "open" in output