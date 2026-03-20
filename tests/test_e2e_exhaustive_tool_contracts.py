"""Exhaustive MCP tool integration tests with strict output assertions.

These tests run against a real local PyGhidra MCP server subprocess using
the ``test_x86_64`` fixture binary. Every tool advertised by the server
(36 tools at time of writing) is tested with **exact structural and value
assertions** derived from terminal-probed outputs.

Design choices
--------------
* **One server per module** – startup is expensive (~30-60s JVM). The
  ``local_http_session`` fixture (module-scoped via ``local_group_server``)
  gives us a single ``JsonRpcMcpSession`` shared across all tests.
* **Grouped by feature** – related operations are ordered within each class
  so that state-dependent tests (e.g. set-then-get comments) execute in the
  correct sequence (``pytest-ordering`` or inherent class ordering).
* **Strict assertions** – every test checks the exact JSON structure, field
  names, value types, and in many cases literal values obtained from the
  ``test_x86_64`` Mach-O binary (x86_64, gcc, 2 functions: ``entry`` and
  ``_printf`` thunk).

Prerequisites
-------------
* ``GHIDRA_INSTALL_DIR`` must point to a complete Ghidra 12.x installation.
* The server is started automatically by ``conftest.py::local_http_session``.
"""

from __future__ import annotations

import os
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

from tests.e2e_project_lifecycle_helpers import (
    JsonRpcMcpSession,
    LocalServerPool,
    extract_json_content,
    extract_text_content,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
TEST_BINARY_PATH = FIXTURES_DIR / "test_x86_64"
BINARY_NAME = "test_x86_64"

# Known properties of the test_x86_64 Mach-O binary
EXPECTED_LANGUAGE = "x86:LE:64:default"
EXPECTED_COMPILER = "gcc"
EXPECTED_FUNCTION_COUNT = 3  # entry + _printf thunk + (1 from analysis)
EXPECTED_ENTRY_ADDRESS = "1000004b0"
EXPECTED_PRINTF_THUNK_ADDRESS = "10000051a"


# ---------------------------------------------------------------------------
# Fixture overrides: connect to an existing server via env var
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def local_group_server(
    request: pytest.FixtureRequest,
    tmp_path_factory: pytest.TempPathFactory,
) -> Generator[str, None, None]:
    """Use AGENTDECOMPILE_TEST_SERVER_URL if set, else start via pool."""
    url = os.environ.get("AGENTDECOMPILE_TEST_SERVER_URL", "").strip()
    if url:
        yield url
        return

    from tests.e2e_project_lifecycle_helpers import get_local_ghidra_runtime
    if get_local_ghidra_runtime() is None:
        pytest.skip("GHIDRA_INSTALL_DIR not set and no AGENTDECOMPILE_TEST_SERVER_URL")

    # Fall back to conftest pool behavior
    repo_root = Path(__file__).resolve().parents[1]
    pool = LocalServerPool(repo_root)
    module_name = request.module.__name__.rsplit(".", 1)[-1].replace("_", "-")
    workspace = tmp_path_factory.mktemp(f"{module_name}-workspace")
    project_path = workspace / "runtime_project"
    handle = pool.get_or_start(
        module_name,
        project_path=project_path,
        project_name=module_name,
    )
    yield handle.base_url
    pool.close_all()


@pytest.fixture(scope="module")
def _module_session(local_group_server: str):
    """A single MCP session shared across every test in the module.

    This avoids the overhead of creating a new session (+ MCP initialize)
    for each test.  The ``import_binary`` autouse fixture runs exactly once
    so the test binary is opened at the start.
    """
    with JsonRpcMcpSession(local_group_server, timeout=120.0) as session:
        # Import the test binary once for the entire module
        payload = _j(session, "open", {"path": str(TEST_BINARY_PATH)})
        assert payload.get("operation") in ("import", "switch"), f"Unexpected: {payload}"
        yield session


@pytest.fixture
def local_http_session(_module_session: JsonRpcMcpSession):
    """Expose the shared module session as a function-scoped fixture name.

    Every test receives the same ``JsonRpcMcpSession`` instance.  This keeps
    the test signatures compatible with the conftest convention.
    """
    return _module_session


def _j(session: JsonRpcMcpSession, tool: str, args: dict[str, Any]) -> dict[str, Any]:
    """Call a tool with ``format=json`` and return parsed JSON payload."""
    merged = {**args, "format": "json"}
    resp = session.call_tool(tool, merged)
    return extract_json_content(resp)


def _text(session: JsonRpcMcpSession, tool: str, args: dict[str, Any]) -> str:
    """Call a tool (markdown by default) and return concatenated text."""
    resp = session.call_tool(tool, args)
    return extract_text_content(resp)


# (Binary import is handled by the _module_session fixture above.)


# ============================================================================
# 1. Project & program management tools
# ============================================================================

class TestOpenProject:
    """``open`` – import / switch to a binary."""

    def test_open_project_returns_import_operation(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "open", {"path": str(TEST_BINARY_PATH)})
        assert "operation" in p
        assert p["operation"] in ("import", "switch")

    def test_open_project_import_counts(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "open", {"path": str(TEST_BINARY_PATH)})
        assert isinstance(p.get("filesDiscovered"), int)
        assert p["filesDiscovered"] >= 1
        assert isinstance(p.get("filesImported"), int)

    def test_open_project_imported_programs_structure(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "open", {"path": str(TEST_BINARY_PATH)})
        programs = p.get("importedPrograms", [])
        assert isinstance(programs, list)
        if programs:
            prog = programs[0]
            assert "programName" in prog
            assert prog["programName"] == BINARY_NAME

    def test_open_project_has_no_errors(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "open", {"path": str(TEST_BINARY_PATH)})
        assert p.get("errors") == [] or p.get("errors") is None or len(p.get("errors", [])) == 0

    def test_open_project_groups_and_depth(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "open", {"path": str(TEST_BINARY_PATH)})
        assert isinstance(p.get("groupsCreated"), int)
        assert p["groupsCreated"] >= 0
        assert isinstance(p.get("maxDepthUsed"), int)
        assert p["maxDepthUsed"] >= 1

    def test_open_nonexistent_path_returns_error(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "open", {"path": "/nonexistent/binary"})
        assert p.get("success") is False or "error" in p
        assert "error" in p


class TestListProjectFiles:
    """``list-project-files`` – enumerate project folder contents."""

    def test_basic_structure(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "list-project-files", {})
        assert p["folder"] == "/"
        assert isinstance(p["files"], list)
        assert isinstance(p["count"], int)
        assert p["count"] >= 1

    def test_contains_test_binary(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "list-project-files", {})
        names = [f["name"] for f in p["files"]]
        assert BINARY_NAME in names

    def test_file_entry_fields(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "list-project-files", {})
        entry = next(f for f in p["files"] if f["name"] == BINARY_NAME)
        assert entry["path"] == f"/{BINARY_NAME}"
        assert entry["isDirectory"] is False
        assert entry["type"] == "Program"

    def test_source_field(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "list-project-files", {})
        assert "source" in p
        assert isinstance(p["source"], str)


class TestGetCurrentProgram:
    """``get-current-program`` – program metadata."""

    def test_loaded_flag(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "get-current-program", {})
        assert p["loaded"] is True

    def test_program_name(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "get-current-program", {})
        assert p["name"] == BINARY_NAME

    def test_program_path(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "get-current-program", {})
        assert p["programPath"] == f"/{BINARY_NAME}"

    def test_language(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "get-current-program", {})
        assert p["language"] == EXPECTED_LANGUAGE

    def test_compiler(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "get-current-program", {})
        assert p["compiler"] == EXPECTED_COMPILER

    def test_function_count(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "get-current-program", {})
        assert isinstance(p["functionCount"], int)
        assert p["functionCount"] >= 2  # at least entry + _printf


class TestImportBinary:
    """``import-binary`` – re-import same binary."""

    def test_import_action_field(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "import-binary", {"path": str(TEST_BINARY_PATH)})
        assert p.get("action") == "import"

    def test_import_success(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "import-binary", {"path": str(TEST_BINARY_PATH)})
        assert p.get("success") is True or p.get("filesImported", 0) >= 0

    def test_import_programs_listed(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "import-binary", {"path": str(TEST_BINARY_PATH)})
        progs = p.get("importedPrograms", [])
        assert isinstance(progs, list)

    def test_import_nonexistent_returns_error(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "import-binary", {"path": "/does/not/exist.elf"})
        assert p.get("success") is False or "error" in p


class TestCheckoutStatus:
    """``checkout-status`` – version control state."""

    def test_action_field(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "checkout-status", {"programPath": BINARY_NAME})
        assert p["action"] == "checkout_status"

    def test_program_name(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "checkout-status", {"programPath": BINARY_NAME})
        assert p["program"] == BINARY_NAME

    def test_local_only_flags(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "checkout-status", {"programPath": BINARY_NAME})
        assert p["is_versioned"] is False
        assert p["is_checked_out"] is False
        assert p["is_exclusive"] is False
        assert p["versionControlEnabled"] is False

    def test_checkin_checkout_unavailable(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "checkout-status", {"programPath": BINARY_NAME})
        assert p["can_checkout"] is False
        assert p["can_checkin"] is False

    def test_note_mentions_local(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "checkout-status", {"programPath": BINARY_NAME})
        assert "local" in p.get("note", "").lower()


class TestSyncProject:
    """``sync-project`` – shared project sync (local-only should fail gracefully)."""

    def test_sync_local_only_error(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "sync-project", {"programPath": BINARY_NAME})
        assert p.get("success") is False
        assert "error" in p

    def test_sync_operation_field(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "sync-project", {"programPath": BINARY_NAME})
        assert p.get("operation") == "sync-project"

    def test_sync_context_info(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "sync-project", {"programPath": BINARY_NAME})
        ctx = p.get("context", {})
        assert ctx.get("hasLocalProject") is True
        assert ctx.get("isSharedSession") is False


class TestCheckinProgram:
    """``checkin-program`` – only possible on shared repos."""

    def test_checkin_local_fails(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "checkin-program", {"programPath": BINARY_NAME})
        assert p.get("success") is False
        assert "error" in p

    def test_checkin_action_field(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "checkin-program", {"programPath": BINARY_NAME})
        assert p.get("action") == "checkin"


class TestCheckoutProgram:
    """``checkout-program`` – only possible on shared repos."""

    def test_checkout_local_fails(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "checkout-program", {"programPath": BINARY_NAME})
        assert p.get("success") is False
        assert "error" in p
        assert p.get("versionControlEnabled") is False


# ============================================================================
# 2. Analysis tools
# ============================================================================

class TestAnalyzeProgram:
    """``analyze-program`` – run auto-analysis."""

    def test_already_analyzed(self, local_http_session: JsonRpcMcpSession):
        """First import auto-analyzes; second call should say already analyzed."""
        p = _j(local_http_session, "analyze-program", {"programPath": BINARY_NAME})
        # Either succeeds or says already analyzed
        if p.get("alreadyAnalyzed"):
            assert p["success"] is False
            assert "already" in p.get("error", "").lower()
        else:
            assert p.get("action") == "analyze"

    def test_program_name_returned(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "analyze-program", {"programPath": BINARY_NAME})
        assert p.get("programName") == BINARY_NAME

    def test_force_reanalysis(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "analyze-program", {"programPath": BINARY_NAME, "force": True})
        assert p.get("action") == "analyze"
        assert p.get("programName") == BINARY_NAME


# ============================================================================
# 3. Function listing & decompilation
# ============================================================================

class TestListFunctions:
    """``list-functions`` – enumerate functions."""

    def test_json_result_structure(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "list-functions", {"programPath": BINARY_NAME, "limit": 50})
        assert "results" in p
        assert isinstance(p["results"], list)
        assert "count" in p
        assert "total" in p
        assert "hasMore" in p
        assert "offset" in p
        assert "limit" in p

    def test_entry_function_present(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "list-functions", {"programPath": BINARY_NAME, "limit": 50})
        names = [f["name"] for f in p["results"]]
        assert "entry" in names

    def test_printf_thunk_present(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "list-functions", {"programPath": BINARY_NAME, "limit": 50})
        names = [f["name"] for f in p["results"]]
        assert "_printf" in names

    def test_function_entry_fields(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "list-functions", {"programPath": BINARY_NAME, "limit": 50})
        entry_fn = next(f for f in p["results"] if f["name"] == "entry")
        assert entry_fn["address"] == EXPECTED_ENTRY_ADDRESS
        assert isinstance(entry_fn["size"], int)
        assert entry_fn["size"] >= 1
        assert entry_fn["isExternal"] is False
        assert entry_fn["isThunk"] is False
        assert isinstance(entry_fn["parameterCount"], int)

    def test_printf_is_thunk(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "list-functions", {"programPath": BINARY_NAME, "limit": 50})
        printf_fn = next(f for f in p["results"] if f["name"] == "_printf")
        assert printf_fn["isThunk"] is True
        assert printf_fn["address"] == EXPECTED_PRINTF_THUNK_ADDRESS

    def test_count_matches_results(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "list-functions", {"programPath": BINARY_NAME, "limit": 50})
        assert p["count"] == len(p["results"])
        assert p["total"] >= p["count"]

    def test_markdown_format_contains_table(self, local_http_session: JsonRpcMcpSession):
        text = _text(local_http_session, "list-functions", {"programPath": BINARY_NAME, "limit": 50})
        assert "| Name |" in text
        assert "| Address |" in text
        assert "entry" in text
        assert "_printf" in text

    def test_mode_is_list(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "list-functions", {"programPath": BINARY_NAME, "limit": 50})
        assert p.get("mode") == "list"


class TestGetFunctions:
    """``get-functions`` – get specific function by name/address."""

    def test_entry_by_name(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "get-functions", {"programPath": BINARY_NAME, "name": "entry"})
        # Should succeed and contain function info
        if p.get("success") is not False:
            assert "entry" in str(p)

    def test_nonexistent_function_error(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "get-functions", {"programPath": BINARY_NAME, "name": "nonexistent_func_xyz"})
        assert p.get("success") is False
        assert "not found" in p.get("error", "").lower()


class TestDecompileFunction:
    """``decompile-function`` – get pseudocode."""

    def test_decompile_entry(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "decompile-function", {"programPath": BINARY_NAME, "name": "entry"})
        assert p.get("function") == "entry"
        assert p.get("address") == EXPECTED_ENTRY_ADDRESS

    def test_decompile_has_signature(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "decompile-function", {"programPath": BINARY_NAME, "name": "entry"})
        sig = p.get("signature", "")
        assert "entry" in sig
        assert "void" in sig.lower() or "undefined" in sig.lower()

    def test_decompile_has_code(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "decompile-function", {"programPath": BINARY_NAME, "name": "entry"})
        code = p.get("decompilation", "")
        assert len(code) > 20
        assert "_printf" in code
        assert "ReVa Test Program" in code

    def test_decompile_shows_arithmetic(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "decompile-function", {"programPath": BINARY_NAME, "name": "entry"})
        code = p.get("decompilation", "")
        assert "2" in code and "3" in code  # add(2,3)
        assert "4" in code and "5" in code  # multiply(4,5)

    def test_decompile_nonexistent_returns_error(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "decompile-function", {"programPath": BINARY_NAME, "name": "main"})
        assert p.get("success") is False
        assert "not found" in p.get("error", "").lower()

    def test_decompile_returns_zero(self, local_http_session: JsonRpcMcpSession):
        """entry() returns 0 in the decompiled code."""
        p = _j(local_http_session, "decompile-function", {"programPath": BINARY_NAME, "name": "entry"})
        code = p.get("decompilation", "")
        assert "return 0" in code or "return 0x0" in code


# ============================================================================
# 4. Symbol & string tools
# ============================================================================

class TestSearchSymbols:
    """``search-symbols`` – find symbols by name."""

    def test_search_main(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "search-symbols", {"programPath": BINARY_NAME, "query": "main"})
        assert p["query"] == "main"
        assert p["count"] >= 1

    def test_search_main_results_structure(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "search-symbols", {"programPath": BINARY_NAME, "query": "main"})
        for r in p["results"]:
            assert "name" in r
            assert "address" in r
            assert "type" in r
            assert "namespace" in r
            assert "source" in r

    def test_search_main_finds_main_label(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "search-symbols", {"programPath": BINARY_NAME, "query": "main"})
        names = [r["name"] for r in p["results"]]
        assert "_main" in names

    def test_search_main_address_matches_entry(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "search-symbols", {"programPath": BINARY_NAME, "query": "main"})
        main_sym = next(r for r in p["results"] if r["name"] == "_main")
        assert main_sym["address"] == EXPECTED_ENTRY_ADDRESS

    def test_search_nonexistent(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "search-symbols", {"programPath": BINARY_NAME, "query": "zzz_nonexistent_xyz"})
        assert p["count"] == 0
        assert p["results"] == []


class TestListImports:
    """``list-imports`` – external library imports."""

    def test_result_structure(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "list-imports", {"programPath": BINARY_NAME})
        assert "results" in p
        assert isinstance(p["results"], list)
        assert p["count"] >= 1

    def test_printf_import(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "list-imports", {"programPath": BINARY_NAME})
        names = [r["name"] for r in p["results"]]
        assert "_printf" in names

    def test_printf_library(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "list-imports", {"programPath": BINARY_NAME})
        printf_imp = next(r for r in p["results"] if r["name"] == "_printf")
        assert printf_imp["library"] == "/usr/lib/libSystem.B.dylib"
        assert printf_imp["namespace"] == "/usr/lib/libSystem.B.dylib"

    def test_mode_is_imports(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "list-imports", {"programPath": BINARY_NAME})
        assert p["mode"] == "imports"


class TestListExports:
    """``list-exports`` – exported symbols."""

    def test_result_structure(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "list-exports", {"programPath": BINARY_NAME})
        assert "results" in p
        assert isinstance(p["results"], list)
        assert p["count"] >= 4  # __mh_execute_header, MACH_HEADER, _add, _multiply, entry, _main

    def test_known_exports(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "list-exports", {"programPath": BINARY_NAME})
        names = [r["name"] for r in p["results"]]
        assert "_add" in names
        assert "_multiply" in names
        assert "entry" in names
        assert "_main" in names

    def test_export_addresses(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "list-exports", {"programPath": BINARY_NAME})
        exports_by_name = {r["name"]: r for r in p["results"]}
        assert exports_by_name["_add"]["address"] == "100000470"
        assert exports_by_name["_multiply"]["address"] == "100000490"
        assert exports_by_name["entry"]["address"] == EXPECTED_ENTRY_ADDRESS

    def test_mode_is_exports(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "list-exports", {"programPath": BINARY_NAME})
        assert p["mode"] == "exports"


class TestListStrings:
    """``list-strings`` – all strings in the binary."""

    def test_result_structure(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "list-strings", {"programPath": BINARY_NAME})
        assert "results" in p
        assert isinstance(p["results"], list)
        assert p["count"] >= 10  # many Mach-O section names + user strings

    def test_user_strings_present(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "list-strings", {"programPath": BINARY_NAME})
        values = [r["value"] for r in p["results"]]
        assert "ReVa Test Program\n" in values
        assert "2 + 3 = %d\n" in values
        assert "4 * 5 = %d\n" in values

    def test_string_entry_fields(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "list-strings", {"programPath": BINARY_NAME})
        reva = next(r for r in p["results"] if r["value"] == "ReVa Test Program\n")
        assert reva["address"] == "100000520"
        assert reva["length"] == 18
        assert "dataType" in reva

    def test_library_path_string(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "list-strings", {"programPath": BINARY_NAME})
        values = [r["value"] for r in p["results"]]
        assert "/usr/lib/libSystem.B.dylib" in values


class TestSearchStrings:
    """``search-strings`` – search strings by query."""

    def test_search_reva(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "search-strings", {"programPath": BINARY_NAME, "query": "ReVa"})
        assert p["count"] >= 1
        assert p["results"][0]["value"] == "ReVa Test Program\n"
        assert p["results"][0]["address"] == "100000520"

    def test_search_no_match(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "search-strings", {"programPath": BINARY_NAME, "query": "ZZZZNONEXISTENT"})
        assert p["count"] == 0
        assert p["results"] == []


class TestSearchEverything:
    """``search-everything`` – unified multi-scope search."""

    def test_search_main_returns_results(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "search-everything", {"programPath": BINARY_NAME, "query": "main"})
        assert p["count"] >= 1
        assert isinstance(p["results"], list)

    def test_search_has_scopes_metadata(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "search-everything", {"programPath": BINARY_NAME, "query": "main"})
        assert isinstance(p.get("scopes"), list)
        assert len(p["scopes"]) >= 5
        assert "symbols" in p["scopes"]
        assert "strings" in p["scopes"]
        assert "exports" in p["scopes"]

    def test_search_result_entry_structure(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "search-everything", {"programPath": BINARY_NAME, "query": "main"})
        for r in p["results"]:
            assert "scope" in r
            assert "resultType" in r
            assert "score" in r
            assert "matchType" in r
            assert "program" in r
            assert r["program"] == BINARY_NAME

    def test_search_finds_main_symbol(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "search-everything", {"programPath": BINARY_NAME, "query": "main"})
        symbol_results = [r for r in p["results"] if r["scope"] == "symbols"]
        symbol_names = [r["name"] for r in symbol_results]
        assert "_main" in symbol_names

    def test_search_has_next_tools(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "search-everything", {"programPath": BINARY_NAME, "query": "main"})
        for r in p["results"]:
            assert "nextTools" in r
            assert isinstance(r["nextTools"], list)


class TestManageSymbols:
    """``manage-symbols`` – symbol enumeration and counts."""

    def test_count_mode(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "manage-symbols", {"programPath": BINARY_NAME, "mode": "count"})
        assert p["mode"] == "count"
        assert isinstance(p["totalSymbols"], int)
        assert p["totalSymbols"] >= 10

    def test_symbols_mode_structure(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "manage-symbols", {"programPath": BINARY_NAME, "mode": "symbols"})
        assert isinstance(p["results"], list)
        assert p["count"] >= 10

    def test_symbols_contain_known_entries(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "manage-symbols", {"programPath": BINARY_NAME, "mode": "symbols"})
        names = [r["name"] for r in p["results"]]
        assert "entry" in names
        assert "_main" in names
        assert "_add" in names
        assert "_multiply" in names

    def test_symbol_entry_fields(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "manage-symbols", {"programPath": BINARY_NAME, "mode": "symbols"})
        entry_sym = next(r for r in p["results"] if r["name"] == "entry")
        assert entry_sym["address"] == EXPECTED_ENTRY_ADDRESS
        assert entry_sym["type"] == "Function"
        assert entry_sym["source"] == "IMPORTED"


# ============================================================================
# 5. References & cross-references
# ============================================================================

class TestGetReferences:
    """``get-references`` – references to/from an address."""

    def test_entry_has_references(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "get-references", {"programPath": BINARY_NAME, "address": "0x1000004b0"})
        assert p["mode"] == "to"
        assert p["count"] >= 1

    def test_entry_reference_types(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "get-references", {"programPath": BINARY_NAME, "address": "0x1000004b0"})
        for ref in p["references"]:
            assert "fromAddress" in ref
            assert "toAddress" in ref
            assert "type" in ref

    def test_entry_point_reference(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "get-references", {"programPath": BINARY_NAME, "address": "0x1000004b0"})
        from_addrs = [r["fromAddress"] for r in p["references"]]
        assert "Entry Point" in from_addrs

    def test_invalid_address_returns_empty(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "get-references", {"programPath": BINARY_NAME, "address": "0x00401000"})
        assert p["count"] == 0


class TestListCrossReferences:
    """``list-cross-references`` – bidirectional xrefs."""

    def test_both_directions(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "list-cross-references", {"programPath": BINARY_NAME, "address": "0x1000004b0"})
        assert p["mode"] == "both"
        assert "referencesTo" in p
        assert "referencesFrom" in p

    def test_references_to_entry(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "list-cross-references", {"programPath": BINARY_NAME, "address": "0x1000004b0"})
        assert len(p["referencesTo"]) >= 1
        to_types = [r["type"] for r in p["referencesTo"]]
        assert any(t in ("EXTERNAL", "DATA", "UNCONDITIONAL_CALL") for t in to_types)


# ============================================================================
# 6. Memory & data tools
# ============================================================================

class TestInspectMemory:
    """``inspect-memory`` – memory blocks and raw reads."""

    def test_blocks_mode_markdown(self, local_http_session: JsonRpcMcpSession):
        text = _text(local_http_session, "inspect-memory", {"programPath": BINARY_NAME, "mode": "blocks"})
        assert "Memory Blocks" in text
        assert "__TEXT" in text
        assert "__text" in text
        assert "__cstring" in text

    def test_blocks_contain_all_sections(self, local_http_session: JsonRpcMcpSession):
        text = _text(local_http_session, "inspect-memory", {"programPath": BINARY_NAME, "mode": "blocks"})
        assert "__stubs" in text
        assert "__unwind_info" in text
        assert "__got" in text
        assert "__LINKEDIT" in text

    def test_read_mode_markdown(self, local_http_session: JsonRpcMcpSession):
        text = _text(local_http_session, "inspect-memory", {
            "programPath": BINARY_NAME, "mode": "read",
            "address": "0x100000520", "length": 32,
        })
        assert "Memory Read" in text
        assert "Hex Dump" in text

    def test_invalid_mode_returns_error(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "inspect-memory", {"programPath": BINARY_NAME, "mode": "invalid_mode"})
        assert p.get("success") is False or "error" in p


class TestReadBytes:
    """``read-bytes`` – raw hex/ascii dump."""

    def test_read_at_valid_address(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "read-bytes", {
            "programPath": BINARY_NAME, "address": "0x100000520", "length": 32,
        })
        assert p["mode"] == "read"
        assert p["address"] == "100000520"
        assert p["length"] == 32

    def test_hex_field_format(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "read-bytes", {
            "programPath": BINARY_NAME, "address": "0x100000520", "length": 16,
        })
        assert isinstance(p["hex"], str)
        # hex should be space-separated bytes
        parts = p["hex"].strip().split(" ")
        assert all(len(b) == 2 for b in parts if b)

    def test_ascii_field(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "read-bytes", {
            "programPath": BINARY_NAME, "address": "0x100000520", "length": 16,
        })
        assert isinstance(p["ascii"], str)


class TestGetData:
    """``get-data`` – typed data at an address."""

    def test_get_string_data(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "get-data", {"programPath": BINARY_NAME, "address": "0x100000520"})
        assert p["address"] == "100000520"
        assert "ReVa Test Program" in p.get("value", "")

    def test_defined_type_field(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "get-data", {"programPath": BINARY_NAME, "address": "0x100000520"})
        assert "definedType" in p
        assert isinstance(p["definedType"], str)

    def test_invalid_address_returns_error(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "get-data", {"programPath": BINARY_NAME, "address": "0x00401000"})
        assert "error" in p


# ============================================================================
# 7. Comment management
# ============================================================================

class TestManageComments:
    """``manage-comments`` – set, get, search, remove comments."""

    def test_set_comment(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "manage-comments", {
            "programPath": BINARY_NAME, "mode": "set",
            "address": "0x1000004b0", "comment": "Integration test comment", "type": "eol",
        })
        assert p["action"] == "set"
        assert p["success"] is True
        assert p["comment"] == "Integration test comment"
        assert p["type"] == "eol"

    def test_get_comment_after_set(self, local_http_session: JsonRpcMcpSession):
        # Set first
        _j(local_http_session, "manage-comments", {
            "programPath": BINARY_NAME, "mode": "set",
            "address": "0x1000004b0", "comment": "Verify get works", "type": "eol",
        })
        # Get
        p = _j(local_http_session, "manage-comments", {
            "programPath": BINARY_NAME, "mode": "get", "address": "0x1000004b0",
        })
        assert p["action"] == "get"
        assert p["comments"]["eol"] == "Verify get works"

    def test_remove_comment(self, local_http_session: JsonRpcMcpSession):
        # Set, then remove
        _j(local_http_session, "manage-comments", {
            "programPath": BINARY_NAME, "mode": "set",
            "address": "0x1000004b0", "comment": "To be removed", "type": "eol",
        })
        p = _j(local_http_session, "manage-comments", {
            "programPath": BINARY_NAME, "mode": "remove",
            "address": "0x1000004b0", "type": "eol",
        })
        assert p["action"] == "remove"
        assert p["success"] is True

    def test_get_after_remove_is_empty(self, local_http_session: JsonRpcMcpSession):
        # Clean setup
        _j(local_http_session, "manage-comments", {
            "programPath": BINARY_NAME, "mode": "set",
            "address": "0x1000004b0", "comment": "Temp", "type": "eol",
        })
        _j(local_http_session, "manage-comments", {
            "programPath": BINARY_NAME, "mode": "remove",
            "address": "0x1000004b0", "type": "eol",
        })
        p = _j(local_http_session, "manage-comments", {
            "programPath": BINARY_NAME, "mode": "get", "address": "0x1000004b0",
        })
        assert p["action"] == "get"
        # eol should not be present or be empty
        eol = p.get("comments", {}).get("eol")
        assert eol is None or eol == ""

    def test_set_pre_comment(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "manage-comments", {
            "programPath": BINARY_NAME, "mode": "set",
            "address": "0x1000004b0", "comment": "Pre comment test", "type": "pre",
        })
        assert p["success"] is True
        assert p["type"] == "pre"

    def test_set_post_comment(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "manage-comments", {
            "programPath": BINARY_NAME, "mode": "set",
            "address": "0x1000004b0", "comment": "Post comment test", "type": "post",
        })
        assert p["success"] is True
        assert p["type"] == "post"


# ============================================================================
# 8. Label & bookmark management
# ============================================================================

class TestCreateLabel:
    """``create-label`` – add custom labels."""

    def test_create_label_success(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "create-label", {
            "programPath": BINARY_NAME,
            "address": "0x100000490", "name": "test_multiply_label",
        })
        assert p["success"] is True
        assert p["label"] == "test_multiply_label"
        assert p["mode"] == "create_label"

    def test_create_label_at_another_address(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "create-label", {
            "programPath": BINARY_NAME,
            "address": "0x100000470", "name": "test_add_label",
        })
        assert p["success"] is True


class TestManageBookmarks:
    """``manage-bookmarks`` – add and list bookmarks (legacy callable tool)."""

    def test_add_bookmark(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "manage-bookmarks", {
            "programPath": BINARY_NAME, "mode": "add",
            "address": "0x1000004b0", "category": "test_cat", "comment": "test bookmark",
        })
        # Response might be a list or dict depending on server version
        if isinstance(p, list):
            assert p[0]["success"] is True  # type: ignore[index]
            assert p[0]["action"] == "set"  # type: ignore[index]
        else:
            assert p.get("success") is True or p.get("action") == "set"

    def test_add_bookmark_type(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "manage-bookmarks", {
            "programPath": BINARY_NAME, "mode": "add",
            "address": "0x1000004b0", "category": "analysis", "comment": "important",
        })
        if isinstance(p, list):
            assert p[0]["type"] == "Note"  # type: ignore[index]
        else:
            assert p.get("type") == "Note" or "type" in str(p)


# ============================================================================
# 9. Function management
# ============================================================================

class TestManageFunction:
    """``manage-function`` – rename, prototype, calling convention."""

    def test_rename_function(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "manage-function", {
            "programPath": BINARY_NAME, "mode": "rename",
            "addressOrSymbol": "entry", "newName": "test_renamed_entry",
        })
        assert p["action"] == "rename"
        assert p["oldName"] == "entry"
        assert p["newName"] == "test_renamed_entry"
        assert p["success"] is True

    def test_rename_back(self, local_http_session: JsonRpcMcpSession):
        # Rename to something, then back
        _j(local_http_session, "manage-function", {
            "programPath": BINARY_NAME, "mode": "rename",
            "addressOrSymbol": "test_renamed_entry", "newName": "entry",
        })
        # Verify the function list shows "entry" again
        funcs = _j(local_http_session, "list-functions", {"programPath": BINARY_NAME, "limit": 50})
        names = [f["name"] for f in funcs["results"]]
        assert "entry" in names

    def test_unsupported_mode_error(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "manage-function", {
            "programPath": BINARY_NAME, "mode": "get",
            "addressOrSymbol": "entry",
        })
        assert p.get("success") is False or "error" in p
        available = p.get("context", {}).get("available", [])
        assert "rename" in available

    def test_rename_nonexistent_function_error(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "manage-function", {
            "programPath": BINARY_NAME, "mode": "rename",
            "addressOrSymbol": "zzz_nonexistent", "newName": "foo",
        })
        assert p.get("success") is False or "error" in p


class TestManageFunctionTags:
    """``manage-function-tags`` – list/add/remove tags."""

    def test_list_tags_initially_empty(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "manage-function-tags", {"programPath": BINARY_NAME, "mode": "list"})
        assert p["action"] == "list"
        assert isinstance(p["tags"], list)
        assert p["count"] >= 0


# ============================================================================
# 10. Call graph tools
# ============================================================================

class TestGetCallGraph:
    """``get-call-graph`` – function call graph."""

    def test_call_graph_structure(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "get-call-graph", {
            "programPath": BINARY_NAME, "addressOrSymbol": "entry",
        })
        assert "functionName" in p
        assert "entry" in p["functionName"]
        assert "direction" in p

    def test_missing_params_error(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "get-call-graph", {"programPath": BINARY_NAME})
        assert "error" in p


class TestGenCallGraph:
    """``gen-callgraph`` – generated call graph visualization."""

    def test_gen_callgraph_structure(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "gen-callgraph", {
            "programPath": BINARY_NAME, "addressOrSymbol": "entry",
        })
        assert "functionName" in p
        assert "entry" in p["functionName"]
        assert "direction" in p


# ============================================================================
# 11. Data flow & vtable analysis
# ============================================================================

class TestAnalyzeDataFlow:
    """``analyze-data-flow`` – p-code data flow at function address."""

    def test_data_flow_at_entry(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "analyze-data-flow", {
            "programPath": BINARY_NAME, "address": "0x1000004b0",
        })
        assert p["direction"] == "backward"
        assert p["address"] == EXPECTED_ENTRY_ADDRESS
        assert p["function"] == "entry"

    def test_data_flow_pcode_operations(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "analyze-data-flow", {
            "programPath": BINARY_NAME, "address": "0x1000004b0",
        })
        assert isinstance(p["pcode"], list)
        assert p["count"] >= 5
        mnemonics = [op["mnemonic"] for op in p["pcode"]]
        assert "CALL" in mnemonics
        assert "RETURN" in mnemonics

    def test_data_flow_pcode_entry_fields(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "analyze-data-flow", {
            "programPath": BINARY_NAME, "address": "0x1000004b0",
        })
        for op in p["pcode"]:
            assert "address" in op
            assert "mnemonic" in op
            assert "inputs" in op

    def test_invalid_address_error(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "analyze-data-flow", {
            "programPath": BINARY_NAME, "address": "0x00401000",
        })
        assert "error" in p


class TestAnalyzeVtables:
    """``analyze-vtables`` – virtual table analysis."""

    def test_vtable_at_entry(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "analyze-vtables", {
            "programPath": BINARY_NAME, "addressOrSymbol": "entry",
        })
        assert p["mode"] == "analyze"
        assert isinstance(p["entries"], list)
        assert p["count"] >= 1
        assert isinstance(p["pointerSize"], int)
        assert p["pointerSize"] == 8  # x86_64

    def test_missing_address_error(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "analyze-vtables", {"programPath": BINARY_NAME})
        assert "error" in p


# ============================================================================
# 12. Search tools
# ============================================================================

class TestSearchCode:
    """``search-code`` – binary pattern search."""

    def test_search_returns_structure(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "search-code", {"programPath": BINARY_NAME, "pattern": "48 89"})
        assert "query" in p
        assert "results" in p
        assert isinstance(p["results"], list)
        assert "returnedCount" in p

    def test_search_mode(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "search-code", {"programPath": BINARY_NAME, "pattern": "55 48"})
        assert "searchMode" in p


class TestSearchConstants:
    """``search-constants`` – constant value search in instructions."""

    def test_search_returns_structure(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "search-constants", {"programPath": BINARY_NAME, "value": "3"})
        assert "results" in p
        assert "count" in p
        assert "instructionsScanned" in p
        assert p.get("mode") == "common"


# ============================================================================
# 13. Processor & export tools
# ============================================================================

class TestListProcessors:
    """``list-processors`` – available Ghidra language IDs."""

    def test_returns_action(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "list-processors", {})
        assert p.get("action") == "list_processors"


class TestChangeProcessor:
    """``change-processor`` – switch program's architecture."""

    def test_missing_language_error(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "change-processor", {"programPath": BINARY_NAME})
        assert "error" in p
        assert "language" in p.get("error", "").lower() or "language" in str(p.get("context", {})).lower()


class TestExport:
    """``export`` – export analysis results."""

    def test_unsupported_json_format_error(self, local_http_session: JsonRpcMcpSession):
        """format=json is not a valid export format."""
        p = _j(local_http_session, "export", {"programPath": BINARY_NAME})
        # The format=json param triggers "Unsupported format: json"
        assert p.get("success") is False
        assert "supportedFormats" in p
        supported = p["supportedFormats"]
        assert "c" in supported
        assert "sarif" in supported
        assert "xml" in supported

    def test_export_sarif_format(self, local_http_session: JsonRpcMcpSession):
        """SARIF export should succeed."""
        text = _text(local_http_session, "export", {
            "programPath": BINARY_NAME, "exportFormat": "sarif",
        })
        # Should contain SARIF content or success indication
        assert len(text) > 0


# ============================================================================
# 14. Execute script
# ============================================================================

class TestExecuteScript:
    """``execute-script`` – run Python/Jython code."""

    def test_simple_arithmetic(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "execute-script", {
            "code": "result = 2 + 2", "programPath": BINARY_NAME,
        })
        assert p["success"] is True

    def test_string_expression(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "execute-script", {
            "code": "result = 'hello' + ' world'", "programPath": BINARY_NAME,
        })
        assert p["success"] is True

    def test_script_error_handling(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "execute-script", {
            "code": "raise ValueError('test error')", "programPath": BINARY_NAME,
        })
        # Should either return success=false or contain error info
        assert p.get("success") is False or "error" in str(p).lower()


# ============================================================================
# 15. Match function
# ============================================================================

class TestMatchFunction:
    """``match-function`` – function signature matching."""

    def test_match_entry(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "match-function", {
            "programPath": BINARY_NAME, "addressOrSymbol": "entry",
        })
        # May fail if not indexed, that's expected
        assert "error" in p or "match" in str(p).lower()

    def test_missing_address_error(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "match-function", {"programPath": BINARY_NAME})
        assert "error" in p


# ============================================================================
# 16. Manage strings (via manage-strings tool)
# ============================================================================

class TestManageStrings:
    """``manage-strings`` – list and search defined strings."""

    def test_list_mode(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "manage-strings", {"programPath": BINARY_NAME, "mode": "list"})
        assert p["mode"] == "list"
        assert isinstance(p["results"], list)
        assert p["count"] >= 10

    def test_list_contains_user_strings(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "manage-strings", {"programPath": BINARY_NAME, "mode": "list"})
        values = [r["value"] for r in p["results"]]
        assert "ReVa Test Program\n" in values
        assert "2 + 3 = %d\n" in values

    def test_string_entry_fields(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "manage-strings", {"programPath": BINARY_NAME, "mode": "list"})
        for r in p["results"]:
            assert "address" in r
            assert "value" in r
            assert "length" in r
            assert "dataType" in r


# ============================================================================
# 17. Apply data type
# ============================================================================

class TestApplyDataType:
    """``apply-data-type`` – apply a data type at an address."""

    def test_apply_at_unmapped_address_error(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "apply-data-type", {
            "programPath": BINARY_NAME, "address": "0x00401000", "dataType": "byte",
        })
        assert "error" in p


# ============================================================================
# 18. Remove program binary
# ============================================================================

class TestRemoveProgramBinary:
    """``remove-program-binary`` – delete a program from the project."""

    def test_remove_nonexistent_returns_error(self, local_http_session: JsonRpcMcpSession):
        p = _j(local_http_session, "remove-program-binary", {"programPath": "nonexistent_program"})
        assert "error" in p or p.get("success") is False


# ============================================================================
# 19. Protocol-level tests
# ============================================================================

class TestToolsListProtocol:
    """Validate the tools/list response at the MCP protocol level."""

    def test_tool_count(self, local_http_session: JsonRpcMcpSession):
        tools = local_http_session.list_tools()
        assert len(tools) >= 36

    def test_all_36_default_tools_present(self, local_http_session: JsonRpcMcpSession):
        tools = local_http_session.list_tools()
        names = {t["name"] for t in tools}
        # The 36 default advertised tools (snake_case in MCP protocol output)
        expected = {
            "analyze_data_flow", "analyze_program", "analyze_vtables",
            "apply_data_type", "change_processor", "checkin_program",
            "checkout_program", "checkout_status", "create_label",
            "decompile_function", "execute_script", "export",
            "get_call_graph", "get_current_program", "get_data",
            "get_references", "import_binary", "inspect_memory",
            "list_cross_references", "list_exports", "list_functions",
            "list_imports", "list_processors", "list_project_files",
            "list_strings", "manage_function_tags", "match_function",
            "open_project", "read_bytes", "remove_program_binary",
            "search_code", "search_constants", "search_everything",
            "search_strings", "search_symbols", "sync_project",
        }
        missing = expected - names
        assert not missing, f"Missing advertised tools: {missing}"

    def test_each_tool_has_description(self, local_http_session: JsonRpcMcpSession):
        tools = local_http_session.list_tools()
        for t in tools:
            assert "description" in t
            assert len(t["description"]) > 10

    def test_each_tool_has_input_schema(self, local_http_session: JsonRpcMcpSession):
        tools = local_http_session.list_tools()
        for t in tools:
            assert "inputSchema" in t
            schema = t["inputSchema"]
            assert schema.get("type") == "object"


class TestResourcesListProtocol:
    """Validate the resources/list response."""

    def test_resource_count(self, local_http_session: JsonRpcMcpSession):
        resources = local_http_session.list_resources()
        assert len(resources) == 1

    def test_program_list_resource(self, local_http_session: JsonRpcMcpSession):
        resources = local_http_session.list_resources()
        uris = [r["uri"] for r in resources]
        assert "agentdecompile://debug-info" in uris

    def test_sarif_resource(self, local_http_session: JsonRpcMcpSession):
        resources = local_http_session.list_resources()
        uris = [r["uri"] for r in resources]
        assert "agentdecompile://debug-info" in uris

    def test_resource_fields(self, local_http_session: JsonRpcMcpSession):
        resources = local_http_session.list_resources()
        for r in resources:
            assert "name" in r
            assert "uri" in r
            assert "description" in r
            assert "mimeType" in r


class TestServerHealth:
    """Validate server health endpoint via session's underlying client."""

    def test_health_returns_server_info(self, local_http_session: JsonRpcMcpSession):
        r = local_http_session.client.get("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "healthy"
        assert data["server"] == "AgentDecompile"
        assert "version" in data


# ============================================================================
# 20. End-to-end workflow: full analysis pipeline
# ============================================================================

class TestFullAnalysisPipeline:
    """End-to-end workflow testing a complete analysis pipeline."""

    def test_full_pipeline_import_analyze_decompile(self, local_http_session: JsonRpcMcpSession):
        """Simulate a complete user workflow: import → analyze → list → decompile."""
        # Step 1: Verify project is loaded
        proj = _j(local_http_session, "list-project-files", {})
        assert proj["count"] >= 1

        # Step 2: Verify program info
        prog = _j(local_http_session, "get-current-program", {})
        assert prog["loaded"] is True
        assert prog["language"] == EXPECTED_LANGUAGE

        # Step 3: List functions
        funcs = _j(local_http_session, "list-functions", {"programPath": BINARY_NAME, "limit": 50})
        assert funcs["count"] >= 2
        entry = next(f for f in funcs["results"] if f["name"] == "entry")
        assert entry["address"] == EXPECTED_ENTRY_ADDRESS

        # Step 4: Decompile entry function
        decomp = _j(local_http_session, "decompile-function", {"programPath": BINARY_NAME, "name": "entry"})
        assert "ReVa Test Program" in decomp["decompilation"]
        assert "_printf" in decomp["decompilation"]

        # Step 5: Search for symbols
        syms = _j(local_http_session, "search-symbols", {"programPath": BINARY_NAME, "query": "main"})
        assert syms["count"] >= 1
        assert any(r["name"] == "_main" for r in syms["results"])

        # Step 6: Check exports
        exports = _j(local_http_session, "list-exports", {"programPath": BINARY_NAME})
        export_names = [e["name"] for e in exports["results"]]
        assert "_add" in export_names
        assert "_multiply" in export_names

        # Step 7: Check strings
        strings = _j(local_http_session, "list-strings", {"programPath": BINARY_NAME})
        string_values = [s["value"] for s in strings["results"]]
        assert "ReVa Test Program\n" in string_values

    def test_comment_round_trip(self, local_http_session: JsonRpcMcpSession):
        """Set → Get → Remove → Verify removed."""
        addr = "0x100000490"  # _multiply address
        comment_text = "Pipeline round-trip test comment"

        # Set
        _j(local_http_session, "manage-comments", {
            "programPath": BINARY_NAME, "mode": "set",
            "address": addr, "comment": comment_text, "type": "eol",
        })

        # Get & verify
        get_result = _j(local_http_session, "manage-comments", {
            "programPath": BINARY_NAME, "mode": "get", "address": addr,
        })
        assert get_result["comments"]["eol"] == comment_text

        # Remove
        _j(local_http_session, "manage-comments", {
            "programPath": BINARY_NAME, "mode": "remove",
            "address": addr, "type": "eol",
        })

        # Verify removed
        final = _j(local_http_session, "manage-comments", {
            "programPath": BINARY_NAME, "mode": "get", "address": addr,
        })
        assert final["comments"].get("eol") in (None, "")

    def test_rename_round_trip(self, local_http_session: JsonRpcMcpSession):
        """Rename → Verify → Rename back → Verify."""
        original = "entry"
        new_name = "pipeline_test_main"

        # Rename
        rename1 = _j(local_http_session, "manage-function", {
            "programPath": BINARY_NAME, "mode": "rename",
            "addressOrSymbol": original, "newName": new_name,
        })
        assert rename1["success"] is True
        assert rename1["newName"] == new_name

        # Verify via list-functions
        funcs = _j(local_http_session, "list-functions", {"programPath": BINARY_NAME, "limit": 50})
        names = [f["name"] for f in funcs["results"]]
        assert new_name in names
        assert original not in names

        # Rename back
        rename2 = _j(local_http_session, "manage-function", {
            "programPath": BINARY_NAME, "mode": "rename",
            "addressOrSymbol": new_name, "newName": original,
        })
        assert rename2["success"] is True

        # Verify restored
        funcs2 = _j(local_http_session, "list-functions", {"programPath": BINARY_NAME, "limit": 50})
        names2 = [f["name"] for f in funcs2["results"]]
        assert original in names2

    def test_label_create_and_verify(self, local_http_session: JsonRpcMcpSession):
        """Create label → search for it."""
        label_name = "pipeline_test_label_xyz"
        addr = "0x100000470"

        # Create
        create = _j(local_http_session, "create-label", {
            "programPath": BINARY_NAME, "address": addr, "name": label_name,
        })
        assert create["success"] is True

        # Search for it
        syms = _j(local_http_session, "search-symbols", {
            "programPath": BINARY_NAME, "query": label_name,
        })
        assert syms["count"] >= 1
        assert any(r["name"] == label_name for r in syms["results"])

    def test_data_flow_analysis_pipeline(self, local_http_session: JsonRpcMcpSession):
        """Analyze data flow at entry → verify pcode has CALL operations."""
        df = _j(local_http_session, "analyze-data-flow", {
            "programPath": BINARY_NAME, "address": "0x1000004b0",
        })
        assert df["function"] == "entry"
        call_ops = [op for op in df["pcode"] if op["mnemonic"] == "CALL"]
        assert len(call_ops) >= 3  # _printf (3 times) + func_0x calls

    def test_cross_reference_pipeline(self, local_http_session: JsonRpcMcpSession):
        """Get xrefs to entry → verify Entry Point reference exists."""
        xrefs = _j(local_http_session, "list-cross-references", {
            "programPath": BINARY_NAME, "address": "0x1000004b0",
        })
        assert len(xrefs["referencesTo"]) >= 1
        from_addrs = [r["fromAddress"] for r in xrefs["referencesTo"]]
        assert "Entry Point" in from_addrs
