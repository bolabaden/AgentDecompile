"""Unit tests for program_metadata helpers."""

from __future__ import annotations

import json

from unittest.mock import MagicMock, patch

import pytest

from agentdecompile_cli.mcp_server.program_metadata import (
    collect_program_summary,
    collect_project_context,
    inject_project_context,
)

# ---------------------------------------------------------------------------
# Fixtures: mock Ghidra Program & related objects
# ---------------------------------------------------------------------------


def _make_mock_program(
    *,
    name: str = "test.exe",
    func_count: int = 42,
    bookmark_count: int = 5,
    instruction_count: int = 1000,
    language_id: str = "x86:LE:32:default",
    compiler_spec: str = "gcc",
    is_versioned: bool = False,
    is_checked_out: bool = False,
) -> MagicMock:
    """Create a mock Ghidra Program with nested managers."""
    program = MagicMock()
    program.getName.return_value = name

    # FunctionManager
    fm = MagicMock()
    fm.getFunctionCount.return_value = func_count
    tag_mgr = MagicMock()
    tag1 = MagicMock()
    tag1.getName.return_value = "KNOWN"
    tag_mgr.getAllFunctionTags.return_value = [tag1]
    tag_mgr.getUseCount.return_value = 3
    fm.getFunctionTagManager.return_value = tag_mgr
    program.getFunctionManager.return_value = fm

    # BookmarkManager
    bm = MagicMock()
    bm.getBookmarkCount.side_effect = lambda *args: 2 if args else bookmark_count
    bm_type = MagicMock()
    bm_type.getTypeString.return_value = "Analysis"
    bm.getBookmarkTypes.return_value = [bm_type]
    program.getBookmarkManager.return_value = bm

    # Listing
    listing = MagicMock()
    listing.getNumInstructions.return_value = instruction_count
    program.getListing.return_value = listing

    # Language / compiler
    program.getLanguageID.return_value = language_id
    compiler = MagicMock()
    compiler.getCompilerSpecID.return_value = compiler_spec
    program.getCompilerSpec.return_value = compiler

    # Metadata
    program.getMetadata.return_value = {
        "Executable Format": "PE",
        "Created With Ghidra Version": "12.0",
    }

    # DomainFile
    df = MagicMock()
    df.isVersioned.return_value = is_versioned
    df.isCheckedOut.return_value = is_checked_out
    df.isCheckedOutExclusive.return_value = False
    df.modifiedSinceCheckout.return_value = False
    df.canCheckout.return_value = not is_checked_out
    df.canCheckin.return_value = is_checked_out
    df.getVersion.return_value = 1
    df.getLatestVersion.return_value = 2
    df.getLastModifiedTime.return_value = 1700000000000  # epoch ms
    df.length.return_value = 123456
    df.getCheckoutStatus.return_value = None
    program.getDomainFile.return_value = df

    return program


def _make_mock_program_info(program: MagicMock | None = None, name: str = "test.exe") -> MagicMock:
    info = MagicMock()
    info.name = name
    info.program = program if program is not None else _make_mock_program(name=name)
    return info


# ---------------------------------------------------------------------------
# collect_program_summary tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCollectProgramSummary:
    def test_basic_fields(self):
        info = _make_mock_program_info()
        result = collect_program_summary(info)
        assert result["name"] == "test.exe"
        assert result["functionCount"] == 42
        assert result["instructionCount"] == 1000
        assert result["languageId"] == "x86:LE:32:default"
        assert result["compilerSpec"] == "gcc"

    def test_function_tags(self):
        info = _make_mock_program_info()
        result = collect_program_summary(info)
        assert "functionTags" in result
        assert len(result["functionTags"]) == 1
        assert result["functionTags"][0]["name"] == "KNOWN"
        assert result["functionTags"][0]["useCount"] == 3

    def test_bookmarks(self):
        info = _make_mock_program_info()
        result = collect_program_summary(info)
        assert result["bookmarkCount"] == 5
        assert "bookmarksByType" in result
        assert "Analysis" in result["bookmarksByType"]

    def test_metadata(self):
        info = _make_mock_program_info()
        result = collect_program_summary(info)
        assert result["metadata"]["Executable Format"] == "PE"
        assert result["metadata"]["Created With Ghidra Version"] == "12.0"

    def test_versioning_local(self):
        info = _make_mock_program_info()
        result = collect_program_summary(info)
        ver = result.get("versioning", {})
        assert ver.get("isVersioned") is False
        assert ver.get("isCheckedOut") is False

    def test_versioning_shared(self):
        program = _make_mock_program(is_versioned=True, is_checked_out=True)
        status = MagicMock()
        status.getUser.return_value = "admin"
        status.getCheckoutVersion.return_value = 1
        program.getDomainFile().getCheckoutStatus.return_value = status
        info = _make_mock_program_info(program=program)
        result = collect_program_summary(info)
        ver = result["versioning"]
        assert ver["isVersioned"] is True
        assert ver["isCheckedOut"] is True
        assert ver["checkoutUser"] == "admin"

    def test_graceful_degradation_no_program(self):
        info = MagicMock()
        info.name = "broken"
        info.program = None
        result = collect_program_summary(info)
        assert result == {"name": "broken"}

    def test_graceful_degradation_api_error(self):
        info = _make_mock_program_info()
        info.program.getFunctionManager.side_effect = Exception("Java error")
        result = collect_program_summary(info)
        assert result["name"] == "test.exe"
        assert "functionCount" not in result  # skipped due to error


# ---------------------------------------------------------------------------
# collect_project_context tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCollectProjectContext:
    @patch("agentdecompile_cli.mcp_server.program_metadata.SESSION_CONTEXTS")
    def test_returns_none_when_empty(self, mock_store: MagicMock):
        session = MagicMock()
        session.project_handle = None
        session.open_programs = {}
        session.active_program_key = None
        mock_store.get_or_create.return_value = session
        assert collect_project_context("test-session") is None

    @patch("agentdecompile_cli.mcp_server.program_metadata.SESSION_CONTEXTS")
    def test_local_project(self, mock_store: MagicMock):
        session = MagicMock()
        session.project_handle = {"mode": "gpr-project", "path": "C:/projects/test.gpr", "projectName": "test"}
        session.open_programs = {"prog1": MagicMock(), "prog2": MagicMock()}
        session.active_program_key = "prog1"
        mock_store.get_or_create.return_value = session
        ctx = collect_project_context("s1")
        assert ctx is not None
        assert ctx["mode"] == "gpr-project"
        assert ctx["projectPath"] == "C:/projects/test.gpr"
        assert ctx["projectName"] == "test"
        assert ctx["programCount"] == 2
        assert ctx["activeProgram"] == "prog1"
        assert "serverHost" not in ctx

    @patch("agentdecompile_cli.mcp_server.program_metadata.SESSION_CONTEXTS")
    def test_shared_project(self, mock_store: MagicMock):
        session = MagicMock()
        session.project_handle = {
            "mode": "shared-server",
            "server_host": "10.0.0.1",
            "server_port": 13100,
            "repository": "kotor",
        }
        session.open_programs = {"swkotor": MagicMock()}
        session.active_program_key = "swkotor"
        mock_store.get_or_create.return_value = session
        ctx = collect_project_context("s2")
        assert ctx is not None
        assert ctx["mode"] == "shared-server"
        assert ctx["serverHost"] == "10.0.0.1"
        assert ctx["serverPort"] == 13100
        assert ctx["repository"] == "kotor"


# ---------------------------------------------------------------------------
# inject_project_context tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestInjectProjectContext:
    @patch("agentdecompile_cli.mcp_server.program_metadata.collect_project_context")
    def test_injects_into_json(self, mock_ctx: MagicMock):
        mock_ctx.return_value = {"mode": "gpr-project", "programCount": 1}
        original = json.dumps({"success": True, "data": "ok"})
        result = inject_project_context(original, "session-1")
        parsed = json.loads(result)
        assert "projectContext" in parsed
        assert parsed["projectContext"]["mode"] == "gpr-project"
        assert parsed["success"] is True

    @patch("agentdecompile_cli.mcp_server.program_metadata.collect_project_context")
    def test_skips_if_already_present(self, mock_ctx: MagicMock):
        mock_ctx.return_value = {"mode": "test"}
        original = json.dumps({"success": True, "projectContext": {"existing": True}})
        result = inject_project_context(original, "s")
        parsed = json.loads(result)
        assert parsed["projectContext"] == {"existing": True}

    @patch("agentdecompile_cli.mcp_server.program_metadata.collect_project_context")
    def test_skips_non_json(self, mock_ctx: MagicMock):
        mock_ctx.return_value = {"mode": "test"}
        original = "not json"
        assert inject_project_context(original, "s") == "not json"

    @patch("agentdecompile_cli.mcp_server.program_metadata.collect_project_context")
    def test_skips_when_no_context(self, mock_ctx: MagicMock):
        mock_ctx.return_value = None
        original = json.dumps({"success": True})
        result = inject_project_context(original, "s")
        parsed = json.loads(result)
        assert "projectContext" not in parsed

    def test_skips_debug_info_tool(self):
        original = json.dumps({"success": True})
        result = inject_project_context(original, "s", tool_name_normalized="debuginfo")
        parsed = json.loads(result)
        assert "projectContext" not in parsed
