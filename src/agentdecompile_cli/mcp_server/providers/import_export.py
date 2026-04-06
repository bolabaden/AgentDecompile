"""Import/Export Tool Provider - import-binary, export, analyze-program, checkin/checkout, etc.

  - import-binary: Load a file or folder into the project (language/compiler optional; analyzeAfterImport, enableVersionControl).
  - export: Write C/C++/gzf/sarif/xml/html from the project (createHeader, includeTypes, includeGlobals, tags filter).
  - analyze-program: Run or re-run Ghidra auto-analysis on an already-imported program.
  - changeprocessor / listprocessors: Processor/language and compiler-spec management.
  - checkin-program / checkout-program / checkout-status: Version-control operations for shared projects.

Session context (SESSION_CONTEXTS, get_current_mcp_session_id) is used to resolve the project and program for these operations.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time

from datetime import datetime, timezone
from itertools import islice
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from ghidrecomp.utility import analyze_program as run_analysis
from mcp import types

from agentdecompile_cli.app_logger import basename_hint, redact_session_id
from agentdecompile_cli.context import ProgramInfo
from agentdecompile_cli.mcp_server.providers._collectors import iter_items
from agentdecompile_cli.mcp_server.providers.project import ProjectToolProvider
from agentdecompile_cli.mcp_server.repository_adapter_listing import list_repository_adapter_items
from agentdecompile_cli.mcp_server.session_context import (
    SESSION_CONTEXTS,
    SessionContext,
    get_current_mcp_session_id,
    is_shared_server_handle,
)
from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
)
from agentdecompile_cli.registry import Tool

if TYPE_CHECKING:
    from ghidra.app.decompiler import DecompInterface as GhidraDecompInterface  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
    from ghidra.base.project import GhidraProject  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
    from ghidra.framework.client import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        RepositoryAdapter as GhidraRepositoryAdapter,
    )
    from ghidra.framework.model import (  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
        DomainFile as GhidraDomainFile,
        ProjectData as GhidraProjectData,
    )
    from ghidra.framework.remote import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]  # noqa: F401
        RepositoryItem as GhidraRepositoryItem,
    )
    from ghidra.program.model.lang import Language as GhidraLanguage  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
    from ghidra.program.model.listing import (  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
        BookmarkManager as GhidraBookmarkManager,
        Function as GhidraFunction,
        FunctionManager as GhidraFunctionManager,
        Program as GhidraProgram,
    )
    from ghidra.program.model.mem import Memory as GhidraMemory  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
    from ghidra.program.model.symbol import ReferenceManager as GhidraReferenceManager  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
    from ghidra.util.task import TaskMonitor as GhidraTaskMonitor  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]

logger = logging.getLogger(__name__)


def _jpype_enum_equal(java_val: Any, py_const: Any) -> bool:
    """Compare Ghidra/Java enum values from JPype to Python-imported constants.

    Direct ``java_val == py_const`` often fails (different proxy objects) so USER_DEFINED
    checks would always fail, emptying versioned check-in label snapshots and uploading
    revisions without create-label symbols (LFG 02d search-symbols empty).
    """
    if java_val is None or py_const is None:
        return False
    try:
        if java_val == py_const:
            return True
    except Exception:
        pass
    try:
        if bool(java_val.equals(py_const)):
            return True
    except Exception:
        pass
    try:
        return str(java_val) == str(py_const)
    except Exception:
        return False


def _sym_is_user_defined_label(sym: Any) -> bool:
    """True if ``sym`` is a USER_DEFINED LABEL (snapshot / reapply; tolerant of JPype enum proxies)."""
    from ghidra.program.model.symbol import SourceType as GhidraSourceType  # pyright: ignore[reportMissingImports]
    from ghidra.program.model.symbol import SymbolType as GhidraSymbolType  # pyright: ignore[reportMissingImports]

    try:
        src = sym.getSource()
        stype = sym.getSymbolType()
    except Exception:
        return False
    ud = _jpype_enum_equal(src, GhidraSourceType.USER_DEFINED)
    if not ud:
        try:
            su = str(src).upper()
            ud = "USER_DEFINED" in su or su.endswith("_USER_DEFINED")
        except Exception:
            ud = False
    if not ud:
        return False
    lab = _jpype_enum_equal(stype, GhidraSymbolType.LABEL)
    if not lab:
        try:
            lab = "LABEL" in str(stype).upper()
        except Exception:
            lab = False
    return bool(lab)


_SNAPSHOT_SKIP_AUTO_LABEL_RE = re.compile(r"^(FUN|LAB|SUB|DAT|EXT|PTR|ARRAY)_[0-9a-fA-F]+$")


def _sym_eligible_for_versioned_label_snapshot(sym: Any) -> bool:
    """Symbols to persist across versioned check-in reopen (JPype may not compare SourceType.USER_DEFINED reliably).

    Prefer strict USER_DEFINED LABEL match; otherwise accept any non-auto LABEL so create-label / custom names
    are not dropped from ``label_snap`` (empty snap → empty server revisions → LFG search-symbols 0).
    """
    if _sym_is_user_defined_label(sym):
        return True
    try:
        from ghidra.program.model.symbol import SymbolType as GhidraSymbolType  # pyright: ignore[reportMissingImports]

        stype = sym.getSymbolType()
        if not (_jpype_enum_equal(stype, GhidraSymbolType.LABEL) or "LABEL" in str(stype).upper()):
            return False
        nm = str(sym.getName()).strip()
        if not nm or _SNAPSHOT_SKIP_AUTO_LABEL_RE.match(nm):
            return False
        # Any remaining LABEL with a non-auto name is worth preserving: JPype/shared sometimes reports
        # user createLabel rows with SourceType strings that are neither USER_DEFINED nor plain ANALYSIS.
        return True
    except Exception:
        return False


def _stderr_is_only_jvm_java_tool_options_echo(stderr: str) -> bool:
    """True when stderr is only repeated ``Picked up JAVA_TOOL_OPTIONS:`` lines (harmless JVM echo noise)."""
    logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:_stderr_is_only_jvm_java_tool_options_echo")
    text = (stderr or "").strip()
    if not text:
        return False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("Picked up JAVA_TOOL_OPTIONS:"):
            continue
        return False
    return True


def _shared_repo_listing_contains_program(binaries_after: list[dict[str, Any]], program_name: str) -> bool:
    logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:_shared_repo_listing_contains_program")
    for item in binaries_after:
        iname = (item.get("name") or "").strip()
        ipath = (item.get("path") or "").strip()
        if iname == program_name or iname.lower() == program_name.lower():
            return True
        if ipath.endswith("/" + program_name) or ipath.endswith("/" + program_name.lower()):
            return True
    return False


def _ghidra_project_open_program_for_domain_file_save(ghidra_project: GhidraProject, domain_file: GhidraDomainFile, fallback_program_name: str) -> GhidraProgram | None:
    """Open a Program for a DomainFile so ``DomainFile.save`` has an open consumer.

    Ghidra 12 exposes ``GhidraProject.openProgram(String, String, boolean)``; ``openProgram(DomainFile, ...)``
    is not always available under JPype.
    """
    try:
        opened = ghidra_project.openProgram(domain_file)
        if opened is not None:
            return opened
    except Exception:
        pass
    pn = ""
    try:
        pn = str(domain_file.getPathname() or "").replace("\\", "/").strip()
    except Exception:
        pn = ""
    name = (fallback_program_name or "").strip()
    try:
        n2 = str(domain_file.getName() or "").strip()
        if n2:
            name = n2
    except Exception:
        pass
    if not name and pn:
        name = Path(pn).name
    if not pn:
        folder_path, program_name = "", name
    else:
        body = pn.strip("/")
        if "/" not in body:
            folder_path = ""
            program_name = name or body
        else:
            parent_body, basename = body.rsplit("/", 1)
            program_name = name or basename
            folder_path = f"/{parent_body}" if parent_body else ""
    if not program_name:
        return None
    return ghidra_project.openProgram(folder_path, program_name, False)


def _normalize_import_destination_folder(args: dict[str, Any]) -> str:
    """Ghidra folder pathname for saveAs (e.g. '/' or '/bin')."""
    logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:_normalize_import_destination_folder")
    raw = ToolProvider._get_str(args, "destinationfolder", "destination_folder", default="/")
    s = (raw or "/").strip().replace("\\", "/")
    if not s:
        s = "/"
    if not s.startswith("/"):
        s = "/" + s
    while "//" in s:
        s = s.replace("//", "/")
    if len(s) > 1:
        s = s.rstrip("/")
    return s or "/"


def _escape_xml_text(raw: str) -> str:
    """Escape text for safe use inside XML character content."""
    logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:_escape_xml_text")
    if not raw:
        return ""
    return str(raw).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;")


def _generate_program_xml(program: GhidraProgram, get_function_manager: Callable[[GhidraProgram], GhidraFunctionManager]) -> str:
    """Generate a comprehensive XML representation of the program (fallback when XmlExporter is unavailable)."""
    logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:_generate_program_xml")
    import xml.etree.ElementTree as ET  # noqa: PLC0415

    root: ET.Element = ET.Element("program")
    root.set("name", _escape_xml_text(program.getName()))
    root.set("language", _escape_xml_text(str(program.getLanguage().getLanguageID()) if program.getLanguage() else ""))
    root.set("compiler", _escape_xml_text(str(program.getCompilerSpec().getCompilerSpecID()) if program.getCompilerSpec() else ""))
    root.set("imageBase", str(program.getImageBase()))

    try:
        func_mgr: GhidraFunctionManager = get_function_manager(program)
        func_count: int = func_mgr.getFunctionCount()
        funcs_el: ET.Element = ET.SubElement(root, "functions")
        funcs_el.set("count", str(func_count))
        func: GhidraFunction
        for func in islice(func_mgr.getFunctions(True), 10000):
            fe = ET.SubElement(funcs_el, "function")
            fe.set("name", _escape_xml_text(func.getName()))
            fe.set("address", str(func.getEntryPoint()))
            fe.set("size", str(func.getBody().getNumAddresses()))
    except Exception:
        pass

    try:
        if program.getMemory() is not None:
            mem: GhidraMemory = program.getMemory()
            blocks_el: ET.Element = ET.SubElement(root, "memoryBlocks")
            for block in mem.getBlocks():
                be: ET.Element = ET.SubElement(blocks_el, "block")
                be.set("start", str(block.getStart()))
                be.set("end", str(block.getEnd()))
                be.set("name", _escape_xml_text(block.getName()))
    except Exception:
        pass

    try:
        ref_mgr: GhidraReferenceManager | None = program.getReferenceManager()
        if ref_mgr is not None:
            root.set("referenceCount", str(ref_mgr.getReferenceCount()))
    except Exception:
        pass

    ET.indent(root, space="  ")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode", default_namespace="")


def _generate_program_ascii_fallback(program: GhidraProgram, get_function_manager: Callable[[GhidraProgram], GhidraFunctionManager]) -> str:
    """Generate a plain-text program summary (fallback when AsciiExporter is unavailable)."""
    logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:_generate_program_ascii_fallback")
    lines: list[str] = []
    name: str = program.getName()
    lines.append(f"Program: {name}")
    lines.append("")
    if program.getLanguage():
        lines.append(f"Language: {program.getLanguage().getLanguageID()}")
    if program.getCompilerSpec():
        lines.append(f"Compiler: {program.getCompilerSpec().getCompilerSpecID()}")
    if program.getImageBase() is not None:
        lines.append(f"Image base: {program.getImageBase()}")
    lines.append("")
    lines.append("Functions:")
    lines.append("-" * 60)
    try:
        func_mgr = get_function_manager(program)
        func: GhidraFunction
        for func in islice(func_mgr.getFunctions(True), 10000):
            addr: str = str(func.getEntryPoint())
            fname: str = func.getName()
            size: str = str(func.getBody().getNumAddresses())
            lines.append(f"  {addr}  {fname}  (size: {size})")
    except Exception:
        lines.append("  (unable to list)")
    return "\n".join(lines)


def _generate_program_html(program: GhidraProgram, get_function_manager: Callable[[GhidraProgram], GhidraFunctionManager]) -> str:
    """Generate a comprehensive HTML report for the program."""
    logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:_generate_program_html")
    name: str = program.getName()
    lang: str = str(program.getLanguage().getLanguageID()) if program.getLanguage() else ""
    comp: str = str(program.getCompilerSpec().getCompilerSpecID()) if program.getCompilerSpec() else ""
    base: str = str(program.getImageBase()) if program.getImageBase() is not None else "0"

    func_rows: list[str] = []
    try:
        func_mgr: GhidraFunctionManager = get_function_manager(program)
        count: int = 0
        func: GhidraFunction
        for func in islice(func_mgr.getFunctions(True), 5000):
            if count >= 5000:
                func_rows.append('<tr><td colspan="5">… (truncated)</td></tr>')
                break
            addr: str = str(func.getEntryPoint())
            fname = (func.getName() or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            size: str = str(func.getBody().getNumAddresses())
            ext: str = "Yes" if func.isExternal() else ""
            thunk: str = "Yes" if func.isThunk() else ""
            func_rows.append(f"<tr><td>{addr}</td><td>{fname}</td><td>{size}</td><td>{ext}</td><td>{thunk}</td></tr>")
            count += 1
        func_count = count
    except Exception:
        func_count = 0
        func_rows.append('<tr><td colspan="5">Unable to list functions</td></tr>')

    functions_table: str = "\n".join(func_rows)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="generator" content="AgentDecompile"/>
<title>Program: {name.replace("&", "&amp;").replace("<", "&lt;")}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 1rem 2rem; background: #1a1a1a; color: #e0e0e0; }}
h1 {{ color: #7dd3fc; }}
h2 {{ color: #a5b4fc; margin-top: 1.5rem; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 0.5rem; }}
th, td {{ border: 1px solid #444; padding: 0.35rem 0.75rem; text-align: left; }}
th {{ background: #2d2d2d; color: #93c5fd; }}
tr:nth-child(even) {{ background: #252525; }}
.meta {{ display: grid; grid-template-columns: auto 1fr; gap: 0.25rem 1.5rem; max-width: 40rem; }}
.meta span:first-child {{ color: #94a3b8; }}
</style>
</head>
<body>
<h1>Program export: {name.replace("&", "&amp;").replace("<", "&lt;")}</h1>
<section>
<h2>Metadata</h2>
<div class="meta">
<span>Name</span><span>{name.replace("&", "&amp;").replace("<", "&lt;")}</span>
<span>Language</span><span>{lang.replace("&", "&amp;").replace("<", "&lt;")}</span>
<span>Compiler</span><span>{comp.replace("&", "&amp;").replace("<", "&lt;")}</span>
<span>Image base</span><span>{base.replace("&", "&amp;").replace("<", "&lt;")}</span>
<span>Functions</span><span>{func_count}</span>
</div>
</section>
<section>
<h2>Functions</h2>
<table>
<thead><tr><th>Address</th><th>Name</th><th>Size</th><th>External</th><th>Thunk</th></tr></thead>
<tbody>
{functions_table}
</tbody>
</table>
</section>
</body>
</html>
"""
    return html


class ImportExportToolProvider(ToolProvider):
    HANDLERS: dict[str, str] = {
        "importbinary": "_handle_import",
        "export": "_handle_export",
        "analyzeprogram": "_handle_analyze",
        "changeprocessor": "_handle_change_processor",
        "checkinprogram": "_handle_checkin",
        "checkoutprogram": "_handle_checkout",
        "checkoutstatus": "_handle_checkout_status",
        "listprocessors": "_handle_list_processors",
    }

    def _is_analysis_complete(self, program: GhidraProgram) -> bool:
        """Return True if program analysis is complete; safe for ProgramDB and headless."""
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._is_analysis_complete")
        try:
            get_state: Callable[[], Any] = program.getAnalysisState
            if get_state is not None:
                state: Any = get_state()
                if state is not None and hasattr(state, "isDone"):
                    return bool(state.isDone())
        except Exception:
            pass
        try:
            from ghidra.program.util import GhidraProgramUtilities  # pyright: ignore[reportMissingModuleSource]

            return bool(GhidraProgramUtilities.isAnalyzed(program))
        except Exception:
            return False

    def _wait_for_program_analysis_idle(self, program: GhidraProgram, *, max_wait_sec: float = 90.0) -> None:
        """If auto-analysis is running, block until it finishes or timeout (analysis holds DB transactions)."""
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._wait_for_program_analysis_idle")
        if program is None or max_wait_sec <= 0:
            return
        try:
            st = program.getAnalysisState()
            if st is None:
                return
            if hasattr(st, "isDone") and st.isDone():
                return
        except Exception:
            return
        deadline = time.time() + max_wait_sec
        while time.time() < deadline:
            try:
                st2 = program.getAnalysisState()
                if st2 is None or (hasattr(st2, "isDone") and st2.isDone()):
                    return
            except Exception:
                return
            time.sleep(0.25)

    def list_tools(self) -> list[types.Tool]:
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider.list_tools")
        return [
            types.Tool(
                name=Tool.IMPORT_BINARY.value,
                description="Load a raw binary file (e.g. .exe, .elf, .bin) from your hard drive into the Ghidra project so that it can be deeply analyzed. Use this to start a reverse engineering session on a new file.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "filePath": {"type": "string", "description": "The exact location on the filesystem of the file you want to bring into the Ghidra environment."},
                        "path": {"type": "string", "description": "Alternative key for filePath."},
                        "programName": {
                            "type": "string",
                            "description": "What to name this file inside the Ghidra project. If not provided, it assumes the original filename.",
                        },
                        "language": {
                            "type": "string",
                            "description": "The processor architecture ID (like 'x86:LE:64:default'). Omitting this uses the auto-analyzer's best guess.",
                        },
                        "compiler": {"type": "string", "description": "The compiler spec ID (like 'gcc' or 'windows'). Omitting this uses the auto analyzer."},
                        "recursive": {"type": "boolean", "default": False, "description": "If filePath is a folder, whether to import everything inside it."},
                        "maxDepth": {"type": "integer", "default": 16, "description": "How deep to recurse if importing a folder."},
                        "analyzeAfterImport": {
                            "type": "boolean",
                            "default": False,
                            "description": "Whether to immediately run Ghidra's heavy auto-analysis (can take a long time) right after importing.",
                        },
                        "enableVersionControl": {
                            "type": "boolean",
                            "default": False,
                            "description": "Request import into shared-project version control. Local-only imports cannot satisfy this request.",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name=Tool.EXPORT.value,
                description="Export your reverse engineering work directly out of the project. This allows you to generate C code files, HTML summaries, or binary save files (like `.gzf`) from your modified data.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The project file name you want to export."},
                        "outputPath": {"type": "string", "description": "Where to place the completed format file in the local filesystem."},
                        "format": {
                            "type": "string",
                            "enum": ["c", "cpp", "cxx", "gzf", "sarif", "xml", "html", "ascii"],
                            "default": "cpp",
                            "description": "What type of file to export. 'c'/'cpp' creates a single massive header/pseudocode file. 'gzf' creates a packed Ghidra Zip File archive.",
                        },
                        "createHeader": {
                            "type": "boolean",
                            "default": True,
                            "description": "Whether to build a standard C/C++ header block at the top containing environment types.",
                        },
                        "includeTypes": {"type": "boolean", "default": True, "description": "Whether to inject custom struct and typedef definitions."},
                        "includeGlobals": {"type": "boolean", "default": True, "description": "Whether to output discovered global variables."},
                        "includeComments": {"type": "boolean", "default": False, "description": "Whether to append user and Ghidra auto comments into the file inline."},
                        "tags": {"type": "string", "description": "If provided, limits the export only to functions matching specifically these tags."},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name=Tool.ANALYZE_PROGRAM.value,
                description="Trigger the heavy auto-analysis subsystem inside Ghidra. Use this after loading a program if you notice data looks incomplete, strings are unbroken, or functions fail to decompile correctly. This tool refuses to rerun once Ghidra already analyzed the program unless you explicitly set force=true.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The target program to run analyzers over."},
                        "analyzers": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "If provided, lists specific string names of Ghidra analyzer modules to use instead of 'all of them'.",
                        },
                        "force": {
                            "type": "boolean",
                            "default": False,
                            "description": "Force re-analysis even when Ghidra already marked the program as analyzed. This should be rare.",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name=Tool.CHECKIN_PROGRAM.value,
                description="If you are using a shared/version-controlled Ghidra Server project, use this to commit your changes directly to the server, preserving your work as a new version. Omit program_path to check in every open program that is checked out and can be checked in (checkin all).",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "program_path": {
                            "type": "string",
                            "description": "Your local version of the file you intend to push upstream. Omit to check in all open programs that are checked out.",
                        },
                        "comment": {"type": "string", "description": "The commit message for history tracking."},
                        "keep_checked_out": {"type": "boolean", "default": False, "description": "Whether to retain an exclusive file lock after pushing the changes."},
                        "format": {
                            "type": "string",
                            "enum": ["markdown", "json"],
                            "default": "markdown",
                            "description": "Output format (default: markdown). Use --format json / -f json only when you strictly need machine-readable output; markdown is recommended.",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name=Tool.CHECKOUT_PROGRAM.value,
                description="Check out a versioned file from the shared Ghidra Server repository so it can be modified. Must be called before making changes when working with a version-controlled project. Use checkin-program when done.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "program_path": {"type": "string", "description": "Path to the program in the Ghidra project to check out."},
                        "exclusive": {
                            "type": "boolean",
                            "default": False,
                            "description": "Whether to request an exclusive (write-lock) checkout. Exclusive checkout fails if others already have it checked out.",
                        },
                        "format": {
                            "type": "string",
                            "enum": ["markdown", "json"],
                            "default": "markdown",
                            "description": "Output format (default: markdown). Use --format json / -f json only when you strictly need machine-readable output; markdown is recommended.",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name=Tool.CHECKOUT_STATUS.value,
                description="Query the checkout state of a versioned Ghidra project file. Shows whether the file is checked out, who has it checked out, and whether it has local modifications since checkout.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "program_path": {"type": "string", "description": "Path to the program in the Ghidra project to query."},
                        "format": {
                            "type": "string",
                            "enum": ["markdown", "json"],
                            "default": "markdown",
                            "description": "Output format (default: markdown). Use --format json / -f json only when you strictly need machine-readable output; markdown is recommended.",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name=Tool.CHANGE_PROCESSOR.value,
                description="Change the CPU architecture or target compiler specification used for disassembling memory. This forces the entire program to restructure itself around a radically different interpretation, so use carefully.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The target project to mutilate."},
                        "language": {"type": "string", "description": "The exact Language ID (like 'ARM:LE:32:v8') to override with."},
                        "compiler": {"type": "string", "description": "The compiler spec ID you want applied."},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name=Tool.LIST_PROCESSORS.value,
                description="List all the CPU instruction architectures currently supported by the Ghidra database engine. Used to discover exact IDs needed for change-processor.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "filter": {"type": "string", "description": "A case-insensitive text substring to narrow down the list (e.g. 'mips')."},
                    },
                    "required": [],
                },
            ),
        ]

    @staticmethod
    def _iter_files_to_import(source: Path, recursive: bool, max_depth: int):
        """Yield candidate files under ``source`` respecting recursion/depth options."""
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._iter_files_to_import")
        if source.is_file():
            yield source
            return

        root_depth = len(source.parts)
        for entry in source.rglob("*"):
            if not entry.is_file():
                continue
            if not recursive and entry.parent != source:
                continue
            if len(entry.parts) - root_depth > max_depth:
                continue
            yield entry

    @staticmethod
    def _list_repository_items(repository_adapter: GhidraRepositoryAdapter) -> list[dict[str, Any]]:
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._list_repository_items")
        return list_repository_adapter_items(repository_adapter, log=logger)

    def _handle_shared_import(
        self,
        source: Path,
        recursive: bool,
        analyze_after_import: bool,
        *,
        program_file_name: str | None = None,
    ) -> dict[str, Any]:
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._handle_shared_import")
        session_id = get_current_mcp_session_id()
        session = SESSION_CONTEXTS.get_or_create(session_id)
        handle = session.project_handle if isinstance(session.project_handle, dict) else None
        if not handle or not is_shared_server_handle(handle):
            return {
                "action": "import",
                "importedFrom": str(source),
                "analysisRequested": analyze_after_import,
                "versionControlRequested": True,
                "versionControlEnabled": False,
                "success": False,
                "error": "Shared version-control import requires an active shared-server session. Call open against the shared server first.",
            }

        server_host = str(handle.get("server_host") or "").strip()
        server_port = int(handle.get("server_port") or 13100)
        repository_name = str(handle.get("repository_name") or "").strip()
        server_username = str(handle.get("server_username") or "").strip()
        server_password = str(handle.get("server_password") or "")
        repository_adapter = handle.get("repository_adapter")

        if not server_host or not repository_name or repository_adapter is None:
            return {
                "action": "import",
                "importedFrom": str(source),
                "analysisRequested": analyze_after_import,
                "versionControlRequested": True,
                "versionControlEnabled": False,
                "success": False,
                "error": "Shared version-control import requires repository session state. Re-run open against the shared server and retry.",
            }

        ghidra_install_dir = os.environ.get("GHIDRA_INSTALL_DIR", "").strip()
        if not ghidra_install_dir:
            return {
                "action": "import",
                "importedFrom": str(source),
                "analysisRequested": analyze_after_import,
                "versionControlRequested": True,
                "versionControlEnabled": False,
                "success": False,
                "error": "GHIDRA_INSTALL_DIR is required for shared version-control import.",
            }

        script_name = "analyzeHeadless.bat" if sys.platform == "win32" else "analyzeHeadless"
        analyze_headless = Path(ghidra_install_dir) / "support" / script_name
        if not analyze_headless.exists():
            return {
                "action": "import",
                "importedFrom": str(source),
                "analysisRequested": analyze_after_import,
                "versionControlRequested": True,
                "versionControlEnabled": False,
                "success": False,
                "error": f"analyzeHeadless script not found: {analyze_headless}",
            }

        effective_program_file_name = (program_file_name or "").strip() or source.name
        source_for_import = source
        staged_parent: Path | None = None
        if effective_program_file_name != source.name:
            import tempfile

            staged_parent = Path(tempfile.mkdtemp(prefix="agentdecompile_staged_import_"))
            staged_file = staged_parent / effective_program_file_name
            shutil.copy2(source, staged_file)
            source_for_import = staged_file

        def _cleanup_staged() -> None:
            if staged_parent is not None:
                shutil.rmtree(staged_parent, ignore_errors=True)

        # ALTERNATIVE: Use PyGhidra API directly with repository adapter to avoid analyzeHeadless auth issues
        # This avoids the th3w1zard1 cached username problem by using the already-authenticated repository_adapter
        try:
            if not repository_adapter.isConnected():
                repository_adapter.connect()

            # Get the manager's ghidra_project or create a temporary one connected to the repository
            ghidra_project: GhidraProject | None = getattr(self._manager, "ghidra_project", None) if self._manager else None
            if ghidra_project is None:
                # Create a temporary project connected to the repository
                import tempfile

                from agentdecompile_cli.launcher import PyGhidraContext

                temp_proj_dir = tempfile.mkdtemp(prefix="agentdecompile_shared_import_")
                try:
                    temp_context = PyGhidraContext(
                        project_name="temp_import",
                        project_path=temp_proj_dir,
                        force_analysis=False,
                        verbose_analysis=False,
                        no_symbols=False,
                    )
                    ghidra_project = temp_context.project
                except Exception as e:
                    logger.warning(f"Failed to create temp project for shared import: {e.__class__.__name__}: {e}, falling back to analyzeHeadless")
                    ghidra_project = None

            if ghidra_project is not None:
                # Use PyGhidra API to import directly into repository
                from ghidra.util.task import TaskMonitor as GhidraTaskMonitor  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
                from java.io import File as JavaFile  # pyright: ignore[reportMissingImports]

                # Import the binary into the (possibly local) project
                program = ghidra_project.importProgram(JavaFile(str(source_for_import)))
                if program is None:
                    raise RuntimeError("importProgram returned None")

                # Use the shared repository's root folder, not the local project's.
                # The repository_adapter is a RepositoryAdapter; we need to get ProjectData from a project connected to the repository.
                # The ghidra_project may be a local project, so we need to get its ProjectData which should be connected to the repository.
                root_folder = None
                try:
                    # Try to get ProjectData from the project - if it's connected to the repository, this will be the repo's root
                    project_data = ghidra_project.getProject().getProjectData()
                    if project_data is not None:
                        root_folder = project_data.getRootFolder()
                        logger.info("Got root folder from project ProjectData for shared repository: %s", repository_name)
                except Exception as repo_exc:
                    logger.warning("Could not get root folder from project ProjectData: %s", repo_exc)

                # If that didn't work, try getRootFolder() directly on the project
                if root_folder is None:
                    try:
                        root_folder = ghidra_project.getRootFolder()
                        logger.info("Got root folder from ghidra_project.getRootFolder() for shared repository: %s", repository_name)
                    except Exception as root_exc:
                        logger.warning("Could not get root folder from ghidra_project.getRootFolder(): %s", root_exc)

                # DO NOT fall back to local project_data - we're in shared-server mode, must use repository
                if root_folder is None:
                    logger.error("Could not get repository root folder for shared import - repository adapter may be disconnected")
                    program.release(ghidra_project)
                    raise RuntimeError(f"repository root folder not available for shared repository '{repository_name}'. Repository adapter may be disconnected.")

                # Save the program to the repository root folder (honor programPath / programName from tool args)
                program_name = effective_program_file_name
                transient_program_released = False
                try:
                    # Strategy: Save program as packed file first, then import the packed file to repository
                    # This avoids "Object is busy" errors from trying to createFile with an active program
                    import tempfile

                    from java.io import File as JavaFile  # pyright: ignore[reportMissingImports]

                    # Save to temp packed file using ghidra_project.saveAsPackedFile
                    temp_packed = tempfile.NamedTemporaryFile(suffix=".gzf", delete=False)
                    temp_packed_path = temp_packed.name
                    temp_packed.close()

                    try:
                        # Save program as packed file
                        ghidra_project.saveAsPackedFile(program, JavaFile(temp_packed_path), True)
                        program.release(ghidra_project)
                        transient_program_released = True

                        # Now import the packed file to the repository root folder
                        packed_file = JavaFile(temp_packed_path)
                        domain_file = None
                        try:
                            domain_file = root_folder.createFile(program_name, packed_file, GhidraTaskMonitor.DUMMY)
                        except Exception as create_exc:
                            err_t = type(create_exc).__name__
                            err_s = str(create_exc).lower()
                            if "duplicate" in err_t.lower() or "already exists" in err_s:
                                try:
                                    if root_folder is not None and hasattr(root_folder, "getFile"):
                                        domain_file = root_folder.getFile(program_name)
                                except Exception:
                                    domain_file = None
                                if domain_file is None:
                                    raise
                            else:
                                raise
                        if domain_file is None:
                            raise RuntimeError("createFile returned None")

                        # DomainFile.save() requires an open Program consumer (else AssertException: domainObj not open).
                        repo_program = _ghidra_project_open_program_for_domain_file_save(ghidra_project, domain_file, program_name)
                        if repo_program is None:
                            raise RuntimeError("openProgram returned None after shared repository createFile")
                        try:
                            # Match _persist_open_program_for_versioned_checkin: gp.save while batch tx active.
                            try:
                                ghidra_project.save(repo_program)
                            except Exception as exc:
                                logger.debug("ghidra_project.save after shared createFile: %s", exc)
                            self._end_all_open_transactions_on_program(repo_program)
                            try:
                                domain_file.save(GhidraTaskMonitor.DUMMY)
                            except Exception as exc:
                                logger.debug("domain_file.save after shared createFile gp.save: %s", exc)
                        finally:
                            repo_program.release(ghidra_project)

                        # addToVersionControl fails with FileInUseException while a Program consumer is open — run after release.
                        if not domain_file.isVersioned():
                            try:
                                # keepCheckedOut=True matches typical GUI flow (keep working copy) and avoids
                                # checkedOut+!canCheckin dead-ends where no domain mutation is recorded yet.
                                domain_file.addToVersionControl("Initial import", True, GhidraTaskMonitor.DUMMY)
                                if domain_file.isVersioned():
                                    logger.info("Added '%s' to version control in shared repository", program_name)
                                else:
                                    logger.warning("addToVersionControl called for '%s' but file is still not versioned", program_name)
                            except Exception as vc_exc:
                                logger.warning("Failed to add '%s' to version control: %s", program_name, vc_exc)
                                import traceback

                                logger.debug("addToVersionControl exception traceback: %s", traceback.format_exc())

                        # Without a server check-in, RepositoryAdapter.getItemList stays empty and other MCP
                        # sessions see programCount=0 even though local ProjectData shows the file as versioned.
                        try:
                            from ghidra.framework.data import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
                                DefaultCheckinHandler as GhidraDefaultCheckinHandler,
                            )

                            if domain_file is not None and bool(domain_file.isVersioned()):
                                df_publish = domain_file
                                try:
                                    if root_folder is not None and hasattr(root_folder, "getFile"):
                                        rf_df = root_folder.getFile(program_name)
                                        if rf_df is not None:
                                            df_publish = rf_df
                                except Exception:
                                    pass
                                domain_file = df_publish

                                # Always record a real program mutation + flush so canCheckin / modifiedSinceCheckout
                                # match Ghidra's checkin contract (same helpers as checkin-program).
                                try:
                                    self._try_mark_versioned_checkout_dirty(df_publish)
                                    bump_prog = _ghidra_project_open_program_for_domain_file_save(
                                        ghidra_project,
                                        df_publish,
                                        program_name,
                                    )
                                    if bump_prog is None:
                                        logger.warning(
                                            "Shared import: openProgram None for %r; initial checkin may fail",
                                            program_name,
                                        )
                                    if bump_prog is not None:
                                        try:
                                            self._bump_versioned_checkout_dirty_bookmark(bump_prog)
                                            self._persist_open_program_for_versioned_checkin(bump_prog)
                                            self._notify_domain_file_changed_for_versioned_checkin(
                                                df_publish,
                                                bump_prog,
                                            )
                                            try:
                                                pdf = bump_prog.getDomainFile()
                                                if pdf is not None and pdf is not df_publish:
                                                    self._try_mark_versioned_checkout_dirty(pdf)
                                                    self._notify_domain_file_changed_for_versioned_checkin(
                                                        pdf,
                                                        bump_prog,
                                                    )
                                            except Exception:
                                                pass
                                            self._end_all_open_transactions_on_program(bump_prog)
                                            try:
                                                df_publish.save(GhidraTaskMonitor.DUMMY)
                                            except Exception as save_exc:
                                                logger.debug("shared import pre-publish domain save: %s", save_exc)
                                        finally:
                                            try:
                                                bump_prog.release(ghidra_project)
                                            except Exception:
                                                pass
                                    self._try_mark_versioned_checkout_dirty(df_publish)
                                except Exception as bump_exc:
                                    logger.warning("Shared import pre-publish dirty bump: %s", bump_exc)

                                def _try_publish_initial() -> bool:
                                    if not domain_file.canCheckin():
                                        return False
                                    try:
                                        pub_h = GhidraDefaultCheckinHandler(
                                            "Initial import (import-binary)",
                                            False,
                                            False,
                                        )
                                        domain_file.checkin(pub_h, GhidraTaskMonitor.DUMMY)
                                        logger.info(
                                            "Shared import: published initial revision of %r to Ghidra Server",
                                            program_name,
                                        )
                                        return True
                                    except Exception as ci_exc:
                                        logger.debug("shared import initial checkin attempt: %s", ci_exc)
                                        return False

                                published = _try_publish_initial()
                                if not published and not domain_file.isCheckedOut():
                                    for exclusive_co in (False, True):
                                        try:
                                            domain_file.checkout(exclusive_co, GhidraTaskMonitor.DUMMY)
                                            logger.debug(
                                                "shared import pre-publish checkout exclusive=%s ok",
                                                exclusive_co,
                                            )
                                            break
                                        except Exception as co_exc:
                                            logger.debug(
                                                "shared import pre-publish checkout exclusive=%s: %s",
                                                exclusive_co,
                                                co_exc,
                                            )
                                if not published:
                                    published = _try_publish_initial()
                                if not published:
                                    logger.warning(
                                        "Shared import: could not publish initial revision of %r (canCheckin=%s checkedOut=%s); server listing may stay empty",
                                        program_name,
                                        domain_file.canCheckin() if domain_file is not None else None,
                                        domain_file.isCheckedOut() if domain_file is not None else None,
                                    )
                        except Exception as pub_exc:
                            logger.warning(
                                "Shared import: initial publish failed for %r (server listing may stay empty): %s",
                                program_name,
                                pub_exc,
                            )

                        if analyze_after_import:
                            from ghidra.program.util import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
                                ProgramUtilities as GhidraProgramUtilities,
                            )

                            repo_program = _ghidra_project_open_program_for_domain_file_save(ghidra_project, domain_file, program_name)
                            if repo_program is None:
                                raise RuntimeError("openProgram returned None for shared import analysis")
                            try:
                                GhidraProgramUtilities.analyze(repo_program, GhidraTaskMonitor.DUMMY)
                                try:
                                    ghidra_project.save(repo_program)
                                except Exception as exc:
                                    logger.debug("ghidra_project.save after shared import analysis: %s", exc)
                                self._end_all_open_transactions_on_program(repo_program)
                                try:
                                    domain_file.save(GhidraTaskMonitor.DUMMY)
                                except Exception as exc:
                                    logger.debug("domain_file.save after analysis: %s", exc)
                            finally:
                                repo_program.release(ghidra_project)
                    finally:
                        # Clean up temp file
                        try:
                            os.unlink(temp_packed_path)
                        except Exception:
                            pass

                    # Confirm the program appears in the server listing (published by initial checkin above).
                    in_folder = False
                    try:
                        if root_folder is not None and hasattr(root_folder, "getFile"):
                            in_folder = root_folder.getFile(program_name) is not None
                    except Exception as exc:
                        logger.debug("shared import folder getFile check: %s", exc)
                    versioned_ok = False
                    try:
                        versioned_ok = bool(domain_file is not None and domain_file.isVersioned())
                    except Exception:
                        versioned_ok = False
                    binaries = self._list_repository_items(repository_adapter)
                    listed = _shared_repo_listing_contains_program(binaries, program_name)
                    if not listed:
                        for attempt in range(8):
                            time.sleep(0.45)
                            try:
                                if not repository_adapter.isConnected():
                                    repository_adapter.connect()
                            except Exception:
                                pass
                            binaries = self._list_repository_items(repository_adapter)
                            if _shared_repo_listing_contains_program(binaries, program_name):
                                listed = True
                                logger.info("PyGhidra shared import: server listing showed %r after retry %s", program_name, attempt + 1)
                                break
                            try:
                                if root_folder is not None and hasattr(root_folder, "getFile"):
                                    in_folder = root_folder.getFile(program_name) is not None
                                    if in_folder:
                                        logger.debug(
                                            "PyGhidra shared import: retry %s folder still has %r (server listing may lag)",
                                            attempt + 1,
                                            program_name,
                                        )
                            except Exception:
                                pass
                            try:
                                versioned_ok = bool(domain_file is not None and domain_file.isVersioned())
                            except Exception:
                                versioned_ok = False
                    if not listed:
                        # RepositoryAdapter listing can lag or stay empty while ProjectData already has the
                        # versioned domain file (LFG: adapter_items=0 → analyzeHeadless → broken VC / 02d empty).
                        if in_folder and versioned_ok:
                            path_key = f"/{str(program_name).lstrip('/')}"
                            binaries = [
                                {
                                    "name": str(program_name),
                                    "path": path_key,
                                    "type": "Program",
                                },
                            ]
                            logger.info(
                                "PyGhidra shared import: adapter listing empty but folder has %r and file is versioned; "
                                "using synthetic listing (skip analyzeHeadless)",
                                program_name,
                            )
                        else:
                            raise RuntimeError(
                                f"PyGhidra shared import: Ghidra Server listing never showed {program_name!r} (local folder={in_folder}, versioned={versioned_ok}, adapter_items={len(binaries)}); will try analyzeHeadless"
                            )

                    SESSION_CONTEXTS.set_project_binaries(session_id, binaries)

                    _cleanup_staged()
                    return {
                        "action": "import",
                        "importedFrom": str(source),
                        "filesDiscovered": 1,
                        "filesImported": 1,
                        "importedPrograms": [{"sourcePath": str(source), "programName": program_name}],
                        "analysisRequested": analyze_after_import,
                        "versionControlRequested": True,
                        "versionControlEnabled": True,
                        "success": True,
                        "repository": repository_name,
                        "programs": binaries,
                        "method": "pyghidra_api",
                    }
                except Exception:
                    if not transient_program_released:
                        try:
                            program.release(ghidra_project)
                        except Exception:
                            pass
                    logger.warning("PyGhidra API createFile failed, falling back to analyzeHeadless", exc_info=True)
                    raise
        except Exception:
            logger.warning("PyGhidra API import failed, falling back to analyzeHeadless", exc_info=True)
            # Fall through to analyzeHeadless method

        # FALLBACK: Use analyzeHeadless (may have auth issues with cached username)
        repository_url = f"ghidra://{server_host}:{server_port}/{repository_name}"
        # Build command: repo URL first (required by AnalyzeHeadless), then -import, then -connect/-p.
        # Use env GHIDRA_USER_DIR (temp dir) so no cached server username is used. Do not pass
        # -ghidraUserDir to analyzeHeadless (not a valid AnalyzeHeadless option).
        try:
            import tempfile

            ghidra_user_dir = tempfile.mkdtemp(prefix="agentdecompile_ghidra_user_")
            env = dict(os.environ)
            env["GHIDRA_USER_DIR"] = ghidra_user_dir
            # Headless runs in a separate JVM: Ghidra's repository client often defaults the Ghidra
            # user id from the OS account (Windows USERNAME) before honoring -connect. Align env with
            # the credentials used for PyGhidra open() so stdin password matches the prompted user.
            if server_username:
                if sys.platform == "win32":
                    env["USERNAME"] = server_username
                else:
                    env["USER"] = server_username
                    env["LOGNAME"] = server_username
            # Also set via Java system property in case the batch file doesn't pass GHIDRA_USER_DIR correctly
            # The launch.bat should pick this up and pass it to the JVM
            java_opts_parts: list[str] = []
            if server_username:
                java_opts_parts.append(f"-Duser.name={server_username}")
            # Add GHIDRA_USER_DIR as a system property too
            java_opts_parts.append(f"-Dghidra.user.dir={ghidra_user_dir}")
            # Merge with existing JAVA_TOOL_OPTIONS
            existing_opts: str = env.get("JAVA_TOOL_OPTIONS", "").strip()
            if existing_opts:
                # Remove any conflicting -Duser.name or -Dghidra.user.dir
                existing_parts: list[str] = [opt for opt in existing_opts.split() if not (opt.startswith("-Duser.name=") or opt.startswith("-Dghidra.user.dir="))]
                java_opts_parts = existing_parts + java_opts_parts
            env["JAVA_TOOL_OPTIONS"] = " ".join(java_opts_parts)

            # Ghidra docs (analyzeHeadlessREADME): ghidra:// URL, then -import, then -connect/-p -commit.
            # Putting -connect before -import causes the repo connection to use the OS login name on Windows.
            command: list[str] = [str(analyze_headless), repository_url, "-import", str(source_for_import)]
            if recursive and source_for_import.is_dir():
                command.append("-recursive")
            if not analyze_after_import:
                command.append("-noanalysis")
            if server_username:
                command.extend(["-connect", server_username, "-p"])
            command.append("-commit")

            # Log command for debugging (redact password)
            logger.info(
                "[_handle_shared_import] Running analyzeHeadless: %s (username: %s, password: %s, GHIDRA_USER_DIR: %s)",
                " ".join(command),
                server_username or "none",
                "***" if server_password else "none",
                ghidra_user_dir,
            )
            if server_username:
                env["GHIDRA_SERVER_USERNAME"] = server_username
            # Use shell=False but ensure password is piped correctly
            # analyzeHeadless -p prompts for password; we pipe it via stdin
            # Note: analyzeHeadless may read username from cached project files before processing -connect flag
            # The -Duser.name JVM option should override cached values
            completed = subprocess.run(
                command,
                input=(server_password + "\n") if server_username else None,
                text=True,
                capture_output=True,
                timeout=600,
                check=False,
                env=env,
            )
        except Exception as exc:
            _cleanup_staged()
            return {
                "action": "import",
                "importedFrom": str(source),
                "analysisRequested": analyze_after_import,
                "versionControlRequested": True,
                "versionControlEnabled": False,
                "success": False,
                "error": str(exc),
            }
        finally:
            _cleanup_staged()

        stdout = completed.stdout.strip()
        stderr = completed.stderr.strip()

        def _refresh_import_succeeded() -> bool:
            try:
                if not repository_adapter.isConnected():
                    repository_adapter.connect()
                listing = self._list_repository_items(repository_adapter)
                return _shared_repo_listing_contains_program(listing, effective_program_file_name)
            except Exception:
                return False

        # Always refresh repository listing and treat as success if file appears (analyzeHeadless
        # may write JVM warnings to stderr or return non-zero despite committing)
        import_succeeded: bool = _refresh_import_succeeded()

        # Windows/JVM often prints only "Picked up JAVA_TOOL_OPTIONS: ..." to stderr while analyzeHeadless
        # still commits; listing can be briefly stale — retry before failing the step.
        if completed.returncode != 0 and not import_succeeded and _stderr_is_only_jvm_java_tool_options_echo(stderr):
            for attempt in range(6):
                time.sleep(1.25)
                import_succeeded = _refresh_import_succeeded()
                if import_succeeded:
                    logger.info(
                        "Shared import: analyzeHeadless rc=%s but program appeared after retry %s",
                        completed.returncode,
                        attempt + 1,
                    )
                    break

        if completed.returncode != 0 and not import_succeeded:
            err_body = stderr or stdout or f"analyzeHeadless exited with {completed.returncode}"
            if _stderr_is_only_jvm_java_tool_options_echo(stderr):
                err_body = (
                    stdout.strip()
                    or f"analyzeHeadless exited with {completed.returncode} (repository listing did not show the imported program; stderr was JVM option echo only)"
                )
            return {
                "action": "import",
                "importedFrom": str(source),
                "analysisRequested": analyze_after_import,
                "versionControlRequested": True,
                "versionControlEnabled": False,
                "success": False,
                "error": err_body,
                "exitCode": completed.returncode,
            }

        # Exit code 0 is not enough: headless may report success without the expected domain file name in the repo.
        if not import_succeeded:
            for attempt in range(8):
                time.sleep(1.25)
                import_succeeded = _refresh_import_succeeded()
                if import_succeeded:
                    logger.info(
                        "Shared import: repository listing showed %r after extra retry %s",
                        effective_program_file_name,
                        attempt + 1,
                    )
                    break
        if not import_succeeded:
            return {
                "action": "import",
                "importedFrom": str(source),
                "analysisRequested": analyze_after_import,
                "versionControlRequested": True,
                "versionControlEnabled": False,
                "success": False,
                "error": (
                    f"Shared import: repository listing does not contain expected program {effective_program_file_name!r} (analyzeHeadless exitCode={completed.returncode}). Stdout/stderr may still show a different imported name."
                ),
                "exitCode": completed.returncode,
            }

        try:
            if not repository_adapter.isConnected():
                repository_adapter.connect()
        except Exception:
            pass

        binaries: list[dict[str, Any]] = self._list_repository_items(repository_adapter)
        SESSION_CONTEXTS.set_project_binaries(session_id, binaries)

        return {
            "action": "import",
            "importedFrom": str(source),
            "filesDiscovered": 1 if source.is_file() else len(list(self._iter_files_to_import(source, recursive, 16))),
            "filesImported": 1,
            "importedPrograms": [{"sourcePath": str(source), "programName": effective_program_file_name}],
            "analysisRequested": analyze_after_import,
            "versionControlRequested": True,
            "versionControlEnabled": True,
            "success": True,
            "repository": repository_name,
            "programs": binaries,
            "stdout": stdout or None,
        }

    def _merge_imported_program_into_session_binaries(
        self,
        session_id: str,
        *,
        program_name: str,
        path_in_project: str,
    ) -> None:
        """Append/replace one program in session binary index so list-project-files works before domain refresh."""
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._merge_imported_program_into_session_binaries")
        cur = SESSION_CONTEXTS.get_project_binaries(session_id, fallback_to_latest=False)
        by_key: dict[str, dict[str, Any]] = {}
        for it in cur:
            p = str(it.get("path") or it.get("name") or "").strip()
            if p:
                by_key[p] = dict(it)
        key = (path_in_project or "").strip() or f"/{program_name}"
        by_key[key] = {"name": program_name, "path": key, "type": "Program"}
        SESSION_CONTEXTS.set_project_binaries(session_id, list(by_key.values()))

    async def _handle_import(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._handle_import")
        file_path: str = self._get_str(args, "path", "filepath", "file", "binarypath", "binary", default="")

        if not file_path:
            # Resource / no-args mode: return open programs instead of trying to import
            session_id = get_current_mcp_session_id()
            snapshot = SESSION_CONTEXTS.get_session_snapshot(session_id)
            open_keys: list[str] = list(snapshot.get("openProgramKeys") or [])
            project_binaries = SESSION_CONTEXTS.get_project_binaries(session_id, fallback_to_latest=True) or []
            return create_success_response(
                {
                    "openPrograms": open_keys,
                    "projectBinaries": project_binaries,
                    "note": "No path provided. Pass path= to import a binary file into the project.",
                }
            )
        prog_name: str = self._get_str(args, "programname", "name")
        language: str = self._get_str(args, "language", "lang", "processor")
        compiler: str = self._get_str(args, "compiler", "compilerspec", "compilerspecid")
        recursive: bool = self._get_bool(args, "recursive", default=False)
        max_depth: int | None = self._get_int(args, "maxdepth", default=16)
        if max_depth is None:
            max_depth = 16
        analyze_after_import: bool = self._get_bool(args, "analyzeafterimport", default=False)
        enable_version_control: bool = self._get_bool(args, "enableversioncontrol", default=False)
        program_path_dest: str = self._get_str(args, "programpath")
        repo_program_name: str | None = (prog_name or "").strip()
        if not repo_program_name and program_path_dest:
            pp = program_path_dest.strip().replace("\\", "/")
            repo_program_name = pp.rsplit("/", 1)[-1].lstrip("/")
        if not repo_program_name:
            repo_program_name = None

        source: Path = Path(file_path).expanduser().resolve()
        if not source.exists():
            raise ValueError(f"File not found: {source}")

        if enable_version_control:
            return create_success_response(
                self._handle_shared_import(
                    source,
                    recursive,
                    analyze_after_import,
                    program_file_name=repo_program_name,
                ),
            )

        imported_programs: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        discovered_count: int = 0
        dest_folder: str = _normalize_import_destination_folder(args)
        session_id: str = get_current_mcp_session_id()

        # Prefer the session's Ghidra project (launcher) so import goes into the correct project.
        ghidra_project: GhidraProject | None = getattr(self._manager, "ghidra_project", None) if self._manager else None

        # If no project is open, try to open it from AGENT_DECOMPILE_PROJECT_PATH so imports persist.
        # This ensures import-binary works even when the project wasn't explicitly opened first.
        if ghidra_project is None and self._manager is not None:
            project_path = os.getenv("AGENT_DECOMPILE_PROJECT_PATH") or os.getenv("AGENTDECOMPILE_PROJECT_PATH")
            if project_path:
                project_path_str = str(project_path).strip()
                if project_path_str:
                    try:
                        _pp = self._manager._get_project_provider()
                        project_tool = _pp if isinstance(_pp, ProjectToolProvider) else None
                        if project_tool is not None:
                            logger.info(
                                "import-binary: ghidra_project is None, attempting to open project from %s",
                                project_path_str,
                            )
                            await project_tool._handle_open_project({"path": project_path_str})
                            # Re-check ghidra_project after opening
                            ghidra_project = getattr(self._manager, "ghidra_project", None)
                            if ghidra_project is None:
                                logger.warning("import-binary: open succeeded but ghidra_project is still None; imports may not persist to the expected project")
                    except Exception as e:
                        logger.warning(
                            "import-binary: failed to auto-open project from %s: %s; will use temporary ProjectManager (imports may not persist)",
                            project_path_str,
                            e,
                        )

        try:
            if ghidra_project is not None:
                from java.io import File  # pyright: ignore[reportMissingImports]

                for item in self._iter_files_to_import(source, recursive, max_depth):
                    discovered_count += 1
                    name = (prog_name or item.name or "").strip() or item.name
                    try:
                        program = ghidra_project.importProgram(File(str(item)))
                        if program is None:
                            raise RuntimeError("importProgram returned None")
                        # Always saveAs into the project domain. Previously saveAs ran only when the
                        # display name differed from the source filename, so imports like foo.exe
                        # never persisted and list-project-files saw an empty tree (matches PyGhidraContext.import_binary).
                        try:
                            if hasattr(program, "setName"):
                                program.setName(name)
                            elif hasattr(program, "name"):
                                setattr(program, "name", name)
                        except Exception:
                            pass
                        ghidra_project.saveAs(program, dest_folder, name, True)
                        final_name = name
                        path_in_project = ""
                        try:
                            df = program.getDomainFile()
                            if df is not None:
                                path_in_project = str(df.getPathname())
                        except Exception:
                            pass
                        if not path_in_project:
                            path_in_project = f"/{final_name}" if dest_folder in ("/", "") else f"{dest_folder}/{final_name}"
                        imported_programs.append(
                            {
                                "sourcePath": str(item),
                                "programName": final_name,
                                "programPath": path_in_project,
                            },
                        )
                        self._merge_imported_program_into_session_binaries(
                            session_id,
                            program_name=final_name,
                            path_in_project=path_in_project,
                        )
                        # Leave program in project; do not release (we are not the consumer)
                    except Exception as exc:
                        errors.append({"path": str(item), "error": str(exc)})
            else:
                # Fallback: no ghidra_project available. Create a temporary ProjectManager.
                # WARNING: This creates a separate project that gets cleaned up, so imports won't
                # persist to the main project. Users should open first or ensure
                # AGENT_DECOMPILE_PROJECT_PATH is set.
                from agentdecompile_cli.project_manager import ProjectManager

                manager = ProjectManager()
                try:
                    for item in self._iter_files_to_import(source, recursive, max_depth):
                        discovered_count += 1
                        try:
                            program = manager.import_binary(item, program_name=prog_name or item.name)
                            if program is None:
                                raise RuntimeError("import_binary returned None")
                            prog_name_final = program.getName() if hasattr(program, "getName") else item.name
                            imported_programs.append({"sourcePath": str(item), "programName": prog_name_final})
                            # Merge into session binaries so list-project-files can see it (even though
                            # the underlying project may be temporary).
                            self._merge_imported_program_into_session_binaries(
                                session_id,
                                program_name=prog_name_final,
                                path_in_project=f"/{prog_name_final}",
                            )
                        except Exception as exc:
                            errors.append({"path": str(item), "error": str(exc)})
                finally:
                    manager.cleanup()
        except Exception as exc:
            return create_success_response(
                {
                    "action": "import",
                    "importedFrom": str(source),
                    "filesDiscovered": discovered_count,
                    "filesImported": 0,
                    "importedPrograms": [],
                    "groupsCreated": 0,
                    "maxDepthUsed": max_depth,
                    "wasRecursive": recursive,
                    "analysisRequested": analyze_after_import,
                    "language": language or None,
                    "compiler": compiler or None,
                    "success": False,
                    "error": str(exc),
                },
            )

        return create_success_response(
            {
                "action": "import",
                "importedFrom": str(source),
                "filesDiscovered": discovered_count,
                "filesImported": len(imported_programs),
                "importedPrograms": imported_programs,
                "groupsCreated": 0,
                "maxDepthUsed": max_depth,
                "wasRecursive": recursive,
                "analysisRequested": analyze_after_import,
                "language": language or None,
                "compiler": compiler or None,
                "success": len(imported_programs) > 0 and not errors,
                "errors": errors,
            },
        )

    async def _handle_export(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._handle_export")
        self._require_program()
        assert self.program_info is not None
        output_path = self._get_str(args, "outputpath", "output", "file", "path")
        fmt = self._get_str(args, "format", default="cpp")
        fmt = (fmt or "cpp").strip().lower()

        supported_formats: list[str] = ["c", "cpp", "cxx", "gzf", "sarif", "xml", "html", "ascii"]
        if fmt not in supported_formats:
            return create_success_response(
                {
                    "action": "export",
                    "success": False,
                    "error": f"Unsupported format: {fmt}",
                    "supportedFormats": supported_formats,
                },
            )

        if output_path:
            out = Path(output_path).expanduser().resolve()
            out.parent.mkdir(parents=True, exist_ok=True)
            program: GhidraProgram | None = self.program_info.program

            if fmt == "gzf":
                if out.suffix.lower() != ".gzf":
                    out = out.with_suffix(".gzf")
                project = getattr(self._manager, "ghidra_project", None) if self._manager is not None else None
                if project is None:
                    return create_success_response(
                        {
                            "action": "export",
                            "format": fmt,
                            "outputPath": str(out),
                            "success": False,
                            "error": "No Ghidra project is active for GZF export",
                            "apiClass": "ghidra.app.util.exporter.GzfExporter",
                        },
                    )
                try:
                    from java.io import File as JavaFile  # pyright: ignore[reportMissingImports]

                    project.saveAsPackedFile(program, JavaFile(str(out)), True)
                    return create_success_response(
                        {
                            "action": "export",
                            "format": fmt,
                            "outputPath": str(out),
                            "success": True,
                            "apiClass": "ghidra.app.util.exporter.GzfExporter",
                        },
                    )
                except Exception as exc:
                    return create_success_response(
                        {
                            "action": "export",
                            "format": fmt,
                            "outputPath": str(out),
                            "success": False,
                            "error": str(exc),
                            "apiClass": "ghidra.app.util.exporter.GzfExporter",
                        },
                    )

            if fmt in {"c", "cpp", "cxx"}:
                ext = ".c" if fmt == "c" else ".cpp"
                if out.suffix.lower() not in {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}:
                    out = out.with_suffix(ext)
                create_header = self._get_bool(args, "createheader", default=True)
                include_types = self._get_bool(args, "includetypes", default=True)
                _include_globals = self._get_bool(args, "includeglobals", default=True)  # reserved for CppExporter API
                tags = self._get_str(args, "tags")

                def _run_cpp_export() -> None:
                    from ghidrecomp.decompile import decompile_to_single_file

                    decompile_to_single_file(
                        out,
                        program,
                        create_header=create_header,
                        create_file=True,
                        emit_types=include_types,
                        exclude_tags=False,
                        tags=tags,
                        verbose=False,
                    )

                try:
                    self._run_program_transaction(program, "export-cpp", _run_cpp_export)
                    return create_success_response(
                        {
                            "action": "export",
                            "format": fmt,
                            "outputPath": str(out),
                            "success": True,
                            "apiClass": "ghidra.app.util.exporter.CppExporter",
                        },
                    )
                except Exception as exc:
                    return create_success_response(
                        {
                            "action": "export",
                            "format": fmt,
                            "outputPath": str(out),
                            "success": False,
                            "error": str(exc),
                            "apiClass": "ghidra.app.util.exporter.CppExporter",
                        },
                    )

            if fmt == "sarif":
                if out.suffix.lower() != ".sarif":
                    out = out.with_suffix(".sarif")
                try:
                    # Generate comprehensive SARIF report with actual analysis data
                    results: list[dict[str, Any]] = []

                    # Collect undefined references
                    try:
                        if program is None:
                            raise RuntimeError("Program is None for collecting undefined references")
                        ref_mgr: GhidraReferenceManager = program.getReferenceManager()
                        for ref in islice(ref_mgr.getExternalReferences(), 50):
                            if ref and ref.getToAddress():
                                results.append(
                                    {
                                        "ruleId": "undefined-reference",
                                        "kind": "fail",
                                        "level": "warning",
                                        "message": {
                                            "text": f"External reference at {hex(ref.getFromAddress().getOffset())} to {ref.getLabel()}",
                                        },
                                        "locations": [
                                            {
                                                "physicalLocation": {
                                                    "artifactIndex": 0,
                                                    "address": hex(ref.getFromAddress().getOffset()),
                                                },
                                            },
                                        ],
                                    },
                                )
                    except Exception as e:
                        logger.debug("Error collecting external references: %s", e)

                    # Collect bookmarks
                    try:
                        if program is None:
                            raise RuntimeError("Program is None for collecting bookmarks")
                        bookmark_mgr: GhidraBookmarkManager = program.getBookmarkManager()
                        if bookmark_mgr is None:
                            raise RuntimeError("Bookmark manager is None for collecting bookmarks")
                        _sarif_analysis = "Analysis"
                        _sarif_bm_n = 0
                        for bookmark in iter_items(bookmark_mgr.getBookmarksIterator()):
                            if not bookmark or bookmark.getCategory() != _sarif_analysis:
                                continue
                            if _sarif_bm_n >= 30:
                                break
                            _sarif_bm_n += 1
                            results.append(
                                {
                                    "ruleId": "analysis-bookmark",
                                    "kind": "informational",
                                    "level": "note",
                                    "message": {
                                        "text": f"Bookmark: {bookmark.getComment() or bookmark.getCategory()}",
                                    },
                                    "locations": [
                                        {
                                            "physicalLocation": {
                                                "artifactIndex": 0,
                                                "address": hex(bookmark.getAddress().getOffset()),
                                            },
                                        },
                                    ],
                                },
                            )
                    except Exception as e:
                        logger.debug("Error collecting bookmarks: %s", e)

                    # Collect analysis warnings (thunk/external functions)
                    try:
                        func_mgr: GhidraFunctionManager = self._get_function_manager(program)
                        for i, func in enumerate(func_mgr.getFunctions(True)):
                            if i > 50:
                                break
                            if func.isThunk():
                                results.append(
                                    {
                                        "ruleId": "analysis-warning",
                                        "kind": "pass",
                                        "level": "note",
                                        "message": {"text": f"Thunk function: {func.getName()}"},
                                        "locations": [
                                            {
                                                "physicalLocation": {
                                                    "artifactIndex": 0,
                                                    "address": hex(func.getEntryPoint().getOffset()),
                                                },
                                            },
                                        ],
                                    },
                                )
                            if func.isExternal():
                                results.append(
                                    {
                                        "ruleId": "analysis-warning",
                                        "kind": "pass",
                                        "level": "note",
                                        "message": {"text": f"External function: {func.getName()}"},
                                        "locations": [
                                            {
                                                "physicalLocation": {
                                                    "artifactIndex": 0,
                                                    "address": hex(func.getEntryPoint().getOffset()),
                                                },
                                            },
                                        ],
                                    },
                                )
                    except Exception as e:
                        logger.debug("Error collecting function analysis: %s", e)

                    assert program is not None, "Program is required to generate SARIF report"
                    now: str = datetime.now(timezone.utc).isoformat() + "Z"
                    sarif_doc: dict[str, Any] = {
                        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                        "version": "2.1.0",
                        "runs": [
                            {
                                "tool": {
                                    "driver": {
                                        "name": "AgentDecompile",
                                        "version": "1.0.0",
                                        "informationUri": "https://github.com/bolabaden/agentdecompile",
                                        "rules": [
                                            {
                                                "id": "undefined-reference",
                                                "name": "Undefined Reference",
                                                "shortDescription": {"text": "Reference to undefined function or symbol"},
                                                "defaultConfiguration": {"level": "warning"},
                                            },
                                            {
                                                "id": "analysis-bookmark",
                                                "name": "Analysis Bookmark",
                                                "shortDescription": {"text": "Code location marked with bookmark during analysis"},
                                                "defaultConfiguration": {"level": "note"},
                                            },
                                            {
                                                "id": "analysis-warning",
                                                "name": "Analysis Warning",
                                                "shortDescription": {"text": "Warning generated during program analysis"},
                                                "defaultConfiguration": {"level": "warning"},
                                            },
                                        ],
                                    },
                                },
                                "artifacts": [
                                    {
                                        "uri": str(program.getName()),
                                        "sourceLanguage": "asm",
                                        "properties": {
                                            "imageBase": hex(program.getImageBase().getOffset()),
                                        },
                                    },
                                ],
                                "results": results,
                                "properties": {
                                    "analysisComplete": self._is_analysis_complete(program),
                                    "generatedAt": now,
                                    "resultsCount": len(results),
                                },
                            },
                        ],
                    }
                    out.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")
                    return create_success_response(
                        {
                            "action": "export",
                            "format": fmt,
                            "outputPath": str(out),
                            "success": True,
                            "resultsCollected": len(results),
                            "apiClass": "SARIF 2.1.0",
                        },
                    )
                except Exception as exc:
                    logger.error("Error generating SARIF report: %s", exc)
                    return create_success_response(
                        {
                            "action": "export",
                            "format": fmt,
                            "outputPath": str(out),
                            "success": False,
                            "error": str(exc),
                            "apiClass": "SARIF 2.1.0",
                        },
                    )

            if fmt == "ascii":
                if out.suffix.lower() not in {".txt", ".ascii", ".lst"}:
                    out = out.with_suffix(".txt")
                ascii_done: bool = False
                try:
                    from ghidra.util.task import TaskMonitor as GhidraTaskMonitor  # pyright: ignore[reportMissingModuleSource]
                    from java.io import File as JavaFile  # pyright: ignore[reportMissingImports]

                    def _run_ascii_export() -> None:
                        from ghidra.app.util.exporter import AsciiExporter as GhidraAsciiExporter  # pyright: ignore[reportMissingModuleSource]
                        from ghidra.program.model.address import AddressSetView as GhidraAddressSetView  # pyright: ignore[reportMissingModuleSource]

                        exporter = GhidraAsciiExporter()
                        addr_set: GhidraAddressSetView | None = None
                        if program is not None and hasattr(program, "getMemory") and program.getMemory():
                            mem = program.getMemory()
                            if hasattr(mem, "getAllInitializedAddressSet"):
                                addr_set = mem.getAllInitializedAddressSet()
                            elif hasattr(mem, "getLoadedAndInitializedAddressSet"):
                                addr_set = mem.getLoadedAndInitializedAddressSet()
                        exporter.export(JavaFile(str(out)), program, addr_set, GhidraTaskMonitor.DUMMY)

                    self._run_program_transaction(program, "export-ascii", _run_ascii_export)
                    ascii_done = True
                except Exception as exc:
                    logger.debug("AsciiExporter failed, using fallback text: %s", exc)
                if not ascii_done:
                    ascii_content = _generate_program_ascii_fallback(program, self._get_function_manager)
                    out.write_text(ascii_content, encoding="utf-8")
                return create_success_response(
                    {
                        "action": "export",
                        "format": fmt,
                        "outputPath": str(out),
                        "success": True,
                        "apiClass": "ghidra.app.util.exporter.AsciiExporter or fallback",
                    },
                )

            if fmt == "xml":
                if out.suffix.lower() != ".xml":
                    out = out.with_suffix(".xml")
                xml_done = False
                try:
                    from ghidra.util.task import TaskMonitor as GhidraTaskMonitor  # pyright: ignore[reportMissingModuleSource]
                    from java.io import File as JavaFile  # pyright: ignore[reportMissingImports]

                    def _run_xml_export() -> None:
                        from ghidra.app.util.exporter import XmlExporter as GhidraXmlExporter  # pyright: ignore[reportMissingModuleSource]
                        from ghidra.program.model.address import AddressSetView as GhidraAddressSetView  # pyright: ignore[reportMissingModuleSource]

                        exporter = GhidraXmlExporter()
                        addr_set: GhidraAddressSetView | None = None
                        if program is not None and hasattr(program, "getMemory") and program.getMemory():
                            mem = program.getMemory()
                            if hasattr(mem, "getAllInitializedAddressSet"):
                                addr_set = mem.getAllInitializedAddressSet()
                            elif hasattr(mem, "getLoadedAndInitializedAddressSet"):
                                addr_set = mem.getLoadedAndInitializedAddressSet()
                        exporter.export(JavaFile(str(out)), program, addr_set, GhidraTaskMonitor.DUMMY)

                    self._run_program_transaction(program, "export-xml", _run_xml_export)
                    xml_done = True
                except Exception as exc:
                    logger.debug("XmlExporter failed, using fallback XML: %s", exc)
                if not xml_done:
                    xml_content = _generate_program_xml(program, self._get_function_manager)
                    out.write_text(xml_content, encoding="utf-8")
                return create_success_response(
                    {
                        "action": "export",
                        "format": fmt,
                        "outputPath": str(out),
                        "success": True,
                        "apiClass": "ghidra.app.util.exporter.XmlExporter or fallback",
                    },
                )

            if fmt == "html":
                if out.suffix.lower() not in {".html", ".htm"}:
                    out = out.with_suffix(".html")
                html_done = False
                try:
                    from ghidra.util.task import TaskMonitor as GhidraTaskMonitor  # pyright: ignore[reportMissingModuleSource]
                    from java.io import File as JavaFile  # pyright: ignore[reportMissingImports]

                    def _run_html_export() -> None:
                        from ghidra.app.util.exporter import HtmlExporter as GhidraHtmlExporter  # pyright: ignore[reportMissingModuleSource]
                        from ghidra.program.model.address import AddressSetView as GhidraAddressSetView  # pyright: ignore[reportMissingModuleSource]

                        exporter = GhidraHtmlExporter()
                        addr_set: GhidraAddressSetView | None = None
                        if program is not None and hasattr(program, "getMemory") and program.getMemory():
                            mem = program.getMemory()
                            if hasattr(mem, "getAllInitializedAddressSet"):
                                addr_set = mem.getAllInitializedAddressSet()
                            elif hasattr(mem, "getLoadedAndInitializedAddressSet"):
                                addr_set = mem.getLoadedAndInitializedAddressSet()
                        exporter.export(JavaFile(str(out)), program, addr_set, GhidraTaskMonitor.DUMMY)

                    self._run_program_transaction(program, "export-html", _run_html_export)
                    html_done = True
                except Exception as exc:
                    logger.debug("HtmlExporter not available or failed, using generated HTML: %s", exc)
                if not html_done:
                    html_content = _generate_program_html(program, self._get_function_manager)
                    out.write_text(html_content, encoding="utf-8")
                return create_success_response(
                    {
                        "action": "export",
                        "format": fmt,
                        "outputPath": str(out),
                        "success": True,
                        "apiClass": "ghidra.app.util.exporter.HtmlExporter or generated report",
                    },
                )

            payload: dict[str, Any] = {
                "name": program.getName() if program is not None else "(none)",
                "address": str(program.getImageBase() if program is not None else "(none)"),
                "language": str(program.getLanguage().getLanguageID() if program is not None else "(none)"),
                "compiler": str(program.getCompilerSpec().getCompilerSpecID() if program is not None else "(none)"),
                "functionCount": self._get_function_manager(program).getFunctionCount() if program is not None else 0,
                "format": fmt,
            }
            out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            return create_success_response({"action": "export", "format": fmt, "outputPath": str(out), "success": True})

        return create_success_response(
            {
                "action": "export",
                "format": fmt,
                "outputPath": output_path or "(stdout)",
                "note": "No output path provided; returning metadata only",
                "supportedFormats": supported_formats,
            },
        )

    async def _handle_analyze(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._handle_analyze")
        self._require_program()
        assert self.program_info is not None
        analyzers: list[str] | None = self._get_list(args, "analyzers")
        force: bool = self._get_bool(args, "force", "forceanalysis", default=False)
        program: GhidraProgram | None = self.program_info.program

        try:
            from ghidra.program.util import GhidraProgramUtilities  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

            session_marked_complete: bool = bool(getattr(self.program_info, "analysis_complete", False))
            ghidra_requires_analysis: bool = True
            try:
                ghidra_requires_analysis = bool(GhidraProgramUtilities.shouldAskToAnalyze(program)) if program is not None else True
            except Exception:
                ghidra_requires_analysis = True if session_marked_complete else False

            already_analyzed: bool = session_marked_complete or not ghidra_requires_analysis
            if already_analyzed and not force:
                return create_success_response(
                    {
                        "action": "analyze",
                        "programName": program.getName() if program is not None else "(none)",
                        "analyzers": analyzers or "all",
                        "success": False,
                        "alreadyAnalyzed": True,
                        "forceAllowed": True,
                        "error": "Program has already been analyzed. Re-run only when you have a specific reason; set force=true to override.",
                    },
                )

            # Single code path: same as CLI/launcher (disables headless-unsafe analyzers, acquires bundle host, runs analysis)
            def _run_auto_analysis() -> None:
                run_analysis(program, force_analysis=True)

            self._run_program_transaction(program, "auto-analysis", _run_auto_analysis)
            if hasattr(self.program_info, "ghidra_analysis_complete"):
                self.program_info.ghidra_analysis_complete = True

            return create_success_response(
                {
                    "action": "analyze",
                    "programName": program.getName() if program is not None else "(none)",
                    "analyzers": analyzers or "all",
                    "force": force,
                    "success": True,
                },
            )
        except ImportError:
            return create_success_response(
                {
                    "action": "analyze",
                    "force": force,
                    "note": "Auto-analysis requires full Ghidra environment",
                },
            )
        except Exception as e:
            return create_success_response({"action": "analyze", "force": force, "success": False, "error": str(e)})

    async def _handle_change_processor(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._handle_change_processor")
        self._require_program()
        assert self.program_info is not None
        language: str = self._get_str(args, "language", "lang", "processor", "languageid", default="")

        if not language:
            # Resource / no-args mode: return current processor info
            program: GhidraProgram | None = self.program_info.program
            assert program is not None, "Program is required to get processor info"
            try:
                lang_id: str = str(program.getLanguage().getLanguageID())
                compiler_id: str = str(program.getCompilerSpec().getCompilerSpecID())
                return create_success_response(
                    {
                        "action": "get_processor",
                        "language": lang_id,
                        "compiler": compiler_id,
                        "note": "Pass language (e.g. x86:LE:32:default) to change the processor.",
                    }
                )
            except Exception as exc:
                return create_success_response({"action": "get_processor", "success": False, "error": str(exc)})
        compiler: str | None = self._get_str(args, "compiler", "compilerspec", "compilerspecid")

        program = self.program_info.program
        try:
            from ghidra.program.model.lang import (  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
                CompilerSpecID as GhidraCompilerSpecID,
                LanguageID as GhidraLanguageID,
            )
            from ghidra.program.util import DefaultLanguageService as GhidraDefaultLanguageService  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
            from ghidra.util.task import TaskMonitor as GhidraTaskMonitor  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

            def _change_processor() -> None:
                language_id = GhidraLanguageID(language)
                language_service = GhidraDefaultLanguageService.getLanguageService()
                language_obj: GhidraLanguage | None = language_service.getLanguage(language_id)
                if language_obj is None:
                    raise RuntimeError(f"Unable to resolve language: {language}")

                compiler_spec_id = GhidraCompilerSpecID(compiler) if compiler else language_obj.getDefaultCompilerSpec().getCompilerSpecID()

                try:
                    assert program is not None
                    program.setLanguage(language_obj, compiler_spec_id, True, GhidraTaskMonitor.DUMMY)
                except Exception:
                    compiler_spec = language_obj.getDefaultCompilerSpec()
                    if compiler:
                        try:
                            compiler_spec = language_obj.getCompilerSpecByID(compiler_spec_id)
                        except Exception:
                            compiler_spec = language_obj.getDefaultCompilerSpec()
                    assert program is not None
                    program.setLanguage(language_obj, compiler_spec, True, GhidraTaskMonitor.DUMMY)

            self._run_program_transaction(program, "change-processor", _change_processor)

            return create_success_response({"action": "change_processor", "language": language, "compiler": compiler or "(default)", "success": True})
        except Exception as exc:
            return create_success_response(
                {
                    "action": "change_processor",
                    "language": language,
                    "compiler": compiler or "(default)",
                    "success": False,
                    "error": str(exc),
                },
            )

        return create_success_response({"action": "change_processor", "language": language, "compiler": compiler or "(default)", "success": False})

    @staticmethod
    def _ghidra_paths_equal(a: str, b: str) -> bool:
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._ghidra_paths_equal")
        aa: str = (a or "").strip().replace("\\", "/").lower()
        bb: str = (b or "").strip().replace("\\", "/").lower()
        return aa == bb or aa.lstrip("/") == bb.lstrip("/")

    def _domain_files_align_for_checkin(self, program_df: GhidraDomainFile, target_df: GhidraDomainFile) -> bool:
        """True if ``program_df`` is the working Program's file and should be flushed before ``target_df`` check-in.

        Shared checkout often leaves ``Program.getDomainFile()`` with a project-local pathname while
        ``_resolve_domain_file_for_checkout_status`` may return a repo-style path — same binary, different strings.
        """
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._domain_files_align_for_checkin")
        if program_df is None or target_df is None:
            return False
        if program_df is target_df:
            return True
        try:
            p = str(program_df.getPathname() or "").strip().replace("\\", "/")
            t = str(target_df.getPathname() or "").strip().replace("\\", "/")
            if self._ghidra_paths_equal(p, t):
                return True
            try:
                pn = str(program_df.getName() or "").strip().lower()
                tn = str(target_df.getName() or "").strip().lower()
                if pn and tn and pn == tn:
                    return True
            except Exception:
                pass
            from pathlib import Path

            pb = Path(p).name.lower() if p else ""
            tb = Path(t).name.lower() if t else ""
            return bool(pb) and pb == tb
        except Exception:
            return False

    def _canonical_program_path_for_session(self, program_path: str) -> str:
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._canonical_program_path_for_session")
        session_id = get_current_mcp_session_id()
        return SESSION_CONTEXTS.canonicalize_program_path(session_id, program_path)

    @staticmethod
    def _end_open_transaction_on_program(program: GhidraProgram) -> None:
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._end_open_transaction_on_program")
        if program is None or not (hasattr(program, "getCurrentTransactionInfo") or hasattr(program, "getCurrentTransaction")):
            return
        try:
            tx = program.getCurrentTransactionInfo() if hasattr(program, "getCurrentTransactionInfo") else program.getCurrentTransaction()
            if tx is not None and hasattr(program, "endTransaction"):
                tx_id = int(tx.getID()) if hasattr(tx, "getID") else int(tx)
                program.endTransaction(tx_id, True)
                logger.debug("Ended open Ghidra transaction before version-control operation")
        except Exception as exc:
            logger.debug("Could not end open transaction: %s", exc)

    @staticmethod
    def _end_all_open_transactions_on_program(program: GhidraProgram, *, max_rounds: int = 64) -> None:
        """End nested Ghidra transactions until none remain (tool tx inside GhidraProject batch tx, etc.)."""
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._end_all_open_transactions_on_program")
        if program is None or not (hasattr(program, "getCurrentTransactionInfo") or hasattr(program, "getCurrentTransaction")):
            return
        ended_count = 0
        for _ in range(max_rounds):
            try:
                tx = program.getCurrentTransactionInfo() if hasattr(program, "getCurrentTransactionInfo") else program.getCurrentTransaction()
                if tx is None:
                    break
                # getCurrentTransactionInfo() returns a TransactionInfo object; endTransaction() expects
                # the int transaction ID.  Passing the TransactionInfo directly causes a JPype type
                # mismatch that silently fails, leaving the batch transaction (and all saves) broken.
                tx_id = int(tx.getID()) if hasattr(tx, "getID") else int(tx)
                tx_desc = str(tx.getDescription()) if hasattr(tx, "getDescription") else "?"
                if hasattr(program, "endTransaction"):
                    program.endTransaction(tx_id, True)
                    ended_count += 1
                    logger.warning("_end_all_open_transactions: ended tx id=%s desc='%s'", tx_id, tx_desc)
            except Exception as exc:
                exc_str = str(exc).lower()
                # "Transaction not found" means the tx was already ended (stale getCurrentTransactionInfo ref);
                # treat as completion, not failure.
                if "transaction not found" in exc_str or "already ended" in exc_str:
                    logger.debug("_end_all_open_transactions: tx already ended (stale ref), stopping drain")
                    break
                logger.warning("_end_all_open_transactions round failed: %s", exc)
                break
        if ended_count == 0:
            logger.warning("_end_all_open_transactions: no transactions found to end")

    @staticmethod
    def _end_nested_non_batch_transactions_on_program(program: GhidraProgram, *, max_rounds: int = 64) -> None:
        """End nested tool transactions but keep the outer batch transaction for ``gp.save``."""
        if program is None or not (hasattr(program, "getCurrentTransactionInfo") or hasattr(program, "getCurrentTransaction")):
            return
        for _ in range(max_rounds):
            try:
                tx = program.getCurrentTransactionInfo() if hasattr(program, "getCurrentTransactionInfo") else program.getCurrentTransaction()
                if tx is None:
                    break
                tx_desc = str(tx.getDescription()) if hasattr(tx, "getDescription") else ""
                # GhidraProject.openProgram starts the batch tx with description "" (empty string).
                # Stop at either empty-string or "Batch Processing" to keep the outer batch tx.
                desc_lower = tx_desc.strip().lower()
                if desc_lower == "batch processing" or desc_lower == "":
                    break
                tx_id = int(tx.getID()) if hasattr(tx, "getID") else int(tx)
                if hasattr(program, "endTransaction"):
                    program.endTransaction(tx_id, True)
            except Exception as exc:
                logger.debug("end_nested_non_batch_transactions failed: %s", exc)
                break

    @staticmethod
    def _local_save_via_reflection(
        ghidra_project: GhidraProject,
        program: GhidraProgram,
        domain_file: GhidraDomainFile,
        save_comment: str,
        *,
        batch_already_ended: bool = False,
    ) -> str | None:
        """Save a local program under the Java monitor with events suppressed.

        **Primary path** (clean): suppress events → drain all transactions by
        calling ``endTransaction(batch_id)`` → save → restart batch.
        The program stays in a healthy state and the next tool call can reuse it.

        **Fallback** (forceLock): if the primary path fails (e.g. ``lockCount``
        won't reach 0), use ``forceLock(rollback=True)`` which atomically clears
        the lock, then save, unlock, and force-close the program by releasing
        all consumers.

        Returns ``"primary"`` if the clean path succeeded, ``"fallback"`` if
        the forceLock path succeeded, or ``None`` if both failed.
        """
        try:
            import jpype  # pyright: ignore[reportMissingImports]

            field = ghidra_project.getClass().getDeclaredField("openPrograms")
            field.setAccessible(True)
            open_programs_map = field.get(ghidra_project)

            from ghidra.util.task import TaskMonitor as GhidraTaskMonitor  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

            batch_id_obj = open_programs_map.get(program)
            if batch_id_obj is None:
                logger.debug("_local_save_via_reflection: no batch ID in openPrograms")
                return None
            batch_id = int(batch_id_obj)

            # ── Primary path: drain transactions + save + restart ─────────
            primary_ok = False
            with jpype.synchronized(program):
                program.setEventsEnabled(False)
                try:
                    drain_round = 0
                    for drain_round in range(30):
                        try:
                            program.endTransaction(batch_id, True)
                        except Exception:
                            break
                    # Also drain via getCurrentTransactionInfo in case IDs differ.
                    for _ in range(30):
                        tx = program.getCurrentTransactionInfo()
                        if tx is None:
                            break
                        try:
                            program.endTransaction(tx.getID(), True)
                        except Exception:
                            break
                    try:
                        program.getDomainFile().save(GhidraTaskMonitor.DUMMY)
                        new_batch = program.startTransaction("")
                        from java.lang import Integer as JInteger  # pyright: ignore[reportMissingImports]

                        open_programs_map.put(program, JInteger(new_batch))
                        primary_ok = True
                    except Exception as save_exc:
                        logger.debug("_local_save_via_reflection primary save failed: %s", save_exc)
                finally:
                    program.setEventsEnabled(True)

            if primary_ok:
                logger.info("_local_save_via_reflection: saved (primary path, %d drain rounds)", drain_round + 1)
                return "primary"

            # ── Fallback: forceLock + save + unlock + force-close ─────────
            logger.debug("_local_save_via_reflection: primary path failed, falling back to forceLock")
            with jpype.synchronized(program):
                program.setEventsEnabled(False)
                try:
                    program.forceLock(True, "checkin-save")
                    program.getDomainFile().save(GhidraTaskMonitor.DUMMY)
                    open_programs_map.remove(program)
                    try:
                        program.unlock()
                    except Exception:
                        pass
                finally:
                    program.setEventsEnabled(True)

            # Force-close: release ALL consumers so refCount reaches 0.
            try:
                consumers = list(program.getConsumerList())
                for consumer in consumers:
                    try:
                        program.release(consumer)
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                if hasattr(program, "isClosed") and not program.isClosed():
                    program.close()
            except Exception:
                pass

            logger.info("_local_save_via_reflection: saved (forceLock fallback)")
            return "fallback"
        except Exception as exc:
            logger.warning("_local_save_via_reflection failed: %s", exc)
            return None

    def _end_open_transactions_on_all_session_programs(self, session_id: str) -> None:
        """Drain nested Ghidra transactions on every open Program (preserves GhidraProject batch txs)."""
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._end_open_transactions_on_all_session_programs")
        try:
            if self.program_info and self.program_info.program:
                self._end_nested_non_batch_transactions_on_program(self.program_info.program)
            session: SessionContext = SESSION_CONTEXTS.get_or_create(session_id)
            for _k, info in list((session.open_programs or {}).items()):
                prog = getattr(info, "program", None) or getattr(info, "current_program", None)
                if prog is not None:
                    self._end_nested_non_batch_transactions_on_program(prog)
            if self._manager is not None:
                for pr in getattr(self._manager, "providers", None) or []:
                    opi = getattr(pr, "program_info", None)
                    if opi is not None and getattr(opi, "program", None) is not None:
                        self._end_nested_non_batch_transactions_on_program(opi.program)
        except Exception as exc:
            logger.debug("Could not end transactions on session programs: %s", exc)

    def _end_open_transactions_on_domain_file_consumers(self, domain_file: GhidraDomainFile) -> None:
        """End nested transactions on Ghidra consumers of this GhidraDomainFile (preserves GhidraProject batch txs)."""
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._end_open_transactions_on_domain_file_consumers")
        if domain_file is None or not hasattr(domain_file, "getConsumers"):
            return
        try:
            consumers: list[GhidraProgram] = domain_file.getConsumers()
            if consumers is None:
                return
            for obj in consumers:
                if obj is None:
                    continue
                if (hasattr(obj, "getCurrentTransactionInfo") or hasattr(obj, "getCurrentTransaction")) and hasattr(obj, "endTransaction"):
                    try:
                        self._end_nested_non_batch_transactions_on_program(obj)
                    except Exception as inner_exc:
                        logger.debug("Could not drain transactions on domain consumer: %s", inner_exc)
        except Exception as exc:
            logger.debug("Could not iterate GhidraDomainFile consumers: %s", exc)

    def _find_domain_file_case_insensitive(self, project_data: GhidraProject, want_path: str) -> tuple[GhidraDomainFile, str] | None:
        """Locate a GhidraDomainFile under project root when getFile(exact) fails (case / slash differences)."""
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._find_domain_file_case_insensitive")
        if project_data is None or not want_path:
            return None
        want = want_path.strip().replace("\\", "/")
        want_l = want.lower()
        base = want_l.split("/")[-1]
        try:
            root = project_data.getRootFolder()
            if root is None:
                return None
            from jpype import JArray

            files_iter: JArray[GhidraDomainFile] = root.getFiles()
            while files_iter.hasNext():
                df: GhidraDomainFile = files_iter.next()
                pn = str(df.getPathname() or "").strip().replace("\\", "/")
                name: str = str(df.getName() or "").strip()
                if self._ghidra_paths_equal(pn, want) or pn.lower().endswith("/" + base) or name.lower() == base:
                    return (df, name or pn or want)
        except Exception:
            return None
        return None

    def _resolve_program_for_domain_file(
        self,
        domain_file: GhidraDomainFile,
        *,
        program_path: str,
        program_display_name: str,
    ) -> GhidraProgram | None:
        """Best-effort: Program handle open in this session for the given GhidraDomainFile (for tx end / release)."""
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._resolve_program_for_domain_file")
        session_id = get_current_mcp_session_id()
        program_obj: GhidraProgram | None = None
        try:
            pinf = SESSION_CONTEXTS.get_program_info(session_id, program_path or program_display_name)
            if pinf is not None:
                candidate = getattr(pinf, "program", None)
                if candidate is not None:
                    try:
                        cdf = candidate.getDomainFile()
                        if cdf is None:
                            program_obj = candidate
                        elif self._ghidra_paths_equal(
                            str(cdf.getPathname() or ""),
                            str(domain_file.getPathname() or ""),
                        ) or self._domain_files_align_for_checkin(cdf, domain_file):
                            program_obj = candidate
                    except Exception:
                        program_obj = candidate
        except Exception:
            pass
        if program_obj is None and self.program_info and self.program_info.program:
            try:
                adf: GhidraDomainFile | None = self.program_info.program.getDomainFile()
                if adf is not None and (
                    self._ghidra_paths_equal(
                        str(adf.getPathname() or ""),
                        str(domain_file.getPathname() or ""),
                    )
                    or self._domain_files_align_for_checkin(adf, domain_file)
                ):
                    program_obj = self.program_info.program
            except Exception:
                pass
        if program_obj is None:
            try:
                session_tmp = SESSION_CONTEXTS.get_or_create(session_id)
                for _k, info in list(session_tmp.open_programs.items()):
                    p = getattr(info, "program", None)
                    if p is None:
                        continue
                    try:
                        df: GhidraDomainFile | None = p.getDomainFile()
                        if df is not None and self._domain_files_align_for_checkin(df, domain_file):
                            program_obj = p
                            break
                    except Exception:
                        continue
            except Exception:
                pass
        return program_obj

    def _end_open_transactions_for_one_open_program(self, session_id: str, program: GhidraProgram) -> None:
        """End Ghidra transactions only on session/provider handles that reference this Program instance."""
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._end_open_transactions_for_one_open_program")
        if program is None:
            return
        try:
            session = SESSION_CONTEXTS.get_or_create(session_id)
            for _k, info in list((session.open_programs or {}).items()):
                p: GhidraProgram | None = getattr(info, "program", None) or getattr(info, "current_program", None)
                if p is not program:
                    continue
                self._end_open_transaction_on_program(p)
        except Exception as exc:
            logger.debug("end transactions on session program handle: %s", exc)
        try:
            if self.program_info is not None and self.program_info.program is program:
                self._end_open_transaction_on_program(program)
        except Exception as exc:
            logger.debug("end transaction on provider program_info: %s", exc)
        if self._manager is not None:
            try:
                for pr in getattr(self._manager, "providers", None) or []:
                    pi = getattr(pr, "program_info", None)
                    if pi is not None and getattr(pi, "program", None) is program:
                        self._end_open_transaction_on_program(program)
                        break
            except Exception as exc:
                logger.debug("end transaction on manager provider program: %s", exc)

    def _ensure_versioned_file_ready_for_checkin(
        self,
        domain_file: GhidraDomainFile,
        program: GhidraProgram | None,
        *,
        end_transactions_on_all_open_programs: bool = True,
        end_domain_file_consumer_transactions: bool = True,
    ) -> None:
        """End open transactions; reclaim checkout only when the holder is not this JVM user.

        A common failure mode: ``analyzeHeadless`` or an old Ghidra GUI session checked the file out as
        ``user.name`` from Roaming prefs while PyGhidra runs as ``ghidra`` — ``canCheckin()`` stays false.
        We only ``undoCheckout(force)`` when ``getCheckoutStatus().getUser()`` differs from
        ``java.lang.System.getProperty("user.name")`` so we do not drop a valid local checkout when
        ``canCheckin()`` is false for other reasons (e.g. server policy).

        For a targeted ``checkin-program`` with a resolved open Program, prefer
        ``end_transactions_on_all_open_programs=False`` so we do not run ``endTransaction`` on unrelated
        session programs (e.g. GhidraProject batch transactions on other handles), which can prevent the
        versioned GhidraDomainFile from observing ``modifiedSinceCheckout`` after mutations.

        When ``end_domain_file_consumer_transactions`` is False, callers should run
        ``_end_open_transactions_on_domain_file_consumers`` **after** persisting the open Program to the
        GhidraDomainFile; ending consumer transactions first can leave ``modifiedSinceCheckout`` false even after
        ``create-label`` / symbol edits.
        """
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._ensure_versioned_file_ready_for_checkin")
        from ghidra.util.task import TaskMonitor as GhidraTaskMonitor  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
        from java.lang import System as JavaSystem  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

        session_id = get_current_mcp_session_id()
        if end_transactions_on_all_open_programs:
            # checkin-all and unknown program: end every open Program tx, then GhidraDomainFile consumers.
            self._end_open_transactions_on_all_session_programs(session_id)
        # Targeted checkin-program: do not end this Program's transactions here — _persist_open_program_for_versioned_checkin
        # ends all nested txs (including GhidraProject batch) immediately before program.save; doing it earlier breaks
        # modifiedSinceCheckout() for shared server check-ins.
        if end_domain_file_consumer_transactions:
            self._end_open_transactions_on_domain_file_consumers(domain_file)
        # Do not call _end_open_transaction_on_program(program) here: checkin-program runs this helper
        # before _save_domain_file_before_versioned_checkin. An extra endTransaction on the open Program
        # after tool nested txs are done can commit the GhidraProject "Batch Processing" outer tx in a way
        # that leaves GhidraDomainFile.modifiedSinceCheckout() false (check-in then fails with "not modified").
        if domain_file is None or not domain_file.isVersioned():
            return
        if not domain_file.isCheckedOut():
            return
        try:
            if domain_file.canCheckin():
                return
        except Exception:
            pass

        reclaim = False
        try:
            jvm_user = str(JavaSystem.getProperty("user.name") or "").strip()
            st = domain_file.getCheckoutStatus()
            holder = str(st.getUser() or "").strip() if st is not None else ""
            if holder and jvm_user and holder != jvm_user:
                reclaim = True
                logger.info(
                    "Checkout holder %r != JVM user.name %r; reclaiming checkout before check-in",
                    holder,
                    jvm_user,
                )
        except Exception as exc:
            logger.debug("Could not compare checkout holder to JVM user: %s", exc)

        if not reclaim:
            return

        try:
            if hasattr(domain_file, "undoCheckout"):
                domain_file.undoCheckout(False, True)
                logger.info("Recovered versioned checkout: undoCheckout(force) before check-in")
        except Exception as exc:
            logger.warning("undoCheckout(force) before check-in failed (continuing): %s", exc)
        try:
            domain_file.checkout(True, GhidraTaskMonitor.DUMMY)
            logger.info("Recovered versioned checkout: exclusive checkout before check-in")
        except Exception as exc:
            logger.warning("Exclusive checkout before check-in failed: %s", exc)

    @staticmethod
    def _force_domain_object_changed_for_versioned_checkin(program: GhidraProgram) -> None:
        """Set Ghidra's internal ``changed`` flag so ``DomainObjectAdapterDB.save`` persists and calls ``fileChanged``.

        After tool transactions commit, ``ProgramDB`` may clear ``changed`` while shared checkout metadata
        (``LocalFolderItem`` / ``modifiedSinceCheckout()``) was never updated. Without a real DB flush plus
        ``GhidraFile.fileChanged()``, ``checkin`` fails with \"File has not been modified since checkout\".
        ``DomainObjectAdapterDB.setChanged(boolean)`` is protected; reflection is used for headless MCP.
        """
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._force_domain_object_changed_for_versioned_checkin")
        if program is None:
            return
        try:
            import jpype

            from java.lang import Boolean as JavaBoolean  # pyright: ignore[reportMissingImports]
            from java.lang.reflect import Modifier  # pyright: ignore[reportMissingImports]

            prim = jpype.JClass("java.lang.Boolean").TYPE
        except Exception as exc:
            logger.debug("Java reflection setup for setChanged: %s", exc)
            return
        try:
            cls = program.getClass()
            while cls is not None:
                try:
                    m = cls.getDeclaredMethod("setChanged", prim)
                except Exception:
                    cls = cls.getSuperclass()
                    continue
                try:
                    if not Modifier.isPublic(m.getModifiers()):
                        m.setAccessible(True)
                    m.invoke(program, JavaBoolean.TRUE)
                except Exception as inv_exc:
                    logger.debug("setChanged(true) invoke failed: %s", inv_exc)
                return
        except Exception as exc:
            logger.debug("force domain object changed before versioned check-in: %s", exc)

    def _persist_open_program_for_versioned_checkin(self, program: GhidraProgram) -> None:
        """Flush program changes to its GhidraDomainFile.

        ``GhidraProject.openProgram`` registers an outer \"Batch Processing\" transaction id in
        ``GhidraProject.openPrograms``. ``GhidraProject.save(program)`` ends that id (commit), then calls
        ``program.getDomainFile().save``. If we drain all program transactions first with
        ``_end_all_open_transactions_on_program``, that outer transaction is ended **outside** ``GhidraProject.save``,
        leaving a stale id in ``openPrograms`` and a save path that does not reliably set
        ``GhidraDomainFile.modifiedSinceCheckout()`` for shared-server check-ins. So call ``ghidra_project.save`` **first**
        while the project still owns the open batch transaction, then drain any remaining transactions and fall back to
        direct ``Program`` / ``GhidraDomainFile`` saves. When Ghidra has cleared the domain ``changed`` flag after tool
        commits, force ``setChanged(true)`` so the save path updates versioned checkout state.
        """
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._persist_open_program_for_versioned_checkin")
        if program is None:
            return
        from ghidra.util.task import TaskMonitor as GhidraTaskMonitor  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

        self._force_domain_object_changed_for_versioned_checkin(program)
        gp = getattr(self._manager, "ghidra_project", None) if self._manager else None
        if gp is not None:
            try:
                gp.save(program)
            except Exception as exc:
                logger.debug("ghidra_project.save before draining transactions (primary flush): %s", exc)
        # Use nested-only drain to PRESERVE the GhidraProject batch tx.  gp.save() manages the
        # batch lifecycle (end → save → restart); ending the batch externally with _end_all leaves
        # a stale id in GhidraProject.openPrograms and breaks subsequent gp.save/checkout cycles.
        self._end_nested_non_batch_transactions_on_program(program)
        try:
            if hasattr(program, "save"):
                program.save("agentdecompile pre-checkin save", GhidraTaskMonitor.DUMMY)
        except Exception as exc:
            logger.debug("Program.save before versioned check-in: %s", exc)
        # Program.save may leave a nested transaction open; drain before any GhidraFile.save.
        self._end_nested_non_batch_transactions_on_program(program)
        if gp is not None:
            try:
                gp.save(program)
            except Exception as exc:
                logger.debug("ghidra_project.save after explicit flush (best-effort): %s", exc)
            self._end_nested_non_batch_transactions_on_program(program)
        # Re-mark after all saves so shared checkout metadata can observe mutations for check-in.
        self._force_domain_object_changed_for_versioned_checkin(program)
        # Do not call program.getDomainFile().save here — optional save lives in
        # ``_save_domain_file_before_versioned_checkin_sync_body`` when ``modifiedSinceCheckout()`` is still false.

    @staticmethod
    def _try_mark_versioned_checkout_dirty(domain_file: GhidraDomainFile) -> None:
        """Call Ghidra mutators that bump checkout dirty state when reflection/setChanged is insufficient."""
        if domain_file is None:
            return
        for name in ("setModifiedSinceCheckout", "markModifiedSinceCheckout"):
            try:
                fn = getattr(domain_file, name, None)
                if fn is None or not callable(fn):
                    continue
                try:
                    fn(True)  # type: ignore[misc]
                    return
                except Exception:
                    try:
                        fn()  # type: ignore[misc]
                        return
                    except Exception:
                        continue
            except Exception:
                continue
        ImportExportToolProvider._reflect_bump_modified_since_checkout_graph(domain_file)

    @staticmethod
    def _reflect_bump_modified_since_checkout_graph(root: Any) -> None:
        """BFS Ghidra object graph from ``DomainFile``; invoke package-private setters that bump ``modifiedSinceCheckout``.

        PyGhidra shared check-in can see ``modifiedSinceCheckout()==false`` on the checkout handle even after
        ``create-label`` + flush — the flag often lives on an internal ``GhidraFileData`` / folder item, not on the
        ``DomainFile`` proxy. Public ``setModifiedSinceCheckout`` is absent on many builds; reflection finds
        ``set*SinceCheckout`` / ``mark*`` on nested objects (LFG step 5 empty ``search-symbols`` after reopen check-in).
        """
        if root is None:
            return
        try:
            from java.lang import Boolean as JavaBoolean  # pyright: ignore[reportMissingImports]
            from java.lang.reflect import Modifier  # pyright: ignore[reportMissingImports]
        except Exception as exc:
            logger.debug("reflect_bump_modified_since_checkout_graph: java imports: %s", exc)
            return
        visited: set[int] = set()
        queue: list[Any] = [root]
        max_nodes = 120
        try:
            from java.lang import System as JavaSystem  # pyright: ignore[reportMissingImports]
        except Exception:
            JavaSystem = None  # type: ignore[assignment,misc]
        while queue and len(visited) < max_nodes:
            obj = queue.pop(0)
            if obj is None:
                continue
            try:
                if JavaSystem is not None:
                    oid = int(JavaSystem.identityHashCode(obj))
                else:
                    oid = id(obj)
            except Exception:
                oid = id(obj)
            if oid in visited:
                continue
            visited.add(oid)
            try:
                cls = obj.getClass()
            except Exception:
                continue
            while cls is not None:
                try:
                    methods = cls.getDeclaredMethods()
                except Exception:
                    methods = []
                for m in methods:
                    try:
                        if Modifier.isStatic(m.getModifiers()):
                            continue
                        name = str(m.getName())
                        low = name.lower()
                        if "sincecheckout" not in low and "since_checkout" not in low:
                            continue
                        if low.startswith("get") or low.startswith("is") or low.startswith("has") or low.startswith("can"):
                            continue
                        if low in ("wait", "notify", "notifyall"):
                            continue
                        m.setAccessible(True)
                        pc = m.getParameterCount()
                        if pc == 0:
                            m.invoke(obj)
                            logger.debug("reflect_bump_modified_since_checkout_graph: invoked %s()", name)
                        elif pc == 1:
                            pt = m.getParameterTypes()[0]
                            ptn = str(pt.getName())
                            if ptn in ("boolean", "java.lang.Boolean"):
                                m.invoke(obj, JavaBoolean.TRUE)
                                logger.debug("reflect_bump_modified_since_checkout_graph: invoked %s(true)", name)
                    except Exception:
                        continue
                try:
                    for field in cls.getDeclaredFields():
                        if Modifier.isStatic(field.getModifiers()):
                            continue
                        try:
                            ft = field.getType()
                            if ft.isPrimitive():
                                continue
                        except Exception:
                            continue
                        fn = str(field.getName()).lower()
                        if not any(
                            s in fn
                            for s in (
                                "file",
                                "item",
                                "data",
                                "folder",
                                "parent",
                                "local",
                                "versioned",
                                "private",
                                "root",
                                "domain",
                                "project",
                                "content",
                                "adapter",
                                "ghidra",
                            )
                        ):
                            continue
                        try:
                            field.setAccessible(True)
                            child = field.get(obj)
                        except Exception:
                            continue
                        if child is None:
                            continue
                        try:
                            cname = str(child.getClass().getName())
                        except Exception:
                            cname = ""
                        if "ghidra" not in cname.lower():
                            continue
                        queue.append(child)
                except Exception:
                    pass
                try:
                    cls = cls.getSuperclass()
                except Exception:
                    break

    @staticmethod
    def _notify_domain_file_changed_for_versioned_checkin(domain_file: GhidraDomainFile, program: GhidraProgram | None) -> None:
        """Best-effort: Ghidra's versioned check-in consults ``modifiedSinceCheckout`` on the DomainFile tree."""
        seen: set[int] = set()
        candidates: list[Any] = []
        if domain_file is not None:
            candidates.append(domain_file)
        try:
            if program is not None:
                pdf = program.getDomainFile()
                if pdf is not None:
                    candidates.append(pdf)
        except Exception:
            pass
        for obj in candidates:
            try:
                oid = id(obj)
                if oid in seen:
                    continue
                seen.add(oid)
                if hasattr(obj, "fileChanged"):
                    obj.fileChanged()
            except Exception:
                continue

    def _bump_versioned_checkout_dirty_bookmark(self, program: GhidraProgram | None) -> None:
        """Apply a tiny bookmark so shared checkout state sees a real program mutation (listing/import edge cases)."""
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._bump_versioned_checkout_dirty_bookmark")
        if program is None:
            return
        try:
            mem = program.getMemory()
            if mem is None:
                return
            addr = mem.getMinAddress()
            if addr is None:
                return
            bm_mgr = program.getBookmarkManager()
            if bm_mgr is None:
                return

            def _set_bm() -> None:
                bm_mgr.setBookmark(addr, "Note", "AgentDecompile", "agentdecompile_vc_checkin_bump")

            self._run_program_transaction(program, "versioned-checkin-bump", _set_bm)
        except Exception as exc:
            logger.debug("bump_versioned_checkout_dirty_bookmark: %s", exc)

    def _snapshot_user_defined_primary_labels(self, program: Any) -> list[tuple[str, str]]:
        """Capture USER_DEFINED LABEL symbols to reapply after reopen-based versioned check-in.

        Includes non-primary labels: LFG create-label can leave a secondary LABEL at an address where a
        function symbol is primary; filtering primary-only dropped ``*_L2``.

        Dedupe exact (address, name) pairs only. Reapply applies **at most one** ``createLabel`` per name
        (sorted by name, then address) so duplicate snapshot rows do not create two ``*_L1`` symbols.
        """
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._snapshot_user_defined_primary_labels")
        out: list[tuple[str, str]] = []
        if program is None:
            return out
        try:
            st = program.getSymbolTable()
            seen_addr_name: set[tuple[str, str]] = set()

            def _take(sym: Any) -> None:
                try:
                    if not _sym_eligible_for_versioned_label_snapshot(sym):
                        return
                    addr_s = str(sym.getAddress())
                    nm = str(sym.getName())
                    key = (addr_s, nm)
                    if key in seen_addr_name:
                        return
                    seen_addr_name.add(key)
                    out.append(key)
                except Exception:
                    return

            for sym in iter_items(st.getDefinedSymbols()):
                _take(sym)
            # JPype/shared: user create-label rows may be visible only via getAllSymbols (or arrive late
            # vs. getDefinedSymbols). Merging always — not only when `out` is empty — fixes versioned
            # reopen check-ins that would otherwise upload revisions without LFG sh_* / loc_* labels.
            if hasattr(st, "getAllSymbols"):
                try:
                    for sym in iter_items(st.getAllSymbols(True)):
                        _take(sym)
                except Exception:
                    logger.debug("snapshot_user_defined_primary_labels getAllSymbols merge failed", exc_info=True)
            if not out and hasattr(st, "getSymbolIterator"):
                try:
                    fwd = st.getSymbolIterator(True)
                except Exception:
                    fwd = st.getSymbolIterator()
                try:
                    for sym in iter_items(fwd):
                        _take(sym)
                except Exception:
                    logger.debug("snapshot_user_defined_primary_labels getSymbolIterator fallback failed", exc_info=True)
            # Secondary USER labels at function entries (LFG *_L2): getAllSymbols may omit them while
            # getSymbols(addr) still lists the LABEL row — expand every defined-symbol address (sort-sized OK).
            try:
                af = program.getAddressFactory()
                seen_addr: set[str] = set()
                for sym in iter_items(st.getDefinedSymbols()):
                    try:
                        seen_addr.add(str(sym.getAddress()))
                    except Exception:
                        continue
                for addr_s in seen_addr:
                    try:
                        a = af.getAddress(addr_s)
                        if a is None:
                            continue
                        for sym in iter_items(st.getSymbols(a)):
                            _take(sym)
                    except Exception:
                        continue
            except Exception:
                logger.debug("snapshot expand getSymbols(per-defined-address) failed", exc_info=True)
        except Exception as exc:
            logger.debug("snapshot_user_defined_primary_labels: %s", exc)
        # One row per label name: expand passes can collect the same name at two VAs; reapply already applies
        # each name once — deduping here avoids ambiguous versioned check-ins and server-side oddities.
        out.sort(key=lambda t: (t[1], t[0]))
        deduped: list[tuple[str, str]] = []
        seen_names: set[str] = set()
        for addr_s, nm in out:
            n = str(nm).strip()
            if not n or n in seen_names:
                continue
            seen_names.add(n)
            deduped.append((addr_s, n))
        return deduped

    def _reapply_user_defined_primary_labels(self, program: Any, snapshots: list[tuple[str, str]]) -> None:
        """Recreate USER_DEFINED labels on a freshly opened Program (versioned check-in reopen path)."""
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._reapply_user_defined_primary_labels")
        if program is None or not snapshots:
            return
        from ghidra.program.model.symbol import SourceType as GhidraSourceType  # pyright: ignore[reportMissingImports]

        st = program.getSymbolTable()

        def _already_has_user_label_at(addr: Any, nm: str) -> bool:
            try:
                for sym in iter_items(st.getSymbols(addr)):
                    try:
                        if not _sym_is_user_defined_label(sym):
                            continue
                        if str(sym.getName()) == nm:
                            return True
                    except Exception:
                        continue
            except Exception:
                return False
            return False

        def _apply() -> None:
            applied_names: set[str] = set()
            for addr_s, name in sorted(snapshots, key=lambda t: (t[1], t[0])):
                nm = str(name).strip()
                if not nm or nm in applied_names:
                    continue
                try:
                    addr = self._resolve_address(str(addr_s).strip(), program=program)
                    if _already_has_user_label_at(addr, nm):
                        applied_names.add(nm)
                        continue
                    fn_at = None
                    try:
                        fm = program.getFunctionManager()
                        if fm is not None:
                            fn_at = fm.getFunctionAt(addr)
                    except Exception:
                        fn_at = None
                    created = False
                    # Function entry: prefer non-primary label first (LFG *_L2); 3-arg often fails there.
                    if fn_at is not None:
                        try:
                            ns = program.getGlobalNamespace()
                            st.createLabel(addr, nm, ns, False, GhidraSourceType.USER_DEFINED)
                            created = True
                        except Exception:
                            pass
                    if not created:
                        try:
                            st.createLabel(addr, nm, GhidraSourceType.USER_DEFINED)
                            created = True
                        except Exception:
                            try:
                                ns = program.getGlobalNamespace()
                                st.createLabel(addr, nm, ns, False, GhidraSourceType.USER_DEFINED)
                                created = True
                            except Exception:
                                pass
                    if created:
                        applied_names.add(nm)
                except Exception:
                    continue

        try:
            self._run_program_transaction(program, "versioned-checkin-reopen-label-reapply", _apply)
        except Exception as exc:
            logger.debug("reapply_user_defined_primary_labels: %s", exc)

    def _invoke_domain_file_save_best_effort(self, domain_file: GhidraDomainFile, monitor: GhidraTaskMonitor) -> None:
        """Run ``GhidraFile.save`` on the Swing EDT when possible; headless PyGhidra can reject saves off-EDT."""
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._invoke_domain_file_save_best_effort")
        try:
            from java.lang import Runnable  # type: ignore[import-untyped]
            from javax.swing import SwingUtilities  # type: ignore[import-untyped]
            from jpype import JImplements, JOverride  # type: ignore[import-untyped]

            err_holder: list[BaseException | None] = [None]

            @JImplements(Runnable)
            class _SaveRunnable:
                def __init__(self, df: GhidraDomainFile, mon: GhidraTaskMonitor, out_err: list[BaseException | None]) -> None:
                    self._df = df
                    self._mon = mon
                    self._out_err = out_err

                @JOverride
                def run(self) -> None:
                    try:
                        self._df.save(self._mon)
                    except Exception as inner:
                        self._out_err[0] = inner

            SwingUtilities.invokeAndWait(_SaveRunnable(domain_file, monitor, err_holder))
            if err_holder[0] is not None:
                raise err_holder[0]
        except Exception as edt_exc:
            logger.debug("EDT domain_file.save fallback to direct save: %s", edt_exc)
            domain_file.save(monitor)

    def _dispose_decompilers_for_domain_file(self, session_id: str, domain_file: GhidraDomainFile) -> None:
        """Release DecompInterface handles that can keep the Program locked for GhidraFile.save (headless MCP)."""
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._dispose_decompilers_for_domain_file")
        if domain_file is None:
            return

        def _program_aligns(prog: GhidraProgram) -> bool:
            if prog is None:
                return False
            try:
                df = prog.getDomainFile()
                return df is not None and self._domain_files_align_for_checkin(df, domain_file)
            except Exception:
                return False

        def _dispose_pi(pi: Any) -> None:
            if pi is None:
                return
            prog = getattr(pi, "program", None) or getattr(pi, "current_program", None)
            if not _program_aligns(prog):
                return
            dec = getattr(pi, "decompiler", None)
            if dec is None:
                return
            try:
                dec.closeProgram()
            except Exception:
                pass
            try:
                dec.dispose()
            except Exception:
                pass

        try:
            sess = SESSION_CONTEXTS.get_or_create(session_id)
            for _k, info in list((sess.open_programs or {}).items()):
                _dispose_pi(info)
        except Exception as exc:
            logger.debug("dispose decompilers (session) for domain file: %s", exc)
        try:
            _dispose_pi(self.program_info)
        except Exception as exc:
            logger.debug("dispose decompiler (provider program_info): %s", exc)
        if self._manager is not None:
            try:
                for pr in getattr(self._manager, "providers", None) or []:
                    _dispose_pi(getattr(pr, "program_info", None))
            except Exception as exc:
                logger.debug("dispose decompilers (manager providers): %s", exc)

    def _save_domain_file_before_versioned_checkin_sync_body(
        self,
        domain_file: GhidraDomainFile,
        program: GhidraProgram | None,
        session_id: str,
    ) -> None:
        """Run flush and transaction drain on the **current** thread (must be Swing EDT).

        Persists via ``GhidraProject.save`` / ``Program.save`` from ``_persist_open_program_for_versioned_checkin``;
        avoids a redundant ``GhidraFile.save`` on the open checkout (see method body).
        """
        logger.debug(
            "diag.enter %s",
            "mcp_server/providers/import_export.py:ImportExportToolProvider._save_domain_file_before_versioned_checkin_sync_body",
        )
        if domain_file is not None:
            try:
                session: SessionContext = SESSION_CONTEXTS.get_or_create(session_id)
                for _k, info in list((session.open_programs or {}).items()):
                    prog: GhidraProgram | None = info.program or info.current_program
                    if prog is None:
                        continue
                    try:
                        df: GhidraDomainFile | None = prog.getDomainFile()
                        if df is None:
                            continue
                        if not self._domain_files_align_for_checkin(df, domain_file):
                            continue
                        self._persist_open_program_for_versioned_checkin(prog)
                        self._notify_domain_file_changed_for_versioned_checkin(domain_file, prog)
                    except Exception as inner_exc:
                        logger.debug("session program save before versioned check-in: %s", inner_exc)
            except Exception as loop_exc:
                logger.debug("iterate session programs for pre-checkin save: %s", loop_exc)

        if program is not None:
            self._persist_open_program_for_versioned_checkin(program)
            self._notify_domain_file_changed_for_versioned_checkin(domain_file, program)
        else:
            self._notify_domain_file_changed_for_versioned_checkin(domain_file, None)
        self._dispose_decompilers_for_domain_file(session_id, domain_file)
        self._end_open_transactions_on_domain_file_consumers(domain_file)
        gp_pre: GhidraProject | None = self._manager.ghidra_project if self._manager is not None else None
        jp_pre: GhidraProject | None = None
        if gp_pre is not None:
            try:
                jp_pre = gp_pre.getProject()
            except Exception as exc:
                logger.debug("getProject before pre-checkin flush: %s", exc)
                jp_pre = None
            for cand in (gp_pre, jp_pre):
                if cand is not None and (hasattr(cand, "getCurrentTransactionInfo") or hasattr(cand, "getCurrentTransaction")) and hasattr(cand, "endTransaction") and hasattr(cand, "save"):
                    try:
                        self._end_nested_non_batch_transactions_on_program(cand)
                    except Exception as gp_exc:
                        logger.debug("end transactions on GhidraProject after pre-checkin flush: %s", gp_exc)
        self._end_open_transactions_on_all_session_programs(session_id)
        self._end_open_transactions_on_domain_file_consumers(domain_file)
        if gp_pre is not None:
            for cand in (gp_pre, jp_pre):
                if cand is not None and (hasattr(cand, "getCurrentTransactionInfo") or hasattr(cand, "getCurrentTransaction")):
                    try:
                        self._end_nested_non_batch_transactions_on_program(cand)
                    except Exception as gp_exc2:
                        logger.debug("end transactions on GhidraProject (second pass): %s", gp_exc2)
        self._end_open_transactions_on_all_session_programs(session_id)
        # Final project-level flush, then optional GhidraFile.save when modifiedSinceCheckout() is still false.
        if gp_pre is not None and program is not None:
            try:
                gp_pre.save(program)
            except Exception as gp_save_final_exc:
                logger.debug("final ghidra_project.save before versioned check-in: %s", gp_save_final_exc)
            self._end_nested_non_batch_transactions_on_program(program)
            self._end_open_transactions_on_domain_file_consumers(domain_file)
        self._dispose_decompilers_for_domain_file(session_id, domain_file)
        self._end_open_transactions_on_domain_file_consumers(domain_file)
        if program is not None:
            self._end_nested_non_batch_transactions_on_program(program)
        # Versioned checkout tracks dirty state on the folder/file tree — Program.setChanged alone is not always enough.
        self._force_domain_object_changed_for_versioned_checkin(program)
        self._force_domain_object_changed_for_versioned_checkin(domain_file)
        try:
            if domain_file is not None and hasattr(domain_file, "getParent"):
                par = domain_file.getParent()
                self._force_domain_object_changed_for_versioned_checkin(par)
        except Exception:
            pass
        self._notify_domain_file_changed_for_versioned_checkin(domain_file, program)
        # GhidraProject.save may persist bytes without bumping modifiedSinceCheckout on the server checkout handle.
        try:
            still_clean = True
            if domain_file is not None and hasattr(domain_file, "modifiedSinceCheckout"):
                still_clean = not bool(domain_file.modifiedSinceCheckout())
        except Exception:
            still_clean = True
        if still_clean:
            from ghidra.util.task import TaskMonitor as GhidraTaskMonitor  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

            self._try_mark_versioned_checkout_dirty(domain_file)
            try:
                still_clean = not bool(domain_file.modifiedSinceCheckout())
            except Exception:
                still_clean = True
            if not still_clean:
                return
            if program is not None:
                self._wait_for_program_analysis_idle(program, max_wait_sec=90.0)
            if gp_pre is not None and program is not None:
                try:
                    gp_pre.save(program)
                except Exception:
                    pass
                self._end_nested_non_batch_transactions_on_program(program)
                self._end_open_transactions_on_domain_file_consumers(domain_file)
            self._dispose_decompilers_for_domain_file(session_id, domain_file)
            self._end_open_transactions_on_domain_file_consumers(domain_file)
            if program is not None:
                self._end_nested_non_batch_transactions_on_program(program)
            save_aligned: GhidraDomainFile | None = None
            if program is not None:
                try:
                    pdf2 = program.getDomainFile()
                    if pdf2 is not None and self._domain_files_align_for_checkin(pdf2, domain_file):
                        save_aligned = pdf2
                except Exception:
                    save_aligned = None
            # Prefer path-resolved checkout handle, then Program's domain file (same logical file, different identity).
            for cand in (domain_file, save_aligned):
                if cand is None:
                    continue
                try:
                    cand.save(GhidraTaskMonitor.DUMMY)
                    break
                except Exception as save_opt_exc:
                    logger.debug("optional GhidraFile.save candidate failed: %s", save_opt_exc)

    def _save_domain_file_before_versioned_checkin(self, domain_file: GhidraDomainFile, program: GhidraProgram | None = None) -> None:
        """Flush open Program state, end transactions, then notify versioned checkout metadata.

        Runs on the **Swing EDT** (``invokeAndWait``) so Ghidra's domain lock checks align with headless PyGhidra.
        """
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._save_domain_file_before_versioned_checkin")
        if domain_file is None:
            return
        session_id = get_current_mcp_session_id()
        try:
            from java.awt import EventQueue as JavaEventQueue  # type: ignore[import-untyped]
            from java.lang import Runnable as JavaRunnable  # type: ignore[import-untyped]
            from javax.swing import SwingUtilities as JavaSwingUtilities  # type: ignore[import-untyped]
            from jpype import JImplements as JavaJImplements, JOverride as JavaJOverride  # type: ignore[import-untyped]

            if JavaEventQueue.isDispatchThread():
                self._save_domain_file_before_versioned_checkin_sync_body(domain_file, program, session_id)
                return

            err_holder: list[BaseException | None] = [None]
            provider: ImportExportToolProvider = self

            @JavaJImplements(JavaRunnable)
            class _FlushSaveOnEdt:
                @JavaJOverride
                def run(self) -> None:
                    try:
                        provider._save_domain_file_before_versioned_checkin_sync_body(domain_file, program, session_id)
                    except Exception as inner:
                        err_holder[0] = inner

            JavaSwingUtilities.invokeAndWait(_FlushSaveOnEdt())
            if err_holder[0] is not None:
                raise err_holder[0]
        except Exception as edt_exc:
            logger.debug("EDT pre-checkin flush failed, falling back to caller-thread save: %s", edt_exc)
            try:
                self._save_domain_file_before_versioned_checkin_sync_body(domain_file, program, session_id)
            except Exception:
                logger.warning(
                    "pre-checkin flush for versioned check-in failed (check-in may error); if the message mentions an active transaction, end open Ghidra transactions or close other consumers of this program before checkin-program",
                    exc_info=True,
                )

    def _domain_object_consumers_for_program(self, session_id: str, program: GhidraProgram) -> list[GhidraProgram]:
        """Consumers passed to ProgramDB/getDomainObject; required for Program.release when ghidra_project is absent/wrong."""
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._domain_object_consumers_for_program")
        out: list[GhidraProgram] = []
        seen: set[int] = set()

        def add(c: GhidraProgram | None) -> None:
            if c is None:
                return
            i: int = id(c)
            if i in seen:
                return
            seen.add(i)
            out.append(c)

        try:
            session: SessionContext = SESSION_CONTEXTS.get_or_create(session_id)
            for _k, info in list((session.open_programs or {}).items()):
                if info.program is not program:
                    continue
                add(info.domain_object_consumer)
        except Exception:
            pass
        pi: ProgramInfo | None = self.program_info
        if pi is not None and pi.program is program:
            add(pi.domain_object_consumer)
        if self._manager is not None:
            for pr in self._manager.providers or []:
                opi: ProgramInfo | None = pr.program_info
                if opi is not None and opi.program is program:
                    add(opi.domain_object_consumer)
        return out

    @staticmethod
    def _ghidra_release_consumer_candidates(ghidra_project: GhidraProject) -> list[GhidraProject]:
        """Consumers to try for Program.release — Ghidra often registers the Java Project, not GhidraProject."""
        out: list[GhidraProject] = []
        if ghidra_project is None:
            return out
        try:
            jp = ghidra_project.getProject()
            if jp is not None:
                out.append(jp)
        except Exception:
            pass
        out.append(ghidra_project)
        return out

    def _try_release_via_domain_file_consumers(
        self,
        *,
        domain_file: GhidraDomainFile,
        program: GhidraProgram,
        ghidra_project: GhidraProject,
        extra_consumers: list[GhidraProgram],
    ) -> bool:
        """If ``program.release`` fails, release objects returned by ``GhidraDomainFile.getConsumers()`` (adapter/JVM edge cases)."""
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._try_release_via_domain_file_consumers")
        candidates: list[GhidraProgram] = []
        seen: set[int] = set()

        def add_obj(o: GhidraProgram) -> None:
            if o is None or not hasattr(o, "release"):
                return
            oid = id(o)
            if oid in seen:
                return
            seen.add(oid)
            candidates.append(o)

        add_obj(program)
        try:
            for c in domain_file.getConsumers() or []:
                add_obj(c)
        except Exception as exc:
            logger.debug("domain_file.getConsumers before check-in: %s", exc)
        proj_cons = self._ghidra_release_consumer_candidates(ghidra_project)
        for obj in candidates:
            self._end_open_transaction_on_program(obj)
            for consumer in (*extra_consumers, None, *proj_cons):
                try:
                    obj.release(consumer)
                    logger.debug("check-in: released via GhidraDomainFile consumer list")
                    if ghidra_project is not None:
                        try:
                            if hasattr(obj, "isClosed") and not obj.isClosed():
                                ghidra_project.close(obj)
                        except Exception:
                            pass
                    return True
                except Exception as exc:
                    logger.debug("check-in: consumer-list release failed: %s", exc)
                    continue
        return False

    def _release_open_program_before_versioned_checkin(
        self,
        *,
        session_id: str,
        program_path_key: str | None,
        program: GhidraProgram | None,
        domain_file: GhidraDomainFile | None = None,
    ) -> bool:
        """Close the Ghidra Program consumer so ``GhidraDomainFile.checkin`` does not throw FileInUseException.

        Returns False if the program could not be released or closed (caller must not check in).
        """
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._release_open_program_before_versioned_checkin")
        if program is None:
            return True
        ghidra_project = getattr(self._manager, "ghidra_project", None) if self._manager else None

        def _dispose_decompiler_for_pi(pi: ProgramInfo) -> None:
            if pi is None or getattr(pi, "program", None) is not program:
                return
            dec: GhidraDecompInterface | None = getattr(pi, "decompiler", None)
            if dec is None:
                return
            try:
                dec.closeProgram()
            except Exception:
                pass
            try:
                dec.dispose()
            except Exception:
                pass

        try:
            session_tmp = SESSION_CONTEXTS.get_or_create(session_id)
            for _k, info in list((session_tmp.open_programs or {}).items()):
                _dispose_decompiler_for_pi(info)
        except Exception as exc:
            logger.debug("decompiler dispose (session) before check-in: %s", exc)
        if self.program_info is not None:
            _dispose_decompiler_for_pi(self.program_info)
        if self._manager is not None:
            for pr in getattr(self._manager, "providers", None) or []:
                if pr is not None and getattr(pr, "program_info", None) is not None:
                    _dispose_decompiler_for_pi(pr.program_info)

        self._end_all_open_transactions_on_program(program)
        released = False
        extra_consumers: list[GhidraProgram] = self._domain_object_consumers_for_program(session_id, program)
        proj_cons: list[GhidraProject] = self._ghidra_release_consumer_candidates(ghidra_project) if ghidra_project is not None else []
        for consumer in (*extra_consumers, None, *proj_cons):
            try:
                program.release(consumer)
                released = True
                logger.debug(
                    "program.release before versioned check-in (path=%r, consumer=%s)",
                    program_path_key,
                    "project" if consumer is not None else "null",
                )
                break
            except Exception as exc:
                logger.debug("program.release(%r) failed: %s", consumer, exc)
                continue
        if ghidra_project is not None:
            try:
                if hasattr(program, "isClosed") and not program.isClosed():
                    ghidra_project.close(program)
                    logger.debug("ghidra_project.close(program) before versioned check-in (path=%r)", program_path_key)
            except Exception as exc:
                logger.debug("ghidra_project.close before check-in: %s", exc)
        try:
            closed_ok = bool(program.isClosed())
        except Exception:
            closed_ok = False
        if not released and not closed_ok and domain_file is not None:
            if self._try_release_via_domain_file_consumers(
                domain_file=domain_file,
                program=program,
                ghidra_project=ghidra_project,
                extra_consumers=extra_consumers,
            ):
                released = True
            try:
                closed_ok = bool(program.isClosed())
            except Exception:
                closed_ok = False
        if not released and not closed_ok:
            logger.warning("Could not release program before check-in for path=%r", program_path_key)
            return False
        try:
            session = SESSION_CONTEXTS.get_or_create(session_id)
            keys: set[str] = set()
            if program_path_key:
                keys.add(self._canonical_program_path_for_session(program_path_key))
            for k, info in list(session.open_programs.items()):
                if getattr(info, "program", None) is program:
                    keys.add(k)
            for k in keys:
                session.open_programs.pop(k, None)
            if session.active_program_key in keys:
                session.active_program_key = next(iter(session.open_programs.keys()), None)
        except Exception as exc:
            logger.debug("Session cleanup after program release: %s", exc)
        return True

    async def _handle_checkin(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._handle_checkin")
        program_path = self._get_str(args, "programpath", "program_path", "path", default="").strip()
        comment = self._get_str(args, "comment", "message", default="AgentDecompile checkin")
        keep_checked_out = self._get_bool(args, "keepcheckedout", default=False)
        auto_checkin_flow = self._get_bool(args, "__auto_checkin_invocation", default=False)

        # Zero-arg: check in all open programs that are versioned and can be checked in
        if not program_path:
            session_id = get_current_mcp_session_id()
            session = SESSION_CONTEXTS.get_or_create(session_id)
            results: list[dict[str, Any]] = []
            all_ok = True
            try:
                from ghidra.framework.data import DefaultCheckinHandler as GhidraDefaultCheckinHandler  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
                from ghidra.util.task import TaskMonitor as GhidraTaskMonitor  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

                checkin_comment = comment or "Checkin all changes"
                # Auto-checkin flow (AGENTDECOMPILE_AUTO_CHECKIN): checkout if not already checked out so we can check in;
                # after check-in, re-checkout only programs that were already checked out (don't leave others exclusively checked out).
                already_checked_out: list[tuple[str, Any]] = []  # (path_key, domain_file)
                we_checked_out: list[str] = []  # path_keys we checked out in this flow
                if auto_checkin_flow:
                    for path_key, info in (session.open_programs or {}).items():
                        prog = getattr(info, "program", None) or getattr(info, "current_program", None)
                        if prog is None:
                            continue
                        domain_file = prog.getDomainFile()
                        if domain_file is None or not domain_file.isVersioned():
                            continue
                        if domain_file.isCheckedOut():
                            already_checked_out.append((path_key, domain_file))
                        else:
                            try:
                                domain_file.checkout(True, GhidraTaskMonitor.DUMMY)
                                we_checked_out.append(path_key)
                            except Exception:
                                all_ok = False
                                # Main loop below will still process this program (will save locally since canCheckin() is false)

                # Use keep_checked_out=False for auto flow so check-in doesn't re-checkout; we'll re-checkout only already_checked_out below.
                _keep = keep_checked_out if not auto_checkin_flow else False
                for path_key, info in (session.open_programs or {}).items():
                    prog: GhidraProgram | None = getattr(info, "program", None) or getattr(info, "current_program", None)
                    if prog is None:
                        results.append({"programPath": path_key, "success": False, "error": "No program handle"})
                        all_ok = False
                        continue
                    domain_file: GhidraDomainFile | None = prog.getDomainFile()
                    if domain_file is None:
                        continue
                    try:
                        repair_path = str(path_key or "").strip()
                        if not repair_path:
                            try:
                                repair_path = str(domain_file.getPathname() or prog.getName() or "").strip()
                            except Exception:
                                repair_path = ""
                        if repair_path and self._shared_repository_has_program_path(repair_path):
                            need_shared_repair = False
                            try:
                                need_shared_repair = not bool(domain_file.isVersioned()) or not bool(domain_file.isCheckedOut())
                            except Exception:
                                need_shared_repair = True
                            if need_shared_repair:
                                repaired = await self._repair_shared_working_copy_for_checkin(
                                    program_path=repair_path,
                                    exclusive=True,
                                )
                                if repaired is not None:
                                    domain_file, repaired_name = repaired
                                    repaired_prog = self._resolve_program_for_domain_file(
                                        domain_file,
                                        program_path=repair_path,
                                        program_display_name=repaired_name,
                                    )
                                    if repaired_prog is not None:
                                        prog = repaired_prog
                        if domain_file.isVersioned() and domain_file.canCheckin():
                            self._ensure_versioned_file_ready_for_checkin(domain_file, prog)
                            self._save_domain_file_before_versioned_checkin(domain_file, prog)
                            if not self._release_open_program_before_versioned_checkin(
                                session_id=session_id,
                                program_path_key=path_key,
                                program=prog,
                                domain_file=domain_file,
                            ):
                                results.append(
                                    {
                                        "programPath": path_key,
                                        "success": False,
                                        "error": ("Could not release program before check-in (still in use). Close other tools holding this program and retry."),
                                        "mode": "checkin",
                                    },
                                )
                                all_ok = False
                                continue
                            handler = GhidraDefaultCheckinHandler(checkin_comment, _keep, False)
                            domain_file.checkin(handler, GhidraTaskMonitor.DUMMY)
                            results.append({"programPath": path_key, "success": True, "mode": "checkin"})
                        elif domain_file.isVersioned():
                            # Versioned but cannot check in (e.g. not checked out to this client, or foreign lock).
                            # Do not report save_local + success — that misleads callers into thinking the server got a check-in.
                            holder: str | None = None
                            try:
                                st = domain_file.getCheckoutStatus()
                                if st is not None and hasattr(st, "getUser"):
                                    holder = str(st.getUser() or "").strip() or None
                            except Exception:
                                pass
                            results.append(
                                {
                                    "programPath": path_key,
                                    "success": False,
                                    "mode": "checkin_blocked",
                                    "reason": "versioned_not_checkinable",
                                    "checkoutHolder": holder,
                                    "error": ("Versioned file cannot be checked in from this session (call checkout-program first, or resolve checkout holder mismatch)."),
                                },
                            )
                            all_ok = False
                        else:
                            # Local (non-versioned): use gp.save(program) FIRST so GhidraProject ends batch tx
                            # and flushes, then drain residual txs, then release, then fallback save.
                            self._ensure_versioned_file_ready_for_checkin(domain_file, prog)
                            self._dispose_decompilers_for_domain_file(session_id, domain_file)
                            self._end_open_transactions_on_domain_file_consumers(domain_file)
                            gp_all = getattr(self._manager, "ghidra_project", None) if self._manager else None
                            saved_all_ok = False
                            if gp_all is not None:
                                try:
                                    self._end_nested_non_batch_transactions_on_program(prog)
                                    gp_all.save(prog)
                                    saved_all_ok = True
                                except Exception as gp_exc_all:
                                    logger.debug("checkin-all local: gp.save (primary): %s", gp_exc_all)
                            self._end_open_transactions_on_all_session_programs(session_id)
                            self._end_open_transactions_on_domain_file_consumers(domain_file)
                            if not saved_all_ok and prog is not None and hasattr(prog, "save"):
                                try:
                                    prog.save("AgentDecompile local save", GhidraTaskMonitor.DUMMY)
                                    saved_all_ok = True
                                except Exception as prog_save_exc:
                                    logger.debug("checkin-all local: program.save (fallback): %s", prog_save_exc)
                            if not self._release_open_program_before_versioned_checkin(
                                session_id=session_id,
                                program_path_key=path_key,
                                program=prog,
                                domain_file=domain_file,
                            ):
                                results.append(
                                    {
                                        "programPath": path_key,
                                        "success": False,
                                        "error": "Could not release program before local save (still in use).",
                                        "mode": "save_local",
                                    },
                                )
                                all_ok = False
                                continue
                            if not saved_all_ok:
                                try:
                                    domain_file.save(GhidraTaskMonitor.DUMMY)
                                    saved_all_ok = True
                                except Exception as save_exc:
                                    results.append(
                                        {
                                            "programPath": path_key,
                                            "success": False,
                                            "error": str(save_exc),
                                            "mode": "save_local",
                                        },
                                    )
                                    all_ok = False
                                    continue
                            results.append({"programPath": path_key, "success": True, "mode": "save_local"})
                    except Exception as e:
                        results.append({"programPath": path_key, "success": False, "error": str(e)})
                        all_ok = False

                # Re-checkout only programs that were already checked out before we did anything (don't leave them checked in if user had them out).
                if auto_checkin_flow and already_checked_out:
                    for _path_key, domain_file in already_checked_out:
                        try:
                            domain_file.checkout(True, GhidraTaskMonitor.DUMMY)
                        except Exception:
                            pass  # best-effort; program remains checked in
            except Exception as e:
                logger.warning(
                    "checkin_all_summary failed session_id=%s exc_type=%s",
                    redact_session_id(session_id),
                    type(e).__name__,
                )
                return create_success_response(
                    {
                        "action": "checkin",
                        "mode": "checkin_all",
                        "success": False,
                        "error": str(e),
                        "results": [],
                    },
                )
            ok_n = sum(1 for r in results if r.get("success"))
            blocked_n = sum(1 for r in results if r.get("mode") == "checkin_blocked")
            fail_n = len(results) - ok_n
            logger.info(
                "checkin_all_summary session_id=%s total=%s ok=%s failed=%s checkin_blocked=%s aggregate_ok=%s",
                redact_session_id(session_id),
                len(results),
                ok_n,
                fail_n,
                blocked_n,
                all_ok,
            )
            if blocked_n or fail_n:
                logger.warning(
                    "checkin_all_summary issues session_id=%s failed=%s checkin_blocked=%s",
                    redact_session_id(session_id),
                    fail_n,
                    blocked_n,
                )
            return create_success_response(
                {
                    "action": "checkin",
                    "mode": "checkin_all",
                    "comment": checkin_comment,
                    "success": all_ok,
                    "results": results,
                    "count": len(results),
                },
            )

        # Align with checkout-program keys (canonical repo path from session listing).
        program_path = self._canonical_program_path_for_session(program_path)

        # When program_path is provided, resolve domain file by path so we check in the requested file, not the active one
        domain_file = None
        program_display_name = program_path or ""
        if program_path:
            resolved = self._resolve_domain_file_for_checkout_status(program_path)
            if resolved is not None:
                domain_file, program_display_name = resolved
            elif program_path.startswith("/") or "/" in program_path:
                if not self.program_info:
                    return create_success_response(
                        {
                            "action": "checkin",
                            "program": program_path,
                            "comment": comment,
                            "keep_checked_out": keep_checked_out,
                            "success": False,
                            "reason": "shared-path-requires-session",
                            "error": "Checkin of shared repository files requires an active session with the shared Ghidra server. Call open with the shared server details first.",
                            "nextSteps": [
                                "Call `open` with `serverHost`, `serverPort`, `serverRepository`, and optional auth credentials.",
                                "Then retry `checkin-program` with the same program_path.",
                            ],
                        },
                    )
            if domain_file is None and program_path:
                return create_success_response(
                    {
                        "action": "checkin",
                        "program": program_path,
                        "comment": comment,
                        "keep_checked_out": keep_checked_out,
                        "success": False,
                        "error": f"Program path '{program_path}' could not be resolved. Call open and checkout-program first, then retry checkin-program with the same program_path.",
                    },
                )

        if domain_file is None:
            self._require_program()
            assert self.program_info is not None, "Program info should be available after _require_program()"
            program = self.program_info.program
            domain_file = program.getDomainFile()
            program_display_name = program.getName()

        try:
            from ghidra.framework.data import DefaultCheckinHandler as GhidraDefaultCheckinHandler  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
            from ghidra.util.task import TaskMonitor as GhidraTaskMonitor  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

            if domain_file is None:
                raise RuntimeError("No domain file associated with active program")

            # domain_file is path-resolved (often the versioned server checkout). Do not replace it with
            # Program.getDomainFile() for check-in — see comment on the block below.

            program_for_ops: GhidraProgram | None = self._resolve_program_for_domain_file(
                domain_file,
                program_path=program_path or "",
                program_display_name=program_display_name,
            )
            if program_for_ops is None and program_path:
                sid_fb = get_current_mcp_session_id()
                session_fb = SESSION_CONTEXTS.get_or_create(sid_fb)
                want_base = Path(program_path.replace("\\", "/")).name.lower()
                for path_key, info in list((session_fb.open_programs or {}).items()):
                    prog_fb = getattr(info, "program", None)
                    if prog_fb is None:
                        continue
                    key_base = Path(str(path_key).replace("\\", "/")).name.lower()
                    if want_base and key_base == want_base:
                        program_for_ops = prog_fb
                        break
                    try:
                        if str(prog_fb.getName()).strip().lower() == want_base:
                            program_for_ops = prog_fb
                            break
                    except Exception:
                        continue
            # Always check in the path-resolved DomainFile. Replacing
            # domain_file with Program.getDomainFile() when both report isVersioned() true can target a
            # different Java object than the checkout GhidraServer tracks, so create-label / symbol edits
            # flush to one handle while checkin consults another → "File has not been modified since checkout".
            # End program transactions and reclaim mismatched checkouts first; defer GhidraDomainFile consumer
            # transaction ends until after persist (see _save_domain_file_before_versioned_checkin below).
            self._ensure_versioned_file_ready_for_checkin(
                domain_file,
                program_for_ops,
                end_transactions_on_all_open_programs=(program_for_ops is None),
                end_domain_file_consumer_transactions=False,
            )

            try:
                versioned = bool(domain_file.isVersioned())
            except Exception:
                versioned = False
            try:
                checked_out = bool(domain_file.isCheckedOut())
            except Exception:
                checked_out = False
            eff_path: str = (program_path or "").strip()
            if not eff_path and program_for_ops is not None:
                try:
                    adf = program_for_ops.getDomainFile()
                    eff_path = str(adf.getPathname() or "").strip() if adf is not None else ""
                except Exception:
                    eff_path = ""
            repo_shared: bool = self._shared_repository_has_program_path((program_path or eff_path).strip())

            if repo_shared and (not versioned or not checked_out):
                repaired = await self._repair_shared_working_copy_for_checkin(
                    program_path=(program_path or eff_path).strip(),
                    exclusive=True,
                )
                if repaired is not None:
                    domain_file, program_display_name = repaired
                    program_for_ops = (
                        self._resolve_program_for_domain_file(
                            domain_file,
                            program_path=(program_path or eff_path).strip(),
                            program_display_name=program_display_name,
                        )
                        or program_for_ops
                    )
                    self._ensure_versioned_file_ready_for_checkin(
                        domain_file,
                        program_for_ops,
                        end_transactions_on_all_open_programs=(program_for_ops is None),
                        end_domain_file_consumer_transactions=False,
                    )
                    try:
                        versioned = bool(domain_file.isVersioned())
                    except Exception:
                        versioned = False
                    try:
                        checked_out = bool(domain_file.isCheckedOut())
                    except Exception:
                        checked_out = False

            # PyGhidra sometimes reports isVersioned() false even after RepositoryAdapter.checkout; if the file is
            # checked out and lives in a shared repo, use Ghidra's versioned checkin path (not local-only save).
            if not versioned:
                if repo_shared and checked_out:
                    versioned = True
                elif repo_shared:
                    return create_success_response(
                        {
                            "action": "checkin",
                            "program": program_display_name,
                            "comment": comment,
                            "keep_checked_out": keep_checked_out,
                            "success": False,
                            "error": (
                                "This program is listed in the shared Ghidra Server repository, but its GhidraDomainFile is not version-controlled in this project and is not checked out. Run checkout-program after open (shared), then retry checkin-program."
                            ),
                            "nextSteps": [
                                "Call open with shared server + repository, then checkout-program for this programPath.",
                                "Retry checkin-program with the same program_path.",
                            ],
                        },
                    )
                else:
                    # Not version-controlled — persist to local disk.
                    #
                    # GhidraProject.save() implementation (from Java source):
                    #   1. id = openPrograms.get(program)  // stored batch ID from startTransaction("Batch Processing")
                    #   2. program.endTransaction(id, true) // end batch tx using correct ID
                    #   3. program.getDomainFile().save(MONITOR) // save (requires no active tx)
                    #   4. openPrograms.put(program, program.startTransaction("")) // restart batch
                    #
                    # Direct gp.save() is NOT used as primary because endTransaction (step 2) fires
                    # domain-object change events that trigger analysis threads.  Those threads call
                    # startTransaction() before getDomainFile().save() can run, creating a persistent
                    # "Unable to lock due to active transaction" race.  Instead, we use a reflection-
                    # based approach that suppresses events around the endTransaction→save→restart
                    # sequence, eliminating the race entirely.
                    sid_loc = get_current_mcp_session_id()
                    save_comment = (comment or "").strip() or "AgentDecompile local save"
                    self._dispose_decompilers_for_domain_file(sid_loc, domain_file)
                    # Brief analysis wait — analysis creates nested txs that can delay save.
                    if program_for_ops is not None:
                        self._wait_for_program_analysis_idle(program_for_ops, max_wait_sec=30.0)
                    gp_loc = getattr(self._manager, "ghidra_project", None) if self._manager else None
                    saved_ok = False
                    save_mode: str | None = None
                    # --- Primary path: events-suppressed reflection save ---
                    # Suppresses events, ends batch tx, waits for any active analysis tx,
                    # then saves + restarts batch atomically under the Java monitor.
                    if gp_loc is not None and program_for_ops is not None:
                        # End any nested tool transactions first (keep batch tx).
                        self._end_nested_non_batch_transactions_on_program(program_for_ops)
                        save_mode = self._local_save_via_reflection(
                            gp_loc,
                            program_for_ops,
                            domain_file,
                            save_comment,
                        )
                        if save_mode is not None:
                            saved_ok = True
                    # If the reflection save succeeded, data is on disk.
                    # "primary" = program still healthy (batch restarted); skip release.
                    # "fallback" = program terminated (forceLock); clear session cache and skip release.
                    if saved_ok and save_mode is not None:
                        if save_mode == "fallback":
                            # Program is terminated after forceLock — clear from session so
                            # the next tool call opens a fresh copy from disk.
                            try:
                                session_cleanup = SESSION_CONTEXTS.get_or_create(sid_loc)
                                keys_to_remove: set[str] = set()
                                if program_path:
                                    keys_to_remove.add(self._canonical_program_path_for_session(program_path))
                                for k, info in list(session_cleanup.open_programs.items()):
                                    if getattr(info, "program", None) is program_for_ops:
                                        keys_to_remove.add(k)
                                for k in keys_to_remove:
                                    session_cleanup.open_programs.pop(k, None)
                                if session_cleanup.active_program_key in keys_to_remove:
                                    session_cleanup.active_program_key = next(
                                        iter(session_cleanup.open_programs.keys()),
                                        None,
                                    )
                            except Exception as sc_exc:
                                logger.debug("session cleanup after forceLock save: %s", sc_exc)
                        return create_success_response(
                            {
                                "action": "checkin",
                                "program": program_display_name,
                                "comment": comment,
                                "keep_checked_out": keep_checked_out,
                                "success": True,
                                "note": "File is not versioned; saved locally.",
                            },
                        )
                    # --- Fallback: drain all transactions then direct saves ---
                    if not saved_ok:
                        if program_for_ops is not None:
                            self._end_all_open_transactions_on_program(program_for_ops)
                        self._end_open_transactions_on_all_session_programs(sid_loc)
                        self._end_open_transactions_on_domain_file_consumers(domain_file)
                        if program_for_ops is not None and hasattr(program_for_ops, "save"):
                            try:
                                program_for_ops.save(save_comment, GhidraTaskMonitor.DUMMY)
                                saved_ok = True
                            except Exception as pre_close_exc:
                                logger.warning("Local check-in: program.save fallback FAILED: %s", pre_close_exc)
                    if not self._release_open_program_before_versioned_checkin(
                        session_id=sid_loc,
                        program_path_key=program_path or None,
                        program=program_for_ops,
                        domain_file=domain_file,
                    ):
                        return create_success_response(
                            {
                                "action": "checkin",
                                "program": program_display_name,
                                "comment": comment,
                                "keep_checked_out": keep_checked_out,
                                "success": False,
                                "error": "Could not release program before local save (still in use).",
                            },
                        )
                    if not saved_ok:
                        try:
                            domain_file.save(GhidraTaskMonitor.DUMMY)
                            saved_ok = True
                        except Exception as save_exc:
                            logger.warning("Local check-in: domain_file.save after release failed: %s", save_exc)
                            return create_success_response(
                                {
                                    "action": "checkin",
                                    "program": program_display_name,
                                    "comment": comment,
                                    "keep_checked_out": keep_checked_out,
                                    "success": False,
                                    "error": str(save_exc),
                                },
                            )
                    return create_success_response(
                        {
                            "action": "checkin",
                            "program": program_display_name,
                            "comment": comment,
                            "keep_checked_out": keep_checked_out,
                            "success": True,
                            "note": "File is not versioned; saved locally.",
                        },
                    )

            if not checked_out:
                raise RuntimeError(
                    "File is not checked out. Call checkout-program first before making changes.",
                )

            _keep: bool = keep_checked_out

            session_id_vc: str = get_current_mcp_session_id()

            program_domain_file: GhidraDomainFile | None = None
            try:
                if program_for_ops is not None:
                    program_domain_file = program_for_ops.getDomainFile()
            except Exception:
                program_domain_file = None

            # Path-resolved ``domain_file`` is the checkout handle Ghidra's server tracks. ``Program.getDomainFile()``
            # can be a different Java object for the same binary. Pre-checkin flush must target the **same** handle
            # ``.checkin()`` uses; flushing only through Program.getDomainFile() can persist to a sibling object so
            # checkin uploads an unmodified tree and the server never sees labels (LFG shared persistence).
            checkin_domain_file: GhidraDomainFile = domain_file
            eff_domain_file: GhidraDomainFile = domain_file
            if program_domain_file is not None and program_domain_file is not domain_file and self._domain_files_align_for_checkin(program_domain_file, domain_file):
                eff_domain_file = program_domain_file
                logger.info(
                    "checkin: program DomainFile differs from path-resolved checkout handle (%s); using program DomainFile for release/session alignment",
                    program_display_name,
                )

            # Prefer Program.getDomainFile() for versioned check-in whenever it aligns with the path-resolved file.
            # getFile() can return a different Java object than the Program's file; path-string equality can fail
            # (repo vs local pathname, slash style) while basename/name still match. Flushing and .checkin() on
            # only the path handle then yields "not modified" and empty server revisions (LFG shared labels).
            checkin_target: GhidraDomainFile = checkin_domain_file
            try:
                if program_for_ops is not None:
                    op_df = program_for_ops.getDomainFile()
                    if op_df is not None and self._domain_files_align_for_checkin(op_df, checkin_domain_file):
                        if op_df is not checkin_domain_file:
                            logger.info(
                                "checkin: using program DomainFile as checkin target (aligned with path handle) program=%s",
                                program_display_name,
                            )
                        checkin_target = op_df
            except Exception:
                pass

            self._save_domain_file_before_versioned_checkin(checkin_target, program_for_ops)
            self._end_open_transactions_on_domain_file_consumers(checkin_target)
            if eff_domain_file is not checkin_target:
                self._end_open_transactions_on_domain_file_consumers(eff_domain_file)
            if eff_domain_file is not checkin_target:
                self._try_mark_versioned_checkout_dirty(checkin_target)
                self._notify_domain_file_changed_for_versioned_checkin(checkin_target, program_for_ops)

            try:
                need_vc_bump = checkin_target is not None and hasattr(checkin_target, "modifiedSinceCheckout") and not bool(checkin_target.modifiedSinceCheckout())
            except Exception:
                need_vc_bump = False
            if need_vc_bump:
                bump_prog = program_for_ops
                if bump_prog is None:
                    gp_bump = getattr(self._manager, "ghidra_project", None) if self._manager else None
                    if gp_bump is not None:
                        bump_prog = _ghidra_project_open_program_for_domain_file_save(
                            gp_bump,
                            eff_domain_file,
                            str(program_display_name or program_path or ""),
                        )
                if bump_prog is not None:
                    self._bump_versioned_checkout_dirty_bookmark(bump_prog)
                    self._persist_open_program_for_versioned_checkin(bump_prog)
                    self._save_domain_file_before_versioned_checkin(checkin_target, bump_prog)
                    self._notify_domain_file_changed_for_versioned_checkin(checkin_target, bump_prog)
                    self._try_mark_versioned_checkout_dirty(eff_domain_file)
                    self._notify_domain_file_changed_for_versioned_checkin(eff_domain_file, bump_prog)
                    if eff_domain_file is not checkin_target:
                        self._try_mark_versioned_checkout_dirty(checkin_target)
                        self._notify_domain_file_changed_for_versioned_checkin(checkin_target, bump_prog)
                    self._end_open_transactions_on_domain_file_consumers(checkin_target)
                    if eff_domain_file is not checkin_target:
                        self._end_open_transactions_on_domain_file_consumers(eff_domain_file)
                    if bump_prog is not program_for_ops:
                        self._release_open_program_before_versioned_checkin(
                            session_id=session_id_vc,
                            program_path_key=None,
                            program=bump_prog,
                            domain_file=eff_domain_file,
                        )

            # Shared import uses _end_all_open_transactions + GhidraDomainFile.save so LocalFolderItem's
            # current version diverges from LOCAL_CHECKOUT_VERSION (GhidraFileData.modifiedSinceCheckout).
            if program_for_ops is not None and checkin_target is not None:
                logger.info(
                    "versioned checkin: hard flush before checkin (gp.save → end-all → domain save) program=%s",
                    program_display_name,
                )
                gp_hf: GhidraProject | None = self._manager.ghidra_project if self._manager else None
                if gp_hf is not None:
                    try:
                        gp_hf.save(program_for_ops)
                    except Exception as exc_gps:
                        logger.debug("versioned checkin hard flush gp.save: %s", exc_gps)
                # Use nested-only drain: _end_all_open_transactions breaks GhidraProject.openPrograms batch
                # bookkeeping (see _persist_open_program_for_versioned_checkin), which can leave
                # modifiedSinceCheckout false after create-label — then reopen check-in uploads no symbols (LFG 02d).
                self._end_nested_non_batch_transactions_on_program(program_for_ops)
                try:
                    self._invoke_domain_file_save_best_effort(checkin_target, GhidraTaskMonitor.DUMMY)
                except Exception as exc_hf:
                    logger.debug("versioned checkin hard flush domain save: %s", exc_hf)
                self._try_mark_versioned_checkout_dirty(checkin_target)
                self._notify_domain_file_changed_for_versioned_checkin(checkin_target, program_for_ops)

            def _release_primary_consumer_after_checkin() -> bool:
                """Release the Program Ghidra held open for edits after a successful versioned check-in."""
                if program_for_ops is None:
                    return True
                try:
                    if bool(program_for_ops.isClosed()):
                        return True
                except Exception:
                    pass
                return self._release_open_program_before_versioned_checkin(
                    session_id=session_id_vc,
                    program_path_key=program_path or None,
                    program=program_for_ops,
                    domain_file=eff_domain_file,
                )

            def _release_session_eff_best_effort() -> None:
                try:
                    mgr: ProjectToolProvider | None = self._manager
                    if mgr is not None:
                        pp: ProjectToolProvider | None = mgr._get_project_provider()
                        if isinstance(pp, ProjectToolProvider):
                            pp._release_session_programs_for_domain_file(
                                session_id=session_id_vc,
                                domain_file=eff_domain_file,
                            )
                except Exception as exc:
                    logger.debug("release_session_programs_for_domain_file (versioned checkin): %s", exc)

            def _versioned_checkin_not_modified(exc: BaseException) -> bool:
                em = str(exc).lower()
                return "not been modified since checkout" in em or ("not modified" in em and "checkout" in em)

            def _versioned_checkin_in_use(exc: BaseException) -> bool:
                em = str(exc).lower()
                return "in use" in em or "fileinuse" in type(exc).__name__.lower()

            def _versioned_checkin_reopen_bump_and_checkin(
                exc_chain: BaseException,
                *,
                label_snapshot: list[tuple[str, str]] | None = None,
            ) -> None:
                gp_retry = getattr(self._manager, "ghidra_project", None) if self._manager else None
                if gp_retry is None:
                    raise exc_chain
                # Must match the DomainFile used by ``checkin_target.checkin(...)`` above. Using only the
                # path-resolved ``checkin_domain_file`` when it differs from the program's file can reopen/save
                # the wrong object so reopen check-in uploads no user labels (LFG 02d search-symbols empty).
                retry_df = checkin_target
                prog_retry = _ghidra_project_open_program_for_domain_file_save(
                    gp_retry,
                    retry_df,
                    str(program_display_name or program_path or ""),
                )
                if prog_retry is None:
                    raise exc_chain
                if label_snapshot:
                    self._reapply_user_defined_primary_labels(prog_retry, label_snapshot)
                self._bump_versioned_checkout_dirty_bookmark(prog_retry)
                self._persist_open_program_for_versioned_checkin(prog_retry)
                self._save_domain_file_before_versioned_checkin(retry_df, prog_retry)
                self._try_mark_versioned_checkout_dirty(retry_df)
                self._notify_domain_file_changed_for_versioned_checkin(retry_df, prog_retry)
                if eff_domain_file is not retry_df:
                    self._try_mark_versioned_checkout_dirty(eff_domain_file)
                    self._notify_domain_file_changed_for_versioned_checkin(eff_domain_file, prog_retry)
                self._end_open_transactions_on_domain_file_consumers(retry_df)
                if not self._release_open_program_before_versioned_checkin(
                    session_id=session_id_vc,
                    program_path_key=program_path or None,
                    program=prog_retry,
                    domain_file=retry_df,
                ):
                    raise exc_chain
                try:
                    mgr_r = self._manager
                    if mgr_r is not None:
                        project_provider_r = mgr_r._get_project_provider()
                        if isinstance(project_provider_r, ProjectToolProvider):
                            project_provider_r._release_session_programs_for_domain_file(
                                session_id=session_id_vc,
                                domain_file=retry_df,
                            )
                except Exception as rel_sess_exc:
                    logger.debug("release_session_programs_for_domain_file (checkin reopen path): %s", rel_sess_exc)
                handler_fb = GhidraDefaultCheckinHandler(comment, _keep, False)
                retry_df.checkin(handler_fb, GhidraTaskMonitor.DUMMY)  # pyright: ignore[reportOptionalMemberAccess]

            # Call check-in before releasing the open Program. Releasing first and then handling
            # "not modified" by reopening loads a fresh ProgramDB without in-memory label/symbol edits,
            # so the retry check-in can upload an empty revision (LFG shared search-symbols sees 0 labels).
            handler = GhidraDefaultCheckinHandler(comment, _keep, False)
            try:
                checkin_target.checkin(handler, GhidraTaskMonitor.DUMMY)  # pyright: ignore[reportOptionalMemberAccess]
            except Exception as checkin_exc:
                if _versioned_checkin_in_use(checkin_exc):
                    logger.info(
                        "versioned checkin file-in-use; releasing consumer then retrying (program=%s)",
                        program_display_name,
                    )
                    if not _release_primary_consumer_after_checkin():
                        return create_success_response(
                            {
                                "action": "checkin",
                                "program": program_display_name,
                                "comment": comment,
                                "keep_checked_out": keep_checked_out,
                                "success": False,
                                "error": (
                                    "Could not release program before check-in (still in use). If another AgentDecompile or Ghidra instance uses the same shared temp project, stop it or retry after it exits."
                                ),
                            },
                        )
                    _release_session_eff_best_effort()
                    handler_in = GhidraDefaultCheckinHandler(comment, _keep, False)
                    checkin_target.checkin(handler_in, GhidraTaskMonitor.DUMMY)  # pyright: ignore[reportOptionalMemberAccess]
                elif _versioned_checkin_not_modified(checkin_exc):
                    logger.warning(
                        "versioned checkin reported not-modified; bumping on still-open program then retry (program=%s)",
                        program_display_name,
                    )
                    po = program_for_ops
                    open_ok = po is not None
                    if open_ok:
                        try:
                            open_ok = not bool(po.isClosed())  # type: ignore[union-attr]
                        except Exception:
                            open_ok = True
                    if open_ok and po is not None:
                        self._bump_versioned_checkout_dirty_bookmark(po)
                        self._persist_open_program_for_versioned_checkin(po)
                        self._save_domain_file_before_versioned_checkin(checkin_target, po)
                        self._try_mark_versioned_checkout_dirty(checkin_target)
                        self._notify_domain_file_changed_for_versioned_checkin(checkin_target, po)
                        if eff_domain_file is not checkin_target:
                            self._try_mark_versioned_checkout_dirty(eff_domain_file)
                            self._notify_domain_file_changed_for_versioned_checkin(eff_domain_file, po)
                        self._end_open_transactions_on_domain_file_consumers(checkin_target)
                        if eff_domain_file is not checkin_target:
                            self._end_open_transactions_on_domain_file_consumers(eff_domain_file)
                        try:
                            handler_nm = GhidraDefaultCheckinHandler(comment, _keep, False)
                            checkin_target.checkin(handler_nm, GhidraTaskMonitor.DUMMY)  # pyright: ignore[reportOptionalMemberAccess]
                        except Exception as exc_nm2:
                            if not _versioned_checkin_not_modified(exc_nm2):
                                raise exc_nm2 from checkin_exc
                            logger.warning(
                                "versioned checkin still not-modified after open-program bump; "
                                "extra aligned-domain save + checkin retry (program=%s)",
                                program_display_name,
                            )
                            try:
                                pdf_align: GhidraDomainFile | None = None
                                try:
                                    pdf_align = po.getDomainFile()  # type: ignore[union-attr]
                                except Exception:
                                    pdf_align = None
                                self._persist_open_program_for_versioned_checkin(po)  # type: ignore[arg-type]
                                for df_extra in (pdf_align, checkin_target, eff_domain_file):
                                    if df_extra is None:
                                        continue
                                    try:
                                        self._invoke_domain_file_save_best_effort(df_extra, GhidraTaskMonitor.DUMMY)
                                    except Exception:
                                        pass
                                self._reflect_bump_modified_since_checkout_graph(checkin_target)
                                if eff_domain_file is not checkin_target:
                                    self._reflect_bump_modified_since_checkout_graph(eff_domain_file)
                                if pdf_align is not None and pdf_align is not checkin_target:
                                    self._reflect_bump_modified_since_checkout_graph(pdf_align)
                                handler_nm3 = GhidraDefaultCheckinHandler(comment, _keep, False)
                                checkin_target.checkin(handler_nm3, GhidraTaskMonitor.DUMMY)  # pyright: ignore[reportOptionalMemberAccess]
                            except Exception as exc_nm3:
                                if not _versioned_checkin_not_modified(exc_nm3):
                                    raise exc_nm3 from exc_nm2
                                logger.warning(
                                    "versioned checkin still not-modified; reopen path (program=%s)",
                                    program_display_name,
                                )
                                label_snap: list[tuple[str, str]] = []
                                if po is not None:
                                    try:
                                        label_snap = self._snapshot_user_defined_primary_labels(po)
                                    except Exception:
                                        label_snap = []
                                _pp_merge = (program_path or eff_path or "").strip()
                                for _t in SESSION_CONTEXTS.copy_pending_versioned_labels_resolved(session_id_vc, _pp_merge):
                                    if _t not in label_snap:
                                        label_snap.append(_t)
                                still_open = False
                                if po is not None:
                                    try:
                                        still_open = not bool(po.isClosed())
                                    except Exception:
                                        still_open = True
                                if still_open:
                                    if not _release_primary_consumer_after_checkin():
                                        raise checkin_exc
                                    _release_session_eff_best_effort()
                                _versioned_checkin_reopen_bump_and_checkin(
                                    checkin_exc,
                                    label_snapshot=label_snap or None,
                                )
                    else:
                        _pp_only = (program_path or eff_path or "").strip()
                        _pend_only = SESSION_CONTEXTS.copy_pending_versioned_labels_resolved(session_id_vc, _pp_only)
                        _versioned_checkin_reopen_bump_and_checkin(
                            checkin_exc,
                            label_snapshot=_pend_only if _pend_only else None,
                        )
                else:
                    raise checkin_exc

            if not _release_primary_consumer_after_checkin():
                return create_success_response(
                    {
                        "action": "checkin",
                        "program": program_display_name,
                        "comment": comment,
                        "keep_checked_out": keep_checked_out,
                        "success": False,
                        "error": (
                            "Could not release program before check-in (still in use). If another AgentDecompile or Ghidra instance uses the same shared temp project, stop it or retry after it exits."
                        ),
                    },
                )
            _release_session_eff_best_effort()
            # Do not clear pending_versioned_labels here: reopen reapply can fail silently for one label
            # (e.g. function-entry *_L2) while check-in still reports success; keeping pending lets the next
            # merge + check-in retry until all create-label rows reach the server (LFG 02d needs L1–L3).
            return create_success_response(
                {
                    "action": "checkin",
                    "program": program_display_name,
                    "comment": comment,
                    "keep_checked_out": keep_checked_out,
                    "version": checkin_domain_file.getLatestVersion(),  # pyright: ignore[reportOptionalMemberAccess]
                    "success": True,
                },
            )
        except Exception as exc:
            return create_success_response(
                {
                    "action": "checkin",
                    "program": program_display_name,
                    "comment": comment,
                    "keep_checked_out": keep_checked_out,
                    "success": False,
                    "error": str(exc),
                },
            )

    async def _handle_checkout(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._handle_checkout")
        exclusive: bool = self._get_bool(args, "exclusive", default=False)
        program_path: str = self._get_str(args, "programpath", "program_path", "path").strip()
        if program_path:
            program_path = self._canonical_program_path_for_session(program_path)

        domain_file: GhidraDomainFile | None = None
        program_display_name: str = program_path or ""

        # Check if this is a shared repository file BEFORE resolving GhidraDomainFile
        # For shared files, use repository_adapter.checkout() directly instead of GhidraDomainFile methods
        is_shared_repo_file: bool = False
        if program_path and (program_path.startswith("/") or "/" in program_path):
            session_id: str = get_current_mcp_session_id()
            session = SESSION_CONTEXTS.get_or_create(session_id)
            handle: dict[str, Any] | None = session.project_handle if isinstance(session.project_handle, dict) else None
            if handle and is_shared_server_handle(handle):
                repo_adapter: GhidraRepositoryAdapter | None = handle.get("repository_adapter")
                if repo_adapter is not None:
                    parts: list[str] = program_path.rsplit("/", 1)
                    folder_path: str = parts[0] if len(parts) == 2 else "/"
                    item_name: str = parts[1] if len(parts) == 2 else parts[0]
                    try:
                        repo_item: GhidraRepositoryItem | None = repo_adapter.getItem(folder_path, item_name)
                        if repo_item is None:
                            for ri in repo_adapter.getItemList(folder_path) or []:
                                rname: str = str(ri.getName()) if hasattr(ri, "getName") else str(ri)
                                if rname == item_name or rname.lower() == item_name.lower():
                                    repo_item = repo_adapter.getItem(folder_path, rname)
                                    break
                        if repo_item is not None:
                            is_shared_repo_file = True
                    except Exception:
                        pass
                # If no adapter (e.g. proxy) but we're in shared-server mode and path is repo-shaped, treat as shared
                if not is_shared_repo_file and (handle.get("repository_name") or handle.get("server_host")):
                    is_shared_repo_file = True

        # For shared repository files, use repository_adapter.checkout() directly
        if is_shared_repo_file:
            logger.info("[_handle_checkout] Detected shared repo file, using repository adapter checkout for %s", program_path)
            session_id = get_current_mcp_session_id()
            session = SESSION_CONTEXTS.get_or_create(session_id)
            handle = session.project_handle if isinstance(session.project_handle, dict) else None
            repo_adapter = handle.get("repository_adapter") if handle else None
            project_provider = None
            if self._manager is not None and hasattr(self._manager, "_get_project_provider"):
                project_provider = self._manager._get_project_provider()
            if isinstance(project_provider, ProjectToolProvider) and repo_adapter is not None:
                try:
                    logger.info("[_handle_checkout] Calling _checkout_shared_program for %s", program_path)
                    # Use repository adapter checkout directly for shared files
                    await project_provider._checkout_shared_program(
                        repo_adapter,
                        program_path,
                        session_id,
                        exclusive=exclusive,
                    )
                    logger.info("[_handle_checkout] _checkout_shared_program succeeded, re-resolving GhidraDomainFile")
                    # After checkout, re-resolve to get the versioned GhidraDomainFile
                    resolved = self._resolve_domain_file_for_checkout_status(program_path)
                    if resolved is not None:
                        domain_file, program_display_name = resolved
                        logger.info("[_handle_checkout] GhidraDomainFile resolved after checkout: %s", program_display_name)
                        return create_success_response(
                            {
                                "action": "checkout",
                                "program": program_display_name,
                                "exclusive": exclusive,
                                "success": True,
                                "is_checked_out": bool(
                                    domain_file is not None and domain_file.isCheckedOut(),
                                ),
                                "note": "Checked out via shared repository adapter.",
                            },
                        )
                    # Checkout succeeded but GhidraDomainFile not yet available - return success
                    logger.info("[_handle_checkout] Checkout succeeded but GhidraDomainFile not yet available")
                    return create_success_response(
                        {
                            "action": "checkout",
                            "program": program_path,
                            "exclusive": exclusive,
                            "success": True,
                            "note": "File checked out via repository adapter. GhidraDomainFile resolution pending.",
                        },
                    )
                except Exception as exc:
                    logger.warning("[_handle_checkout] _checkout_shared_program failed: %s", exc)
                    # Check if file is already checked out (might be from session or previous checkout)
                    try:
                        resolved = self._resolve_domain_file_for_checkout_status(program_path)
                        if resolved is not None:
                            domain_file_check, _ = resolved
                            if domain_file_check is not None and domain_file_check.isCheckedOut():
                                logger.info("[_handle_checkout] File '%s' is already checked out, returning success", program_path)
                                return create_success_response(
                                    {
                                        "action": "checkout",
                                        "program": program_path,
                                        "exclusive": exclusive,
                                        "success": True,
                                        "note": "File was already checked out",
                                    },
                                )
                    except Exception:
                        pass
                    return create_success_response(
                        {
                            "action": "checkout",
                            "program": program_path,
                            "exclusive": exclusive,
                            "success": False,
                            "reason": "repository-checkout-failed",
                            "error": str(exc),
                        },
                    )
            else:
                logger.warning(
                    "[_handle_checkout] Cannot use repository checkout: project_provider=%s, repo_adapter=%s", project_provider is not None, repo_adapter is not None
                )

        # When program_path is provided, resolve GhidraDomainFile by path (shared or session) so checkout
        # works for shared repo paths even when that program is not the active one.
        if program_path and not is_shared_repo_file:
            resolved = self._resolve_domain_file_for_checkout_status(program_path)
            if resolved is not None:
                domain_file, program_display_name = resolved
            elif program_path.startswith("/") or "/" in program_path:
                # Shared path but could not resolve: bring the file from the repo into the project
                # via the project provider's _checkout_shared_program, then re-resolve.
                session_id = get_current_mcp_session_id()
                session = SESSION_CONTEXTS.get_or_create(session_id)
                handle = session.project_handle if isinstance(session.project_handle, dict) else None
                repo_adapter = handle.get("repository_adapter") if handle else None
                project_provider = None
                if self._manager is not None and hasattr(self._manager, "_get_project_provider"):
                    project_provider = self._manager._get_project_provider()
                if isinstance(project_provider, ProjectToolProvider) and repo_adapter is not None and handle is not None and is_shared_server_handle(handle):
                    try:
                        await project_provider._checkout_shared_program(
                            repo_adapter,
                            program_path,
                            session_id,
                            exclusive=exclusive,
                        )
                        resolved = self._resolve_domain_file_for_checkout_status(program_path)
                        if resolved is not None:
                            domain_file, program_display_name = resolved
                    except Exception as exc:
                        return create_success_response(
                            {
                                "action": "checkout",
                                "program": program_path,
                                "exclusive": exclusive,
                                "success": False,
                                "reason": "shared-checkout-failed",
                                "error": str(exc),
                            },
                        )
                if domain_file is None:
                    return create_success_response(
                        {
                            "action": "checkout",
                            "program": program_path,
                            "exclusive": exclusive,
                            "success": False,
                            "reason": "path-not-resolved",
                            "error": "Could not resolve program path in the current project. This server session has no shared project open. Call open first with shared-server options (e.g. --ghidra-server-host, --server-repository), use the same --server-url and ensure the server process was not restarted, or run open then checkout-program in one session (e.g. tool-seq).",
                            "nextSteps": [
                                'Same session: run one command with server options, e.g. `... --ghidra-server-host HOST --server-repository REPO tool checkout-program \'{"programPath": "/K1/..."}\'` so open runs first in this session.',
                                'Or use tool-seq: `tool-seq \'[{"name": "open", "arguments": {"path": "Odyssey"}}, {"name": "checkout-program", "arguments": {"programPath": "/K1/k1_win_gog_swkotor.exe"}}]\'` with server URL and ghidra-server-* options.',
                            ],
                        },
                    )

        # If we didn't resolve by path, use active program
        if domain_file is None:
            self._require_program()
            assert self.program_info is not None
            program = self.program_info.program
            try:
                domain_file = program.getDomainFile()
                program_display_name = program.getName()
            except Exception:
                domain_file = None
            if domain_file is None:
                return create_success_response(
                    {
                        "action": "checkout",
                        "program": program_display_name or program_path,
                        "exclusive": exclusive,
                        "success": False,
                        "error": "No domain file associated with active program.",
                    },
                )

        try:
            # Check if this is a shared repository file before validating isVersioned()
            # Files from shared repositories may not be marked as versioned locally if they
            # were created via createFile() fallback, but they are still version-controlled in the repo.
            # When in shared-server mode and path looks like a repo path, treat as versioned
            # so we don't depend on getItem() (which may fail across proxy/session boundaries).
            is_shared_repo_file = False
            if program_path and (program_path.startswith("/") or "/" in program_path):
                session_id = get_current_mcp_session_id()
                session = SESSION_CONTEXTS.get_or_create(session_id)
                handle = session.project_handle if isinstance(session.project_handle, dict) else None
                if handle and is_shared_server_handle(handle):
                    # Confirm file in repo when we have adapter; otherwise trust shared-server + path shape
                    repo_adapter = handle.get("repository_adapter")
                    if repo_adapter is not None:
                        parts = program_path.rsplit("/", 1)
                        folder_path = parts[0] if len(parts) == 2 else "/"
                        item_name = parts[1] if len(parts) == 2 else parts[0]
                        try:
                            repo_item = repo_adapter.getItem(folder_path, item_name)
                            if repo_item is not None:
                                is_shared_repo_file = True
                        except Exception:
                            pass
                    # If no adapter (e.g. proxy) but we're in shared-server mode and path is repo-shaped, treat as shared
                    if not is_shared_repo_file and (handle.get("repository_name") or handle.get("server_host")):
                        is_shared_repo_file = True

            # For shared repository files, use repository_adapter.checkout() directly
            # instead of relying on GhidraDomainFile methods which may fail for local project files
            if is_shared_repo_file:
                repo_adapter = handle.get("repository_adapter") if handle else None
                project_provider = None
                if self._manager is not None and hasattr(self._manager, "_get_project_provider"):
                    project_provider = self._manager._get_project_provider()
                if isinstance(project_provider, ProjectToolProvider) and repo_adapter is not None:
                    try:
                        # Use repository adapter checkout directly for shared files
                        await project_provider._checkout_shared_program(
                            repo_adapter,
                            program_path,
                            session_id,
                            exclusive=exclusive,
                        )
                        # After checkout, re-resolve to get the versioned GhidraDomainFile
                        resolved = self._resolve_domain_file_for_checkout_status(program_path)
                        if resolved is not None:
                            domain_file, program_display_name = resolved
                        else:
                            # Checkout succeeded but GhidraDomainFile not yet available - return success
                            return create_success_response(
                                {
                                    "action": "checkout",
                                    "program": program_path,
                                    "exclusive": exclusive,
                                    "success": True,
                                    "note": "File checked out via repository adapter. GhidraDomainFile resolution pending.",
                                },
                            )
                    except Exception as exc:
                        return create_success_response(
                            {
                                "action": "checkout",
                                "program": program_path,
                                "exclusive": exclusive,
                                "success": False,
                                "reason": "repository-checkout-failed",
                                "error": str(exc),
                            },
                        )

            # Only check isVersioned() for non-repository files
            # Shared repository files are version-controlled even if the local GhidraDomainFile
            # isn't marked as versioned (e.g., when created via createFile() fallback)
            if not is_shared_repo_file and domain_file is not None and not bool(domain_file.isVersioned()):
                # Local .gpr files are editable without server checkout; treat checkout as a no-op
                # so the same tool-seq pattern works for local and shared projects.
                return create_success_response(
                    {
                        "action": "checkout",
                        "program": program_display_name,
                        "success": True,
                        "already_private": True,
                        "versionControlEnabled": False,
                        "note": "Local project file (not version-controlled); no repository checkout required.",
                    },
                )

            from ghidra.util.task import TaskMonitor as GhidraTaskMonitor  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

            if domain_file is not None and bool(domain_file.isCheckedOut()):
                return create_success_response(
                    {
                        "action": "checkout",
                        "program": program_display_name,
                        "success": True,
                        "already_checked_out": True,
                        "exclusive": domain_file.isCheckedOutExclusive(),
                        "note": "File is already checked out.",
                    },
                )

            if domain_file is not None and not bool(domain_file.canCheckout()):
                raise RuntimeError(
                    "Cannot check out this file (read-only repository access or versioning restriction).",
                )

            success = False if domain_file is None else domain_file.checkout(exclusive, GhidraTaskMonitor.DUMMY)
            return create_success_response(
                {
                    "action": "checkout",
                    "program": program_display_name,
                    "exclusive": exclusive,
                    "success": success,
                    "is_checked_out": False if domain_file is None else bool(domain_file.isCheckedOut()),
                    "note": None if success else "Exclusive checkout was not available; others have it checked out.",
                },
            )
        except Exception as exc:
            return create_success_response(
                {
                    "action": "checkout",
                    "program": program_display_name,
                    "exclusive": exclusive,
                    "success": False,
                    "error": str(exc),
                },
            )

    def _shared_repository_has_program_path(self, program_path: str) -> bool:
        """True if the current MCP session has a shared server open and the adapter lists this path."""
        pp = (program_path or "").strip().replace("\\", "/")
        if not pp or not (pp.startswith("/") or "/" in pp):
            return False
        session_id = get_current_mcp_session_id()
        session = SESSION_CONTEXTS.get_or_create(session_id)
        handle = session.project_handle if isinstance(session.project_handle, dict) else None
        if not handle or not is_shared_server_handle(handle):
            return False
        repo_adapter = handle.get("repository_adapter")
        if repo_adapter is None:
            return False
        parts = pp.rstrip("/").rsplit("/", 1)
        folder_path = parts[0] if len(parts) == 2 and parts[0] else "/"
        item_name = parts[1] if len(parts) == 2 else parts[0]
        try:
            return repo_adapter.getItem(folder_path, item_name) is not None
        except Exception:
            return False

    def _resolve_domain_file_for_checkout_status(self, program_path: str) -> tuple[Any, str] | None:
        """Resolve GhidraDomainFile and display name for the given program path. Returns (domain_file, display_name) or None."""
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._resolve_domain_file_for_checkout_status")
        if not program_path:
            return None
        session_id = get_current_mcp_session_id()
        normalized = self._canonical_program_path_for_session(program_path.strip())
        session = SESSION_CONTEXTS.get_or_create(session_id)
        handle = session.project_handle if isinstance(session.project_handle, dict) else None
        shared_session = bool(handle and is_shared_server_handle(handle))

        def _df_usable_for_shared(df: GhidraDomainFile) -> bool:
            if not shared_session:
                return True
            try:
                return bool(df.isVersioned()) or bool(df.isCheckedOut())
            except Exception:
                return False

        # 1) Session: program open under this path (exact or path-normalized match)
        info: ProgramInfo | None = SESSION_CONTEXTS.get_program_info(session_id, normalized)
        if info is not None:
            norm_base = Path(normalized.replace("\\", "/")).name.lower()
            # Prefer Program.getDomainFile() before ProgramInfo.domain_file: two GhidraDomainFile wrappers
            # can share the same repo path/basename but reference different GhidraFileData instances.
            # Versioned checkin uses folderItem.getCurrentVersion() vs getLocalCheckoutVersion() on the
            # target file's data — flushing/checking in the "other" wrapper leaves checkout metadata stale
            # ("not modified") and uploads empty revisions (LFG shared search-symbols sees no labels).
            if getattr(info, "program", None) is not None:
                try:
                    df_live: GhidraDomainFile | None = info.program.getDomainFile()
                    if df_live is not None:
                        df_path_live: str = str(df_live.getPathname() or "").strip()
                        if self._ghidra_paths_equal(df_path_live, normalized):
                            return (df_live, df_live.getName() or df_path_live or normalized)
                        p_slash_live: str = df_path_live.replace("\\", "/")
                        db_live: str = Path(p_slash_live).name.lower() if p_slash_live else ""
                        if not db_live:
                            db_live = str(df_live.getName() or "").strip().lower()
                        if norm_base and db_live == norm_base:
                            return (df_live, df_live.getName() or df_path_live or normalized)
                except Exception:
                    pass
            stored_df: GhidraDomainFile | None = getattr(info, "domain_file", None)
            if stored_df is not None:
                try:
                    sp = str(stored_df.getPathname() or "").strip()
                    if self._ghidra_paths_equal(sp, normalized):
                        return (stored_df, stored_df.getName() or sp or normalized)
                    sp_slash = sp.replace("\\", "/")
                    sb = Path(sp_slash).name.lower() if sp_slash else ""
                    if not sb:
                        sb = str(stored_df.getName() or "").strip().lower()
                    if norm_base and sb == norm_base:
                        return (stored_df, stored_df.getName() or sp or normalized)
                except Exception:
                    pass

        # 2) Project data: getFile by path (shared or local project)
        project_data: GhidraProjectData | None = None
        if self._manager is not None and hasattr(self._manager, "_resolve_project_data"):
            try:
                project_data = self._manager._resolve_project_data()
            except Exception:
                project_data = None
        if project_data is None and self.program_info is not None and self.program_info.program is not None:
            try:
                active_df = self.program_info.program.getDomainFile()
                if active_df is not None:
                    project_data = active_df.getProjectData()
            except Exception:
                pass
        if project_data is not None:
            for candidate in (normalized, f"/{normalized.lstrip('/')}", normalized.lstrip("/")):
                try:
                    df = project_data.getFile(candidate)
                    if df is not None:
                        if shared_session and not _df_usable_for_shared(df):
                            continue
                        return (df, df.getName() or df.getPathname() or candidate)
                except Exception:
                    continue
            found = self._find_domain_file_case_insensitive(project_data, normalized)
            if found is not None:
                fdf, fn = found
                if not shared_session or _df_usable_for_shared(fdf):
                    return found
            if shared_session and self._manager is not None and hasattr(self._manager, "_get_project_provider"):
                project_provider = self._manager._get_project_provider()
                if isinstance(project_provider, ProjectToolProvider):
                    parts = normalized.rstrip("/").rsplit("/", 1)
                    item_name = parts[1] if len(parts) == 2 else parts[0]
                    alt = project_provider._resolve_shared_checkout_domain_file(
                        project_data,
                        normalized,
                        item_name,
                    )
                    if alt is not None:
                        try:
                            display = str(alt.getName() or alt.getPathname() or normalized)
                        except Exception:
                            display = normalized
                        return (alt, display)
        return None

    async def _repair_shared_working_copy_for_checkin(
        self,
        *,
        program_path: str,
        exclusive: bool = True,
    ) -> tuple[Any, str] | None:
        """Best-effort: turn a shared repo path into a versioned, checked-out working copy for check-in."""
        normalized = self._canonical_program_path_for_session((program_path or "").strip())
        if not normalized or not (normalized.startswith("/") or "/" in normalized):
            return None

        session_id = get_current_mcp_session_id()
        session = SESSION_CONTEXTS.get_or_create(session_id)
        handle = session.project_handle if isinstance(session.project_handle, dict) else None
        if not handle or not is_shared_server_handle(handle):
            return None

        repo_adapter = handle.get("repository_adapter")
        if repo_adapter is None or self._manager is None or not hasattr(self._manager, "_get_project_provider"):
            return None

        project_provider = self._manager._get_project_provider()
        if not isinstance(project_provider, ProjectToolProvider):
            return None

        try:
            await project_provider._checkout_shared_program(
                repo_adapter,
                normalized,
                session_id,
                exclusive=exclusive,
            )
        except Exception as exc:
            logger.warning(
                "shared checkin repair: checkout_shared_program failed program=%s exc_type=%s",
                basename_hint(normalized),
                type(exc).__name__,
            )

        resolved = self._resolve_domain_file_for_checkout_status(normalized)
        if resolved is None:
            return None

        domain_file, display_name = resolved
        try:
            ensure_vc = getattr(project_provider, "_ensure_shared_domain_file_registered_for_version_control", None)
            if callable(ensure_vc):
                ensure_vc(domain_file, normalized)
        except Exception as exc:
            logger.debug("shared checkin repair: ensure version-control registration failed: %s", exc)

        try:
            if domain_file is not None and hasattr(domain_file, "isCheckedOut") and not bool(domain_file.isCheckedOut()) and hasattr(domain_file, "checkout"):
                from ghidra.util.task import TaskMonitor as GhidraTaskMonitor  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

                domain_file.checkout(exclusive, GhidraTaskMonitor.DUMMY)
        except Exception as exc:
            logger.debug("shared checkin repair: final domain_file.checkout failed: %s", exc)

        return (domain_file, display_name)

    async def _handle_checkout_status(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._handle_checkout_status")
        program_path = self._get_str(args, "programpath", "program_path", "path").strip()
        if program_path:
            program_path = self._canonical_program_path_for_session(program_path)

        # If a specific program_path is provided, resolve the domain file for that path (not the active program)
        domain_file = None
        program_display_name = program_path or ""
        if program_path:
            resolved = self._resolve_domain_file_for_checkout_status(program_path)
            if resolved is not None:
                domain_file, program_display_name = resolved
            elif program_path.startswith("/") or "/" in program_path:
                # Shared path: try same as checkout-program — bring file into project then re-resolve
                session_id = get_current_mcp_session_id()
                session = SESSION_CONTEXTS.get_or_create(session_id)
                handle = session.project_handle if isinstance(session.project_handle, dict) else None
                repo_adapter = handle.get("repository_adapter") if handle else None
                project_provider = None
                if self._manager is not None and hasattr(self._manager, "_get_project_provider"):
                    project_provider = self._manager._get_project_provider()
                if isinstance(project_provider, ProjectToolProvider) and repo_adapter is not None and handle is not None and is_shared_server_handle(handle):
                    try:
                        # Non-exclusive implicit checkout so status resolution does not steal exclusive locks
                        await project_provider._checkout_shared_program(
                            repo_adapter,
                            program_path,
                            session_id,
                            exclusive=False,
                        )
                        resolved = self._resolve_domain_file_for_checkout_status(program_path)
                        if resolved is not None:
                            domain_file, program_display_name = resolved
                    except Exception:
                        pass
            if domain_file is None and (program_path.startswith("/") or "/" in program_path) and not self.program_info:
                return create_success_response(
                    {
                        "action": "checkout_status",
                        "program": program_path,
                        "is_versioned": True,
                        "is_checked_out": False,
                        "is_exclusive": False,
                        "modified_since_checkout": False,
                        "can_checkout": True,
                        "can_checkin": False,
                        "versionControlEnabled": True,
                        "note": "Program path indicates shared repository. Could not open or resolve. Call open first.",
                        "nextSteps": [
                            "Call `open` with shared server credentials.",
                            "Retry `checkout-status` after opening the shared repository.",
                        ],
                    },
                )

        # If we didn't resolve by path, use active program only when path was not provided or path matches active
        if domain_file is None:
            if not self.program_info or self.program_info.program is None:
                return create_success_response(
                    {
                        "action": "checkout_status",
                        "program": program_path or "",
                        "success": False,
                        "error": f"Program path '{program_path}' could not be resolved from the current project or session, and no program is active. Call open or list-project-files first."
                        if program_path
                        else "No program loaded. Call open or import-binary first.",
                    },
                )
            program = self.program_info.program
            try:
                domain_file = program.getDomainFile()
                if domain_file is None:
                    raise RuntimeError("No domain file associated with active program")
                program_display_name = program.getName()
                # If user asked for a specific path that we didn't resolve, ensure we're not reporting the wrong program
                if program_path:
                    df_path = str(domain_file.getPathname() or "").strip()
                    if not self._ghidra_paths_equal(df_path, program_path):
                        return create_success_response(
                            {
                                "action": "checkout_status",
                                "program": program_path,
                                "success": False,
                                "error": f"Requested program path '{program_path}' could not be resolved. Active program is '{program_display_name}' (path: {df_path}). Open the requested program first (e.g. open with that path) or omit program_path to query the active program.",
                                "activeProgram": program_display_name,
                                "activePath": df_path,
                            },
                        )
            except Exception as exc:
                return create_success_response(
                    {
                        "action": "checkout_status",
                        "program": program_path or (program.getName() if program else "unknown"),
                        "success": False,
                        "error": str(exc),
                    },
                )

        if domain_file is None:
            return create_success_response(
                {
                    "action": "checkout_status",
                    "program": program_path,
                    "success": False,
                    "error": f"Program path '{program_path}' could not be resolved from the current project or session. Call open or list-project-files first.",
                },
            )

        try:
            is_versioned = bool(domain_file.isVersioned())
            try:
                is_checked_out = bool(domain_file.isCheckedOut())
            except Exception:
                is_checked_out = False
            try:
                is_exclusive = bool(domain_file.isCheckedOutExclusive()) if is_checked_out else False
            except Exception:
                is_exclusive = False
            try:
                modified = bool(domain_file.modifiedSinceCheckout()) if is_checked_out else False
            except Exception:
                modified = False
            try:
                can_checkin = bool(domain_file.canCheckin())
            except Exception:
                can_checkin = False
            try:
                can_checkout = bool(domain_file.canCheckout())
            except Exception:
                can_checkout = False
            latest_version = domain_file.getLatestVersion() if is_versioned else None
            current_version = domain_file.getVersion() if is_versioned else None

            checkout_status_obj = None
            if is_checked_out:
                try:
                    status = domain_file.getCheckoutStatus()
                    if status is not None:
                        checkout_status_obj = {
                            "checkout_id": status.getCheckoutId(),
                            "user": status.getUser(),
                            "checkout_version": status.getCheckoutVersion(),
                            "checkout_time": status.getCheckoutTime(),
                        }
                except Exception:
                    pass

            return create_success_response(
                {
                    "action": "checkout_status",
                    "program": program_display_name,
                    "is_versioned": is_versioned,
                    "is_checked_out": is_checked_out,
                    "is_exclusive": is_exclusive,
                    "modified_since_checkout": modified,
                    "can_checkout": can_checkout,
                    "can_checkin": can_checkin,
                    "latest_version": latest_version,
                    "current_version": current_version,
                    "checkout_status": checkout_status_obj,
                    "versionControlEnabled": is_versioned,
                    "note": None if is_versioned else "Program is local-only. Shared checkout/checkin is unavailable until the program exists in a shared Ghidra repository.",
                },
            )
        except Exception as exc:
            return create_success_response(
                {
                    "action": "checkout_status",
                    "program": program_display_name,
                    "success": False,
                    "error": str(exc),
                },
            )

    async def _handle_list_processors(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/import_export.py:ImportExportToolProvider._handle_list_processors")
        filter_str = self._get_str(args, "filter", "query", "search")

        try:
            from ghidra.framework.main import AppInfo as GhidraAppInfo  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

            GhidraAppInfo.getActiveProject().getProjectData()
            # This needs proper language service access
            return create_success_response(
                {
                    "action": "list_processors",
                    "note": "Processor listing requires Ghidra LanguageService",
                    "filter": filter_str,
                },
            )
        except Exception:
            # Common processors
            common = [
                "x86:LE:32:default",
                "x86:LE:64:default",
                "ARM:LE:32:v8",
                "ARM:LE:64:v8A",
                "AARCH64:LE:64:v8A",
                "MIPS:BE:32:default",
                "MIPS:LE:32:default",
                "PowerPC:BE:32:default",
                "PowerPC:BE:64:default",
            ]
            if filter_str:
                common = [p for p in common if filter_str.lower() in p.lower()]
            return create_success_response(
                {
                    "action": "list_processors",
                    "processors": common,
                    "note": "Showing common processors; full list requires Ghidra environment",
                    "count": len(common),
                },
            )
