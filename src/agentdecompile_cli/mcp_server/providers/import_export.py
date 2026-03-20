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
import subprocess
import sys

from datetime import datetime, timezone
from itertools import islice
from pathlib import Path
from typing import Any

from mcp import types

from agentdecompile_cli.mcp_server.session_context import (
    SESSION_CONTEXTS,
    get_current_mcp_session_id,
    is_shared_server_handle,
)
from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
    n,
)
from ghidrecomp.utility import analyze_program as run_analysis
from agentdecompile_cli.registry import Tool

logger = logging.getLogger(__name__)


def _normalize_import_destination_folder(args: dict[str, Any]) -> str:
    """Ghidra folder pathname for saveAs (e.g. '/' or '/bin')."""
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
    if not raw:
        return ""
    return (
        str(raw)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _generate_program_xml(program: Any, get_function_manager: Any) -> str:
    """Generate a comprehensive XML representation of the program (fallback when XmlExporter is unavailable)."""
    import xml.etree.ElementTree as ET  # noqa: PLC0415

    root = ET.Element("program")
    root.set("name", _escape_xml_text(program.getName() if hasattr(program, "getName") else ""))
    root.set("language", _escape_xml_text(str(program.getLanguage().getLanguageID()) if program.getLanguage() else ""))
    root.set("compiler", _escape_xml_text(str(program.getCompilerSpec().getCompilerSpecID()) if program.getCompilerSpec() else ""))
    root.set("imageBase", str(program.getImageBase()) if hasattr(program, "getImageBase") and program.getImageBase() else "0")

    try:
        func_mgr = get_function_manager(program)
        func_count = func_mgr.getFunctionCount() if hasattr(func_mgr, "getFunctionCount") else 0
        funcs_el = ET.SubElement(root, "functions")
        funcs_el.set("count", str(func_count))
        for func in islice(func_mgr.getFunctions(True), 10000):
            fe = ET.SubElement(funcs_el, "function")
            fe.set("name", _escape_xml_text(func.getName() if hasattr(func, "getName") else ""))
            if hasattr(func, "getEntryPoint") and func.getEntryPoint():
                fe.set("address", str(func.getEntryPoint()))
            if hasattr(func, "getBody") and func.getBody():
                fe.set("size", str(func.getBody().getNumAddresses()))
    except Exception:
        pass

    try:
        if hasattr(program, "getMemory") and program.getMemory():
            mem = program.getMemory()
            blocks_el = ET.SubElement(root, "memoryBlocks")
            for block in mem.getBlocks() if hasattr(mem, "getBlocks") else []:
                be = ET.SubElement(blocks_el, "block")
                if hasattr(block, "getStart"):
                    be.set("start", str(block.getStart()))
                if hasattr(block, "getEnd"):
                    be.set("end", str(block.getEnd()))
                if hasattr(block, "getName"):
                    be.set("name", _escape_xml_text(block.getName()))
    except Exception:
        pass

    try:
        ref_mgr = program.getReferenceManager() if hasattr(program, "getReferenceManager") else None
        if ref_mgr and hasattr(ref_mgr, "getReferenceCount"):
            root.set("referenceCount", str(ref_mgr.getReferenceCount()))
    except Exception:
        pass

    ET.indent(root, space="  ")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode", default_namespace="")


def _generate_program_ascii_fallback(program: Any, get_function_manager: Any) -> str:
    """Generate a plain-text program summary (fallback when AsciiExporter is unavailable)."""
    lines: list[str] = []
    name = program.getName() if hasattr(program, "getName") else "Program"
    lines.append(f"Program: {name}")
    lines.append("")
    if program.getLanguage():
        lines.append(f"Language: {program.getLanguage().getLanguageID()}")
    if program.getCompilerSpec():
        lines.append(f"Compiler: {program.getCompilerSpec().getCompilerSpecID()}")
    if hasattr(program, "getImageBase") and program.getImageBase():
        lines.append(f"Image base: {program.getImageBase()}")
    lines.append("")
    lines.append("Functions:")
    lines.append("-" * 60)
    try:
        func_mgr = get_function_manager(program)
        for func in islice(func_mgr.getFunctions(True), 10000):
            addr = str(func.getEntryPoint()) if hasattr(func, "getEntryPoint") and func.getEntryPoint() else ""
            fname = func.getName() if hasattr(func, "getName") else ""
            size = ""
            if hasattr(func, "getBody") and func.getBody():
                size = str(func.getBody().getNumAddresses())
            lines.append(f"  {addr}  {fname}  (size: {size})")
    except Exception:
        lines.append("  (unable to list)")
    return "\n".join(lines)


def _generate_program_html(program: Any, get_function_manager: Any) -> str:
    """Generate a comprehensive HTML report for the program."""
    name = program.getName() if hasattr(program, "getName") else "Program"
    lang = str(program.getLanguage().getLanguageID()) if program.getLanguage() else ""
    comp = str(program.getCompilerSpec().getCompilerSpecID()) if program.getCompilerSpec() else ""
    base = str(program.getImageBase()) if hasattr(program, "getImageBase") and program.getImageBase() else "0"

    func_rows: list[str] = []
    try:
        func_mgr = get_function_manager(program)
        count = 0
        for func in func_mgr.getFunctions(True):
            if count >= 5000:
                func_rows.append('<tr><td colspan="5">… (truncated)</td></tr>')
                break
            addr = str(func.getEntryPoint()) if hasattr(func, "getEntryPoint") and func.getEntryPoint() else ""
            fname = (func.getName() or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            size = ""
            if hasattr(func, "getBody") and func.getBody():
                size = str(func.getBody().getNumAddresses())
            ext = "Yes" if (hasattr(func, "isExternal") and func.isExternal()) else ""
            thunk = "Yes" if (hasattr(func, "isThunk") and func.isThunk()) else ""
            func_rows.append(f"<tr><td>{addr}</td><td>{fname}</td><td>{size}</td><td>{ext}</td><td>{thunk}</td></tr>")
            count += 1
        func_count = count
    except Exception:
        func_count = 0
        func_rows.append("<tr><td colspan=\"5\">Unable to list functions</td></tr>")

    functions_table = "\n".join(func_rows)

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
    HANDLERS = {
        "importbinary": "_handle_import",
        "export": "_handle_export",
        "analyzeprogram": "_handle_analyze",
        "changeprocessor": "_handle_change_processor",
        "checkinprogram": "_handle_checkin",
        "checkoutprogram": "_handle_checkout",
        "checkoutstatus": "_handle_checkout_status",
        "listprocessors": "_handle_list_processors",
    }

    def _is_analysis_complete(self, program: Any) -> bool:
        """Return True if program analysis is complete; safe for ProgramDB and headless."""
        try:
            get_state = getattr(program, "getAnalysisState", None)
            if get_state is not None:
                state = get_state()
                if state is not None and hasattr(state, "isDone"):
                    return bool(state.isDone())
        except Exception:
            pass
        try:
            from ghidra.program.util import GhidraProgramUtilities  # pyright: ignore[reportMissingModuleSource]
            return bool(GhidraProgramUtilities.isAnalyzed(program))
        except Exception:
            return False

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name=Tool.IMPORT_BINARY.value,
                description="Load a raw binary file (e.g. .exe, .elf, .bin) from your hard drive into the Ghidra project so that it can be deeply analyzed. Use this to start a reverse engineering session on a new file.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "filePath": {"type": "string", "description": "The exact location on the filesystem of the file you want to bring into the Ghidra environment."},
                        "path": {"type": "string", "description": "Alternative key for filePath."},
                        "programName": {"type": "string", "description": "What to name this file inside the Ghidra project. If not provided, it assumes the original filename."},
                        "language": {"type": "string", "description": "The processor architecture ID (like 'x86:LE:64:default'). Omitting this uses the auto-analyzer's best guess."},
                        "compiler": {"type": "string", "description": "The compiler spec ID (like 'gcc' or 'windows'). Omitting this uses the auto analyzer."},
                        "recursive": {"type": "boolean", "default": False, "description": "If filePath is a folder, whether to import everything inside it."},
                        "maxDepth": {"type": "integer", "default": 16, "description": "How deep to recurse if importing a folder."},
                        "analyzeAfterImport": {"type": "boolean", "default": False, "description": "Whether to immediately run Ghidra's heavy auto-analysis (can take a long time) right after importing."},
                        "enableVersionControl": {"type": "boolean", "default": False, "description": "Request import into shared-project version control. Local-only imports cannot satisfy this request."},
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
                        "createHeader": {"type": "boolean", "default": True, "description": "Whether to build a standard C/C++ header block at the top containing environment types."},
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
                        "analyzers": {"type": "array", "items": {"type": "string"}, "description": "If provided, lists specific string names of Ghidra analyzer modules to use instead of 'all of them'."},
                        "force": {"type": "boolean", "default": False, "description": "Force re-analysis even when Ghidra already marked the program as analyzed. This should be rare."},
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
                        "program_path": {"type": "string", "description": "Your local version of the file you intend to push upstream. Omit to check in all open programs that are checked out."},
                        "comment": {"type": "string", "description": "The commit message for history tracking."},
                        "keep_checked_out": {"type": "boolean", "default": False, "description": "Whether to retain an exclusive file lock after pushing the changes."},
                        "format": {"type": "string", "enum": ["markdown", "json"], "default": "markdown", "description": "Output format (default: markdown). Use --format json / -f json only when you strictly need machine-readable output; markdown is recommended."},
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
                        "exclusive": {"type": "boolean", "default": False, "description": "Whether to request an exclusive (write-lock) checkout. Exclusive checkout fails if others already have it checked out."},
                        "format": {"type": "string", "enum": ["markdown", "json"], "default": "markdown", "description": "Output format (default: markdown). Use --format json / -f json only when you strictly need machine-readable output; markdown is recommended."},
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
                        "format": {"type": "string", "enum": ["markdown", "json"], "default": "markdown", "description": "Output format (default: markdown). Use --format json / -f json only when you strictly need machine-readable output; markdown is recommended."},
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
    def _list_repository_items(repository_adapter: Any) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []

        def _walk(folder_path: str) -> None:
            subfolders: list[Any] = repository_adapter.getSubfolderList(folder_path) or []
            for subfolder in subfolders:
                subfolder_name = str(subfolder)
                next_path = f"{folder_path.rstrip('/')}/{subfolder_name}" if folder_path != "/" else f"/{subfolder_name}"
                _walk(next_path)

            repo_items: list[Any] = repository_adapter.getItemList(folder_path) or []
            for repo_item in repo_items:
                name = str(repo_item.getName()) if hasattr(repo_item, "getName") else str(repo_item)
                path = f"{folder_path.rstrip('/')}/{name}" if folder_path != "/" else f"/{name}"
                item_type = str(repo_item.getContentType()) if hasattr(repo_item, "getContentType") else "Program"
                items.append({"name": name, "path": path, "type": item_type})

        _walk("/")
        return items

    def _handle_shared_import(
        self,
        source: Path,
        recursive: bool,
        analyze_after_import: bool,
    ) -> dict[str, Any]:
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

        # ALTERNATIVE: Use PyGhidra API directly with repository adapter to avoid analyzeHeadless auth issues
        # This avoids the th3w1zard1 cached username problem by using the already-authenticated repository_adapter
        try:
            if not repository_adapter.isConnected():
                repository_adapter.connect()
            
            # Get the manager's ghidra_project or create a temporary one connected to the repository
            ghidra_project = getattr(self._manager, "ghidra_project", None) if self._manager else None
            if ghidra_project is None:
                # Create a temporary project connected to the repository
                from agentdecompile_cli.launcher import PyGhidraContext
                import tempfile
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
                    logger.warning(f"Failed to create temp project for shared import: {e}, falling back to analyzeHeadless")
                    ghidra_project = None
            
            if ghidra_project is not None:
                # Use PyGhidra API to import directly into repository
                from java.io import File  # pyright: ignore[reportMissingImports]
                from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingImports]
                
                # Import the binary into the (possibly local) project
                program = ghidra_project.importProgram(File(str(source)))
                if program is None:
                    raise RuntimeError("importProgram returned None")
                
                # Use the shared repository's root folder, not the local project's.
                # repository_adapter is the ServerRepositoryAdapter; get Repository then getRootFolder().
                root_folder = None
                try:
                    repository = repository_adapter.getRepository()
                    if repository is not None and hasattr(repository, "getRootFolder"):
                        root_folder = repository.getRootFolder()
                        logger.info("Got root folder from shared repository: %s", repository_name)
                except Exception as repo_exc:
                    logger.warning("Could not get root folder from repository_adapter.getRepository(): %s", repo_exc)
                
                # DO NOT fall back to local project_data - we're in shared-server mode, must use repository
                if root_folder is None:
                    logger.error("Could not get repository root folder for shared import - repository adapter may be disconnected")
                    program.release(ghidra_project)
                    raise RuntimeError(f"repository root folder not available for shared repository '{repository_name}'. Repository adapter may be disconnected.")
                
                # Save the program to the repository root folder
                program_name = source.name
                try:
                    domain_file = root_folder.createFile(program_name, program, TaskMonitor.DUMMY)
                    if domain_file is None:
                        raise RuntimeError("createFile returned None")
                    
                    # Run analysis if requested
                    if analyze_after_import:
                        from ghidra.program.util import ProgramUtilities  # pyright: ignore[reportMissingImports]
                        ProgramUtilities.analyze(program, TaskMonitor.DUMMY)
                        # Save changes after analysis
                        domain_file.save(TaskMonitor.DUMMY)
                    
                    # Release the program
                    program.release(ghidra_project)
                    
                    # Refresh repository listing
                    binaries = self._list_repository_items(repository_adapter)
                    SESSION_CONTEXTS.set_project_binaries(session_id, binaries)
                    
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
                except Exception as create_exc:
                    program.release(ghidra_project)
                    logger.warning(f"PyGhidra API createFile failed: {create_exc}, falling back to analyzeHeadless")
                    raise
        except Exception as api_exc:
            logger.warning(f"PyGhidra API import failed: {api_exc}, falling back to analyzeHeadless")
            # Fall through to analyzeHeadless method
        
        # FALLBACK: Use analyzeHeadless (may have auth issues with cached username)
        repository_url = f"ghidra://{server_host}:{server_port}/{repository_name}"
        # Build command: repository URL, then -import, then -connect, then -p, then -commit
        # Order per analyzeHeadless help: <repo_url> [[-import ...] | [-process ...]] [-connect [<userID>]] [-p] [-commit]
        # Try putting -connect BEFORE repository URL to set credentials first
        command = [str(analyze_headless)]
        if server_username:
            # Put -connect before repository URL to ensure credentials are set before connection
            command.extend(["-connect", server_username, "-p"])
        command.append(repository_url)
        command.extend(["-import", str(source)])
        if recursive and source.is_dir():
            command.append("-recursive")
        if not analyze_after_import:
            command.append("-noanalysis")
        command.append("-commit")

        # Log command for debugging (redact password)
        logger.info(
            "[_handle_shared_import] Running analyzeHeadless: %s (username: %s, password: %s)",
            " ".join(command),
            server_username or "none",
            "***" if server_password else "none",
        )
        try:
            # Set environment variables to override any cached username
            # analyzeHeadless may read username from cached project files or Java system properties
            env = dict(os.environ)
            if server_username:
                env["GHIDRA_SERVER_USERNAME"] = server_username
                # Clear any existing JAVA_TOOL_OPTIONS to avoid conflicts
                java_opts = env.get("JAVA_TOOL_OPTIONS", "").strip()
                # Remove any existing -Duser.name settings
                java_opts = " ".join([opt for opt in java_opts.split() if not opt.startswith("-Duser.name=")])
                # Add our user.name override
                if java_opts:
                    env["JAVA_TOOL_OPTIONS"] = f"{java_opts} -Duser.name={server_username}".strip()
                else:
                    env["JAVA_TOOL_OPTIONS"] = f"-Duser.name={server_username}"
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
            return {
                "action": "import",
                "importedFrom": str(source),
                "analysisRequested": analyze_after_import,
                "versionControlRequested": True,
                "versionControlEnabled": False,
                "success": False,
                "error": str(exc),
            }

        stdout = completed.stdout.strip()
        stderr = completed.stderr.strip()
        if completed.returncode != 0:
            return {
                "action": "import",
                "importedFrom": str(source),
                "analysisRequested": analyze_after_import,
                "versionControlRequested": True,
                "versionControlEnabled": False,
                "success": False,
                "error": stderr or stdout or f"analyzeHeadless exited with {completed.returncode}",
                "exitCode": completed.returncode,
            }

        try:
            if not repository_adapter.isConnected():
                repository_adapter.connect()
        except Exception:
            pass

        binaries = self._list_repository_items(repository_adapter)
        SESSION_CONTEXTS.set_project_binaries(session_id, binaries)

        return {
            "action": "import",
            "importedFrom": str(source),
            "filesDiscovered": 1 if source.is_file() else len(list(self._iter_files_to_import(source, recursive, 16))),
            "filesImported": 1,
            "importedPrograms": [{"sourcePath": str(source), "programName": source.name}],
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
        file_path = self._require_str(args, "path", "filepath", "file", "binarypath", "binary", name="filePath")
        prog_name = self._get_str(args, "programname", "name")
        language = self._get_str(args, "language", "lang", "processor")
        compiler = self._get_str(args, "compiler", "compilerspec", "compilerspecid")
        recursive = self._get_bool(args, "recursive", default=False)
        max_depth = self._get_int(args, "maxdepth", default=16)
        analyze_after_import = self._get_bool(args, "analyzeafterimport", default=False)
        enable_version_control = self._get_bool(args, "enableversioncontrol", default=False)

        source = Path(file_path).expanduser().resolve()
        if not source.exists():
            raise ValueError(f"File not found: {source}")

        if enable_version_control:
            return create_success_response(self._handle_shared_import(source, recursive, analyze_after_import))

        imported_programs: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        discovered_count = 0
        dest_folder = _normalize_import_destination_folder(args)
        session_id = get_current_mcp_session_id()

        # Prefer the session's Ghidra project (launcher) so import goes into the correct project.
        ghidra_project = getattr(self._manager, "ghidra_project", None) if self._manager else None

        # If no project is open, try to open it from AGENT_DECOMPILE_PROJECT_PATH so imports persist.
        # This ensures import-binary works even when the project wasn't explicitly opened first.
        if ghidra_project is None and self._manager is not None:
            project_path = os.getenv("AGENT_DECOMPILE_PROJECT_PATH") or os.getenv("AGENTDECOMPILE_PROJECT_PATH")
            if project_path:
                project_path_str = str(project_path).strip()
                if project_path_str:
                    try:
                        project_provider = self._manager._get_project_provider()
                        if project_provider is not None:
                            logger.info(
                                "import-binary: ghidra_project is None, attempting to open project from %s",
                                project_path_str,
                            )
                            await project_provider._handle_open_project({"path": project_path_str})
                            # Re-check ghidra_project after opening
                            ghidra_project = getattr(self._manager, "ghidra_project", None)
                            if ghidra_project is None:
                                logger.warning(
                                    "import-binary: open succeeded but ghidra_project is still None; "
                                    "imports may not persist to the expected project"
                                )
                    except Exception as e:
                        logger.warning(
                            "import-binary: failed to auto-open project from %s: %s; "
                            "will use temporary ProjectManager (imports may not persist)",
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
                            path_in_project = (
                                f"/{final_name}" if dest_folder in ("/", "") else f"{dest_folder}/{final_name}"
                            )
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
            program = self.program_info.program

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
                    from java.io import File

                    project.saveAsPackedFile(program, File(str(out)), True)
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
                        ref_mgr: Any = program.getReferenceManager()
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
                        bookmark_mgr: Any = program.getBookmarkManager()
                        bookmarks: list[Any] = bookmark_mgr.getBookmarks("Analysis")
                        if bookmarks:
                            for bookmark in islice(bookmarks, 30):
                                if bookmark:
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
                        func_mgr: Any = self._get_function_manager(program)
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
                ascii_done = False
                try:
                    from java.io import File  # pyright: ignore[reportMissingImports]
                    from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingModuleSource]

                    def _run_ascii_export() -> None:
                        from ghidra.app.util.exporter import AsciiExporter  # pyright: ignore[reportMissingModuleSource]

                        exporter = AsciiExporter()
                        exporter.export(File(str(out)), program, None, TaskMonitor.DUMMY)

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
                    from java.io import File  # pyright: ignore[reportMissingImports]
                    from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingModuleSource]

                    def _run_xml_export() -> None:
                        from ghidra.app.util.exporter import XmlExporter  # pyright: ignore[reportMissingModuleSource]

                        exporter = XmlExporter()
                        addr_set = None
                        if hasattr(program, "getMemory") and program.getMemory():
                            mem = program.getMemory()
                            if hasattr(mem, "getAllInitializedAddressSet"):
                                addr_set = mem.getAllInitializedAddressSet()
                            elif hasattr(mem, "getLoadedAndInitializedAddressSet"):
                                addr_set = mem.getLoadedAndInitializedAddressSet()
                        exporter.export(File(str(out)), program, addr_set, TaskMonitor.DUMMY)

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
                    from java.io import File  # pyright: ignore[reportMissingImports]
                    from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingModuleSource]

                    def _run_html_export() -> None:
                        from ghidra.app.util.exporter import HtmlExporter  # pyright: ignore[reportMissingModuleSource]

                        exporter = HtmlExporter()
                        exporter.export(File(str(out)), program, None, TaskMonitor.DUMMY)

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

            payload = {
                "name": program.getName(),
                "address": str(program.getImageBase()),
                "language": str(program.getLanguage().getLanguageID()),
                "compiler": str(program.getCompilerSpec().getCompilerSpecID()),
                "functionCount": self._get_function_manager(program).getFunctionCount(),
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
        self._require_program()
        assert self.program_info is not None
        analyzers = self._get_list(args, "analyzers")
        force = self._get_bool(args, "force", "forceanalysis", default=False)
        program = self.program_info.program

        try:
            from ghidra.program.util import GhidraProgramUtilities  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

            session_marked_complete = bool(getattr(self.program_info, "analysis_complete", False))
            ghidra_requires_analysis = True
            try:
                ghidra_requires_analysis = bool(GhidraProgramUtilities.shouldAskToAnalyze(program))
            except Exception:
                ghidra_requires_analysis = not session_marked_complete

            already_analyzed = session_marked_complete or not ghidra_requires_analysis
            if already_analyzed and not force:
                return create_success_response(
                    {
                        "action": "analyze",
                        "programName": program.getName(),
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
                    "programName": program.getName(),
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
        self._require_program()
        assert self.program_info is not None
        language = self._require_str(args, "language", "lang", "processor", "languageid", name="language")
        compiler = self._get_str(args, "compiler", "compilerspec", "compilerspecid")

        program = self.program_info.program
        try:
            from ghidra.program.model.lang import CompilerSpecID, LanguageID  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
            from ghidra.program.util import DefaultLanguageService  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
            from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

            def _change_processor() -> None:
                language_id = LanguageID(language)
                language_service = DefaultLanguageService.getLanguageService()
                language_obj = language_service.getLanguage(language_id)
                if language_obj is None:
                    raise RuntimeError(f"Unable to resolve language: {language}")

                compiler_spec_id = CompilerSpecID(compiler) if compiler else language_obj.getDefaultCompilerSpec().getCompilerSpecID()

                try:
                    program.setLanguage(language_obj, compiler_spec_id, True, TaskMonitor.DUMMY)
                except Exception:
                    compiler_spec = language_obj.getDefaultCompilerSpec()
                    if compiler:
                        try:
                            compiler_spec = language_obj.getCompilerSpecByID(compiler_spec_id)
                        except Exception:
                            compiler_spec = language_obj.getDefaultCompilerSpec()
                    program.setLanguage(language_obj, compiler_spec, True, TaskMonitor.DUMMY)

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

    async def _handle_checkin(self, args: dict[str, Any]) -> list[types.TextContent]:
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
                from ghidra.framework.data import CheckinHandler  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
                from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

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
                                domain_file.checkout(True, TaskMonitor.DUMMY)
                                we_checked_out.append(path_key)
                            except Exception:
                                all_ok = False
                                # Main loop below will still process this program (will save locally since canCheckin() is false)

                # Use keep_checked_out=False for auto flow so check-in doesn't re-checkout; we'll re-checkout only already_checked_out below.
                _keep = keep_checked_out if not auto_checkin_flow else False
                for path_key, info in (session.open_programs or {}).items():
                    prog = getattr(info, "program", None) or getattr(info, "current_program", None)
                    if prog is None:
                        results.append({"programPath": path_key, "success": False, "error": "No program handle"})
                        all_ok = False
                        continue
                    domain_file = prog.getDomainFile()
                    if domain_file is None:
                        continue
                    try:
                        if domain_file.isVersioned() and domain_file.canCheckin():
                            class _SimpleCheckinHandler(CheckinHandler):  # type: ignore[misc]
                                def getComment(self) -> str:  # noqa: N802
                                    return checkin_comment

                                def keepCheckedOut(self) -> bool:  # noqa: N802
                                    return _keep

                                def createKeepFile(self) -> bool:  # noqa: N802
                                    return False

                            domain_file.checkin(_SimpleCheckinHandler(), TaskMonitor.DUMMY)
                            results.append({"programPath": path_key, "success": True, "mode": "checkin"})
                        else:
                            # Local (non-versioned) project: save to disk so changes persist
                            domain_file.save(TaskMonitor.DUMMY)
                            results.append({"programPath": path_key, "success": True, "mode": "save_local"})
                    except Exception as e:
                        results.append({"programPath": path_key, "success": False, "error": str(e)})
                        all_ok = False

                # Re-checkout only programs that were already checked out before we did anything (don't leave them checked in if user had them out).
                if auto_checkin_flow and already_checked_out:
                    for _path_key, domain_file in already_checked_out:
                        try:
                            domain_file.checkout(True, TaskMonitor.DUMMY)
                        except Exception:
                            pass  # best-effort; program remains checked in
            except Exception as e:
                return create_success_response(
                    {
                        "action": "checkin",
                        "mode": "checkin_all",
                        "success": False,
                        "error": str(e),
                        "results": [],
                    },
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
            from ghidra.framework.data import CheckinHandler  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
            from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingModuleSource, reportMissingImports]
            if domain_file is None:
                raise RuntimeError("No domain file associated with active program")

            if not domain_file.isVersioned():
                # Not version-controlled — just save locally.
                domain_file.save(TaskMonitor.DUMMY)
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

            if not domain_file.isCheckedOut():
                raise RuntimeError(
                    "File is not checked out. Call checkout-program first before making changes.",
                )

            _keep = keep_checked_out

            class _SimpleCheckinHandler(CheckinHandler):  # type: ignore[misc]
                def getComment(self) -> str:  # noqa: N802
                    return comment

                def keepCheckedOut(self) -> bool:  # noqa: N802
                    return _keep

                def createKeepFile(self) -> bool:  # noqa: N802
                    return False

            domain_file.checkin(_SimpleCheckinHandler(), TaskMonitor.DUMMY)
            return create_success_response(
                {
                    "action": "checkin",
                    "program": program_display_name,
                    "comment": comment,
                    "keep_checked_out": keep_checked_out,
                    "version": domain_file.getLatestVersion(),
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
        exclusive = self._get_bool(args, "exclusive", default=False)
        program_path = self._get_str(args, "programpath", "program_path", "path").strip()

        # When program_path is provided, resolve DomainFile by path (shared or session) so checkout
        # works for shared repo paths even when that program is not the active one.
        domain_file = None
        program_display_name = program_path or ""
        if program_path:
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
                if project_provider is not None and repo_adapter is not None and handle is not None and is_shared_server_handle(handle):
                    try:
                        await project_provider._checkout_shared_program(repo_adapter, program_path, session_id)
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
                                "Same session: run one command with server options, e.g. `... --ghidra-server-host HOST --server-repository REPO tool checkout-program '{\"programPath\": \"/K1/...\"}'` so open runs first in this session.",
                                "Or use tool-seq: `tool-seq '[{\"name\": \"open\", \"arguments\": {\"path\": \"Odyssey\"}}, {\"name\": \"checkout-program\", \"arguments\": {\"programPath\": \"/K1/k1_win_gog_swkotor.exe\"}}]'` with server URL and ghidra-server-* options.",
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

            # Only check isVersioned() for non-repository files
            # Shared repository files are version-controlled even if the local DomainFile
            # isn't marked as versioned (e.g., when created via createFile() fallback)
            if not is_shared_repo_file and not domain_file.isVersioned():
                return create_success_response(
                    {
                        "action": "checkout",
                        "program": program_display_name,
                        "success": False,
                        "already_private": True,
                        "versionControlEnabled": False,
                        "error": "File is not version-controlled in a shared Ghidra repository. Checkout is unavailable for local-only project files.",
                    },
                )

            from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

            if domain_file.isCheckedOut():
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

            if not domain_file.canCheckout():
                raise RuntimeError(
                    "Cannot check out this file (read-only repository access or versioning restriction).",
                )

            success = domain_file.checkout(exclusive, TaskMonitor.DUMMY)
            return create_success_response(
                {
                    "action": "checkout",
                    "program": program_display_name,
                    "exclusive": exclusive,
                    "success": success,
                    "is_checked_out": domain_file.isCheckedOut(),
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

    def _resolve_domain_file_for_checkout_status(self, program_path: str) -> tuple[Any, str] | None:
        """Resolve DomainFile and display name for the given program path. Returns (domain_file, display_name) or None."""
        if not program_path:
            return None
        normalized = program_path.strip()
        session_id = get_current_mcp_session_id()

        # 1) Session: program open under this path (exact or path-normalized match)
        info = SESSION_CONTEXTS.get_program_info(session_id, normalized)
        if info is not None and getattr(info, "program", None) is not None:
            try:
                df = info.program.getDomainFile()
                if df is not None:
                    df_path = str(df.getPathname() or "").strip()
                    if df_path == normalized or df_path.lstrip("/") == normalized.lstrip("/"):
                        return (df, df.getName() or df_path or normalized)
            except Exception:
                pass

        # 2) Project data: getFile by path (shared or local project)
        project_data = None
        if self._manager is not None and hasattr(self._manager, "_resolve_project_data"):
            try:
                project_data = self._manager._resolve_project_data()
            except Exception:
                project_data = None
        if project_data is None and self.program_info is not None and getattr(self.program_info, "program", None) is not None:
            try:
                active_df = self.program_info.program.getDomainFile()
                if active_df is not None:
                    project_data = active_df.getProjectData()
            except Exception:
                pass
        if project_data is not None:
            for candidate in (normalized, f"/{normalized.lstrip('/')}"):
                try:
                    df = project_data.getFile(candidate)
                    if df is not None:
                        return (df, df.getName() or df.getPathname() or candidate)
                except Exception:
                    continue
        return None

    async def _handle_checkout_status(self, args: dict[str, Any]) -> list[types.TextContent]:
        program_path = self._get_str(args, "programpath", "program_path", "path").strip()

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
                if project_provider is not None and repo_adapter is not None and handle is not None and is_shared_server_handle(handle):
                    try:
                        await project_provider._checkout_shared_program(repo_adapter, program_path, session_id)
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
            if not self.program_info or getattr(self.program_info, "program", None) is None:
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
                    if df_path != program_path and df_path.lstrip("/") != program_path.strip().lstrip("/"):
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
            is_versioned = domain_file.isVersioned()
            is_checked_out = domain_file.isCheckedOut() if is_versioned else False
            is_exclusive = domain_file.isCheckedOutExclusive() if is_checked_out else False
            modified = domain_file.modifiedSinceCheckout() if is_checked_out else False
            can_checkin = domain_file.canCheckin() if is_versioned else False
            can_checkout = domain_file.canCheckout() if is_versioned else False
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
        filter_str = self._get_str(args, "filter", "query", "search")

        try:
            from ghidra.framework.main import AppInfo  # pyright: ignore[reportMissingModuleSource, reportMissingImports]

            AppInfo.getActiveProject().getProjectData()
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
