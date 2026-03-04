"""Import/Export Tool Provider - import-binary, export, analyze-program, etc.

Handles binary import, export, analysis control, and processor management.
"""

from __future__ import annotations

import json
import logging
from itertools import islice
from pathlib import Path
from typing import Any

from mcp import types

from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
)

logger = logging.getLogger(__name__)


class ImportExportToolProvider(ToolProvider):
    HANDLERS = {
        "importbinary": "_handle_import",
        "export": "_handle_export",
        "analyzeprogram": "_handle_analyze",
        "changeprocessor": "_handle_change_processor",
        "checkinprogram": "_handle_checkin",
        "listprocessors": "_handle_list_processors",
    }

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="import-binary",
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
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="export",
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
                name="analyze-program",
                description="Trigger the heavy auto-analysis subsystem inside Ghidra. Use this after loading a program if you notice data looks incomplete, strings are unbroken, or functions fail to decompile correctly. Be warned: this takes time.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The target program to run analyzers over."},
                        "analyzers": {"type": "array", "items": {"type": "string"}, "description": "If provided, lists specific string names of Ghidra analyzer modules to use instead of 'all of them'."},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="checkin-program",
                description="If you are using a shared/version-controlled Ghidra Server project, use this to commit your changes directly to the server, preserving your work as a new version.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "Your local version of the file you intend to push upstream."},
                        "message": {"type": "string", "description": "The commit message for history tracking."},
                        "keepCheckedOut": {"type": "boolean", "default": False, "description": "Whether to retain an exclusive file lock after pushing the changes."},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="change-processor",
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
                name="list-processors",
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

    async def _handle_import(self, args: dict[str, Any]) -> list[types.TextContent]:
        file_path = self._require_str(args, "filepath", "path", "file", "binarypath", "binary", name="filePath")
        prog_name = self._get_str(args, "programname", "name")
        language = self._get_str(args, "language", "lang", "processor")
        compiler = self._get_str(args, "compiler", "compilerspec", "compilerspecid")
        recursive = self._get_bool(args, "recursive", default=False)
        max_depth = self._get_int(args, "maxdepth", default=16)
        analyze_after_import = self._get_bool(args, "analyzeafterimport", default=False)

        source = Path(file_path).expanduser().resolve()
        if not source.exists():
            raise ValueError(f"File not found: {source}")

        imported_programs: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        discovered_count = 0

        try:
            from agentdecompile_cli.launcher import ProjectManager

            manager = ProjectManager()
            try:
                for item in self._iter_files_to_import(source, recursive, max_depth):
                    discovered_count += 1
                    try:
                        program = manager.import_binary(item, program_name=prog_name or item.name)
                        if program is None:
                            raise RuntimeError("import_binary returned None")
                        imported_programs.append({"sourcePath": str(item), "programName": program.getName() if hasattr(program, "getName") else item.name})
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

        supported_formats = ["c", "cpp", "cxx", "gzf", "sarif", "xml", "html", "ascii"]
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
                include_globals = self._get_bool(args, "includeglobals", default=True)
                tags = self._get_str(args, "tags")
                try:
                    from agentdecompile_cli.ghidrecomp.decompile import decompile_to_single_file

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
                    from datetime import datetime

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
                        logger.debug(f"Error collecting external references: {e}")
                    
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
                        logger.debug(f"Error collecting bookmarks: {e}")
                    
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
                        logger.debug(f"Error collecting function analysis: {e}")
                    
                    now = datetime.utcnow().isoformat() + "Z"
                    sarif_doc = {
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
                                    "analysisComplete": program.getAnalysisState().isDone(),
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
                    logger.error(f"Error generating SARIF report: {exc}")
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
        program = self.program_info.program

        try:
            from ghidra.app.plugin.core.analysis import AutoAnalysisManager  # pyright: ignore[reportMissingModuleSource]
            from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingModuleSource]

            mgr = AutoAnalysisManager.getAnalysisManager(program)

            def _run_auto_analysis() -> None:
                monitor = TaskMonitor.DUMMY
                reanalyze_done = False
                try:
                    from ghidra.program.model.address import AddressSet  # pyright: ignore[reportMissingModuleSource]

                    addr_set = None
                    if hasattr(program, "getMemory"):
                        memory = self._get_memory(program)
                        if memory is not None:
                            if hasattr(memory, "getLoadedAndInitializedAddressSet"):
                                addr_set = memory.getLoadedAndInitializedAddressSet()
                            elif hasattr(memory, "getAllInitializedAddressSet"):
                                addr_set = memory.getAllInitializedAddressSet()
                    if addr_set is None:
                        addr_set = AddressSet()
                    mgr.reAnalyzeAll(addr_set)
                    reanalyze_done = True
                except Exception:
                    pass

                if not reanalyze_done:
                    mgr.reAnalyzeAll(monitor)
                mgr.startAnalysis(monitor)

            self._run_program_transaction(program, "auto-analysis", _run_auto_analysis)

            return create_success_response(
                {
                    "action": "analyze",
                    "programName": program.getName(),
                    "analyzers": analyzers or "all",
                    "success": True,
                },
            )
        except ImportError:
            return create_success_response(
                {
                    "action": "analyze",
                    "note": "Auto-analysis requires full Ghidra environment",
                },
            )
        except Exception as e:
            return create_success_response({"action": "analyze", "success": False, "error": str(e)})

    async def _handle_change_processor(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        assert self.program_info is not None
        language = self._require_str(args, "language", "lang", "processor", "languageid", name="language")
        compiler = self._get_str(args, "compiler", "compilerspec", "compilerspecid")

        program = self.program_info.program
        try:
            from ghidra.program.model.lang import CompilerSpecID, LanguageID  # pyright: ignore[reportMissingModuleSource]
            from ghidra.program.util import DefaultLanguageService  # pyright: ignore[reportMissingModuleSource]
            from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingModuleSource]

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
        self._require_program()
        assert self.program_info is not None
        message = self._get_str(args, "message", default="AgentDecompile checkin")
        keep_checked_out = self._get_bool(args, "keepcheckedout", default=False)
        program = self.program_info.program

        try:
            from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingModuleSource]
            
            domain_file = program.getDomainFile()
            if domain_file is None:
                raise RuntimeError("No domain file associated with active program")
            domain_file.save(TaskMonitor.DUMMY)
            return create_success_response(
                {
                    "action": "checkin",
                    "program": program.getName(),
                    "message": message,
                    "keepCheckedOut": keep_checked_out,
                    "success": True,
                    "note": "Saved domain file; repository check-in API may vary by backend.",
                },
            )
        except Exception as exc:
            return create_success_response(
                {
                    "action": "checkin",
                    "program": program.getName(),
                    "message": message,
                    "keepCheckedOut": keep_checked_out,
                    "success": False,
                    "error": str(exc),
                },
            )

    async def _handle_list_processors(self, args: dict[str, Any]) -> list[types.TextContent]:
        filter_str = self._get_str(args, "filter", "query", "search")

        try:
            from ghidra.framework.main import AppInfo  # pyright: ignore[reportMissingModuleSource]

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
