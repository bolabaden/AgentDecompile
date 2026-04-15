"""Universal search provider - search-everything.

Single tool that searches across many scopes (strings, symbols, functions,
comments, bookmarks, constants, data types, structures, imports/exports, etc.)
in one or more programs. Query can be literal or regex; scope and programPath
narrow the search. Used for discovery when the user has a keyword or pattern
but does not know which tool to call.
"""

from __future__ import annotations

import difflib
import logging
import os
import re

from contextlib import nullcontext
from time import perf_counter
from typing import TYPE_CHECKING, Any, ClassVar, cast

from mcp import types

from agentdecompile_cli.context import (
    ProgramInfo,
)
from agentdecompile_cli.mcp_server.profiling import ProfileCapture
from agentdecompile_cli.mcp_server.providers._collectors import (
    collect_bookmarks,
    collect_comments,
    collect_constants,
    collect_data_type_archives,
    collect_data_types,
    collect_exports,
    collect_functions,
    collect_imports,
    collect_strings,
    collect_structure_fields,
    collect_structures,
    collect_symbols,
    collect_vtable_candidates,
)
from agentdecompile_cli.mcp_server.session_context import (
    SESSION_CONTEXTS,
    get_current_mcp_session_id,
)
from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    ToolProviderManager,
    n,
)
from agentdecompile_cli.registry import Tool

if TYPE_CHECKING:
    from ghidra.app.decompiler import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]  # noqa: F401
        DecompileResults as GhidraDecompileResults,
        DecompiledFunction as GhidraDecompiledFunction,
    )
    from ghidra.app.decompiler.component import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]  # noqa: F401 # noqa: F401
        Decompiler as GhidraDecompiler,
    )
    from ghidra.framework.model import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]  # noqa: F401 # noqa: F401
        DomainFile as GhidraDomainFile,
        DomainFolder as GhidraDomainFolder,
        ProjectData as GhidraProjectData,
    )
    from ghidra.program.model.address import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]  # noqa: F401
        AddressSetView as GhidraAddressSetView,
    )
    from ghidra.program.model.data import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]  # noqa: F401
        Category as GhidraCategory,
        DataType as GhidraDataType,
        DataTypeManager as GhidraDataTypeManager,
        StringDataInstance as GhidraStringDataInstance,
        Structure as GhidraStructure,
    )
    from ghidra.program.model.lang import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]  # noqa: F401
        LanguageDescription as GhidraLanguageDescription,
        Processor as GhidraProcessor,
    )
    from ghidra.program.model.listing import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]  # noqa: F401
        Function as GhidraFunction,
        FunctionManager as GhidraFunctionManager,
        InstructionIterator as GhidraInstructionIterator,
        Listing as GhidraListing,
        Program as GhidraProgram,
    )
    from ghidra.program.util import DefaultLanguageService as GhidraDefaultLanguageService  # pyright: ignore[reportMissingImports, reportMissingModuleSource]  # noqa: F401
logger = logging.getLogger(__name__)

_REGEX_HINT = re.compile(r"[\[\]\\(){}|*+?^$]")

# Detects patterns that look like file extensions (e.g., ".sav", ".exe", ".dll")
# where the dot should be treated literally, not as a regex wildcard.
_FILE_EXTENSION_PATTERN = re.compile(r"^\.[a-zA-Z0-9]{1,10}$")
_EXPENSIVE_SCOPES: frozenset[str] = frozenset({"decompilation", "disassembly"})
_MAX_FUZZY_FULL_TEXT_CHARS = 512
_MAX_FUZZY_SEGMENT_CHARS = 240
_MAX_FUZZY_SEGMENTS = 48
_COMMENT_TYPES: tuple[tuple[str, int], ...] = (
    ("eol", 0),
    ("pre", 1),
    ("post", 2),
    ("plate", 3),
    ("repeatable", 4),
)

_ALL_SCOPES: tuple[str, ...] = (
    "bookmarks",  # bookmark category/type/comment text
    "classes",  # class symbol names
    "comments",  # listing comment text across comment types
    "constants",  # numeric constant values in instructions (hex searchable)
    "data_type_archives",  # source archive names for data types
    "data_types",  # datatype names/display names/descriptions
    "decompilation",  # decompiled C text snippets
    "disassembly",  # instruction text (asm)
    "exports",  # exported symbol names
    "function_parameters",  # parameter names and types
    "function_signatures",  # full function signatures
    "function_tags",  # custom tags set in the program
    "functions",  # function names
    "imports",  # imported/external symbol names
    "namespaces",  # namespace symbol names
    "strings",  # defined string values
    "vtables",  # discovered vtable-like defined data
    "structure_fields",  # structure field names/types/comments
    "structures",  # structure names/descriptions
    "symbols",  # all symbol names
)

_OPTIONAL_SCOPES: tuple[str, ...] = (
    "processors",
    "project_files",
)


class SearchEverythingToolProvider(ToolProvider):
    HANDLERS = {"searcheverything": "_handle"}
    _TEXT_MATCH_MODES: ClassVar[frozenset[str]] = frozenset({"auto", "literal", "regex", "fuzzy"})
    _LEGACY_CONSTANT_MODES: ClassVar[frozenset[str]] = frozenset({"specific", "range", "common"})

    def list_tools(self) -> list[types.Tool]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider.list_tools")
        return [
            types.Tool(
                name=Tool.SEARCH_EVERYTHING.value,
                description="CALL THIS TOOL FIRST FOR DISCOVERY/LOOKUP TASKS. UNIFIED SEARCH ACROSS MOST STRING-BEARING ANALYSIS DATA. Pass ALL related search terms as a 'queries' array in ONE call instead of calling this tool multiple times with individual keywords.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {
                            "description": "Program path(s). String or array. If omitted, searches all programs in current project when available.",
                            "oneOf": [
                                {"type": "string"},
                                {"type": "array", "items": {"type": "string"}},
                            ],
                        },
                        "binaryName": {
                            "description": "Program path or binary name. String or array.",
                            "oneOf": [
                                {"type": "string"},
                                {"type": "array", "items": {"type": "string"}},
                            ],
                        },
                        "programName": {
                            "description": "Program path or name. String or array.",
                            "oneOf": [
                                {"type": "string"},
                                {"type": "array", "items": {"type": "string"}},
                            ],
                        },
                        "query": {
                            "type": "string",
                            "description": "Single search term or pattern. PREFER queries (array) over this when you have multiple terms — do NOT call this tool repeatedly with individual keywords.",
                        },
                        "queries": {
                            "oneOf": [
                                {"type": "string"},
                                {"type": "array", "items": {"type": "string"}},
                            ],
                            "description": 'BATCH multiple search terms in ONE call instead of calling this tool repeatedly. E.g. ["SaveGame", "LoadGame", ".sav", "SAVEGAME"] searches all at once. Deduplication and ranking are automatic.',
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["auto", "literal", "regex", "fuzzy"],
                            "default": "auto",
                            "description": "Match strategy. 'auto' detects regex chars and falls back to substring — WARNING: can produce false positives (e.g. '.sav' matches 'handleScreenSaver'). Use 'literal' to force exact substring matching (required for file extensions like '.sav', '.exe', or identifiers with dots). Use 'regex' to write an explicit anchored pattern. Use 'fuzzy' for approximate/similarity matching.",
                        },
                        "scopes": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Scopes to search; omit for defaults.",
                        },
                        "caseSensitive": {"type": "boolean", "default": False, "description": "Case-sensitive matching."},
                        "similarityThreshold": {"type": "number", "default": 0.7, "description": "Minimum fuzzy score (0-1)."},
                        "limit": {"type": "integer", "default": 100, "description": "Total number of results to return across all scopes. Typical values are 100–500."},
                        "offset": {"type": "integer", "default": 0, "description": "Pagination offset."},
                        "perScopeLimit": {
                            "type": "integer",
                            "default": 300,
                            "description": "Number of matches per individual scope (e.g. functions, strings, comments). Typical values are 200–500. Do not reduce this below 100 unless you have a specific reason.",
                        },
                        "maxFunctionsScan": {
                            "type": "integer",
                            "default": 500,
                            "description": "Number of functions to scan in expensive scopes (e.g. decompiled-code search). Typical values are 500–5000. Do not set this below 200 unless the binary is tiny or the user requests a quick scan.",
                        },
                        "maxInstructionsScan": {
                            "type": "integer",
                            "default": 200000,
                            "description": "Number of assembly instructions to scan when searching disassembly. Typical values are 100 000–500 000. Do not set this below 50 000 unless the user explicitly wants a shallow scan.",
                        },
                        "decompileTimeout": {"type": "integer", "default": 10, "description": "Decompiler timeout (seconds) per function."},
                        "groupByFunction": {"type": "boolean", "default": True, "description": "When true, merges function-centric results into grouped entries."},
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._handle")
        constant_request = self._collect_legacy_constant_request(args)
        queries = self._collect_queries(args)
        if not queries and constant_request is None:
            raise ValueError("query or queries is required")

        mode_n = self._resolve_text_match_mode(args, constant_request)

        case_sensitive = self._get_bool(args, "casesensitive", default=False)
        threshold_raw = self._get(args, "similaritythreshold", "threshold", default=0.7)
        try:
            threshold = float(threshold_raw)
        except (TypeError, ValueError):
            threshold = 0.7
        threshold = max(0.0, min(1.0, threshold))

        offset, limit = self._get_pagination_params(args, default_limit=100)
        per_scope_limit = self._get_int(args, "perscopelimit", "scope_limit", default=300) or 300
        max_functions_scan = self._get_int(args, "maxfunctionsscan", "maxfunctions", default=500) or 500
        max_instructions_scan = self._get_int(args, "maxinstructionsscan", "maxinstructions", default=200000) or 200000
        samples_per_constant = self._get_int(args, "samplesperconstant", default=5) or 5
        decompile_timeout = self._get_int(args, "decompiletimeout", "timeout", default=10) or 10
        group_by_function = self._get_bool(args, "groupbyfunction", default=True)
        scopes = self._collect_scopes(args, prefer_constants_only=constant_request is not None)
        explicit_scopes_requested = bool(self._get_list(args, "scopes", "scope", "domains", "sources", "types"))
        capture_ctx = self._maybe_profile_capture(
            args,
            queries=queries,
            scopes=scopes,
            limit=limit,
            per_scope_limit=per_scope_limit,
            max_functions_scan=max_functions_scan,
            max_instructions_scan=max_instructions_scan,
            decompile_timeout=decompile_timeout,
        )

        with capture_ctx as capture:
            try:
                compiled: dict[str, re.Pattern[str]] = self._compile_regexes(queries, mode_n, case_sensitive)

                target_programs, target_warnings = await self._resolve_target_programs(args)
                if not target_programs:
                    raise ValueError("No target programs found. Open a program, pass programPath/programName/binaryName, or ensure project programs are available.")

                if capture is not None:
                    capture.add_metadata(
                        targetProgramCount=len(target_programs),
                        targetPrograms=[str(tp.get("programKey", "")) for tp in target_programs],
                        explicitScopesRequested=explicit_scopes_requested,
                    )

                all_results: list[dict[str, Any]] = []
                warnings: list[str] = list(target_warnings)
                scope_diagnostics: list[dict[str, Any]] = []
                requested_result_count = max(offset + limit, 1)
                ordered_scopes = self._prioritize_scopes(scopes)

                for target in target_programs:
                    program_key = str(target.get("programKey", ""))
                    program: GhidraProgram | None = target.get("program")
                    program_info: ProgramInfo | None = target.get("programInfo")
                    if program is None:
                        continue
                    for scope in ordered_scopes:
                        if self._should_skip_expensive_scope(scope, explicit_scopes_requested, len(all_results), requested_result_count):
                            diagnostic = {
                                "scope": scope,
                                "program": program_key,
                                "skipped": True,
                                "reason": f"Skipped expensive default scope after collecting {len(all_results)} results from cheaper scopes",
                            }
                            scope_diagnostics.append(diagnostic)
                            warnings.append(f"{program_key or '<active>'}:{scope}: {diagnostic['reason']}")
                            continue
                        try:
                            scoped, diagnostic = self._search_scope(
                                scope=scope,
                                program=program,
                                program_info=program_info,
                                queries=queries,
                                mode=mode_n,
                                case_sensitive=case_sensitive,
                                threshold=threshold,
                                compiled_regexes=compiled,
                                per_scope_limit=per_scope_limit,
                                constant_request=constant_request,
                                max_functions_scan=max_functions_scan,
                                max_instructions_scan=max_instructions_scan,
                                samples_per_constant=samples_per_constant,
                                decompile_timeout=decompile_timeout,
                            )
                            if diagnostic is not None:
                                diagnostic.setdefault("program", program_key)
                                scope_diagnostics.append(diagnostic)
                                warning = self._scope_diagnostic_warning(program_key, diagnostic)
                                if warning:
                                    warnings.append(warning)
                            for row in scoped:
                                row.setdefault("program", program_key)
                            all_results.extend(scoped)
                        except Exception as e:
                            warnings.append(f"{program_key or '<active>'}:{scope}: {e}")

                all_results = [self._attach_next_tools(item) for item in all_results]
                if group_by_function:
                    all_results = self._group_function_results(all_results)

                all_results.sort(key=lambda item: (float(item.get("score", 0.0)), str(item.get("scope", ""))), reverse=True)
                if capture is not None:
                    capture.add_metadata(
                        resultCount=len(all_results),
                        warningCount=len(warnings),
                        scopeDiagnostics=scope_diagnostics,
                        requestOutcome="success",
                    )
                paginated, _has_more = self._paginate_results(all_results, offset, limit)
                return self._create_paginated_response(
                    paginated,
                    offset,
                    limit,
                    total=len(all_results),
                    mode="search",
                    scopes=scopes,
                    queries=queries,
                    targetPrograms=[str(tp.get("programKey", "")) for tp in target_programs],
                    searchMode=mode_n,
                    caseSensitive=case_sensitive,
                    similarityThreshold=threshold,
                    legacyConstantMode=constant_request.get("mode") if constant_request else None,
                    groupByFunction=group_by_function,
                    warnings=warnings,
                    scopeDiagnostics=scope_diagnostics,
                )
            except BaseException as exc:
                if capture is not None:
                    capture.add_metadata(
                        requestOutcome="cancelled" if exc.__class__.__name__ == "CancelledError" else "error",
                        requestErrorType=exc.__class__.__name__,
                        requestError=str(exc),
                    )
                raise

    def _maybe_profile_capture(
        self,
        args: dict[str, Any],
        *,
        queries: list[str],
        scopes: list[str],
        limit: int,
        per_scope_limit: int,
        max_functions_scan: int,
        max_instructions_scan: int,
        decompile_timeout: int,
    ):
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._maybe_profile_capture")
        enabled = str(os.getenv("AGENTDECOMPILE_PROFILE_SEARCH_EVERYTHING", "")).strip().lower() in {"1", "true", "yes", "on"}
        if not enabled:
            return nullcontext(None)
        target = ",".join(self._collect_requested_program_keys(args)[:5])
        return ProfileCapture(
            "search-everything",
            target=target,
            metadata={
                "queries": queries,
                "scopes": scopes,
                "limit": limit,
                "perScopeLimit": per_scope_limit,
                "maxFunctionsScan": max_functions_scan,
                "maxInstructionsScan": max_instructions_scan,
                "decompileTimeout": decompile_timeout,
            },
        )

    def _prioritize_scopes(self, scopes: list[str]) -> list[str]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._prioritize_scopes")
        cheap = [scope for scope in scopes if scope not in _EXPENSIVE_SCOPES]
        expensive = [scope for scope in scopes if scope in _EXPENSIVE_SCOPES]
        return cheap + expensive

    def _should_skip_expensive_scope(
        self,
        scope: str,
        explicit_scopes_requested: bool,
        current_result_count: int,
        requested_result_count: int,
    ) -> bool:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._should_skip_expensive_scope")
        return (not explicit_scopes_requested) and scope in _EXPENSIVE_SCOPES and current_result_count >= requested_result_count

    def _scope_diagnostic_warning(self, program_key: str, diagnostic: dict[str, Any]) -> str | None:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._scope_diagnostic_warning")
        if diagnostic.get("skipped"):
            return None

        scope = str(diagnostic.get("scope", ""))
        timed_out = int(diagnostic.get("timedOutCount", 0) or 0)
        cancelled = int(diagnostic.get("cancelledCount", 0) or 0)
        failed = int(diagnostic.get("failedCount", 0) or 0)
        if scope == "decompilation" and (timed_out or cancelled or failed):
            details = [
                f"scannedFunctions={int(diagnostic.get('scannedFunctions', 0) or 0)}",
                f"timedOut={timed_out}",
                f"cancelled={cancelled}",
                f"failed={failed}",
            ]
            return f"{program_key or '<active>'}:{scope}: {' '.join(details)}"
        return None

    def _resolve_text_match_mode(self, args: dict[str, Any], constant_request: dict[str, Any] | None) -> str:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._resolve_text_match_mode")
        explicit_search_mode = self._get_str(args, "searchmode", default="")
        if explicit_search_mode:
            normalized = n(explicit_search_mode)
            if constant_request is not None and normalized in self._LEGACY_CONSTANT_MODES:
                return "literal"
            if normalized == "semantic":
                return "fuzzy"
            if normalized in self._TEXT_MATCH_MODES:
                return normalized
            raise ValueError("searchMode must be one of: semantic, literal, regex, fuzzy")

        explicit_mode = self._get_str(args, "mode", default="auto")
        normalized_mode = n(explicit_mode)
        if normalized_mode in self._TEXT_MATCH_MODES:
            return normalized_mode
        if constant_request is not None:
            return "literal"
        raise ValueError("mode must be one of: auto, literal, regex, fuzzy")

    def _collect_legacy_constant_request(self, args: dict[str, Any]) -> dict[str, Any] | None:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._collect_legacy_constant_request")
        explicit_mode = n(self._get_str(args, "mode", default=""))
        has_numeric_args = any(self._get(args, key) is not None for key in ("value", "minvalue", "maxvalue", "topn", "includesmallvalues"))
        if explicit_mode not in self._LEGACY_CONSTANT_MODES and not has_numeric_args:
            return None

        mode = explicit_mode if explicit_mode in self._LEGACY_CONSTANT_MODES else "specific"
        request: dict[str, Any] = {
            "mode": mode,
            "value": self._get_int(args, "value", default=0),
            "minValue": self._get_int(args, "minvalue", default=0),
            "maxValue": self._get_int(args, "maxvalue", default=0xFFFFFFFF),
            "includeSmallValues": self._get_bool(args, "includesmallvalues", default=False),
            "topN": self._get_int(args, "topn", default=0),
        }
        if mode == "specific" and self._get(args, "value") is None:
            raise ValueError("value is required when mode is specific")
        if mode == "range" and (self._get(args, "minvalue") is None or self._get(args, "maxvalue") is None):
            raise ValueError("minValue and maxValue are required when mode is range")
        return request

    async def _resolve_target_programs(self, args: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._resolve_target_programs")
        warnings: list[str] = []
        requested_program_keys: list[str] = self._collect_requested_program_keys(args)

        session_id: str = get_current_mcp_session_id()
        targets: list[dict[str, Any]] = []
        seen: set[str] = set()

        if requested_program_keys:
            for key in requested_program_keys:
                info: ProgramInfo | None = SESSION_CONTEXTS.get_program_info(session_id, key)
                if info is None and self._manager is not None:
                    try:
                        info = await self._manager._activate_requested_program(session_id, key)
                    except Exception as e:
                        warnings.append(f"program '{key}': {e}")
                if info is None or info.program is None:
                    warnings.append(f"program '{key}': not found")
                    continue
                name = str(key)
                if name in seen:
                    continue
                seen.add(name)
                targets.append({"programKey": name, "program": info.program, "programInfo": info})
            return targets, warnings

        # No explicit program target: search all programs in project if available.
        project_paths: list[str] = self._collect_project_program_paths()
        if project_paths and self._manager is not None:
            for path in project_paths:
                info = SESSION_CONTEXTS.get_program_info(session_id, path)
                if info is None:
                    try:
                        info = await self._manager._activate_requested_program(session_id, path)
                    except Exception as e:
                        warnings.append(f"program '{path}': {e}")
                if info is None or info.program is None:
                    continue
                key = str(path)
                if key in seen:
                    continue
                seen.add(key)
                targets.append({"programKey": key, "program": info.program, "programInfo": info})

        if targets:
            return targets, warnings

        # Fallback to active session program.
        active_info: ProgramInfo | None = SESSION_CONTEXTS.get_active_program_info(session_id) or self.program_info
        if active_info is not None and active_info.program is not None:
            active_name: str = self._get_str(args, "programpath", "programname", "binaryname", default="<active>") or "<active>"
            targets.append({"programKey": active_name, "program": active_info.program, "programInfo": active_info})

        return targets, warnings

    def _collect_requested_program_keys(self, args: dict[str, Any]) -> list[str]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._collect_requested_program_keys")
        keys: list[str] = []

        for alias in ("programpath", "programname", "binaryname"):
            raw_list: list[Any] = self._get_list(args, alias) or []
            if raw_list:
                for value in raw_list:
                    if value is None:
                        continue
                    item: str = str(value).strip()
                    if item:
                        keys.append(item)

            raw_single: Any = self._get(args, alias)
            if isinstance(raw_single, str):
                for part in raw_single.split(","):
                    item = part.strip()
                    if item:
                        keys.append(item)

        unique: list[str] = []
        seen: set[str] = set()
        for key in keys:
            nk: str = key.lower()
            if nk in seen:
                continue
            seen.add(nk)
            unique.append(key)
        return unique

    def _collect_project_program_paths(self) -> list[str]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._collect_project_program_paths")
        manager: ToolProviderManager | None = self._manager
        if manager is None:
            return []

        project_data: GhidraProjectData | None = None
        try:
            project_data = manager._resolve_project_data()
        except Exception:
            project_data = None
        if project_data is None:
            return []

        try:
            root: GhidraDomainFolder | None = project_data.getRootFolder()
        except Exception:
            return []

        paths: list[str] = []
        stack: list[GhidraDomainFolder] = [root]
        while stack:
            folder = stack.pop()
            try:
                domain_file: GhidraDomainFile | None = None
                for domain_file in self._iter_items(folder.getFiles() or []):
                    if domain_file is None:
                        continue
                    pathname = str(domain_file.getPathname() or "")
                    if pathname:
                        paths.append(pathname)
                for sub_folder in self._iter_items(folder.getFolders() or []):
                    stack.append(sub_folder)
            except Exception:
                continue

        unique: list[str] = []
        seen: set[str] = set()
        for path in paths:
            key = path.strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            unique.append(path)
        return unique

    def _collect_queries(self, args: dict[str, Any]) -> list[str]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._collect_queries")
        queries: list[str] = []
        raw_list: list[Any] = self._get_list(args, "queries", "patterns", "terms") or []
        for value in raw_list:
            if isinstance(value, str) and value.strip():
                queries.append(value.strip())

        raw_queries_csv: str | None = self._get_str(args, "queries")
        if raw_queries_csv and not raw_list:
            for value in raw_queries_csv.split(","):
                if value is None:
                    continue
                if value.strip():
                    queries.append(value.strip())

        single: str | None = self._get_str(
            args,
            "query",
            "pattern",
            "search",
            "searchstring",
            "search_text",
            "namepattern",
            "filter",
            "libraryfilter",
            "tag",
            "tagname",
            "comment",
            "datatypestring",
            "text",
        )
        if single:
            queries.append(single.strip())

        unique: list[str] = []
        seen: set[str] = set()
        for q in queries:
            key: str = q if self._get_bool(args, "casesensitive", default=False) else q.lower()
            if key in seen:
                continue
            seen.add(key)
            unique.append(q)
        return unique

    def _collect_scopes(self, args: dict[str, Any], prefer_constants_only: bool = False) -> list[str]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._collect_scopes")
        raw_scopes: list[Any] = self._get_list(args, "scopes", "scope", "domains", "sources", "types") or []
        if not raw_scopes:
            if prefer_constants_only:
                return ["constants"]
            return list(_ALL_SCOPES)

        aliases: dict[str, str] = {
            "all": "all",
            "everything": "all",
            "functions": "functions",
            "function": "functions",
            "functionnames": "functions",
            "functionsignatures": "function_signatures",
            "signatures": "function_signatures",
            "signature": "function_signatures",
            "functionparameters": "function_parameters",
            "parameters": "function_parameters",
            "tags": "function_tags",
            "tag": "function_tags",
            "functiontags": "function_tags",
            "function_tags": "function_tags",
            "functiontag": "function_tags",
            "bookmarks": "bookmarks",
            "bookmark": "bookmarks",
            "comments": "comments",
            "comment": "comments",
            "constants": "constants",
            "constant": "constants",
            "magic": "constants",
            "magicnumbers": "constants",
            "scalars": "constants",
            "decompilation": "decompilation",
            "decompile": "decompilation",
            "code": "decompilation",
            "disassembly": "disassembly",
            "asm": "disassembly",
            "symbols": "symbols",
            "symbol": "symbols",
            "imports": "imports",
            "import": "imports",
            "exports": "exports",
            "export": "exports",
            "namespaces": "namespaces",
            "namespace": "namespaces",
            "classes": "classes",
            "class": "classes",
            "strings": "strings",
            "string": "strings",
            "vtables": "vtables",
            "vtable": "vtables",
            "vftables": "vtables",
            "vftable": "vtables",
            "datatypes": "data_types",
            "datatype": "data_types",
            "types": "data_types",
            "datatypearchives": "data_type_archives",
            "archives": "data_type_archives",
            "structures": "structures",
            "structure": "structures",
            "structurefields": "structure_fields",
            "fields": "structure_fields",
            "processors": "processors",
            "processor": "processors",
            "architectures": "processors",
            "projectfiles": "project_files",
            "files": "project_files",
        }

        resolved: list[str] = []
        for scope in raw_scopes:
            key: str = aliases.get(n(str(scope)), "")
            if key == "all":
                return list(_ALL_SCOPES)
            if key and key not in resolved:
                resolved.append(key)

        return resolved or list(_ALL_SCOPES)

    def _compile_regexes(
        self,
        queries: list[str],
        mode: str,
        case_sensitive: bool,
    ) -> dict[str, re.Pattern[str]]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._compile_regexes")
        if mode not in {"regex", "auto"}:
            return {}

        flags: int = 0 if case_sensitive else re.IGNORECASE
        compiled: dict[str, re.Pattern[str]] = {}
        for q in queries:
            if q is None:
                continue
            if mode == "regex":
                # Explicit regex mode: compile as-is
                try:
                    compiled[q] = re.compile(q, flags)
                except re.error as e:
                    raise ValueError(f"Invalid regex '{q}': {e}") from e
            elif mode == "auto":
                # Auto mode: only compile as regex if it has real regex syntax
                # (brackets, pipes, quantifiers, etc.) but NOT mere dots.
                # File extension patterns like ".sav" should remain literal.
                if _FILE_EXTENSION_PATTERN.match(q):
                    continue  # Treat as literal — skip regex compilation
                if _REGEX_HINT.search(q):
                    try:
                        compiled[q] = re.compile(q, flags)
                    except re.error as e:
                        raise ValueError(f"Invalid regex '{q}': {e}") from e
        return compiled

    def _search_scope(
        self,
        *,
        scope: str,
        program: GhidraProgram,
        program_info: ProgramInfo | None,
        queries: list[str],
        mode: str,
        case_sensitive: bool,
        threshold: float,
        compiled_regexes: dict[str, re.Pattern[str]],
        per_scope_limit: int,
        constant_request: dict[str, Any] | None,
        max_functions_scan: int,
        max_instructions_scan: int,
        samples_per_constant: int,
        decompile_timeout: int,
    ) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
        """Dispatch to the _search_* method for the given scope; program-agnostic scopes (processors, project_files) omit program."""
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._search_scope")
        if scope == "functions":
            return self._search_functions(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit), None
        if scope == "function_signatures":
            return self._search_function_signatures(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit), None
        if scope == "function_parameters":
            return self._search_function_parameters(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit), None
        if scope == "function_tags":
            return self._search_tags(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit), None
        if scope == "bookmarks":
            return self._search_bookmarks(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit), None
        if scope == "comments":
            return self._search_comments(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit), None
        if scope == "constants":
            return self._search_constants(
                program,
                queries,
                mode,
                case_sensitive,
                threshold,
                compiled_regexes,
                per_scope_limit,
                max_instructions_scan,
                samples_per_constant,
                constant_request,
            ), None
        if scope == "decompilation":
            return self._search_decompilation(program, program_info, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit, max_functions_scan, decompile_timeout)
        if scope == "disassembly":
            return self._search_disassembly(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit, max_functions_scan, max_instructions_scan)
        if scope == "symbols":
            return self._search_symbols(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit), None
        if scope == "imports":
            return self._search_imports(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit), None
        if scope == "exports":
            return self._search_exports(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit), None
        if scope == "namespaces":
            return self._search_namespaces(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit), None
        if scope == "classes":
            return self._search_classes(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit), None
        if scope == "strings":
            return self._search_strings(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit), None
        if scope == "vtables":
            return self._search_vtables(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit), None
        if scope == "data_types":
            return self._search_data_types(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit), None
        if scope == "data_type_archives":
            return self._search_data_type_archives(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit), None
        if scope == "structures":
            return self._search_structures(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit), None
        if scope == "structure_fields":
            return self._search_structure_fields(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit), None
        if scope == "processors":
            return self._search_processors(queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit), None
        if scope == "project_files":
            return self._search_project_files(queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit), None
        return [], None

    @staticmethod
    def _iter_items(source: Any):
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._iter_items")
        if source is None:
            return
        if hasattr(source, "hasNext") and hasattr(source, "next"):
            while source.hasNext():
                yield source.next()
            return
        for item in source:
            yield item

    def _match_text(
        self,
        *,
        text: str,
        queries: list[str],
        mode: str,
        case_sensitive: bool,
        threshold: float,
        compiled_regexes: dict[str, re.Pattern[str]],
    ) -> dict[str, Any] | None:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._match_text")
        if not text:
            return None

        cmp_text: str = text if case_sensitive else text.lower()
        fuzzy_candidates: list[str] | None = None
        best: dict[str, Any] | None = None
        for q in queries:
            q_cmp: str = q if case_sensitive else q.lower()
            kind: str = "literal"
            score: float = 0.0
            matched: bool = False

            pattern: re.Pattern[str] | None = compiled_regexes.get(q)
            if pattern is not None:
                if pattern.search(text):
                    matched = True
                    score = 1.0
                    kind = "regex"
                else:
                    continue
            elif mode == "regex":
                continue
            elif q_cmp in cmp_text:
                matched = True
                score = 1.0
                kind = "literal"
            elif mode in {"fuzzy", "auto"}:
                if fuzzy_candidates is None:
                    fuzzy_candidates = self._prepare_fuzzy_candidates(text, case_sensitive)
                similarity = self._fuzzy_similarity(q_cmp, text, case_sensitive, prepared_candidates=fuzzy_candidates)
                if similarity >= threshold:
                    matched = True
                    score = float(similarity)
                    kind = "fuzzy"

            if not matched:
                continue
            candidate = {"query": q, "score": score, "matchType": kind}
            if best is None or candidate["score"] > best["score"]:
                best = candidate
                if float(candidate["score"]) >= 1.0:
                    break

        return best

    def _prepare_fuzzy_candidates(self, text: str, case_sensitive: bool) -> list[str]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._prepare_fuzzy_candidates")
        if not text:
            return []

        if len(text) <= _MAX_FUZZY_FULL_TEXT_CHARS:
            return [text if case_sensitive else text.lower()]

        return [segment if case_sensitive else segment.lower() for segment in self._iter_fuzzy_segments(text)]

    def _fuzzy_similarity(self, query: str, text: str, case_sensitive: bool, *, prepared_candidates: list[str] | None = None) -> float:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._fuzzy_similarity")
        if not text:
            return 0.0

        candidates: list[str] = prepared_candidates if prepared_candidates is not None else self._prepare_fuzzy_candidates(text, case_sensitive)
        if not candidates:
            return 0.0
        if len(candidates) == 1:
            return float(difflib.SequenceMatcher(None, query, candidates[0]).ratio())

        best = 0.0
        for candidate in candidates:
            similarity = float(difflib.SequenceMatcher(None, query, candidate).ratio())
            if similarity > best:
                best = similarity
            if best >= 1.0:
                break
        return best

    def _iter_fuzzy_segments(self, text: str):
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._iter_fuzzy_segments")
        seen: set[str] = set()
        count = 0
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            segment = line[:_MAX_FUZZY_SEGMENT_CHARS]
            if segment in seen:
                continue
            seen.add(segment)
            yield segment
            count += 1
            if count >= _MAX_FUZZY_SEGMENTS:
                return

        if count == 0:
            yield text[:_MAX_FUZZY_SEGMENT_CHARS]

    def _extract_match_snippet(self, text: str, match: dict[str, Any], case_sensitive: bool) -> str:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._extract_match_snippet")
        query = str(match.get("query", "") or "")
        if not text:
            return ""
        if not query:
            return text[:400]

        haystack = text if case_sensitive else text.lower()
        needle = query if case_sensitive else query.lower()
        index = haystack.find(needle)
        if index >= 0:
            start = max(index - 120, 0)
            end = min(index + len(query) + 240, len(text))
            return text[start:end]

        pattern = match.get("matchType") == "regex" and query
        if pattern:
            flags = 0 if case_sensitive else re.IGNORECASE
            try:
                compiled = re.compile(query, flags)
                regex_match = compiled.search(text)
                if regex_match is not None:
                    start = max(regex_match.start() - 120, 0)
                    end = min(regex_match.end() + 240, len(text))
                    return text[start:end]
            except re.error:
                pass

        return text[:400]

    def _search_functions(
        self,
        program: GhidraProgram,
        queries: list[str],
        mode: str,
        case_sensitive: bool,
        threshold: float,
        compiled_regexes: dict[str, re.Pattern[str]],
        per_scope_limit: int,
    ) -> list[dict[str, Any]]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._search_functions")
        functions: list[dict[str, Any]] = collect_functions(program, limit=per_scope_limit)
        results: list[dict[str, Any]] = []
        for function in functions:
            match: dict[str, Any] | None = self._match_text(
                text=str(function.get("name", "")), queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes
            )
            if not match:
                continue
            row: dict[str, Any] = self._function_base_result(function)
            row.update({"scope": "functions", "resultType": "function", **match})
            results.append(row)
        return results

    def _search_function_signatures(
        self,
        program: GhidraProgram,
        queries: list[str],
        mode: str,
        case_sensitive: bool,
        threshold: float,
        compiled_regexes: dict[str, re.Pattern[str]],
        per_scope_limit: int,
    ) -> list[dict[str, Any]]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._search_function_signatures")
        functions: list[dict[str, Any]] = collect_functions(program, limit=per_scope_limit)
        results: list[dict[str, Any]] = []
        for function in functions:
            sig: str = str(function.get("signature", ""))
            match: dict[str, Any] | None = self._match_text(
                text=sig, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes
            )
            if not match:
                continue
            row: dict[str, Any] = self._function_base_result(function)
            row.update({"scope": "function_signatures", "resultType": "function", **match})
            results.append(row)
        return results

    def _search_function_parameters(
        self,
        program: GhidraProgram,
        queries: list[str],
        mode: str,
        case_sensitive: bool,
        threshold: float,
        compiled_regexes: dict[str, re.Pattern[str]],
        per_scope_limit: int,
    ) -> list[dict[str, Any]]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._search_function_parameters")
        functions: list[dict[str, Any]] = collect_functions(program, limit=per_scope_limit)
        results: list[dict[str, Any]] = []
        for function in functions:
            param: dict[str, Any]
            for param in list(function.get("parameters", [])):
                if len(results) >= per_scope_limit:
                    return results
                texts: list[str] = [str(param.get("name", "") or ""), str(param.get("type", "") or "")]
                best: dict[str, Any] | None = None
                for txt in texts:
                    match: dict[str, Any] | None = self._match_text(
                        text=txt, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes
                    )
                    if match and (best is None or float(match["score"]) > float(best["score"])):
                        best = match
                if not best:
                    continue
                row: dict[str, Any] = self._function_base_result(function)
                row.update(
                    {
                        "scope": "function_parameters",
                        "resultType": "function_parameter",
                        "parameter": str(param.get("name", "")),
                        "parameterType": str(param.get("type", "")),
                        "ordinal": int(param.get("ordinal", 0)),
                        **best,
                    },
                )
                results.append(row)
        return results

    def _search_tags(
        self,
        program: GhidraProgram,
        queries: list[str],
        mode: str,
        case_sensitive: bool,
        threshold: float,
        compiled_regexes: dict[str, re.Pattern[str]],
        per_scope_limit: int,
    ) -> list[dict[str, Any]]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._search_tags")
        functions = collect_functions(program, limit=per_scope_limit)
        results: list[dict[str, Any]] = []
        for function in functions:
            for tag_name in list(function.get("tags", [])):
                if len(results) >= per_scope_limit:
                    return results
                match = self._match_text(text=tag_name, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes)
                if not match:
                    continue
                row = self._function_base_result(function)
                row.update({"scope": "function_tags", "resultType": "function_tag", "tag": tag_name, **match})
                results.append(row)
        return results

    def _search_bookmarks(
        self,
        program: GhidraProgram,
        queries: list[str],
        mode: str,
        case_sensitive: bool,
        threshold: float,
        compiled_regexes: dict[str, re.Pattern[str]],
        per_scope_limit: int,
    ) -> list[dict[str, Any]]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._search_bookmarks")
        results: list[dict[str, Any]] = []
        for bm in collect_bookmarks(program, limit=per_scope_limit):
            if len(results) >= per_scope_limit:
                break
            candidates: list[str] = [str(bm.get("comment", "")), str(bm.get("category", "")), str(bm.get("type", ""))]
            best: dict[str, Any] | None = None
            for field_text in candidates:
                match = self._match_text(text=field_text, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes)
                if match and (best is None or float(match["score"]) > float(best["score"])):
                    best = match
            if not best:
                continue
            results.append(
                {
                    "scope": "bookmarks",
                    "resultType": "bookmark",
                    "address": str(bm.get("address", "")),
                    "type": str(bm.get("type", "")),
                    "category": str(bm.get("category", "")),
                    "comment": str(bm.get("comment", "")),
                    **best,
                }
            )
        return results

    def _search_comments(
        self,
        program: GhidraProgram,
        queries: list[str],
        mode: str,
        case_sensitive: bool,
        threshold: float,
        compiled_regexes: dict[str, re.Pattern[str]],
        per_scope_limit: int,
    ) -> list[dict[str, Any]]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._search_comments")
        results: list[dict[str, Any]] = []
        for comment in collect_comments(program, limit=per_scope_limit):
            if len(results) >= per_scope_limit:
                break
            comment_text: str = str(comment.get("comment", ""))
            match: dict[str, Any] | None = self._match_text(
                text=comment_text, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes
            )
            if not match:
                continue
            results.append(
                {
                    "scope": "comments",
                    "resultType": "comment",
                    "address": str(comment.get("address", "")),
                    "commentType": str(comment.get("commentType", "")),
                    "comment": comment_text,
                    "function": str(comment.get("function", "")),
                    "functionAddress": str(comment.get("functionAddress", "")),
                    **match,
                },
            )
        return results

    def _search_constants(
        self,
        program: GhidraProgram,
        queries: list[str],
        mode: str,
        case_sensitive: bool,
        threshold: float,
        compiled_regexes: dict[str, re.Pattern[str]],
        per_scope_limit: int,
        max_instructions_scan: int,
        samples_per_constant: int,
        constant_request: dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._search_constants")
        value_filter = self._build_constant_filter(constant_request)
        constants, _instr_count = collect_constants(
            program,
            value_filter=value_filter,
            max_instructions=max_instructions_scan,
            samples_per_constant=samples_per_constant,
        )
        if constant_request is not None and constant_request.get("mode") == "common":
            if not constant_request.get("includeSmallValues"):
                constants = [item for item in constants if abs(int(item.get("value", 0))) >= 0x100]
            top_n = int(constant_request.get("topN") or 0)
            if top_n > 0:
                constants = constants[:top_n]
        results: list[dict[str, Any]] = []
        for item in constants:
            if len(results) >= per_scope_limit:
                break
            fields: list[str] = [str(item.get("hex", "")), str(item.get("value", ""))]
            best: dict[str, Any] | None = None
            for text in fields:
                match = self._match_text(text=text, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes)
                if match and (best is None or float(match["score"]) > float(best["score"])):
                    best = match
            if not best:
                continue
            results.append(
                {
                    "scope": "constants",
                    "resultType": "constant",
                    "value": int(item.get("value", 0)),
                    "hex": str(item.get("hex", "")),
                    "occurrences": int(item.get("occurrences", 0)),
                    "samples": item.get("samples", []),
                    **best,
                }
            )
        return results

    @staticmethod
    def _build_constant_filter(constant_request: dict[str, Any] | None):
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._build_constant_filter")
        if constant_request is None:
            return None
        mode = str(constant_request.get("mode", "specific"))
        if mode == "specific":
            target = int(constant_request.get("value", 0))
            return lambda value: value == target
        if mode == "range":
            min_value = int(constant_request.get("minValue", 0))
            max_value = int(constant_request.get("maxValue", 0xFFFFFFFF))
            return lambda value: min_value <= value <= max_value
        return lambda value: True

    def _search_decompilation(
        self,
        program: GhidraProgram,
        program_info: ProgramInfo | None,
        queries: list[str],
        mode: str,
        case_sensitive: bool,
        threshold: float,
        compiled_regexes: dict[str, re.Pattern[str]],
        per_scope_limit: int,
        max_functions_scan: int,
        decompile_timeout: int,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._search_decompilation")
        results: list[dict[str, Any]] = []
        diagnostic: dict[str, Any] = {
            "scope": "decompilation",
            "scannedFunctions": 0,
            "timedOutCount": 0,
            "cancelledCount": 0,
            "failedCount": 0,
            "matches": 0,
        }
        started_at = perf_counter()
        try:
            from ghidra.util.task import ConsoleTaskMonitor as GhidraConsoleTaskMonitor  # pyright: ignore[reportMissingImports,reportMissingModuleSource]

            from agentdecompile_cli.mcp_utils.decompiler_util import acquire_decompiler_for_program, get_decompiled_function_from_results

            fm: GhidraFunctionManager | None = self._get_function_manager(program)
            if fm is None:
                return results, diagnostic
            monitor = GhidraConsoleTaskMonitor()
            session_decompiler: GhidraDecompiler | None = None
            if program_info is not None:
                getter = getattr(program_info, "get_decompiler", None)
                if callable(getter):
                    try:
                        session_decompiler = getter()
                    except Exception:
                        session_decompiler = getattr(program_info, "decompiler", None)
                else:
                    session_decompiler = getattr(program_info, "decompiler", None)
            if session_decompiler is None:
                session_decompiler = getattr(self.program_info, "decompiler", None)
            with acquire_decompiler_for_program(session_decompiler, program) as lease:
                diagnostic["reusedSessionDecompiler"] = bool(lease.reused_session)
                func: GhidraFunction
                for func in fm.getFunctions(True):
                    if diagnostic["scannedFunctions"] >= max_functions_scan or len(results) >= per_scope_limit:
                        break
                    diagnostic["scannedFunctions"] += 1
                    try:
                        dr: GhidraDecompileResults | None = lease.decompiler.decompileFunction(func, decompile_timeout, monitor)
                        if not dr or not dr.decompileCompleted():
                            diagnostic["timedOutCount"] += int(self._result_flag(dr, "isTimedOut"))
                            diagnostic["cancelledCount"] += int(self._result_flag(dr, "isCancelled"))
                            diagnostic["failedCount"] += 1
                            continue
                        decompiled: GhidraDecompiledFunction | None = get_decompiled_function_from_results(dr)
                        text = decompiled.getC() if decompiled else ""
                        match = self._match_text(text=str(text), queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes)
                        if not match:
                            continue
                        snippet = self._extract_match_snippet(str(text), match, case_sensitive)
                        results.append(
                            {
                                "scope": "decompilation",
                                "resultType": "decompiled_code",
                                "function": str(func.getName()),
                                "functionAddress": str(func.getEntryPoint()),
                                "address": str(func.getEntryPoint()),
                                "snippet": snippet,
                                **match,
                            }
                        )
                    except Exception:
                        diagnostic["failedCount"] += 1
                        continue
        except Exception as e:
            logger.warning("Decompilation scope failed: %s", e)
            diagnostic["error"] = str(e)
        diagnostic["matches"] = len(results)
        diagnostic["elapsedMs"] = int((perf_counter() - started_at) * 1000)
        return results, diagnostic

    def _result_flag(self, result: GhidraDecompileResults | None, method_name: str) -> bool:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._result_flag")
        if result is None:
            return False
        try:
            value = getattr(result, method_name)
        except Exception:
            return False
        try:
            return bool(value() if callable(value) else value)
        except Exception:
            return False

    def _search_disassembly(
        self,
        program: GhidraProgram,
        queries: list[str],
        mode: str,
        case_sensitive: bool,
        threshold: float,
        compiled_regexes: dict[str, re.Pattern[str]],
        per_scope_limit: int,
        max_functions_scan: int,
        max_instructions_scan: int,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._search_disassembly")
        fm: GhidraFunctionManager | None = self._get_function_manager(program)
        listing: GhidraListing | None = self._get_listing(program)
        if fm is None or listing is None:
            return [], {"scope": "disassembly", "scannedFunctions": 0, "instructionsScanned": 0, "matches": 0}
        results: list[dict[str, Any]] = []
        function_count: int = 0
        instruction_count: int = 0
        started_at = perf_counter()

        for func in fm.getFunctions(True):
            if function_count >= max_functions_scan or len(results) >= per_scope_limit or instruction_count >= max_instructions_scan:
                break
            function_count += 1
            body: GhidraAddressSetView | None = func.getBody()
            if not body:
                continue
            instructions: GhidraInstructionIterator = listing.getInstructions(body, True)
            for ins in self._iter_items(instructions):
                instruction_count += 1
                if len(results) >= per_scope_limit or instruction_count >= max_instructions_scan:
                    break
                text: str = str(ins)
                match: dict[str, Any] | None = self._match_text(
                    text=text, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes
                )
                if not match:
                    continue
                results.append(
                    {
                        "scope": "disassembly",
                        "resultType": "instruction",
                        "function": str(func.getName()),
                        "functionAddress": str(func.getEntryPoint()),
                        "address": str(ins.getAddress()),
                        "instruction": text,
                        **match,
                    }
                )
        return results, {
            "scope": "disassembly",
            "scannedFunctions": function_count,
            "instructionsScanned": instruction_count,
            "matches": len(results),
            "elapsedMs": int((perf_counter() - started_at) * 1000),
        }

    def _search_symbols(
        self,
        program: GhidraProgram,
        queries: list[str],
        mode: str,
        case_sensitive: bool,
        threshold: float,
        compiled_regexes: dict[str, re.Pattern[str]],
        per_scope_limit: int,
    ) -> list[dict[str, Any]]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._search_symbols")
        results: list[dict[str, Any]] = []
        for sym in collect_symbols(program, limit=per_scope_limit):
            if len(results) >= per_scope_limit:
                break
            name: str = str(sym.get("name", ""))
            match: dict[str, Any] | None = self._match_text(
                text=name, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes
            )
            if not match:
                continue
            results.append(
                {
                    "scope": "symbols",
                    "resultType": "symbol",
                    "name": name,
                    "address": str(sym.get("address", "")),
                    "symbolType": str(sym.get("symbolType", "")),
                    "namespace": str(sym.get("namespace", "")),
                    "source": str(sym.get("source", "")),
                    **match,
                }
            )
        return results

    def _search_imports(
        self,
        program: GhidraProgram,
        queries: list[str],
        mode: str,
        case_sensitive: bool,
        threshold: float,
        compiled_regexes: dict[str, re.Pattern[str]],
        per_scope_limit: int,
    ) -> list[dict[str, Any]]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._search_imports")
        results: list[dict[str, Any]] = []
        for sym in collect_imports(program, limit=per_scope_limit):
            if len(results) >= per_scope_limit:
                break
            name: str = str(sym.get("name", ""))
            match: dict[str, Any] | None = self._match_text(
                text=name, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes
            )
            if not match:
                continue
            results.append(
                {
                    "scope": "imports",
                    "resultType": "import",
                    "name": name,
                    "address": str(sym.get("address", "")),
                    "namespace": str(sym.get("namespace", "")),
                    "library": str(sym.get("library", "")),
                    **match,
                }
            )
        return results

    def _search_exports(
        self,
        program: GhidraProgram,
        queries: list[str],
        mode: str,
        case_sensitive: bool,
        threshold: float,
        compiled_regexes: dict[str, re.Pattern[str]],
        per_scope_limit: int,
    ) -> list[dict[str, Any]]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._search_exports")
        results: list[dict[str, Any]] = []
        for sym in collect_exports(program, limit=per_scope_limit):
            if len(results) >= per_scope_limit:
                break
            name: str = str(sym.get("name", ""))
            match = self._match_text(text=name, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes)
            if not match:
                continue
            results.append(
                {"scope": "exports", "resultType": "export", "name": name, "address": str(sym.get("address", "")), "namespace": str(sym.get("namespace", "")), **match}
            )
        return results

    def _search_namespaces(
        self,
        program: GhidraProgram,
        queries: list[str],
        mode: str,
        case_sensitive: bool,
        threshold: float,
        compiled_regexes: dict[str, re.Pattern[str]],
        per_scope_limit: int,
    ) -> list[dict[str, Any]]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._search_namespaces")
        try:
            from ghidra.program.model.symbol import SymbolType  # pyright: ignore[reportMissingImports,reportMissingModuleSource]
        except Exception:
            return []
        results: list[dict[str, Any]] = []
        for sym in collect_symbols(program, symbol_type=SymbolType.NAMESPACE, limit=per_scope_limit):
            if len(results) >= per_scope_limit:
                break
            name: str = str(sym.get("name", ""))
            match: dict[str, Any] | None = self._match_text(
                text=name, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes
            )
            if not match:
                continue
            results.append({"scope": "namespaces", "resultType": "namespace", "name": name, "address": str(sym.get("address", "")), **match})
        return results

    def _search_classes(
        self,
        program: GhidraProgram,
        queries: list[str],
        mode: str,
        case_sensitive: bool,
        threshold: float,
        compiled_regexes: dict[str, re.Pattern[str]],
        per_scope_limit: int,
    ) -> list[dict[str, Any]]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._search_classes")
        try:
            from ghidra.program.model.symbol import SymbolType  # pyright: ignore[reportMissingImports,reportMissingModuleSource]
        except Exception:
            return []
        results: list[dict[str, Any]] = []
        for sym in collect_symbols(program, symbol_type=SymbolType.CLASS, limit=per_scope_limit):
            if len(results) >= per_scope_limit:
                break
            name: str = str(sym.get("name", ""))
            match: dict[str, Any] | None = self._match_text(
                text=name, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes
            )
            if not match:
                continue
            results.append(
                {"scope": "classes", "resultType": "class", "name": name, "address": str(sym.get("address", "")), "namespace": str(sym.get("namespace", "")), **match}
            )
        return results

    def _search_strings(
        self,
        program: GhidraProgram,
        queries: list[str],
        mode: str,
        case_sensitive: bool,
        threshold: float,
        compiled_regexes: dict[str, re.Pattern[str]],
        per_scope_limit: int,
    ) -> list[dict[str, Any]]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._search_strings")
        results: list[dict[str, Any]] = []
        for data in collect_strings(program, min_len=1, limit=per_scope_limit, ghidra_tools=self.ghidra_tools):
            if len(results) >= per_scope_limit:
                break
            value: str = str(data.get("value", ""))
            match: dict[str, Any] | None = self._match_text(
                text=value, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes
            )
            if not match:
                continue
            results.append(
                {
                    "scope": "strings",
                    "resultType": "string",
                    "address": str(data.get("address", "")),
                    "value": value,
                    "length": int(data.get("length", len(value))),
                    "dataType": str(data.get("dataType", "")),
                    **match,
                }
            )
        return results

    def _search_data_types(
        self,
        program: GhidraProgram,
        queries: list[str],
        mode: str,
        case_sensitive: bool,
        threshold: float,
        compiled_regexes: dict[str, re.Pattern[str]],
        per_scope_limit: int,
    ) -> list[dict[str, Any]]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._search_data_types")
        results: list[dict[str, Any]] = []
        for dt in collect_data_types(program, limit=per_scope_limit):
            if len(results) >= per_scope_limit:
                break
            values: list[str] = [str(dt.get("name", "")), str(dt.get("description", "")), str(dt.get("displayName", ""))]
            best: dict[str, Any] | None = None
            for value in values:
                match: dict[str, Any] | None = self._match_text(
                    text=value, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes
                )
                if match and (best is None or float(match["score"]) > float(best["score"])):
                    best = match
            if not best:
                continue
            results.append(
                {
                    "scope": "data_types",
                    "resultType": "data_type",
                    "name": str(dt.get("name", "")),
                    "displayName": str(dt.get("displayName", "")),
                    "categoryPath": str(dt.get("categoryPath", "")),
                    "description": str(dt.get("description", "")),
                    "length": int(dt.get("length", 0)),
                    **best,
                }
            )
        return results

    def _search_vtables(
        self,
        program: GhidraProgram,
        queries: list[str],
        mode: str,
        case_sensitive: bool,
        threshold: float,
        compiled_regexes: dict[str, re.Pattern[str]],
        per_scope_limit: int,
    ) -> list[dict[str, Any]]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._search_vtables")
        results: list[dict[str, Any]] = []
        for candidate in collect_vtable_candidates(program, limit=per_scope_limit):
            haystack = " | ".join(
                part for part in [str(candidate.get("name", "")), str(candidate.get("type", "")), str(candidate.get("address", ""))] if part
            )
            match: dict[str, Any] | None = self._match_text(
                text=haystack,
                queries=queries,
                mode=mode,
                case_sensitive=case_sensitive,
                threshold=threshold,
                compiled_regexes=compiled_regexes,
            )
            if not match:
                continue
            results.append(
                {
                    "scope": "vtables",
                    "resultType": "vtable",
                    "name": str(candidate.get("name", "")),
                    "address": str(candidate.get("address", "")),
                    "type": str(candidate.get("type", "")),
                    "size": int(candidate.get("size", 0)),
                    **match,
                },
            )
        return results

    def _search_data_type_archives(
        self,
        program: GhidraProgram,
        queries: list[str],
        mode: str,
        case_sensitive: bool,
        threshold: float,
        compiled_regexes: dict[str, re.Pattern[str]],
        per_scope_limit: int,
    ) -> list[dict[str, Any]]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._search_data_type_archives")
        results: list[dict[str, Any]] = []
        for archive in collect_data_type_archives(program, limit=per_scope_limit):
            if len(results) >= per_scope_limit:
                break
            name: str = str(archive.get("name", ""))
            match: dict[str, Any] | None = self._match_text(
                text=name, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes
            )
            if not match:
                continue
            results.append(
                {
                    "scope": "data_type_archives",
                    "resultType": "data_type_archive",
                    "name": name,
                    "id": str(archive.get("id", "")),
                    "type": str(archive.get("type", "")),
                    "categoryCount": archive.get("categoryCount"),
                    "dataTypeCount": archive.get("dataTypeCount"),
                    **match,
                }
            )
        return results

    def _search_structures(
        self,
        program: GhidraProgram,
        queries: list[str],
        mode: str,
        case_sensitive: bool,
        threshold: float,
        compiled_regexes: dict[str, re.Pattern[str]],
        per_scope_limit: int,
    ) -> list[dict[str, Any]]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._search_structures")
        results: list[dict[str, Any]] = []
        for struct in collect_structures(program, limit=per_scope_limit):
            if len(results) >= per_scope_limit:
                break
            values: list[str] = [str(struct.get("name", "")), str(struct.get("description", ""))]
            best: dict[str, Any] | None = None
            for value in values:
                match: dict[str, Any] | None = self._match_text(
                    text=value, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes
                )
                if match and (best is None or float(match["score"]) > float(best["score"])):
                    best = match
            if not best:
                continue
            results.append(
                {
                    "scope": "structures",
                    "resultType": "structure",
                    "name": str(struct.get("name", "")),
                    "categoryPath": str(struct.get("categoryPath", "")),
                    "description": str(struct.get("description", "")),
                    "length": int(struct.get("length", 0)),
                    "numComponents": int(struct.get("numComponents", 0)),
                    "isUnion": bool(struct.get("isUnion", False)),
                    **best,
                },
            )
        return results

    def _search_structure_fields(
        self,
        program: GhidraProgram,
        queries: list[str],
        mode: str,
        case_sensitive: bool,
        threshold: float,
        compiled_regexes: dict[str, re.Pattern[str]],
        per_scope_limit: int,
    ) -> list[dict[str, Any]]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._search_structure_fields")
        results: list[dict[str, Any]] = []
        for struct in collect_structures(program):
            struct_obj = struct.get("structure")
            if struct_obj is None:
                continue
            for component in collect_structure_fields(struct_obj):
                if len(results) >= per_scope_limit:
                    return results
                values: list[str] = [str(component.get("name", "")), str(component.get("comment", "")), str(component.get("type", ""))]
                best: dict[str, Any] | None = None
                for value in values:
                    match: dict[str, Any] | None = self._match_text(
                        text=value, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes
                    )
                    if match and (best is None or float(match["score"]) > float(best["score"])):
                        best = match
                if not best:
                    continue
                results.append(
                    {
                        "scope": "structure_fields",
                        "resultType": "structure_field",
                        "structure": str(struct.get("name", "")),
                        "field": str(component.get("name", "")),
                        "fieldType": str(component.get("type", "")),
                        "comment": str(component.get("comment", "")),
                        "offset": int(component.get("offset", 0)),
                        "length": int(component.get("length", 0)),
                        **best,
                    },
                )
        return results

    def _function_base_result(self, function: dict[str, Any]) -> dict[str, Any]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._function_base_result")
        return {
            "name": str(function.get("name", "")),
            "function": str(function.get("name", "")),
            "address": str(function.get("address", "")),
            "functionAddress": str(function.get("address", "")),
            "signature": str(function.get("signature", "")),
            "returnType": str(function.get("returnType", "")),
            "callingConvention": str(function.get("callingConvention", "")),
            "parameterCount": int(function.get("parameterCount", 0)),
            "size": int(function.get("size", 0)),
            "isExternal": bool(function.get("isExternal")),
            "isThunk": bool(function.get("isThunk")),
            "hasVarArgs": bool(function.get("hasVarArgs")),
            "parameters": function.get("parameters", []),
            "comments": function.get("comments", {}),
            "tags": function.get("tags", []),
            "callerCount": int(function.get("callerCount", 0)),
            "calleeCount": int(function.get("calleeCount", 0)),
        }

    def _attach_next_tools(self, row: dict[str, Any]) -> dict[str, Any]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._attach_next_tools")
        result_type: str = str(row.get("resultType", ""))
        address: str = str(row.get("functionAddress") or row.get("address") or "")
        function_name: str = str(row.get("function") or row.get("name") or "")

        next_tools: list[dict[str, Any]] = []
        if result_type == "function":
            next_tools = [
                {"tool": Tool.GET_FUNCTIONS.value, "args": {"identifier": function_name, "mode": "decompile"}},
                {"tool": Tool.GET_FUNCTION.value, "args": {"addressOrSymbol": address or function_name}},
                {"tool": Tool.GET_REFERENCES.value, "args": {"address": address, "mode": "to"}},
                {"tool": "manage-comments", "args": {"address": address, "mode": "get"}},
            ]
        elif result_type == "function_parameter":
            next_tools = [
                {"tool": Tool.GET_FUNCTIONS.value, "args": {"identifier": function_name}},
                {"tool": Tool.GET_FUNCTION.value, "args": {"addressOrSymbol": function_name}},
            ]
        elif result_type == "function_tag":
            next_tools = [{"tool": Tool.GET_FUNCTIONS.value, "args": {"mode": "tags", "tag": row.get("tag", "")}}]
        elif result_type in {"bookmark", "comment", "instruction", "export", "symbol", "string"}:
            next_tools = [
                {"tool": Tool.GET_FUNCTION.value, "args": {"addressOrSymbol": address}},
                {"tool": Tool.ANALYZE_DATA_FLOW.value, "args": {"addressOrSymbol": address}},
            ]
        elif result_type == "decompiled_code":
            next_tools = [
                {"tool": Tool.GET_FUNCTIONS.value, "args": {"identifier": function_name, "mode": "decompile"}},
                {"tool": Tool.GET_FUNCTION.value, "args": {"addressOrSymbol": address or function_name}},
            ]
        elif result_type == "import":
            next_tools = [
                {"tool": Tool.GET_REFERENCES.value, "args": {"mode": "import", "importName": row.get("name", "")}},
                {"tool": "list-imports", "args": {"query": row.get("name", "")}},
            ]
        elif result_type in {"namespace", "class"}:
            next_tools = [
                {"tool": Tool.GET_FUNCTIONS.value, "args": {"identifier": row.get("name", "")}},
                {"tool": Tool.SEARCH_EVERYTHING.value, "args": {"query": row.get("name", ""), "scopes": ["vtables"]}},
            ]
        elif result_type == "vtable":
            next_tools = [
                {"tool": Tool.GET_REFERENCES.value, "args": {"address": address, "mode": "to"}},
                {"tool": Tool.ANALYZE_VTABLES.value, "args": {"mode": "analyze", "addressOrSymbol": address}},
            ]
        elif result_type == "data_type":
            next_tools = [{"tool": "manage-data-types", "args": {"mode": "info", "dataTypeString": row.get("name", "")}}]
        elif result_type == "data_type_archive":
            next_tools = [{"tool": "manage-data-types", "args": {"mode": "archives"}}]
        elif result_type == "structure":
            next_tools = [{"tool": "manage-structures", "args": {"mode": "info", "name": row.get("name", "")}}]
        elif result_type == "structure_field":
            next_tools = [{"tool": "manage-structures", "args": {"mode": "info", "name": row.get("structure", "")}}]
        elif result_type == "constant":
            next_tools = [{"tool": "search-constants", "args": {"mode": "specific", "value": row.get("value", 0)}}]

        enriched = dict(row)
        enriched["nextTools"] = next_tools
        return enriched

    def _group_function_results(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._group_function_results")
        grouped: dict[tuple[str, str], dict[str, Any]] = {}
        remainder: list[dict[str, Any]] = []

        for row in rows:
            function_addr: str = str(row.get("functionAddress", "") or "")
            program: str = str(row.get("program", "") or "")
            if not function_addr:
                remainder.append(row)
                continue

            key: tuple[str, str] = (program, function_addr)
            if key not in grouped:
                grouped[key] = dict(row)
                grouped[key]["relatedResults"] = []
            else:
                cast("list[dict[str, Any]]", grouped[key]["relatedResults"]).append(
                    {
                        "scope": row.get("scope"),
                        "resultType": row.get("resultType"),
                        "query": row.get("query"),
                        "score": row.get("score"),
                        "matchType": row.get("matchType"),
                        "comment": row.get("comment"),
                        "commentType": row.get("commentType"),
                        "snippet": row.get("snippet"),
                        "instruction": row.get("instruction"),
                        "tag": row.get("tag"),
                        "parameter": row.get("parameter"),
                        "parameterType": row.get("parameterType"),
                    },
                )
                if float(row.get("score", 0.0)) > float(grouped[key].get("score", 0.0)):
                    base_related: list[dict[str, Any]] = cast("list[dict[str, Any]]", grouped[key].get("relatedResults", []))
                    grouped[key] = dict(row)
                    grouped[key]["relatedResults"] = base_related

        return [*grouped.values(), *remainder]

    def _search_processors(
        self,
        queries: list[str],
        mode: str,
        case_sensitive: bool,
        threshold: float,
        compiled_regexes: dict[str, re.Pattern[str]],
        per_scope_limit: int,
    ) -> list[dict[str, Any]]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._search_processors")
        results: list[dict[str, Any]] = []
        try:
            svc: GhidraDefaultLanguageService = GhidraDefaultLanguageService.getLanguageService()
            desc: GhidraLanguageDescription | None = None
            for desc in self._iter_items(svc.getLanguageDescriptions(False)):
                if desc is None:
                    continue
                if len(results) >= per_scope_limit:
                    break
                values: list[str] = [str(desc.getLanguageID()), str(cast("GhidraProcessor", desc.getProcessor()).toString()), str(desc.getDescription())]
                if not values:
                    continue
                best: dict[str, Any] | None = None
                for value in values:
                    match: dict[str, Any] | None = self._match_text(
                        text=value, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes
                    )
                    if match and (best is None or float(match["score"]) > float(best["score"])):
                        best = match
                if not best:
                    continue
                results.append(
                    {
                        "scope": "processors",
                        "languageId": str(desc.getLanguageID()),
                        "processor": str(desc.getProcessor().toString()),
                        "description": str(desc.getDescription()),
                        **best,
                    }
                )
        except Exception as e:
            logger.warning("Processor scope failed: %s", e)
        return results

    def _search_project_files(
        self,
        queries: list[str],
        mode: str,
        case_sensitive: bool,
        threshold: float,
        compiled_regexes: dict[str, re.Pattern[str]],
        per_scope_limit: int,
    ) -> list[dict[str, Any]]:
        logger.debug("diag.enter %s", "mcp_server/providers/search_everything.py:SearchEverythingToolProvider._search_project_files")
        results: list[dict[str, Any]] = []
        manager: ToolProviderManager | None = self._manager
        if manager is None:
            return results

        try:
            project_data: GhidraProjectData | None = manager._resolve_project_data()
        except Exception:
            project_data = None
        if project_data is None:
            return results

        try:
            root: GhidraDomainFolder | None = project_data.getRootFolder()
        except Exception:
            return results

        stack: list[GhidraDomainFolder] = [root]
        while stack and len(results) < per_scope_limit:
            folder: GhidraDomainFolder = stack.pop()
            try:
                domain_file: GhidraDomainFile | None = None
                for domain_file in self._iter_items(folder.getFiles() or []):
                    if domain_file is None:
                        continue
                    if len(results) >= per_scope_limit:
                        break
                    file_name: str = str(domain_file.getName())
                    file_path: str = str(domain_file.getPathname()) if hasattr(domain_file, "getPathname") else file_name
                    best: dict[str, Any] | None = None
                    for value in (file_name, file_path):
                        match: dict[str, Any] | None = self._match_text(
                            text=value, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes
                        )
                        if match and (best is None or float(match["score"]) > float(best["score"])):
                            best = match
                    if not best:
                        continue
                    results.append({"scope": "project_files", "name": file_name, "path": file_path, **best})

                for sub_folder in self._iter_items(folder.getFolders() or []):
                    stack.append(sub_folder)
            except Exception:
                continue

        return results
