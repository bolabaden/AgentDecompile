"""Universal search provider - search-everything.

Searches across string-bearing analysis data.
"""

from __future__ import annotations

import difflib
import logging
import re

from typing import Any

from mcp import types

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
)
from agentdecompile_cli.mcp_server.session_context import (
    SESSION_CONTEXTS,
    get_current_mcp_session_id,
)
from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    n,
)

logger = logging.getLogger(__name__)

_REGEX_HINT = re.compile(r"[\[\]\\(){}|*+?^$]")

# Detects patterns that look like file extensions (e.g., ".sav", ".exe", ".dll")
# where the dot should be treated literally, not as a regex wildcard.
_FILE_EXTENSION_PATTERN = re.compile(r"^\.[a-zA-Z0-9]{1,10}$")
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
    "structure_fields",  # structure field names/types/comments
    "structures",  # structure names/descriptions
    "symbols",  # all symbol names
)

_OPTIONAL_SCOPES: tuple[str, ...] = (
    "processors",
    "project_files",
)


class SearchEverythingToolProvider(ToolProvider):
    HANDLERS = {
        "searcheverything": "_handle",
        "globalsearch": "_handle",
        "searchanything": "_handle",
    }

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="search-everything",
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
                        "query": {"type": "string", "description": "Single search term or pattern. PREFER queries (array) over this when you have multiple terms — do NOT call this tool repeatedly with individual keywords."},
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
                        "limit": {"type": "integer", "default": 100, "description": "Total number of results to return across all scopes. Typical values are 100–500. Do not set this below 50 unless the user explicitly asks for only a handful of results."},
                        "offset": {"type": "integer", "default": 0, "description": "Pagination offset."},
                        "perScopeLimit": {"type": "integer", "default": 300, "description": "Number of matches per individual scope (e.g. functions, strings, comments). Typical values are 200–500. Do not reduce this below 100 unless you have a specific reason."},
                        "maxFunctionsScan": {"type": "integer", "default": 500, "description": "Number of functions to scan in expensive scopes (e.g. decompiled-code search). Typical values are 500–5000. Do not set this below 200 unless the binary is tiny or the user requests a quick scan."},
                        "maxInstructionsScan": {"type": "integer", "default": 200000, "description": "Number of assembly instructions to scan when searching disassembly. Typical values are 100 000–500 000. Do not set this below 50 000 unless the user explicitly wants a shallow scan."},
                        "decompileTimeout": {"type": "integer", "default": 10, "description": "Decompiler timeout (seconds) per function."},
                        "groupByFunction": {"type": "boolean", "default": True, "description": "When true, merges function-centric results into grouped entries."},
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        queries = self._collect_queries(args)
        if not queries:
            raise ValueError("query or queries is required")

        mode = self._get_str(args, "mode", "searchmode", default="auto")
        mode_n = n(mode)
        if mode_n not in {"auto", "literal", "regex", "fuzzy"}:
            raise ValueError("mode must be one of: auto, literal, regex, fuzzy")

        case_sensitive = self._get_bool(args, "casesensitive", default=False)
        threshold_raw = self._get(args, "similaritythreshold", "threshold", default=0.7)
        try:
            threshold = float(threshold_raw)
        except (TypeError, ValueError):
            threshold = 0.7
        threshold = max(0.0, min(1.0, threshold))

        offset, limit = self._get_pagination_params(args, default_limit=100)
        per_scope_limit = self._get_int(args, "perscopelimit", "scope_limit", default=300)
        max_functions_scan = self._get_int(args, "maxfunctionsscan", "maxfunctions", default=500)
        max_instructions_scan = self._get_int(args, "maxinstructionsscan", "maxinstructions", default=200000)
        decompile_timeout = self._get_int(args, "decompiletimeout", "timeout", default=10)
        group_by_function = self._get_bool(args, "groupbyfunction", default=True)
        scopes = self._collect_scopes(args)

        compiled = self._compile_regexes(queries, mode_n, case_sensitive)

        target_programs, target_warnings = await self._resolve_target_programs(args)
        if not target_programs:
            raise ValueError("No target programs found. Open a program, pass programPath/programName/binaryName, or ensure project programs are available.")

        all_results: list[dict[str, Any]] = []
        warnings: list[str] = list(target_warnings)

        for target in target_programs:
            program_key = str(target.get("programKey", ""))
            program = target.get("program")
            if program is None:
                continue
            for scope in scopes:
                try:
                    scoped = self._search_scope(
                        scope=scope,
                        program=program,
                        queries=queries,
                        mode=mode_n,
                        case_sensitive=case_sensitive,
                        threshold=threshold,
                        compiled_regexes=compiled,
                        per_scope_limit=per_scope_limit,
                        max_functions_scan=max_functions_scan,
                        max_instructions_scan=max_instructions_scan,
                        decompile_timeout=decompile_timeout,
                    )
                    for row in scoped:
                        row.setdefault("program", program_key)
                    all_results.extend(scoped)
                except Exception as e:
                    warnings.append(f"{program_key or '<active>'}:{scope}: {e}")

        all_results = [self._attach_next_tools(item) for item in all_results]
        if group_by_function:
            all_results = self._group_function_results(all_results)

        all_results.sort(key=lambda item: (float(item.get("score", 0.0)), str(item.get("scope", ""))), reverse=True)
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
            groupByFunction=group_by_function,
            warnings=warnings,
        )

    async def _resolve_target_programs(self, args: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
        warnings: list[str] = []
        requested_program_keys = self._collect_requested_program_keys(args)

        session_id = get_current_mcp_session_id()
        targets: list[dict[str, Any]] = []
        seen: set[str] = set()

        if requested_program_keys:
            for key in requested_program_keys:
                info = SESSION_CONTEXTS.get_program_info(session_id, key)
                if info is None and self._manager is not None:
                    try:
                        info = await self._manager._activate_requested_program(session_id, key)
                    except Exception as e:
                        warnings.append(f"program '{key}': {e}")
                if info is None or getattr(info, "program", None) is None:
                    warnings.append(f"program '{key}': not found")
                    continue
                name = str(key)
                if name in seen:
                    continue
                seen.add(name)
                targets.append({"programKey": name, "program": info.program})
            return targets, warnings

        # No explicit program target: search all programs in project if available.
        project_paths = self._collect_project_program_paths()
        if project_paths and self._manager is not None:
            for path in project_paths:
                info = SESSION_CONTEXTS.get_program_info(session_id, path)
                if info is None:
                    try:
                        info = await self._manager._activate_requested_program(session_id, path)
                    except Exception as e:
                        warnings.append(f"program '{path}': {e}")
                if info is None or getattr(info, "program", None) is None:
                    continue
                key = str(path)
                if key in seen:
                    continue
                seen.add(key)
                targets.append({"programKey": key, "program": info.program})

        if targets:
            return targets, warnings

        # Fallback to active session program.
        active_info = SESSION_CONTEXTS.get_active_program_info(session_id) or self.program_info
        if active_info is not None and getattr(active_info, "program", None) is not None:
            active_name = self._get_str(args, "programpath", "programname", "binaryname", default="<active>") or "<active>"
            targets.append({"programKey": active_name, "program": active_info.program})

        return targets, warnings

    def _collect_requested_program_keys(self, args: dict[str, Any]) -> list[str]:
        keys: list[str] = []

        for alias in ("programpath", "programname", "binaryname"):
            raw_list = self._get_list(args, alias)
            if raw_list:
                for value in raw_list:
                    if value is None:
                        continue
                    item = str(value).strip()
                    if item:
                        keys.append(item)

            raw_single = self._get(args, alias)
            if isinstance(raw_single, str):
                for part in raw_single.split(","):
                    item = part.strip()
                    if item:
                        keys.append(item)

        unique: list[str] = []
        seen: set[str] = set()
        for key in keys:
            nk = key.lower()
            if nk in seen:
                continue
            seen.add(nk)
            unique.append(key)
        return unique

    def _collect_project_program_paths(self) -> list[str]:
        manager = getattr(self, "_manager", None)
        if manager is None:
            return []

        project_data = None
        try:
            project_data = manager._resolve_project_data()
        except Exception:
            project_data = None
        if project_data is None:
            return []

        try:
            root = project_data.getRootFolder()
        except Exception:
            return []

        paths: list[str] = []
        stack = [root]
        while stack:
            folder = stack.pop()
            try:
                for domain_file in self._iter_items(folder.getFiles() or []):
                    pathname = ""
                    if hasattr(domain_file, "getPathname"):
                        pathname = str(domain_file.getPathname())
                    if not pathname:
                        pathname = str(domain_file.getName())
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
        queries: list[str] = []
        raw_list = self._get_list(args, "queries", "patterns", "terms") or []
        for value in raw_list:
            if isinstance(value, str) and value.strip():
                queries.append(value.strip())

        raw_queries_csv = self._get_str(args, "queries")
        if raw_queries_csv and not raw_list:
            for value in raw_queries_csv.split(","):
                if value.strip():
                    queries.append(value.strip())

        single = self._get_str(
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
            key = q if self._get_bool(args, "casesensitive", default=False) else q.lower()
            if key in seen:
                continue
            seen.add(key)
            unique.append(q)
        return unique

    def _collect_scopes(self, args: dict[str, Any]) -> list[str]:
        raw_scopes = self._get_list(args, "scopes", "scope", "domains", "sources", "types")
        if not raw_scopes:
            return list(_ALL_SCOPES)

        aliases = {
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
            key = aliases.get(n(str(scope)), "")
            if key == "all":
                return list(_ALL_SCOPES)
            if key and key not in resolved:
                resolved.append(key)

        return resolved or list(_ALL_SCOPES)

    def _compile_regexes(self, queries: list[str], mode: str, case_sensitive: bool) -> dict[str, re.Pattern[str]]:
        if mode not in {"regex", "auto"}:
            return {}

        flags = 0 if case_sensitive else re.IGNORECASE
        compiled: dict[str, re.Pattern[str]] = {}
        for q in queries:
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
        program: Any,
        queries: list[str],
        mode: str,
        case_sensitive: bool,
        threshold: float,
        compiled_regexes: dict[str, re.Pattern[str]],
        per_scope_limit: int,
        max_functions_scan: int,
        max_instructions_scan: int,
        decompile_timeout: int,
    ) -> list[dict[str, Any]]:
        if scope == "functions":
            return self._search_functions(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit)
        if scope == "function_signatures":
            return self._search_function_signatures(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit)
        if scope == "function_parameters":
            return self._search_function_parameters(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit)
        if scope == "function_tags":
            return self._search_tags(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit)
        if scope == "bookmarks":
            return self._search_bookmarks(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit)
        if scope == "comments":
            return self._search_comments(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit)
        if scope == "constants":
            return self._search_constants(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit, max_instructions_scan)
        if scope == "decompilation":
            return self._search_decompilation(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit, max_functions_scan, decompile_timeout)
        if scope == "disassembly":
            return self._search_disassembly(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit, max_functions_scan, max_instructions_scan)
        if scope == "symbols":
            return self._search_symbols(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit)
        if scope == "imports":
            return self._search_imports(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit)
        if scope == "exports":
            return self._search_exports(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit)
        if scope == "namespaces":
            return self._search_namespaces(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit)
        if scope == "classes":
            return self._search_classes(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit)
        if scope == "strings":
            return self._search_strings(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit)
        if scope == "data_types":
            return self._search_data_types(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit)
        if scope == "data_type_archives":
            return self._search_data_type_archives(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit)
        if scope == "structures":
            return self._search_structures(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit)
        if scope == "structure_fields":
            return self._search_structure_fields(program, queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit)
        if scope == "processors":
            return self._search_processors(queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit)
        if scope == "project_files":
            return self._search_project_files(queries, mode, case_sensitive, threshold, compiled_regexes, per_scope_limit)
        return []

    @staticmethod
    def _iter_items(source: Any):
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
        if not text:
            return None

        cmp_text = text if case_sensitive else text.lower()
        best: dict[str, Any] | None = None
        for q in queries:
            q_cmp = q if case_sensitive else q.lower()
            kind = "literal"
            score = 0.0
            matched = False

            pattern = compiled_regexes.get(q)
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
                similarity = difflib.SequenceMatcher(None, q_cmp, cmp_text).ratio()
                if similarity >= threshold:
                    matched = True
                    score = float(similarity)
                    kind = "fuzzy"

            if not matched:
                continue
            candidate = {"query": q, "score": score, "matchType": kind}
            if best is None or candidate["score"] > best["score"]:
                best = candidate

        return best

    def _search_functions(self, program: Any, queries: list[str], mode: str, case_sensitive: bool, threshold: float, compiled_regexes: dict[str, re.Pattern[str]], per_scope_limit: int) -> list[dict[str, Any]]:
        functions = collect_functions(program, limit=per_scope_limit)
        results: list[dict[str, Any]] = []
        for function in functions:
            match = self._match_text(text=str(function.get("name", "")), queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes)
            if not match:
                continue
            row = self._function_base_result(function)
            row.update({"scope": "functions", "resultType": "function", **match})
            results.append(row)
        return results

    def _search_function_signatures(self, program: Any, queries: list[str], mode: str, case_sensitive: bool, threshold: float, compiled_regexes: dict[str, re.Pattern[str]], per_scope_limit: int) -> list[dict[str, Any]]:
        functions = collect_functions(program, limit=per_scope_limit)
        results: list[dict[str, Any]] = []
        for function in functions:
            sig = str(function.get("signature", ""))
            match = self._match_text(text=sig, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes)
            if not match:
                continue
            row = self._function_base_result(function)
            row.update({"scope": "function_signatures", "resultType": "function", **match})
            results.append(row)
        return results

    def _search_function_parameters(self, program: Any, queries: list[str], mode: str, case_sensitive: bool, threshold: float, compiled_regexes: dict[str, re.Pattern[str]], per_scope_limit: int) -> list[dict[str, Any]]:
        functions = collect_functions(program, limit=per_scope_limit)
        results: list[dict[str, Any]] = []
        for function in functions:
            for param in list(function.get("parameters", [])):
                if len(results) >= per_scope_limit:
                    return results
                texts = [str(param.get("name", "") or ""), str(param.get("type", "") or "")]
                best: dict[str, Any] | None = None
                for txt in texts:
                    match = self._match_text(text=txt, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes)
                    if match and (best is None or float(match["score"]) > float(best["score"])):
                        best = match
                if not best:
                    continue
                row = self._function_base_result(function)
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

    def _search_tags(self, program: Any, queries: list[str], mode: str, case_sensitive: bool, threshold: float, compiled_regexes: dict[str, re.Pattern[str]], per_scope_limit: int) -> list[dict[str, Any]]:
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

    def _search_bookmarks(self, program: Any, queries: list[str], mode: str, case_sensitive: bool, threshold: float, compiled_regexes: dict[str, re.Pattern[str]], per_scope_limit: int) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for bm in collect_bookmarks(program, limit=per_scope_limit):
            if len(results) >= per_scope_limit:
                break
            candidates = [str(bm.get("comment", "")), str(bm.get("category", "")), str(bm.get("type", ""))]
            best: dict[str, Any] | None = None
            for field_text in candidates:
                match = self._match_text(text=field_text, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes)
                if match and (best is None or float(match["score"]) > float(best["score"])):
                    best = match
            if not best:
                continue
            results.append({"scope": "bookmarks", "resultType": "bookmark", "address": str(bm.get("address", "")), "type": str(bm.get("type", "")), "category": str(bm.get("category", "")), "comment": str(bm.get("comment", "")), **best})
        return results

    def _search_comments(self, program: Any, queries: list[str], mode: str, case_sensitive: bool, threshold: float, compiled_regexes: dict[str, re.Pattern[str]], per_scope_limit: int) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for comment in collect_comments(program, limit=per_scope_limit):
            if len(results) >= per_scope_limit:
                break
            comment_text = str(comment.get("comment", ""))
            match = self._match_text(text=comment_text, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes)
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

    def _search_constants(self, program: Any, queries: list[str], mode: str, case_sensitive: bool, threshold: float, compiled_regexes: dict[str, re.Pattern[str]], per_scope_limit: int, max_instructions_scan: int) -> list[dict[str, Any]]:
        constants, _instr_count = collect_constants(program, max_instructions=max_instructions_scan)
        results: list[dict[str, Any]] = []
        for item in constants:
            if len(results) >= per_scope_limit:
                break
            fields = [str(item.get("hex", "")), str(item.get("value", ""))]
            best: dict[str, Any] | None = None
            for text in fields:
                match = self._match_text(text=text, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes)
                if match and (best is None or float(match["score"]) > float(best["score"])):
                    best = match
            if not best:
                continue
            results.append({"scope": "constants", "resultType": "constant", "value": int(item.get("value", 0)), "hex": str(item.get("hex", "")), "occurrences": int(item.get("occurrences", 0)), "samples": item.get("samples", []), **best})
        return results

    def _search_decompilation(self, program: Any, queries: list[str], mode: str, case_sensitive: bool, threshold: float, compiled_regexes: dict[str, re.Pattern[str]], per_scope_limit: int, max_functions_scan: int, decompile_timeout: int) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        try:
            from ghidra.app.decompiler import DecompInterface, DecompileOptions  # pyright: ignore[reportMissingImports,reportMissingModuleSource]
            from ghidra.util.task import ConsoleTaskMonitor  # pyright: ignore[reportMissingImports,reportMissingModuleSource]

            fm = self._get_function_manager(program)
            decomp = DecompInterface()
            opts = DecompileOptions()
            opts.grabFromProgram(program)
            decomp.setOptions(opts)
            decomp.openProgram(program)
            monitor = ConsoleTaskMonitor()

            scanned = 0
            for func in fm.getFunctions(True):
                if scanned >= max_functions_scan or len(results) >= per_scope_limit:
                    break
                scanned += 1
                try:
                    dr = decomp.decompileFunction(func, decompile_timeout, monitor)
                    if not dr or not dr.decompileCompleted():
                        continue
                    decompiled = dr.getDecompiledFunction()
                    text = decompiled.getC() if decompiled else ""
                    match = self._match_text(text=str(text), queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes)
                    if not match:
                        continue
                    snippet = str(text)[:400]
                    results.append({"scope": "decompilation", "resultType": "decompiled_code", "function": str(func.getName()), "functionAddress": str(func.getEntryPoint()), "address": str(func.getEntryPoint()), "snippet": snippet, **match})
                except Exception:
                    continue
            decomp.dispose()
        except Exception as e:
            logger.warning(f"Decompilation scope failed: {e}")
        return results

    def _search_disassembly(self, program: Any, queries: list[str], mode: str, case_sensitive: bool, threshold: float, compiled_regexes: dict[str, re.Pattern[str]], per_scope_limit: int, max_functions_scan: int, max_instructions_scan: int) -> list[dict[str, Any]]:
        fm = self._get_function_manager(program)
        listing = self._get_listing(program)
        results: list[dict[str, Any]] = []
        function_count = 0
        instruction_count = 0

        for func in fm.getFunctions(True):
            if function_count >= max_functions_scan or len(results) >= per_scope_limit or instruction_count >= max_instructions_scan:
                break
            function_count += 1
            body = func.getBody()
            if not body:
                continue
            instructions = listing.getInstructions(body, True)
            for ins in self._iter_items(instructions):
                instruction_count += 1
                if len(results) >= per_scope_limit or instruction_count >= max_instructions_scan:
                    break
                text = str(ins)
                match = self._match_text(text=text, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes)
                if not match:
                    continue
                results.append({"scope": "disassembly", "resultType": "instruction", "function": str(func.getName()), "functionAddress": str(func.getEntryPoint()), "address": str(ins.getAddress()), "instruction": text, **match})
        return results

    def _search_symbols(self, program: Any, queries: list[str], mode: str, case_sensitive: bool, threshold: float, compiled_regexes: dict[str, re.Pattern[str]], per_scope_limit: int) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for sym in collect_symbols(program, limit=per_scope_limit):
            if len(results) >= per_scope_limit:
                break
            name = str(sym.get("name", ""))
            match = self._match_text(text=name, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes)
            if not match:
                continue
            results.append({"scope": "symbols", "resultType": "symbol", "name": name, "address": str(sym.get("address", "")), "symbolType": str(sym.get("symbolType", "")), "namespace": str(sym.get("namespace", "")), "source": str(sym.get("source", "")), **match})
        return results

    def _search_imports(self, program: Any, queries: list[str], mode: str, case_sensitive: bool, threshold: float, compiled_regexes: dict[str, re.Pattern[str]], per_scope_limit: int) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for sym in collect_imports(program, limit=per_scope_limit):
            if len(results) >= per_scope_limit:
                break
            name = str(sym.get("name", ""))
            match = self._match_text(text=name, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes)
            if not match:
                continue
            results.append({"scope": "imports", "resultType": "import", "name": name, "address": str(sym.get("address", "")), "namespace": str(sym.get("namespace", "")), "library": str(sym.get("library", "")), **match})
        return results

    def _search_exports(self, program: Any, queries: list[str], mode: str, case_sensitive: bool, threshold: float, compiled_regexes: dict[str, re.Pattern[str]], per_scope_limit: int) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for sym in collect_exports(program, limit=per_scope_limit):
            if len(results) >= per_scope_limit:
                break
            name = str(sym.get("name", ""))
            match = self._match_text(text=name, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes)
            if not match:
                continue
            results.append({"scope": "exports", "resultType": "export", "name": name, "address": str(sym.get("address", "")), "namespace": str(sym.get("namespace", "")), **match})
        return results

    def _search_namespaces(self, program: Any, queries: list[str], mode: str, case_sensitive: bool, threshold: float, compiled_regexes: dict[str, re.Pattern[str]], per_scope_limit: int) -> list[dict[str, Any]]:
        try:
            from ghidra.program.model.symbol import SymbolType  # pyright: ignore[reportMissingImports,reportMissingModuleSource]
        except Exception:
            return []
        results: list[dict[str, Any]] = []
        for sym in collect_symbols(program, symbol_type=SymbolType.NAMESPACE, limit=per_scope_limit):
            if len(results) >= per_scope_limit:
                break
            name = str(sym.get("name", ""))
            match = self._match_text(text=name, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes)
            if not match:
                continue
            results.append({"scope": "namespaces", "resultType": "namespace", "name": name, "address": str(sym.get("address", "")), **match})
        return results

    def _search_classes(self, program: Any, queries: list[str], mode: str, case_sensitive: bool, threshold: float, compiled_regexes: dict[str, re.Pattern[str]], per_scope_limit: int) -> list[dict[str, Any]]:
        try:
            from ghidra.program.model.symbol import SymbolType  # pyright: ignore[reportMissingImports,reportMissingModuleSource]
        except Exception:
            return []
        results: list[dict[str, Any]] = []
        for sym in collect_symbols(program, symbol_type=SymbolType.CLASS, limit=per_scope_limit):
            if len(results) >= per_scope_limit:
                break
            name = str(sym.get("name", ""))
            match = self._match_text(text=name, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes)
            if not match:
                continue
            results.append({"scope": "classes", "resultType": "class", "name": name, "address": str(sym.get("address", "")), "namespace": str(sym.get("namespace", "")), **match})
        return results

    def _search_strings(self, program: Any, queries: list[str], mode: str, case_sensitive: bool, threshold: float, compiled_regexes: dict[str, re.Pattern[str]], per_scope_limit: int) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for data in collect_strings(program, min_len=1, limit=per_scope_limit, ghidra_tools=self.ghidra_tools):
            if len(results) >= per_scope_limit:
                break
            value = str(data.get("value", ""))
            match = self._match_text(text=value, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes)
            if not match:
                continue
            results.append({"scope": "strings", "resultType": "string", "address": str(data.get("address", "")), "value": value, "length": int(data.get("length", len(value))), "dataType": str(data.get("dataType", "")), **match})
        return results

    def _search_data_types(self, program: Any, queries: list[str], mode: str, case_sensitive: bool, threshold: float, compiled_regexes: dict[str, re.Pattern[str]], per_scope_limit: int) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for dt in collect_data_types(program, limit=per_scope_limit):
            if len(results) >= per_scope_limit:
                break
            values = [str(dt.get("name", "")), str(dt.get("description", "")), str(dt.get("displayName", ""))]
            best: dict[str, Any] | None = None
            for value in values:
                match = self._match_text(text=value, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes)
                if match and (best is None or float(match["score"]) > float(best["score"])):
                    best = match
            if not best:
                continue
            results.append({"scope": "data_types", "resultType": "data_type", "name": str(dt.get("name", "")), "displayName": str(dt.get("displayName", "")), "categoryPath": str(dt.get("categoryPath", "")), "description": str(dt.get("description", "")), "length": int(dt.get("length", 0)), **best})
        return results

    def _search_data_type_archives(self, program: Any, queries: list[str], mode: str, case_sensitive: bool, threshold: float, compiled_regexes: dict[str, re.Pattern[str]], per_scope_limit: int) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for archive in collect_data_type_archives(program, limit=per_scope_limit):
            if len(results) >= per_scope_limit:
                break
            name = str(archive.get("name", ""))
            match = self._match_text(text=name, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes)
            if not match:
                continue
            results.append({"scope": "data_type_archives", "resultType": "data_type_archive", "name": name, "id": str(archive.get("id", "")), "type": str(archive.get("type", "")), "categoryCount": archive.get("categoryCount"), "dataTypeCount": archive.get("dataTypeCount"), **match})
        return results

    def _search_structures(self, program: Any, queries: list[str], mode: str, case_sensitive: bool, threshold: float, compiled_regexes: dict[str, re.Pattern[str]], per_scope_limit: int) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for struct in collect_structures(program, limit=per_scope_limit):
            if len(results) >= per_scope_limit:
                break
            values = [str(struct.get("name", "")), str(struct.get("description", ""))]
            best: dict[str, Any] | None = None
            for value in values:
                match = self._match_text(text=value, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes)
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
                }
            )
        return results

    def _search_structure_fields(self, program: Any, queries: list[str], mode: str, case_sensitive: bool, threshold: float, compiled_regexes: dict[str, re.Pattern[str]], per_scope_limit: int) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for struct in collect_structures(program):
            struct_obj = struct.get("structure")
            if struct_obj is None:
                continue
            for component in collect_structure_fields(struct_obj):
                if len(results) >= per_scope_limit:
                    return results
                values = [str(component.get("name", "")), str(component.get("comment", "")), str(component.get("type", ""))]
                best: dict[str, Any] | None = None
                for value in values:
                    match = self._match_text(text=value, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes)
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
                    }
                )
        return results

    def _function_base_result(self, function: dict[str, Any]) -> dict[str, Any]:
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
            "isExternal": bool(function.get("isExternal", False)),
            "isThunk": bool(function.get("isThunk", False)),
            "hasVarArgs": bool(function.get("hasVarArgs", False)),
            "parameters": function.get("parameters", []),
            "comments": function.get("comments", {}),
            "tags": function.get("tags", []),
            "callerCount": int(function.get("callerCount", 0)),
            "calleeCount": int(function.get("calleeCount", 0)),
        }

    def _attach_next_tools(self, row: dict[str, Any]) -> dict[str, Any]:
        result_type = str(row.get("resultType", ""))
        address = str(row.get("functionAddress") or row.get("address") or "")
        function_name = str(row.get("function") or row.get("name") or "")

        next_tools: list[dict[str, Any]] = []
        if result_type == "function":
            next_tools = [
                {"tool": "decompile-function", "args": {"name": function_name}},
                {"tool": "get-call-graph", "args": {"name": function_name, "mode": "graph"}},
                {"tool": "get-references", "args": {"address": address, "mode": "to"}},
                {"tool": "manage-comments", "args": {"address": address, "mode": "get"}},
            ]
        elif result_type == "function_parameter":
            next_tools = [
                {"tool": "decompile-function", "args": {"name": function_name}},
                {"tool": "manage-function", "args": {"name": function_name, "mode": "info"}},
            ]
        elif result_type == "function_tag":
            next_tools = [{"tool": "get-functions", "args": {"mode": "tags", "tag": row.get("tag", "")}}]
        elif result_type in {"bookmark", "comment", "instruction", "export", "symbol", "string"}:
            next_tools = [
                {"tool": "get-references", "args": {"address": address, "mode": "to"}},
                {"tool": "decompile-function", "args": {"address": address}},
            ]
        elif result_type == "decompiled_code":
            next_tools = [
                {"tool": "decompile-function", "args": {"name": function_name}},
                {"tool": "get-call-graph", "args": {"name": function_name, "mode": "graph"}},
            ]
        elif result_type == "import":
            next_tools = [
                {"tool": "get-references", "args": {"mode": "import", "importName": row.get("name", "")}},
                {"tool": "manage-symbols", "args": {"mode": "imports", "query": row.get("name", "")}},
            ]
        elif result_type in {"namespace", "class"}:
            next_tools = [{"tool": "manage-symbols", "args": {"mode": "symbols", "query": row.get("name", "")}}]
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
        grouped: dict[tuple[str, str], dict[str, Any]] = {}
        remainder: list[dict[str, Any]] = []

        for row in rows:
            function_addr = str(row.get("functionAddress", "") or "")
            program = str(row.get("program", "") or "")
            if not function_addr:
                remainder.append(row)
                continue

            key = (program, function_addr)
            if key not in grouped:
                grouped[key] = dict(row)
                grouped[key]["relatedResults"] = []
            else:
                grouped[key]["relatedResults"].append(
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
                    base_related = grouped[key].get("relatedResults", [])
                    grouped[key] = dict(row)
                    grouped[key]["relatedResults"] = base_related

        return [*grouped.values(), *remainder]

    def _search_processors(self, queries: list[str], mode: str, case_sensitive: bool, threshold: float, compiled_regexes: dict[str, re.Pattern[str]], per_scope_limit: int) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        try:
            from ghidra.program.util import DefaultLanguageService  # pyright: ignore[reportMissingImports,reportMissingModuleSource]

            svc = DefaultLanguageService.getLanguageService()
            for desc in self._iter_items(svc.getLanguageDescriptions(False)):
                if len(results) >= per_scope_limit:
                    break
                values = [str(desc.getLanguageID()), str(desc.getProcessor().toString()), str(desc.getDescription())]
                best: dict[str, Any] | None = None
                for value in values:
                    match = self._match_text(text=value, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes)
                    if match and (best is None or float(match["score"]) > float(best["score"])):
                        best = match
                if not best:
                    continue
                results.append({"scope": "processors", "languageId": str(desc.getLanguageID()), "processor": str(desc.getProcessor().toString()), "description": str(desc.getDescription()), **best})
        except Exception as e:
            logger.warning(f"Processor scope failed: {e}")
        return results

    def _search_project_files(self, queries: list[str], mode: str, case_sensitive: bool, threshold: float, compiled_regexes: dict[str, re.Pattern[str]], per_scope_limit: int) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        manager = getattr(self, "_manager", None)
        if manager is None:
            return results

        try:
            project_data = manager._resolve_project_data()
        except Exception:
            project_data = None
        if project_data is None:
            return results

        try:
            root = project_data.getRootFolder()
        except Exception:
            return results

        stack = [root]
        while stack and len(results) < per_scope_limit:
            folder = stack.pop()
            try:
                for domain_file in self._iter_items(folder.getFiles() or []):
                    if len(results) >= per_scope_limit:
                        break
                    file_name = str(domain_file.getName())
                    file_path = str(domain_file.getPathname()) if hasattr(domain_file, "getPathname") else file_name
                    best: dict[str, Any] | None = None
                    for value in (file_name, file_path):
                        match = self._match_text(text=value, queries=queries, mode=mode, case_sensitive=case_sensitive, threshold=threshold, compiled_regexes=compiled_regexes)
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
