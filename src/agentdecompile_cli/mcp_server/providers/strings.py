"""Strings Tool Provider - manage-strings.

Modes: list, search, count.
"""

from __future__ import annotations

import difflib
import logging
import re

from typing import Any

from mcp import types

from agentdecompile_cli.mcp_server.providers._collectors import collect_strings
from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
    n,
)

logger = logging.getLogger(__name__)


class StringToolProvider(ToolProvider):
    HANDLERS = {
        "managestrings": "_handle",
        "liststrings": "_handle_list_strings",
        "searchstrings": "_handle_search_strings",
        "searchcode": "_handle_search_code",
    }

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="manage-strings",
                description="Search, filter, list, and measure literal text strings embedded in the compiled program's data segments.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The active program project."},
                        "mode": {"type": "string", "description": "What operation to perform on the text data.", "enum": ["list", "search", "count"], "default": "list"},
                        "query": {"type": "string", "description": "Search query or regex pattern to look for in the program strings."},
                        "minLength": {"type": "integer", "default": 4, "description": "Ignore any text string shorter than this number of characters."},
                        "limit": {"type": "integer", "default": 100, "description": "Max results; omit to use default, only set if you need a different page size."},
                        "offset": {"type": "integer", "default": 0, "description": "Pagination offset; omit unless fetching beyond the first page."},
                        "includeReferencingFunctions": {"type": "boolean", "default": False, "description": "If true, also looks up what exact function uses this string (can be slow)."},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="list-strings",
                description="Dump all recognized text strings found in the current program's memory.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The active program project."},
                        "minLength": {"type": "integer", "default": 4, "description": "Ignore any text string shorter than this number of characters."},
                        "limit": {"type": "integer", "default": 100, "description": "Max results; omit to use default."},
                        "offset": {"type": "integer", "default": 0, "description": "Pagination offset; omit unless fetching beyond the first page."},
                        "includeReferencingFunctions": {"type": "boolean", "default": False, "description": "If true, identifies exactly which function references the text."},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="search-strings",
                description="Search the program's defined strings for a specific text pattern.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The active program project."},
                        "query": {"type": "string", "description": "The exact text or regex to find."},
                        "mode": {"type": "string", "description": "Internal routing fallback logic.", "enum": ["search", "list"], "default": "list"},
                        "limit": {"type": "integer", "default": 100, "description": "Omit and do not specify this in most cases."},
                        "offset": {"type": "integer", "default": 0, "description": "Pagination offset."},
                        "includeReferencingFunctions": {"type": "boolean", "default": False, "description": "Find referencing functions."},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="search-code",
                description="Scan all function names across the entire program looking for a specific text string.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The active program project."},
                        "binaryName": {"type": "string", "description": "Alternative parameter for programPath."},
                        "query": {"type": "string", "description": "The function name fragment to hunt for."},
                        "searchMode": {"type": "string", "description": "How to match the text against functions.", "enum": ["semantic", "literal"], "default": "semantic"},
                        "limit": {"type": "integer", "default": 10, "description": "Max results; omit to use default."},
                        "offset": {"type": "integer", "default": 0, "description": "Pagination offset."},
                    },
                    "required": ["query"],
                },
            ),
        ]

    async def _handle_list_strings(self, args: dict[str, Any]) -> list[types.TextContent]:
        updated = dict(args)
        updated["mode"] = "list"
        return await self._handle(updated)

    async def _handle_search_strings(self, args: dict[str, Any]) -> list[types.TextContent]:
        updated = dict(args)
        if not self._get_str(updated, "mode"):
            updated["mode"] = "search"
        return await self._handle(updated)

    async def _handle_search_code(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        query: str = self._require_str(args, "query", "pattern", "text", name="query")
        offset, limit = self._get_pagination_params(args, default_limit=10)
        mode: str = self._get_str(args, "searchmode", "mode", default="semantic")

        if self.ghidra_tools is not None:
            try:
                from agentdecompile_cli.models import SearchMode

                mode_norm: str = mode.strip().lower()
                search_mode = SearchMode.LITERAL if mode_norm == "literal" else SearchMode.SEMANTIC
                results = self.ghidra_tools.search_code(
                    query=query,
                    limit=limit,
                    offset=offset,
                    search_mode=search_mode,
                )
                if hasattr(results, "model_dump"):
                    return create_success_response(results.model_dump())
                return create_success_response({"query": query, "results": results})
            except Exception as e:
                logger.warning(f"search-code semantic/literal backend unavailable, using fallback search: {e}")

        assert self.program_info is not None, "Program info is required for search-code"
        program = self.program_info.program
        fm = self._get_function_manager(program)

        matches: list[dict[str, Any]] = []
        skipped = 0
        needle = query.lower()
        for func in fm.getFunctions(True):
            function_name = str(func.getName())
            if needle not in function_name.lower():
                continue
            if skipped < offset:
                skipped += 1
                continue
            if len(matches) >= limit:
                break
            matches.append(
                {
                    "function": function_name,
                    "address": str(func.getEntryPoint()),
                    "match": "name",
                },
            )

        return create_success_response(
            {
                "query": query,
                "searchMode": "literal-fallback",
                "returnedCount": len(matches),
                "offset": offset,
                "limit": limit,
                "results": matches,
            },
        )

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        mode = self._get_str(args, "mode", default="list")
        pattern = self._get_str(args, "pattern", "query", "search", "text", "regex", "searchstring", "filter")
        min_len = self._get_int(args, "minlength", "minlen", default=4)
        offset, max_results = self._get_pagination_params(args, default_limit=100)
        include_refs = self._get_bool(args, "includereferencingfunctions", "includerefs", default=False)

        # Collect strings using GhidraTools or direct API
        strings = self._collect_strings(min_len)

        return await self._dispatch_handler(
            args,
            mode,
            {
                "list": "_handle_list",
                "search": "_handle_search",
                "regex": "_handle_regex",
                "count": "_handle_count",
                "similarity": "_handle_search",
            },
            strings=strings,
            pattern=pattern,
            min_len=min_len,
            offset=offset,
            max_results=max_results,
            include_refs=include_refs,
        )

    def _collect_strings(self, min_len: int) -> list[dict[str, Any]]:
        """Collect all strings from the program using GhidraTools or direct API.

        Returns empty list if string enumeration is unavailable in the current context
        (e.g., shared-server checkout without iterator support). Diagnostics are logged.
        """
        assert self.program_info is not None, "Program info is required to collect strings"
        program = self.program_info.program
        strings = collect_strings(
            program,
            min_len=min_len,
            ghidra_tools=self.ghidra_tools,
        )

        # Add diagnostic if no strings were found - could indicate collection failure
        if not strings:
            import logging

            logger = logging.getLogger(__name__)
            logger.debug(
                "String collection returned empty results. This may indicate: (1) binary contains no strings, or (2) string iterators unavailable in current program context (shared-server/proxy mode).",
            )

        return strings

    async def _handle_list(
        self,
        args: dict[str, Any],
        strings: list[dict],
        pattern: str,
        min_len: int,
        offset: int,
        max_results: int,
        include_refs: bool,
    ) -> list[types.TextContent]:
        return self._filter_strings(strings, "list", "", min_len, max_results, offset, include_refs)

    async def _handle_regex(
        self,
        args: dict[str, Any],
        strings: list[dict],
        pattern: str,
        min_len: int,
        offset: int,
        max_results: int,
        include_refs: bool,
    ) -> list[types.TextContent]:
        return self._filter_strings(strings, "regex", pattern, min_len, max_results, offset, include_refs)

    async def _handle_search(
        self,
        args: dict[str, Any],
        strings: list[dict],
        pattern: str,
        min_len: int,
        offset: int,
        max_results: int,
        include_refs: bool,
    ) -> list[types.TextContent]:
        return self._filter_strings(strings, "search", pattern, min_len, max_results, offset, include_refs)

    async def _handle_count(
        self,
        args: dict[str, Any],
        strings: list[dict],
        pattern: str,
        min_len: int,
        offset: int,
        max_results: int,
        include_refs: bool,
    ) -> list[types.TextContent]:
        return self._filter_strings(strings, "count", pattern, min_len, max_results, offset, include_refs)

    def _filter_strings(
        self,
        strings: list[dict[str, Any]],
        mode: str,
        pattern: str,
        min_len: int,
        max_results: int,
        offset: int,
        include_refs: bool,
    ) -> list[types.TextContent]:
        """Filter and format strings based on search mode and pattern.

        Consolidates multiple string search/filtering pipelines (regex, fuzzy,
        substring) into a single method to reduce code duplication across list/search
        operations. Handles pagination separately from filtering.

        **Filtering Modes**:
        - count: Return total count only (no results)
        - search: Unified search mode (regex/literal/fuzzy heuristic)
        - literal (default): Substring match, case-insensitive

        **Performance Notes**:
        - Regex compilation happens once per call (not per-string)
        - Fuzzy mode uses SequenceMatcher scoring for ranking
        - Pagination happens after filtering to avoid over-iterating
        - Reference lookup is optional and only when explicitly requested

        Parameters
        ----------
        strings : list[dict]
            Input strings with address and value keys
        mode : str
            Filter mode: 'count', 'search', 'regex', or default (literal)
        pattern : str
            Search pattern/regex for filtering
        min_len : int
            Minimum string length to include (unused in this method; pre-filtered)
        max_results : int
            Maximum number of results to return after pagination
        offset : int
            Pagination offset
        include_refs : bool
            Whether to add referencing functions to each string result

        Returns:
        -------
        list[TextContent]
            Paginated response with filtered results
        """
        mode_n: str = n(mode)
        total: int = len(strings)

        if mode_n == "count":
            return create_success_response({"mode": "count", "totalStrings": len(strings)})

        if mode_n in {"search", "similarity"} and pattern:
            search_text = pattern.strip()
            regex_hint = bool(re.search(r"[\[\]\\(){}|*+?^$.]", search_text))
            if regex_hint:
                try:
                    pat = re.compile(search_text, re.IGNORECASE)
                    strings = [s for s in strings if pat.search(s.get("value", ""))]
                    total = len(strings)
                    strings, has_more = self._paginate_results(strings, offset, max_results)
                    return self._create_paginated_response(strings, offset, max_results, total=total, mode=mode)
                except re.error:
                    pass

            query_lower = search_text.lower()
            scored: list[tuple[float, dict[str, Any]]] = []
            for s in strings:
                val = str(s.get("value", ""))
                val_lower = val.lower()
                if query_lower in val_lower:
                    score = 1.0
                else:
                    score = difflib.SequenceMatcher(None, query_lower, val_lower).ratio()
                if score >= 0.6:
                    scored.append((score, s))

            scored.sort(key=lambda item: item[0], reverse=True)
            total = len(scored)
            strings = [s for _, s in scored]
            strings, has_more = self._paginate_results(strings, offset, max_results)
            return self._create_paginated_response(strings, offset, max_results, total=total, mode=mode)

        if mode_n == "regex" and pattern:
            try:
                pat = re.compile(pattern, re.IGNORECASE)
                strings = [s for s in strings if pat.search(s.get("value", ""))]
            except re.error as e:
                raise ValueError(f"Invalid regex pattern: {e.__class__}: {e}")

        elif pattern:
            p_lower = pattern.lower()
            strings = [s for s in strings if p_lower in str(s.get("value", "")).lower()]

        total: int = len(strings)

        strings, has_more = self._paginate_results(strings, offset, max_results)

        if include_refs and self.program_info:
            try:
                program: Any = self.program_info.program
                ref_mgr: Any = program.getReferenceManager()
                fm = self._get_function_manager(program)
                for s in strings:
                    try:
                        addr: Any = self._resolve_address(s["address"], program=program)
                        funcs = set()
                        ref_count = 0
                        for ref in ref_mgr.getReferencesTo(addr):
                            if ref_count >= 20:
                                break
                            ref_count += 1
                            f = fm.getFunctionContaining(ref.getFromAddress())
                            if f:
                                funcs.add(f.getName())
                        s["referencingFunctions"] = sorted(funcs)
                    except Exception:
                        pass
            except Exception:
                pass

        return self._create_paginated_response(strings, offset, max_results, total=total, mode=mode)
