"""Strings Tool Provider - manage-strings.

Modes: list, regex, count, similarity.
"""

from __future__ import annotations

import logging
import re
import heapq

from typing import Any

from mcp import types

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
                description="Search and manage string data in the program",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "mode": {"type": "string", "enum": ["list", "regex", "count", "similarity"], "default": "list"},
                        "query": {"type": "string", "description": "Search query or regex pattern"},
                        "minLength": {"type": "integer", "default": 4},
                        "limit": {"type": "integer", "default": 100},
                        "offset": {"type": "integer", "default": 0},
                        "includeReferencingFunctions": {"type": "boolean", "default": False},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="list-strings",
                description="List strings (alias for manage-strings mode=list)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "minLength": {"type": "integer", "default": 4},
                        "limit": {"type": "integer", "default": 100},
                        "offset": {"type": "integer", "default": 0},
                        "includeReferencingFunctions": {"type": "boolean", "default": False},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="search-strings",
                description="Search strings (alias for manage-strings mode=regex/similarity/list)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "query": {"type": "string"},
                        "mode": {"type": "string", "enum": ["regex", "similarity", "list"], "default": "list"},
                        "limit": {"type": "integer", "default": 100},
                        "offset": {"type": "integer", "default": 0},
                        "includeReferencingFunctions": {"type": "boolean", "default": False},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="search-code",
                description="Search code using semantic/literal strategies (falls back to function-name literal search when semantic index is unavailable)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "binaryName": {"type": "string"},
                        "query": {"type": "string"},
                        "searchMode": {"type": "string", "enum": ["semantic", "literal"], "default": "semantic"},
                        "limit": {"type": "integer", "default": 10},
                        "offset": {"type": "integer", "default": 0},
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
            updated["mode"] = "list"
        return await self._handle(updated)

    async def _handle_search_code(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        query = self._require_str(args, "query", "pattern", "text", name="query")
        offset, limit = self._get_pagination_params(args, default_limit=10)
        mode = self._get_str(args, "searchmode", "mode", default="semantic")

        if self.ghidra_tools is not None:
            try:
                from agentdecompile_cli.models import SearchMode

                mode_norm = mode.strip().lower()
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

        program = self.program_info.program
        fm = self._get_function_manager(program)

        matches = []
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

        return await self._dispatch_handler(args, mode, {
            "list": "_handle_list",
            "regex": "_handle_regex", 
            "count": "_handle_count",
            "similarity": "_handle_similarity",
        }, strings=strings, pattern=pattern, min_len=min_len, offset=offset, max_results=max_results, include_refs=include_refs)

    def _collect_strings(self, min_len: int) -> list[dict]:
        """Collect all strings from the program using GhidraTools or direct API."""
        # Try GhidraTools first
        if self.ghidra_tools is not None:
            try:
                return self.ghidra_tools.get_all_strings()
            except Exception as e:
                logger.warning(f"GhidraTools.get_all_strings failed: {e}")

        # Direct Ghidra API
        program = self.program_info.program
        strings = []
        try:
            from ghidra.program.util import DefinedDataIterator

            for data in DefinedDataIterator.definedStrings(program):
                val = str(data.getValue()) if data.getValue() else ""
                if len(val) < min_len:
                    continue
                strings.append(
                    {
                        "address": str(data.getAddress()),
                        "value": val,
                        "length": len(val),
                        "dataType": str(data.getDataType()),
                    },
                )
        except Exception as e:
            logger.warning(f"String iteration error: {e}")

        return strings

    async def _handle_list(self, args: dict[str, Any], strings: list[dict], pattern: str, min_len: int, offset: int, max_results: int, include_refs: bool) -> list[types.TextContent]:
        return self._filter_strings(strings, "list", "", min_len, max_results, offset, include_refs)

    async def _handle_regex(self, args: dict[str, Any], strings: list[dict], pattern: str, min_len: int, offset: int, max_results: int, include_refs: bool) -> list[types.TextContent]:
        return self._filter_strings(strings, "regex", pattern, min_len, max_results, offset, include_refs)

    async def _handle_count(self, args: dict[str, Any], strings: list[dict], pattern: str, min_len: int, offset: int, max_results: int, include_refs: bool) -> list[types.TextContent]:
        return self._filter_strings(strings, "count", pattern, min_len, max_results, offset, include_refs)

    async def _handle_similarity(self, args: dict[str, Any], strings: list[dict], pattern: str, min_len: int, offset: int, max_results: int, include_refs: bool) -> list[types.TextContent]:
        return self._filter_strings(strings, "similarity", pattern, min_len, max_results, offset, include_refs)

    def _filter_strings(self, strings: list, mode: str, pattern: str, min_len: int, max_results: int, offset: int, include_refs: bool) -> list[types.TextContent]:
        """Filter and format strings based on search mode and pattern.
        
        Consolidates multiple string search/filtering pipelines (regex, similarity,
        substring) into a single method to reduce code duplication across list/search
        operations. Handles pagination separately from filtering.
        
        **Filtering Modes**:
        - count: Return total count only (no results)
        - regex: Match pattern as regex expression (case-insensitive)
        - similarity: Score matches by query length / result length, rank by score
        - literal (default): Substring match, case-insensitive
        
        **Similarity Scoring**: Used for fuzzy matching where shorter matches score
        higher than longer matches containing the query. Example:
            query="str" in "string" → score=0.33 (3/9)
            query="str" in "str" → score=1.0 (3/3)
        
        **Performance Notes**:
        - Regex compilation happens once per call (not per-string)
        - Similarity mode uses heapq.nlargest for efficient top-k selection
        - Pagination happens after filtering to avoid over-iterating
        - Reference lookup is optional and only when explicitly requested
        
        Parameters
        ----------
        strings : list[dict]
            Input strings with address and value keys
        mode : str
            Filter mode: 'count', 'regex', 'similarity', or default (literal)
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
            
        Returns
        -------
        list[TextContent]
            Paginated response with filtered results
        """
        mode_n = n(mode)
        total = len(strings)

        if mode_n == "count":
            return create_success_response({"mode": "count", "totalStrings": len(strings)})

        if mode_n == "regex" and pattern:
            try:
                pat = re.compile(pattern, re.IGNORECASE)
                strings = [s for s in strings if pat.search(s.get("value", ""))]
            except re.error as e:
                raise ValueError(f"Invalid regex pattern: {e}")

        elif mode_n == "similarity" and pattern:
            query_lower = pattern.lower()
            scored = []
            top_k = max(offset + max_results, 1)
            for s in strings:
                val = s.get("value", "").lower()
                if query_lower in val:
                    score = len(query_lower) / max(len(val), 1)
                    scored.append((score, s))

            total = len(scored)
            ranked = heapq.nlargest(top_k, scored, key=lambda item: item[0])
            strings = [s for _, s in ranked]

        elif pattern:
            p_lower = pattern.lower()
            strings = [s for s in strings if p_lower in s.get("value", "").lower()]

        if mode_n != "similarity" or not pattern:
            total = len(strings)
        
        strings, has_more = self._paginate_results(strings, offset, max_results)

        if include_refs and self.program_info:
            try:
                program = self.program_info.program
                ref_mgr = program.getReferenceManager()
                fm = self._get_function_manager(program)
                for s in strings:
                    try:
                        addr = self._resolve_address(s["address"], program=program)
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
