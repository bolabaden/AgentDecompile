"""Symbol Tool Provider - manage-symbols, search-symbols, list-imports, list-exports, create-label.

- manage-symbols: mode = symbols|classes|namespaces|imports|exports|create_label|count|
  rename_data|demangle. List/search/rename symbols; filterDefaultNames skips auto-generated
  names like FUN_00101000.
- search-symbols (search-symbols-by-name): Query symbols by name/pattern.
- list-imports / list-exports: Aliases that delegate to manage-symbols with mode imports/exports.
- create-label: Alias for manage-symbols mode create_label.
"""

from __future__ import annotations

import logging
import re
import uuid

from pathlib import Path
from typing import TYPE_CHECKING, Any

from mcp import types

from agentdecompile_cli.mcp_server.providers._collectors import (
    collect_exports,
    collect_imports,
    collect_symbols,
    iter_items,
)
from agentdecompile_cli.mcp_server.session_context import SESSION_CONTEXTS, get_current_mcp_session_id
from agentdecompile_cli.mcp_server.tool_providers import (
    FORCE_APPLY_CONFLICT_ID_KEY,
    ToolProvider,
    create_conflict_response,
    create_success_response,
    n,
)
from agentdecompile_cli.mcp_utils.symbol_util import SymbolUtil
from agentdecompile_cli.registry import Tool

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from ghidra.framework.model import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        DomainFile as GhidraDomainFile,
        ProjectData as GhidraProjectData,
    )
    from ghidra.program.model.address import Address as GhidraAddress  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
    from ghidra.program.model.listing import Program as GhidraProgram  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
    from ghidra.program.model.symbol import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        Symbol as GhidraSymbol,
        SymbolTable as GhidraSymbolTable,
    )


logger = logging.getLogger(__name__)

# Default name filter for auto-generated symbols
_DEFAULT_NAME_RE = re.compile(r"^(FUN|LAB|SUB|DAT|EXT|PTR|ARRAY)_[0-9a-fA-F]+$")


class SymbolToolProvider(ToolProvider):
    HANDLERS = {
        "createlabel": "_handle_create_label_alias",
        "listexports": "_handle_list_exports_alias",
        "listimports": "_handle_list_imports_alias",
        "managesymbols": "_handle",
        "searchsymbols": "_handle_search",
        "searchsymbolsbyname": "_handle_search",
    }

    def list_tools(self) -> list[types.Tool]:
        logger.debug("diag.enter %s", "mcp_server/providers/symbols.py:SymbolToolProvider.list_tools")
        base_manage_schema: dict[str, Any] = {
            "type": "object",
            "properties": {
                "programPath": {
                    "type": "string",
                    "description": "The active program project.",
                },
                "mode": {
                    "type": "string",
                    "enum": [
                        "symbols",
                        "classes",
                        "namespaces",
                        "imports",
                        "exports",
                        "create_label",
                        "count",
                        "rename_data",
                        "demangle",
                    ],
                    "default": "symbols",
                    "description": "What operation to perform regarding symbols (names assigned to addresses).",
                },
                "query": {
                    "type": "string",
                    "description": "Regex pattern or exact text to find matching labels.",
                },
                "addressOrSymbol": {
                    "type": "string",
                    "description": "The hex memory address or existing symbol name you want to interact with.",
                },
                "labelName": {
                    "type": "string",
                    "description": "The new label name to apply (if creating/renaming).",
                },
                "newName": {
                    "type": "string",
                    "description": "Alternative parameter for labelName.",
                },
                "filterDefaultNames": {
                    "type": "boolean",
                    "default": True,
                    "description": "Ignore auto-generated messy labels like 'FUN_00101000'.",
                },
                "limit": {
                    "type": "integer",
                    "default": 100,
                    "description": "Number of symbols to return. Typical values are 100\u2013500.",
                },
                "offset": {
                    "type": "integer",
                    "default": 0,
                    "description": "Pagination offset.",
                },
            },
            "required": [],
        }

        return [
            types.Tool(
                name=Tool.MANAGE_SYMBOLS.value,
                description="Central utility to search, rename, count, and categorize all programmatic labels (symbols, imports, exports) in the program.",
                inputSchema=base_manage_schema,
            ),
            types.Tool(
                name="search-symbols-by-name",
                description="Look up a list of program symbols by matching parts of their names.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {
                            "type": "string",
                            "description": "The active program project.",
                        },
                        "query": {"type": "string", "description": "Regex or substring to match text."},
                        "namePattern": {"type": "string", "description": "Alternative parameter for query."},
                        "limit": {
                            "type": "integer",
                            "default": 100,
                            "description": "Number of symbols to return. Typical values are 100\u2013500.",
                        },
                        "offset": {"type": "integer", "default": 0, "description": "Pagination offset."},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name=Tool.SEARCH_SYMBOLS.value,
                description="Look up a list of program symbols by matching parts of their names.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The active program project."},
                        "query": {"type": "string", "description": "Regex or substring to match text."},
                        "namePattern": {"type": "string", "description": "Alternative parameter for query."},
                        "limit": {
                            "type": "integer",
                            "default": 100,
                            "description": "Number of symbols to return. Typical values are 100\u2013500.",
                        },
                        "offset": {"type": "integer", "default": 0, "description": "Pagination offset."},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name=Tool.LIST_IMPORTS.value,
                description="Retrieve a list of all external library functions the program loads to function.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The active program project."},
                        "limit": {
                            "type": "integer",
                            "default": 100,
                            "description": "Number of imports to return. Typical values are 100\u2013500.",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name=Tool.LIST_EXPORTS.value,
                description="Retrieve a list of all internal library functions the program exposes for others to use.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The active program project."},
                        "limit": {
                            "type": "integer",
                            "default": 100,
                            "description": "Number of exports to return. Typical values are 100\u2013500.",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name=Tool.CREATE_LABEL.value,
                description="Slap a custom string tag (label) onto a specific memory address.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The active program project."},
                        "addressOrSymbol": {"type": "string", "description": "Where to place the label (hex address)."},
                        "labelName": {"type": "string", "description": "The text tag to apply."},
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle_mode_alias(self, args: dict[str, Any], mode: str) -> list[types.TextContent]:
        """Forward to _handle with mode preset (helper for alias dispatch).

        Consolidates the repeated pattern of:
            1. Copy args
            2. Set default mode
            3. Call _handle()

        This pattern appears in _handle_list_imports_alias and _handle_list_exports_alias.
        By factoring out this common flow, we:
            - Reduce duplication by 6+ lines per alias handler
            - Make the mode dispatch intention explicit in handler names
            - Enable future alias handlers to reuse this pattern

        Args:
            args: Original arguments from caller
            mode: Mode to forward (imports, exports, etc.)

        Returns:
            Result from _handle() after setting mode
        """
        logger.debug("diag.enter %s", "mcp_server/providers/symbols.py:SymbolToolProvider._handle_mode_alias")
        forwarded_args = dict(args)
        forwarded_args.setdefault("mode", mode)
        return await self._handle(forwarded_args)

    async def _handle_list_imports_alias(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/symbols.py:SymbolToolProvider._handle_list_imports_alias")
        return await self._handle_mode_alias(args, "imports")

    async def _handle_list_exports_alias(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/symbols.py:SymbolToolProvider._handle_list_exports_alias")
        return await self._handle_mode_alias(args, "exports")

    async def _handle_create_label_alias(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/symbols.py:SymbolToolProvider._handle_create_label_alias")
        return await self._create_label(args)

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Dispatch to mode-specific handler.

        Modes: symbols, classes, namespaces, imports, exports, create_label, count, rename_data, demangle.
        Uses normalized mode string (lowercase a-z only) to select handler function.
        """
        logger.debug("diag.enter %s", "mcp_server/providers/symbols.py:SymbolToolProvider._handle")
        self._require_program()
        mode = self._get_str(args, "mode", "action", "operation", default="symbols")

        # Dispatch table: mode → handler function.
        # Each handler is responsible for its own validation and error handling.
        dispatch: dict[str, Callable[[dict[str, Any]], Coroutine[Any, Any, list[types.TextContent]]]] = {
            "symbols": self._list_symbols,
            "classes": self._list_classes,
            "namespaces": self._list_namespaces,
            "imports": self._list_imports,
            "exports": self._list_exports,
            "createlabel": self._create_label,
            "count": self._count,
            "renamedata": self._rename_data,
            "demangle": self._demangle,
        }
        handler = self._dispatch_handler(dispatch, mode, "mode")
        return await handler(args)

    async def _handle_search(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Search for symbols by name pattern across the program.

        Consolidates symbol search operations to find matching function/variable names
        across the entire program. Supports both GhidraTools semantic search (if available)
        and fallback to direct symbol iteration via Ghidra API. Results are paginated to
        handle large programs efficiently.

        Parameters
        ----------
        query : str
            Name pattern to search for (case-insensitive substring match)
        offset : int, default=0
            Pagination start offset
        maxresults/limit : int, default=100
            Maximum number of results to return

        Returns:
        -------
        list[TextContent]
            Paginated response with matching symbols, count, total, and hasMore flag

        Examples:
        --------
        >>> await provider._handle_search({"query": "malloc", "limit": 10})
        [TextContent(text='{"mode":"symbols","results":[...],"count":10,"total":42,"hasMore":true}')]
        """
        logger.debug("diag.enter %s", "mcp_server/providers/symbols.py:SymbolToolProvider._handle_search")
        self._require_program()
        query: str = self._get_str(args, "query", "namepattern", "pattern", "search", "name")
        offset, max_results = self._get_pagination_params(args, default_limit=100)

        def _rows_to_dicts(rows: list[Any]) -> list[dict[str, Any]]:
            out: list[dict[str, Any]] = []
            for r in rows:
                if isinstance(r, dict):
                    out.append(dict(r))
                elif hasattr(r, "model_dump"):
                    out.append(r.model_dump())
                else:
                    out.append(
                        {
                            "name": str(getattr(r, "name", "")),
                            "address": str(getattr(r, "address", "")),
                            "type": str(getattr(r, "type", "")),
                            "namespace": str(getattr(r, "namespace", "") or ""),
                            "source": str(getattr(r, "source", "") or ""),
                        },
                    )
            return out

        # Prefer GhidraTools when it returns matches. On empty (common for some shared-server /
        # iterator edge cases), fall through to a full symbol-table scan — same substring semantics
        # as GhidraTools.search_symbols_by_name (documented: case-insensitive substring).
        # Queries containing '_' (e.g. LFG `sh_<runId>_`): GhidraTools.search_symbols_by_name can return a
        # **non-empty but incomplete** subset; early return then drops labels (strict /lfg step 5/7/11).
        if self.ghidra_tools and "_" not in query:
            try:
                gt_rows = self.ghidra_tools.search_symbols_by_name(query)
                gt_dicts = _rows_to_dicts(list(gt_rows))
                if gt_dicts:
                    paginated, _has_more = self._paginate_results(gt_dicts, offset, max_results)
                    return self._create_paginated_response(
                        paginated,
                        offset,
                        max_results,
                        total=len(gt_dicts),
                        query=query,
                    )
            except Exception:
                logger.debug("search-symbols GhidraTools path failed; using symbol table scan", exc_info=True)

        # Direct API: iterate all symbols (includes labels) with substring match
        assert self.program_info is not None  # for type checker
        program: GhidraProgram = self.program_info.program
        qnorm = query.strip().lower() if query else ""

        # Ghidra native query iterator (substring/pattern); works when bulk getAllSymbols iterators are empty (JPype/shared).
        st: GhidraSymbolTable = program.getSymbolTable()
        if qnorm:
            sym_it = None
            # Ghidra's getSymbolIterator(String, caseSensitive) matches the query with wildcard rules where '_'
            # is often a single-character wildcard; LFG / agent queries like sh_<runId>_ then return the wrong
            # set or nothing while substring search over the full table would find user labels.
            if "_" not in query:
                try:
                    sym_it = st.getSymbolIterator(query, False)
                except Exception:
                    sym_it = None
                    logger.debug("search-symbols getSymbolIterator(query) failed", exc_info=True)
            if sym_it is not None:
                by_query: list[dict[str, Any]] = []
                for sym in iter_items(sym_it):
                    name = str(sym.getName())
                    if qnorm not in name.lower():
                        continue
                    by_query.append(
                        {
                            "name": name,
                            "address": str(sym.getAddress()),
                            "type": str(sym.getSymbolType()),
                            "namespace": str(sym.getParentNamespace()),
                            "source": str(sym.getSource()),
                        },
                    )
                if by_query:
                    paginated, _has_more = self._paginate_results(by_query, offset, max_results)
                    return self._create_paginated_response(
                        paginated,
                        offset,
                        max_results,
                        total=len(by_query),
                        query=query,
                        mode="search",
                    )

        all_symbols = collect_symbols(program)

        # Queries containing '_': merge collect_symbols matches with getDefinedSymbols (USER labels).
        # Bulk getAllSymbols scans can omit user labels on some shared-server checkouts while
        # getDefinedSymbols still lists create-label symbols (/lfg step 5 after MCP restart).
        if qnorm and "_" in query:

            def _row_from_collect_dict(sym: dict[str, Any]) -> dict[str, Any]:
                return {
                    "name": str(sym.get("name", "")),
                    "address": str(sym.get("address", "")),
                    "type": str(sym.get("symbolType", "")),
                    "namespace": str(sym.get("namespace", "")),
                    "source": str(sym.get("source", "")),
                }

            def _row_from_java_symbol(sym: Any) -> dict[str, Any]:
                name = str(sym.getName(True))
                return {
                    "name": name,
                    "address": str(sym.getAddress()),
                    "type": str(sym.getSymbolType()),
                    "namespace": str(sym.getParentNamespace()),
                    "source": str(sym.getSource()),
                }

            all_matches: list[dict[str, Any]] = []
            seen_keys: set[tuple[str, str]] = set()
            for sym in all_symbols:
                row = _row_from_collect_dict(sym)
                nl = row["name"].lower()
                if qnorm not in nl:
                    continue
                key = (row["address"], nl)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                all_matches.append(row)

            if hasattr(st, "getDefinedSymbols"):
                try:
                    for sym in iter_items(st.getDefinedSymbols()):
                        row = _row_from_java_symbol(sym)
                        if qnorm not in row["name"].lower():
                            continue
                        key = (row["address"], row["name"].lower())
                        if key in seen_keys:
                            continue
                        seen_keys.add(key)
                        all_matches.append(row)
                except Exception:
                    logger.debug("search-symbols underscore-query getDefinedSymbols merge failed", exc_info=True)

            if not all_matches and hasattr(st, "getSymbolIterator"):
                try:
                    bare_it = st.getSymbolIterator()
                    for sym in iter_items(bare_it):
                        row = _row_from_java_symbol(sym)
                        if qnorm not in row["name"].lower():
                            continue
                        key = (row["address"], row["name"].lower())
                        if key in seen_keys:
                            continue
                        seen_keys.add(key)
                        all_matches.append(row)
                except Exception:
                    logger.debug("search-symbols underscore-query bare iterator failed", exc_info=True)

            paginated_u, _hm_u = self._paginate_results(all_matches, offset, max_results)
            return self._create_paginated_response(
                paginated_u,
                offset,
                max_results,
                total=len(all_matches),
                query=query,
                mode="search",
            )

        results: list[dict[str, Any]] = []
        count: int = 0

        for sym in all_symbols:
            name = str(sym.get("name", ""))
            if qnorm and qnorm not in name.lower():
                continue
            if count < offset:
                count += 1
                continue
            if len(results) >= max_results:
                count += 1
                continue
            results.append(
                {
                    "name": name,
                    "address": str(sym.get("address", "")),
                    "type": str(sym.get("symbolType", "")),
                    "namespace": str(sym.get("namespace", "")),
                    "source": str(sym.get("source", "")),
                },
            )
            count += 1

        # Shared-server / JPype: getAllSymbols can return many entries yet omit user labels; collect_symbols
        # then skips getDefinedSymbols because the primary list was non-empty. Scan defined symbols for
        # substring matches when the filtered set is empty (LFG step 5/7/11 search-symbols).
        if qnorm and len(results) == 0 and hasattr(st, "getDefinedSymbols"):
            try:
                defined_rows: list[dict[str, Any]] = []
                for sym in iter_items(st.getDefinedSymbols()):
                    name = str(sym.getName(True))
                    if qnorm not in name.lower():
                        continue
                    defined_rows.append(
                        {
                            "name": name,
                            "address": str(sym.getAddress()),
                            "type": str(sym.getSymbolType()),
                            "namespace": str(sym.getParentNamespace()),
                            "source": str(sym.getSource()),
                        },
                    )
                if defined_rows:
                    paginated, _has_more = self._paginate_results(defined_rows, offset, max_results)
                    return self._create_paginated_response(
                        paginated,
                        offset,
                        max_results,
                        total=len(defined_rows),
                        query=query,
                        mode="search",
                    )
            except Exception:
                logger.debug("search-symbols getDefinedSymbols substring fallback failed", exc_info=True)

        if qnorm and len(results) == 0 and hasattr(st, "getSymbolIterator"):
            try:
                label_rows: list[dict[str, Any]] = []
                # No-arg iterator: Ghidra API — "Get all label symbols" (memory labels; matches createLabel).
                bare_it = st.getSymbolIterator()
                for sym in iter_items(bare_it):
                    name = str(sym.getName(True))
                    if qnorm not in name.lower():
                        continue
                    label_rows.append(
                        {
                            "name": name,
                            "address": str(sym.getAddress()),
                            "type": str(sym.getSymbolType()),
                            "namespace": str(sym.getParentNamespace()),
                            "source": str(sym.getSource()),
                        },
                    )
                if label_rows:
                    paginated, _has_more = self._paginate_results(label_rows, offset, max_results)
                    return self._create_paginated_response(
                        paginated,
                        offset,
                        max_results,
                        total=len(label_rows),
                        query=query,
                        mode="search",
                    )
            except Exception:
                logger.debug("search-symbols getSymbolIterator() label fallback failed", exc_info=True)

        return create_success_response(
            {
                "query": query,
                "results": results,
                "count": len(results),
                "totalMatched": count,
                "hasMore": count > offset + len(results),
            },
        )

    async def _list_symbols(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/symbols.py:SymbolToolProvider._list_symbols")
        query = self._get_str(args, "query", "pattern", "search")
        filter_default = self._get_bool(args, "filterdefaultnames", default=True)
        offset, max_results = self._get_pagination_params(args, default_limit=100)

        # Try GhidraTools
        if self.ghidra_tools:
            try:
                all_syms = self.ghidra_tools.get_all_symbols()
                if filter_default:
                    all_syms = [s for s in all_syms if not _DEFAULT_NAME_RE.match(s.get("name", ""))]
                if query:
                    pat = re.compile(query, re.IGNORECASE)
                    all_syms = [s for s in all_syms if pat.search(s.get("name", ""))]
                paginated, has_more = self._paginate_results(all_syms, offset, max_results)
                return self._create_paginated_response(paginated, offset, max_results, total=len(all_syms), mode="symbols")
            except Exception:
                pass

        return await self._handle_search(args)

    async def _list_classes(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/symbols.py:SymbolToolProvider._list_classes")
        assert self.program_info is not None  # for type checker
        program: GhidraProgram = self.program_info.program
        st: GhidraSymbolTable = self._get_symbol_table(program)
        max_results: int | None = self._get_int(args, "maxresults", "limit", default=100)

        from ghidra.program.model.symbol import SymbolType as GhidraSymbolType  # pyright: ignore[reportMissingModuleSource]

        classes: list[dict[str, Any]] = []
        for sym in st.getAllSymbols(True):
            if sym.getSymbolType() == GhidraSymbolType.CLASS:
                classes.append({"name": sym.getName(), "address": str(sym.getAddress()), "namespace": str(sym.getParentNamespace())})
                if max_results is not None and len(classes) >= max_results:
                    break
        return create_success_response({"mode": "classes", "results": classes, "count": len(classes)})

    async def _list_namespaces(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/symbols.py:SymbolToolProvider._list_namespaces")
        assert self.program_info is not None  # for type checker
        program: GhidraProgram = self.program_info.program
        st: GhidraSymbolTable = self._get_symbol_table(program)
        max_results: int | None = self._get_int(args, "maxresults", "limit", default=100)

        from ghidra.program.model.symbol import SymbolType as GhidraSymbolType  # pyright: ignore[reportMissingModuleSource]

        namespaces: list[dict[str, Any]] = []
        for sym in st.getAllSymbols(True):
            if sym.getSymbolType() == GhidraSymbolType.NAMESPACE:
                namespaces.append({"name": sym.getName(), "address": str(sym.getAddress())})
                if max_results is not None and len(namespaces) >= max_results:
                    break
        return create_success_response({"mode": "namespaces", "results": namespaces, "count": len(namespaces)})

    async def _list_imports(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/symbols.py:SymbolToolProvider._list_imports")
        self._require_program()
        offset, max_results = self._get_pagination_params(args)

        if self.ghidra_tools:
            try:
                imports = self.ghidra_tools.list_imports()
                paginated, has_more = self._paginate_results(imports, offset, max_results)
                return self._create_paginated_response(paginated, offset, max_results, total=len(imports), mode="imports")
            except Exception:
                pass

        assert self.program_info is not None  # for type checker
        program: GhidraProgram = self.program_info.program
        imports = collect_imports(program)
        paginated, has_more = self._paginate_results(imports, offset, max_results)
        return self._create_paginated_response(paginated, offset, max_results, total=len(imports), mode="imports")

    async def _list_exports(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/symbols.py:SymbolToolProvider._list_exports")
        self._require_program()
        offset, max_results = self._get_pagination_params(args)

        if self.ghidra_tools:
            try:
                exports = self.ghidra_tools.list_exports()
                paginated, has_more = self._paginate_results(exports, offset, max_results)
                return self._create_paginated_response(paginated, offset, max_results, total=len(exports), mode="exports")
            except Exception:
                pass

        assert self.program_info is not None  # for type checker
        program: GhidraProgram = self.program_info.program
        exports = [{"name": row.get("name", ""), "address": row.get("address", "")} for row in collect_exports(program)]
        paginated, has_more = self._paginate_results(exports, offset, max_results)
        return self._create_paginated_response(paginated, offset, max_results, total=len(exports), mode="exports")

    def _iter_domain_files_for_versioned_notify(self, program: GhidraProgram, program_path: str | None) -> list[GhidraDomainFile]:
        """Unique DomainFiles for checkout metadata: open Program + path-resolved (match ProjectToolProvider._resolve_domain_file)."""
        logger.debug("diag.enter %s", "mcp_server/providers/symbols.py:SymbolToolProvider._iter_domain_files_for_versioned_notify")
        seen: set[int] = set()
        out: list[GhidraDomainFile] = []

        def add(df: GhidraDomainFile) -> None:
            if df is None:
                return
            try:
                oid = id(df)
                if oid in seen:
                    return
                seen.add(oid)
                out.append(df)
            except Exception:
                return

        path = (program_path or "").strip()
        if not path and self.program_info is not None:
            pi_path = getattr(self.program_info, "path", None) or getattr(self.program_info, "file_path", None)
            if pi_path is not None:
                path = str(pi_path).strip()
        path_candidates: list[str] = []
        if path:
            path_candidates = [path]
            if not path.startswith("/"):
                path_candidates.append(f"/{path}")

        pdf0: GhidraDomainFile | None = None
        try:
            pdf0 = program.getDomainFile()
            add(pdf0)
        except Exception:
            pass

        mgr = self._manager

        def add_from_project_data(project_data: GhidraProjectData) -> None:
            if project_data is None or not path_candidates:
                return
            for cand in path_candidates:
                try:
                    df2 = project_data.getFile(cand)
                except Exception:
                    df2 = None
                if df2 is not None:
                    add(df2)
                    return
            file_name = Path(path.replace("\\", "/")).name
            if file_name and mgr is not None:
                try:
                    root = project_data.getRootFolder()
                    add(mgr._find_domain_file_by_name(root, file_name))
                except Exception:
                    pass

        # Shared-server: correct ProjectData often comes from the open Program's DomainFile, not GhidraProject.getProjectData().
        if pdf0 is not None:
            try:
                add_from_project_data(pdf0.getProjectData())
            except Exception:
                pass
        if mgr is not None:
            add_from_project_data(mgr._resolve_project_data())
        return out

    def _notify_versioned_checkout_after_program_edit(self, program: GhidraProgram, program_path: str | None = None) -> None:
        """Align shared checkout metadata with symbol/label edits (same hooks as versioned check-in path)."""
        logger.debug("diag.enter %s", "mcp_server/providers/symbols.py:SymbolToolProvider._notify_versioned_checkout_after_program_edit")
        if program is None:
            return
        try:
            from agentdecompile_cli.mcp_server.providers.import_export import (
                ImportExportToolProvider as _ImportExport,
            )
            from agentdecompile_cli.mcp_server.session_context import (
                SESSION_CONTEXTS,
                get_current_mcp_session_id,
                is_shared_server_handle,
            )

            sid = get_current_mcp_session_id()
            sess = SESSION_CONTEXTS.get_or_create(sid)
            handle = sess.project_handle if isinstance(sess.project_handle, dict) else None
            shared_server = bool(handle and is_shared_server_handle(handle))
            # Shared Ghidra Server: symbol/label edits must reach the versioned DomainFile backing store
            # before checkin-program runs; otherwise checkin sees "not modified" and follow-up reopen uploads
            # revisions without user labels (LFG shared persistence / search-symbols empty).
            # Do not gate on DomainFile.isVersioned(): PyGhidra sometimes reports false even for server checkouts.
            if shared_server and self._manager is not None:
                iep = None
                for pr in getattr(self._manager, "providers", None) or []:
                    if hasattr(pr, "_persist_open_program_for_versioned_checkin"):
                        iep = pr
                        break
                if iep is not None:
                    iep._persist_open_program_for_versioned_checkin(program)

            _ImportExport._force_domain_object_changed_for_versioned_checkin(program)
            for df in self._iter_domain_files_for_versioned_notify(program, program_path):
                _ImportExport._try_mark_versioned_checkout_dirty(df)
                _ImportExport._notify_domain_file_changed_for_versioned_checkin(df, program)
                if hasattr(df, "getParent"):
                    par = df.getParent()
                    if par is not None and hasattr(par, "fileChanged"):
                        try:
                            par.fileChanged()
                        except Exception:
                            pass
            # Local-only: avoid GhidraProject.save here — see checkin-program / import_export batch-tx notes.
            _ImportExport._force_domain_object_changed_for_versioned_checkin(program)
        except Exception as exc:
            logger.debug("notify_versioned_checkout_after_program_edit: %s", exc)

    @staticmethod
    def _touch_listing_for_shared_checkin(program: GhidraProgram) -> None:
        """Bookmark bump in the same transaction as symbol edits so VC sees a listing change."""
        try:
            mem = program.getMemory()
            if mem is None:
                return
            addr = mem.getMinAddress()
            if addr is None:
                return
            bmm = program.getBookmarkManager()
            if bmm is None:
                return
            bmm.setBookmark(addr, "Note", "AgentDecompile", "agentdecompile_vc_checkin_bump")
        except Exception:
            pass

    def _record_pending_versioned_label(self, program_path_hint: str | None, addr: str, name: str) -> None:
        """Session backup for versioned check-in reopen when symbol-table snapshots miss USER labels."""
        sid = get_current_mcp_session_id()
        pp = (program_path_hint or "").strip()
        if not pp:
            pp = (SESSION_CONTEXTS.get_or_create(sid).active_program_key or "").strip()
        if pp:
            SESSION_CONTEXTS.record_pending_versioned_label(sid, pp, addr, name)

    async def _create_label(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/symbols.py:SymbolToolProvider._create_label")
        addr_str = self._require_str(args, "addressorsymbol", "address", "addr", name="addressOrSymbol")
        label = self._require_str(args, "labelname", "label", "name", name="labelName")

        assert self.program_info is not None  # for type checker
        program: GhidraProgram = self.program_info.program
        from ghidra.program.model.symbol import SourceType as GhidraSourceType  # pyright: ignore[reportMissingModuleSource]

        label_pp = (self._get_str(args, "programpath", "binary", "path") or "").strip() or None

        # Batch support
        addr_list = self._get_list(args, "addressorsymbol", "addresses")
        label_list = self._get_list(args, "labelname", "labels")
        if addr_list and label_list and len(addr_list) > 1:
            results = []
            st: GhidraSymbolTable = self._get_symbol_table(program)

            def _create_labels_batch() -> None:
                for a, l in zip(addr_list, label_list):  # noqa: E741
                    try:
                        addr = self._resolve_address(str(a), program=program)
                        st.createLabel(addr, str(l), GhidraSourceType.USER_DEFINED)
                        results.append({"address": str(addr), "label": str(l), "success": True})
                        self._record_pending_versioned_label(label_pp, str(addr), str(l))
                    except Exception as e:
                        results.append({"address": str(a), "label": str(l), "success": False, "error": str(e)})
                self._touch_listing_for_shared_checkin(program)

            self._run_program_transaction(program, "batch-create-labels", _create_labels_batch)
            self._notify_versioned_checkout_after_program_edit(program, label_pp)
            return create_success_response({"mode": "create_label", "batch": True, "results": results})

        addr: GhidraAddress = self._resolve_address(addr_str, program=program)
        st: GhidraSymbolTable = self._get_symbol_table(program)

        # Force-apply path: skip conflict check when re-invoked from resolve-modification-conflict
        if not args.get(FORCE_APPLY_CONFLICT_ID_KEY):
            sym_at_addr: GhidraSymbol | None = st.getPrimarySymbol(addr)
            if sym_at_addr is not None:
                from agentdecompile_cli.mcp_server.conflict_store import store as conflict_store_store

                conflict_id = str(uuid.uuid4())
                existing_name = sym_at_addr.getName()
                conflict_summary = f"Create label would conflict with existing symbol at address:\n\n```diff\n- (existing) {existing_name}\n+ {label}\n```"
                next_step = f'To apply this change, call `resolve-modification-conflict` with `conflictId` = "{conflict_id}" and `resolution` = "overwrite". To discard, use `resolution` = "skip".'
                program_path = args.get(n("programPath")) or getattr(self.program_info, "path", None) or getattr(self.program_info, "file_path", None)
                program_path_str = str(program_path) if program_path is not None else None
                store_args = dict(args)
                store_args["mode"] = "create_label"
                conflict_store_store(
                    get_current_mcp_session_id(),
                    conflict_id,
                    tool=Tool.MANAGE_SYMBOLS.value,
                    arguments=store_args,
                    program_path=program_path_str,
                    summary=conflict_summary,
                )
                return create_conflict_response(conflict_id, Tool.MANAGE_SYMBOLS.value, conflict_summary, next_step)

        def _create_label_single() -> None:
            st.createLabel(addr, label, GhidraSourceType.USER_DEFINED)
            self._touch_listing_for_shared_checkin(program)

        self._run_program_transaction(program, "create-label", _create_label_single)
        self._notify_versioned_checkout_after_program_edit(program, label_pp)
        self._record_pending_versioned_label(label_pp, str(addr), str(label))
        return create_success_response({"mode": "create_label", "address": str(addr), "label": label, "success": True})

    async def _count(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/symbols.py:SymbolToolProvider._count")
        assert self.program_info is not None  # for type checker
        program: GhidraProgram = self.program_info.program
        st: GhidraSymbolTable = self._get_symbol_table(program)
        return create_success_response({"mode": "count", "totalSymbols": st.getNumSymbols()})

    async def _rename_data(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/symbols.py:SymbolToolProvider._rename_data")
        addr_str = self._require_str(args, "addressorsymbol", "address", "addr", name="addressOrSymbol")
        new_name = self._require_str(args, "newname", "name", "labelname", name="newName")

        assert self.program_info is not None  # for type checker
        program: GhidraProgram = self.program_info.program
        from ghidra.program.model.symbol import SourceType as GhidraSourceType  # pyright: ignore[reportMissingModuleSource]

        addr: GhidraAddress = self._resolve_address(addr_str, program=program)
        st: GhidraSymbolTable = self._get_symbol_table(program)
        sym: GhidraSymbol | None = st.getPrimarySymbol(addr)
        if sym is None:
            raise ValueError(f"No symbol at {addr_str}")

        # Force-apply path: resolve-modification-conflict re-invoked with this set; skip conflict check
        if args.get(FORCE_APPLY_CONFLICT_ID_KEY):

            def _rename_symbol() -> None:
                sym.setName(new_name, GhidraSourceType.USER_DEFINED)

            self._run_program_transaction(program, "rename-data", _rename_symbol)
            return create_success_response({"mode": "rename_data", "address": str(addr), "newName": new_name, "success": True})

        current_name = sym.getName()
        if SymbolUtil.is_default_symbol_name(current_name):
            # Auto-generated name; no conflict, apply immediately
            def _rename_symbol() -> None:
                sym.setName(new_name, GhidraSourceType.USER_DEFINED)

            self._run_program_transaction(program, "rename-data", _rename_symbol)
            return create_success_response({"mode": "rename_data", "address": str(addr), "newName": new_name, "success": True})

        # Custom name would be overwritten; two-step conflict
        from agentdecompile_cli.mcp_server.conflict_store import store as conflict_store_store
        from agentdecompile_cli.mcp_server.session_context import get_current_mcp_session_id

        conflict_id = str(uuid.uuid4())
        conflict_summary = f"Rename would overwrite existing custom symbol name:\n\n```diff\n- {current_name}\n+ {new_name}\n```"
        next_step = f'To apply this change, call `resolve-modification-conflict` with `conflictId` = "{conflict_id}" and `resolution` = "overwrite". To discard, use `resolution` = "skip".'
        program_path = args.get(n("programPath")) or getattr(self.program_info, "path", None) or getattr(self.program_info, "file_path", None)
        program_path_str = str(program_path) if program_path is not None else None
        conflict_store_store(
            get_current_mcp_session_id(),
            conflict_id,
            tool=Tool.MANAGE_SYMBOLS.value,
            arguments=dict(args),
            program_path=program_path_str,
            summary=conflict_summary,
        )
        return create_conflict_response(conflict_id, Tool.MANAGE_SYMBOLS.value, conflict_summary, next_step)

    async def _demangle(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/symbols.py:SymbolToolProvider._demangle")
        query: str = self._get_str(args, "query", "symbol", "name", "addressorsymbol")
        max_results: int = self._get_int(args, "maxresults", "limit", default=100)  # pyright: ignore[reportAssignmentType]

        assert self.program_info is not None  # for type checker
        program: GhidraProgram = self.program_info.program
        results: list[dict[str, Any]] = []

        try:
            from ghidra.app.util.demangler import DemanglerUtil as GhidraDemanglerUtil  # pyright: ignore[reportMissingModuleSource]

            st: GhidraSymbolTable = self._get_symbol_table(program)
            for sym in st.getAllSymbols(True):
                if len(results) >= max_results:
                    break
                name = sym.getName()
                if query and query.lower() not in name.lower():
                    continue
                try:
                    demangled = GhidraDemanglerUtil.demangle(program, name)
                    if demangled:
                        results.append(
                            {
                                "original": name,
                                "demangled": str(demangled),
                                "address": str(sym.getAddress()),
                            },
                        )
                except Exception:
                    continue
        except ImportError:
            return create_success_response({"mode": "demangle", "note": "DemanglerUtil not available", "results": []})

        return create_success_response({"mode": "demangle", "results": results, "count": len(results)})
