"""Symbol Tool Provider - manage-symbols, search-symbols-by-name.

Modes: symbols, classes, namespaces, imports, exports, create_label, count, rename_data, demangle.
"""

from __future__ import annotations

import logging
import re

from collections.abc import Callable, Coroutine
from typing import Any

from mcp import types

from agentdecompile_cli.mcp_server.providers._collectors import (
    collect_exports,
    collect_imports,
    collect_symbols,
)
from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
)

logger = logging.getLogger(__name__)

# Default name filter for auto-generated symbols
_DEFAULT_NAME_RE = re.compile(r"^(FUN|LAB|SUB|DAT|EXT|PTR|ARRAY)_[0-9a-fA-F]+$")


class SymbolToolProvider(ToolProvider):
    HANDLERS = {
        "managesymbols": "_handle",
        "searchsymbolsbyname": "_handle_search",
        "searchsymbols": "_handle_search",
        "listimports": "_handle_list_imports_alias",
        "listexports": "_handle_list_exports_alias",
        "createlabel": "_handle_create_label_alias",
    }

    def list_tools(self) -> list[types.Tool]:
        base_manage_schema = {
            "type": "object",
            "properties": {
                "programPath": {"type": "string", "description": "The active program project."},
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
                "query": {"type": "string", "description": "Regex pattern or exact text to find matching labels."},
                "addressOrSymbol": {"type": "string", "description": "The hex memory address or existing symbol name you want to interact with."},
                "labelName": {"type": "string", "description": "The new label name to apply (if creating/renaming)."},
                "newName": {"type": "string", "description": "Alternative parameter for labelName."},
                "filterDefaultNames": {"type": "boolean", "default": True, "description": "Ignore auto-generated messy labels like 'FUN_00101000'."},
                "limit": {"type": "integer", "default": 100, "description": "Number of symbols to return. Typical values are 100\u2013500. Do not set this below 50 unless the user explicitly asks for only a handful of results."},
                "offset": {"type": "integer", "default": 0, "description": "Pagination offset."},
            },
            "required": [],
        }

        return [
            types.Tool(
                name="manage-symbols",
                description="Central utility to search, rename, count, and categorize all programmatic labels (symbols, imports, exports) in the program.",
                inputSchema=base_manage_schema,
            ),
            types.Tool(
                name="search-symbols-by-name",
                description="Look up a list of program symbols by matching parts of their names.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The active program project."},
                        "query": {"type": "string", "description": "Regex or substring to match text."},
                        "namePattern": {"type": "string", "description": "Alternative parameter for query."},
                        "limit": {"type": "integer", "default": 100, "description": "Number of symbols to return. Typical values are 100\u2013500. Do not set this below 50 unless the user explicitly asks for only a handful of results."},
                        "offset": {"type": "integer", "default": 0, "description": "Pagination offset."},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="search-symbols",
                description="Look up a list of program symbols by matching parts of their names.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The active program project."},
                        "query": {"type": "string", "description": "Regex or substring to match text."},
                        "namePattern": {"type": "string", "description": "Alternative parameter for query."},
                        "limit": {"type": "integer", "default": 100, "description": "Number of symbols to return. Typical values are 100\u2013500. Do not set this below 50 unless the user explicitly asks for only a handful of results."},
                        "offset": {"type": "integer", "default": 0, "description": "Pagination offset."},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="list-imports",
                description="Retrieve a list of all external library functions the program loads to function.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The active program project."},
                        "limit": {"type": "integer", "default": 100, "description": "Number of imports to return. Typical values are 100\u2013500. Do not set this below 50 unless the user explicitly asks for only a handful of results."},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="list-exports",
                description="Retrieve a list of all internal library functions the program exposes for others to use.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The active program project."},
                        "limit": {"type": "integer", "default": 100, "description": "Number of exports to return. Typical values are 100\u2013500. Do not set this below 50 unless the user explicitly asks for only a handful of results."},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="create-label",
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
        forwarded_args = dict(args)
        forwarded_args.setdefault("mode", mode)
        return await self._handle(forwarded_args)

    async def _handle_list_imports_alias(self, args: dict[str, Any]) -> list[types.TextContent]:
        return await self._handle_mode_alias(args, "imports")

    async def _handle_list_exports_alias(self, args: dict[str, Any]) -> list[types.TextContent]:
        return await self._handle_mode_alias(args, "exports")

    async def _handle_create_label_alias(self, args: dict[str, Any]) -> list[types.TextContent]:
        return await self._create_label(args)

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Dispatch to mode-specific handler.

        Modes: symbols, classes, namespaces, imports, exports, create_label, count, rename_data, demangle.
        Uses normalized mode string (lowercase a-z only) to select handler function.
        """
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
        self._require_program()
        query: str = self._get_str(args, "query", "namepattern", "pattern", "search", "name")
        offset, max_results = self._get_pagination_params(args, default_limit=100)

        # Try GhidraTools
        if self.ghidra_tools:
            try:
                results: list[dict[str, Any]] = self.ghidra_tools.search_symbols_by_name(query)
                paginated, has_more = self._paginate_results(results, offset, max_results)
                return self._create_paginated_response(paginated, offset, max_results, total=len(results), query=query)
            except Exception:
                pass

        # Direct API
        assert self.program_info is not None  # for type checker
        program: Any = self.program_info.program
        all_symbols = collect_symbols(program)
        results: list[dict[str, Any]] = []
        count: int = 0

        pat = re.compile(query, re.IGNORECASE) if query else None
        for sym in all_symbols:
            name = str(sym.get("name", ""))
            if pat and not pat.search(name):
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
        assert self.program_info is not None  # for type checker
        program: Any = self.program_info.program
        st: Any = self._get_symbol_table(program)
        max_results: int = self._get_int(args, "maxresults", "limit", default=100)

        from ghidra.program.model.symbol import SymbolType  # pyright: ignore[reportMissingModuleSource]

        classes: list[dict[str, Any]] = []
        for sym in st.getAllSymbols(True):
            if sym.getSymbolType() == SymbolType.CLASS:
                classes.append({"name": sym.getName(), "address": str(sym.getAddress()), "namespace": str(sym.getParentNamespace())})
                if len(classes) >= max_results:
                    break
        return create_success_response({"mode": "classes", "results": classes, "count": len(classes)})

    async def _list_namespaces(self, args: dict[str, Any]) -> list[types.TextContent]:
        assert self.program_info is not None  # for type checker
        program: Any = self.program_info.program
        st: Any = self._get_symbol_table(program)
        max_results: int = self._get_int(args, "maxresults", "limit", default=100)

        from ghidra.program.model.symbol import SymbolType  # pyright: ignore[reportMissingModuleSource]

        namespaces: list[dict[str, Any]] = []
        for sym in st.getAllSymbols(True):
            if sym.getSymbolType() == SymbolType.NAMESPACE:
                namespaces.append({"name": sym.getName(), "address": str(sym.getAddress())})
                if len(namespaces) >= max_results:
                    break
        return create_success_response({"mode": "namespaces", "results": namespaces, "count": len(namespaces)})

    async def _list_imports(self, args: dict[str, Any]) -> list[types.TextContent]:
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
        program: Any = self.program_info.program
        imports = collect_imports(program)
        paginated, has_more = self._paginate_results(imports, offset, max_results)
        return self._create_paginated_response(paginated, offset, max_results, total=len(imports), mode="imports")

    async def _list_exports(self, args: dict[str, Any]) -> list[types.TextContent]:
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
        program: Any = self.program_info.program
        exports = [{"name": row.get("name", ""), "address": row.get("address", "")} for row in collect_exports(program)]
        paginated, has_more = self._paginate_results(exports, offset, max_results)
        return self._create_paginated_response(paginated, offset, max_results, total=len(exports), mode="exports")

    async def _create_label(self, args: dict[str, Any]) -> list[types.TextContent]:
        addr_str = self._require_str(args, "addressorsymbol", "address", "addr", name="addressOrSymbol")
        label = self._require_str(args, "labelname", "label", "name", name="labelName")

        assert self.program_info is not None  # for type checker
        program: Any = self.program_info.program
        from ghidra.program.model.symbol import SourceType  # pyright: ignore[reportMissingModuleSource]

        # Batch support
        addr_list = self._get_list(args, "addressorsymbol", "addresses")
        label_list = self._get_list(args, "labelname", "labels")
        if addr_list and label_list and len(addr_list) > 1:
            results = []
            st = self._get_symbol_table(program)

            def _create_labels_batch() -> None:
                for a, l in zip(addr_list, label_list):  # noqa: E741
                    try:
                        addr = self._resolve_address(str(a), program=program)
                        st.createLabel(addr, str(l), SourceType.USER_DEFINED)
                        results.append({"address": str(addr), "label": str(l), "success": True})
                    except Exception as e:
                        results.append({"address": str(a), "label": str(l), "success": False, "error": str(e)})

            self._run_program_transaction(program, "batch-create-labels", _create_labels_batch)
            return create_success_response({"mode": "create_label", "batch": True, "results": results})

        addr: Any = self._resolve_address(addr_str, program=program)
        st = self._get_symbol_table(program)

        def _create_label_single() -> None:
            st.createLabel(addr, label, SourceType.USER_DEFINED)

        self._run_program_transaction(program, "create-label", _create_label_single)
        return create_success_response({"mode": "create_label", "address": str(addr), "label": label, "success": True})

    async def _count(self, args: dict[str, Any]) -> list[types.TextContent]:
        assert self.program_info is not None  # for type checker
        program: Any = self.program_info.program
        st: Any = self._get_symbol_table(program)
        return create_success_response({"mode": "count", "totalSymbols": st.getNumSymbols()})

    async def _rename_data(self, args: dict[str, Any]) -> list[types.TextContent]:
        addr_str = self._require_str(args, "addressorsymbol", "address", "addr", name="addressOrSymbol")
        new_name = self._require_str(args, "newname", "name", "labelname", name="newName")

        assert self.program_info is not None  # for type checker
        program: Any = self.program_info.program
        from ghidra.program.model.symbol import SourceType  # pyright: ignore[reportMissingModuleSource]

        addr: Any = self._resolve_address(addr_str, program=program)
        st: Any = self._get_symbol_table(program)
        sym: Any = st.getPrimarySymbol(addr)
        if sym is None:
            raise ValueError(f"No symbol at {addr_str}")

        def _rename_symbol() -> None:
            sym.setName(new_name, SourceType.USER_DEFINED)

        self._run_program_transaction(program, "rename-data", _rename_symbol)
        return create_success_response({"mode": "rename_data", "address": str(addr), "newName": new_name, "success": True})

    async def _demangle(self, args: dict[str, Any]) -> list[types.TextContent]:
        query: str = self._get_str(args, "query", "symbol", "name", "addressorsymbol")
        max_results: int = self._get_int(args, "maxresults", "limit", default=100)

        assert self.program_info is not None  # for type checker
        program: Any = self.program_info.program
        results: list[dict[str, Any]] = []

        try:
            from ghidra.app.util.demangler import DemanglerUtil  # pyright: ignore[reportMissingModuleSource]

            st: Any = self._get_symbol_table(program)
            for sym in st.getAllSymbols(True):
                if len(results) >= max_results:
                    break
                name = sym.getName()
                if query and query.lower() not in name.lower():
                    continue
                try:
                    demangled = DemanglerUtil.demangle(program, name)
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
