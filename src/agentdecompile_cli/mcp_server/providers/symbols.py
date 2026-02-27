"""Symbol Tool Provider - manage-symbols, search-symbols-by-name.

Modes: symbols, classes, namespaces, imports, exports, create_label, count, rename_data, demangle.
"""

from __future__ import annotations

import logging
import re

from typing import Any

from mcp import types

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
                "programPath": {"type": "string"},
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
                    "description": "Operation mode. Also accepts 'action' as an alias.",
                },
                "action": {
                    "type": "string",
                    "description": "Alias for 'mode'. Either 'mode' or 'action' may be used interchangeably.",
                },
                "query": {"type": "string", "description": "Search query / pattern"},
                "addressOrSymbol": {"type": "string"},
                "labelName": {"type": "string"},
                "newName": {"type": "string"},
                "filterDefaultNames": {"type": "boolean", "default": True},
                "maxResults": {"type": "integer", "default": 100},
                "offset": {"type": "integer", "default": 0},
            },
            "required": [],
        }

        return [
            types.Tool(
                name="manage-symbols",
                description="Manage symbols: list, search, create labels, rename, demangle, imports/exports",
                inputSchema=base_manage_schema,
            ),
            types.Tool(
                name="search-symbols-by-name",
                description="Search symbols by name pattern",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "query": {"type": "string"},
                        "namePattern": {"type": "string"},
                        "maxResults": {"type": "integer", "default": 100},
                        "offset": {"type": "integer", "default": 0},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="search-symbols",
                description="Search symbols by name pattern (alias)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "query": {"type": "string"},
                        "namePattern": {"type": "string"},
                        "maxResults": {"type": "integer", "default": 100},
                        "offset": {"type": "integer", "default": 0},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="list-imports",
                description="List imported symbols (alias for manage-symbols mode=imports)",
                inputSchema={"type": "object", "properties": {"programPath": {"type": "string"}, "maxResults": {"type": "integer", "default": 100}}, "required": []},
            ),
            types.Tool(
                name="list-exports",
                description="List exported symbols (alias for manage-symbols mode=exports)",
                inputSchema={"type": "object", "properties": {"programPath": {"type": "string"}, "maxResults": {"type": "integer", "default": 100}}, "required": []},
            ),
            types.Tool(
                name="create-label",
                description="Create a label at address (alias for manage-symbols mode=create_label)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "addressOrSymbol": {"type": "string"},
                        "labelName": {"type": "string"},
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle_list_imports_alias(self, args: dict[str, Any]) -> list[types.TextContent]:
        return await self._list_imports(args)

    async def _handle_list_exports_alias(self, args: dict[str, Any]) -> list[types.TextContent]:
        return await self._list_exports(args)

    async def _handle_create_label_alias(self, args: dict[str, Any]) -> list[types.TextContent]:
        return await self._create_label(args)

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        mode = self._get_str(args, "mode", "action", default="symbols")

        from agentdecompile_cli.registry import normalize_identifier as n

        dispatch = {
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
        handler = dispatch.get(n(mode))
        if handler is None:
            raise ValueError(f"Unknown mode: {mode}")
        return await handler(args)

    async def _handle_search(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        query = self._get_str(args, "query", "namepattern", "pattern", "search", "name")
        max_results = self._get_int(args, "maxresults", "limit", default=100)
        offset = self._get_int(args, "offset", "startindex", default=0)

        # Try GhidraTools
        if self.ghidra_tools:
            try:
                results = self.ghidra_tools.search_symbols_by_name(query)
                paginated = results[offset : offset + max_results]
                return create_success_response(
                    {
                        "query": query,
                        "results": paginated,
                        "count": len(paginated),
                        "total": len(results),
                        "hasMore": offset + len(paginated) < len(results),
                    }
                )
            except Exception:
                pass

        # Direct API
        program = self.program_info.program
        st = program.getSymbolTable()
        results = []
        count = 0

        pat = re.compile(query, re.IGNORECASE) if query else None
        for sym in st.getAllSymbols(True):
            name = sym.getName()
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
                    "address": str(sym.getAddress()),
                    "type": str(sym.getSymbolType()),
                    "namespace": str(sym.getParentNamespace()),
                    "source": str(sym.getSource()),
                }
            )
            count += 1

        return create_success_response(
            {
                "query": query,
                "results": results,
                "count": len(results),
                "totalMatched": count,
                "hasMore": count > offset + len(results),
            }
        )

    async def _list_symbols(self, args: dict[str, Any]) -> list[types.TextContent]:
        query = self._get_str(args, "query", "pattern", "search")
        filter_default = self._get_bool(args, "filterdefaultnames", default=True)
        max_results = self._get_int(args, "maxresults", "limit", default=100)
        offset = self._get_int(args, "offset", "startindex", default=0)

        # Try GhidraTools
        if self.ghidra_tools:
            try:
                all_syms = self.ghidra_tools.get_all_symbols()
                if filter_default:
                    all_syms = [s for s in all_syms if not _DEFAULT_NAME_RE.match(s.get("name", ""))]
                if query:
                    pat = re.compile(query, re.IGNORECASE)
                    all_syms = [s for s in all_syms if pat.search(s.get("name", ""))]
                paginated = all_syms[offset : offset + max_results]
                return create_success_response(
                    {
                        "mode": "symbols",
                        "results": paginated,
                        "count": len(paginated),
                        "total": len(all_syms),
                        "hasMore": offset + len(paginated) < len(all_syms),
                    }
                )
            except Exception:
                pass

        return await self._handle_search(args)

    async def _list_classes(self, args: dict[str, Any]) -> list[types.TextContent]:
        program = self.program_info.program
        st = program.getSymbolTable()
        max_results = self._get_int(args, "maxresults", "limit", default=100)

        from ghidra.program.model.symbol import SymbolType

        classes = []
        for sym in st.getAllSymbols(True):
            if sym.getSymbolType() == SymbolType.CLASS:
                classes.append({"name": sym.getName(), "address": str(sym.getAddress()), "namespace": str(sym.getParentNamespace())})
                if len(classes) >= max_results:
                    break
        return create_success_response({"mode": "classes", "results": classes, "count": len(classes)})

    async def _list_namespaces(self, args: dict[str, Any]) -> list[types.TextContent]:
        program = self.program_info.program
        st = program.getSymbolTable()
        max_results = self._get_int(args, "maxresults", "limit", default=100)

        from ghidra.program.model.symbol import SymbolType

        namespaces = []
        for sym in st.getAllSymbols(True):
            if sym.getSymbolType() == SymbolType.NAMESPACE:
                namespaces.append({"name": sym.getName(), "address": str(sym.getAddress())})
                if len(namespaces) >= max_results:
                    break
        return create_success_response({"mode": "namespaces", "results": namespaces, "count": len(namespaces)})

    async def _list_imports(self, args: dict[str, Any]) -> list[types.TextContent]:
        max_results = self._get_int(args, "maxresults", "limit", default=100)

        if self.ghidra_tools:
            try:
                imports = self.ghidra_tools.list_imports()
                return create_success_response({"mode": "imports", "results": imports[:max_results], "count": min(len(imports), max_results), "total": len(imports)})
            except Exception:
                pass

        program = self.program_info.program
        st = program.getSymbolTable()
        imports = []
        for sym in st.getExternalSymbols():
            imports.append({"name": sym.getName(), "address": str(sym.getAddress()), "namespace": str(sym.getParentNamespace())})
            if len(imports) >= max_results:
                break
        return create_success_response({"mode": "imports", "results": imports, "count": len(imports)})

    async def _list_exports(self, args: dict[str, Any]) -> list[types.TextContent]:
        max_results = self._get_int(args, "maxresults", "limit", default=100)

        if self.ghidra_tools:
            try:
                exports = self.ghidra_tools.list_exports()
                return create_success_response({"mode": "exports", "results": exports[:max_results], "count": min(len(exports), max_results), "total": len(exports)})
            except Exception:
                pass

        program = self.program_info.program
        st = program.getSymbolTable()
        exports = []
        for sym in st.getAllSymbols(True):
            if sym.isExternalEntryPoint():
                exports.append({"name": sym.getName(), "address": str(sym.getAddress())})
                if len(exports) >= max_results:
                    break
        return create_success_response({"mode": "exports", "results": exports, "count": len(exports)})

    async def _create_label(self, args: dict[str, Any]) -> list[types.TextContent]:
        addr_str = self._require_str(args, "addressorsymbol", "address", "addr", name="addressOrSymbol")
        label = self._require_str(args, "labelname", "label", "name", name="labelName")

        program = self.program_info.program
        from ghidra.program.model.symbol import SourceType

        from agentdecompile_cli.mcp_utils.address_util import AddressUtil

        # Batch support
        addr_list = self._get_list(args, "addressorsymbol", "addresses")
        label_list = self._get_list(args, "labelname", "labels")
        if addr_list and label_list and len(addr_list) > 1:
            results = []
            tx = program.startTransaction("batch-create-labels")
            try:
                for a, l in zip(addr_list, label_list):
                    try:
                        addr = AddressUtil.resolve_address_or_symbol(program, str(a))
                        program.getSymbolTable().createLabel(addr, str(l), SourceType.USER_DEFINED)
                        results.append({"address": str(addr), "label": str(l), "success": True})
                    except Exception as e:
                        results.append({"address": str(a), "label": str(l), "success": False, "error": str(e)})
                program.endTransaction(tx, True)
            except Exception:
                program.endTransaction(tx, False)
                raise
            return create_success_response({"mode": "create_label", "batch": True, "results": results})

        addr = AddressUtil.resolve_address_or_symbol(program, addr_str)
        tx = program.startTransaction("create-label")
        try:
            program.getSymbolTable().createLabel(addr, label, SourceType.USER_DEFINED)
            program.endTransaction(tx, True)
        except Exception:
            program.endTransaction(tx, False)
            raise
        return create_success_response({"mode": "create_label", "address": str(addr), "label": label, "success": True})

    async def _count(self, args: dict[str, Any]) -> list[types.TextContent]:
        program = self.program_info.program
        st = program.getSymbolTable()
        return create_success_response({"mode": "count", "totalSymbols": st.getNumSymbols()})

    async def _rename_data(self, args: dict[str, Any]) -> list[types.TextContent]:
        addr_str = self._require_str(args, "addressorsymbol", "address", "addr", name="addressOrSymbol")
        new_name = self._require_str(args, "newname", "name", "labelname", name="newName")

        program = self.program_info.program
        from ghidra.program.model.symbol import SourceType

        from agentdecompile_cli.mcp_utils.address_util import AddressUtil

        addr = AddressUtil.resolve_address_or_symbol(program, addr_str)
        st = program.getSymbolTable()
        sym = st.getPrimarySymbol(addr)
        if sym is None:
            raise ValueError(f"No symbol at {addr_str}")

        tx = program.startTransaction("rename-data")
        try:
            sym.setName(new_name, SourceType.USER_DEFINED)
            program.endTransaction(tx, True)
        except Exception:
            program.endTransaction(tx, False)
            raise
        return create_success_response({"mode": "rename_data", "address": str(addr), "newName": new_name, "success": True})

    async def _demangle(self, args: dict[str, Any]) -> list[types.TextContent]:
        query = self._get_str(args, "query", "symbol", "name", "addressorsymbol")
        max_results = self._get_int(args, "maxresults", "limit", default=100)

        program = self.program_info.program
        results = []

        try:
            from ghidra.app.util.demangler import DemanglerUtil

            st = program.getSymbolTable()
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
                            }
                        )
                except Exception:
                    continue
        except ImportError:
            return create_success_response({"mode": "demangle", "note": "DemanglerUtil not available", "results": []})

        return create_success_response({"mode": "demangle", "results": results, "count": len(results)})
