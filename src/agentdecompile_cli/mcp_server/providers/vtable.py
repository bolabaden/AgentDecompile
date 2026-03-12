"""Vtable Tool Provider - analyze-vtables.

Modes: analyze, callers, containing.
"""

from __future__ import annotations

import logging

from typing import Any

from mcp import types

from agentdecompile_cli.registry import ToolName
from agentdecompile_cli.mcp_server.tool_providers import (
    DEFAULT_MAX_ENTRIES,
    DEFAULT_PAGE_LIMIT,
    ToolProvider,
    create_success_response,
)

logger = logging.getLogger(__name__)


class VtableToolProvider(ToolProvider):
    HANDLERS = {"analyzevtables": "_handle"}

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name=ToolName.ANALYZE_VTABLES.value,
                description="Find and examine virtual function tables (vtables) belonging to C++ classes. A vtable is an array of function pointers used for dynamic dispatch in object-oriented programs. Use this to rebuild class inheritance or find virtual methods of an object.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The path to the program containing the virtual tables."},
                        "addressOrSymbol": {"type": "string", "description": "The starting address or symbol name representing the vtable location or the class constructor."},
                        "mode": {
                            "type": "string",
                            "enum": ["analyze", "callers", "containing"],
                            "default": "analyze",
                            "description": "What to do: 'analyze' lists the actual function pointers inside a specific vtable. 'containing' scans the whole program for arrays that look like vtables. 'callers' finds code that references/uses a specific vtable.",
                        },
                        "maxEntries": {
                            "type": "integer",
                            "default": 200,
                            "description": "When analyzing a specific vtable, the maximum number of pointers to parse before stopping.",
                        },
                        "limit": {"type": "integer", "default": 100, "description": "Number of vtable results to return. Typical values are 100–500. Do not set this below 50 unless the user explicitly asks for only a handful of results."},
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        mode = self._get_str(args, "mode", default="analyze")

        assert self.program_info is not None  # for type checker
        return await self._dispatch_handler(
            args,
            mode,
            {
                "containing": "_handle_containing",
                "analyze": "_handle_analyze",
                "callers": "_handle_callers",
            },
            program=self.program_info.program,
            listing=self._get_listing(self.program_info.program),
            memory=self._get_memory(self.program_info.program),
            fm=self._get_function_manager(self.program_info.program),
            addr_str=self._get_address_or_symbol(args),
            max_entries=self._get_int(args, "maxentries", default=DEFAULT_MAX_ENTRIES),
            offset=self._get_pagination_params(args, default_limit=DEFAULT_PAGE_LIMIT)[0],
            max_results=self._get_pagination_params(args, default_limit=DEFAULT_PAGE_LIMIT)[1],
        )

    async def _handle_containing(
        self,
        args: dict[str, Any],
        program: Any,
        listing: Any,
        memory: Any,
        fm: Any,
        addr_str: str,
        max_entries: int,
        offset: int,
        max_results: int,
    ) -> list[types.TextContent]:
        # Find vtables in the program by scanning for pointer arrays
        all_results: list[dict[str, Any]] = []
        for data in listing.getDefinedData(True):
            dt = data.getDataType()
            dt_name = dt.getName().lower() if dt else ""
            if "vtable" in dt_name or "vftable" in dt_name:
                all_results.append(
                    {
                        "address": str(data.getAddress()),
                        "name": str(data.getLabel()) if hasattr(data, "getLabel") and data.getLabel() else dt_name,
                        "type": str(dt),
                        "size": data.getLength(),
                    },
                )
        paginated, has_more = self._paginate_results(all_results, offset, max_results)
        return self._create_paginated_response(paginated, offset, max_results, total=len(all_results), mode="containing")

    async def _handle_analyze(
        self,
        args: dict[str, Any],
        program: Any,
        listing: Any,
        memory: Any,
        fm: Any,
        addr_str: str,
        max_entries: int,
        offset: int,
        max_results: int,
    ) -> list[types.TextContent]:
        if not addr_str:
            raise ValueError("addressOrSymbol required for analyze mode")

        addr = self._resolve_address(addr_str, program=program)

        # Read vtable entries (pointers to functions)
        entries = []
        ptr_size = program.getDefaultPointerSize()
        for i in range(max_entries):
            entry_addr = addr.add(i * ptr_size)
            try:
                buf = bytearray(ptr_size)
                memory.getBytes(entry_addr, buf)
                # Interpret as pointer
                ptr_val = int.from_bytes(buf, byteorder="little")
                target_addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(ptr_val)
                func = fm.getFunctionAt(target_addr)
                if func is None and i > 0:
                    # End of vtable
                    break
                entries.append(
                    {
                        "index": i,
                        "address": str(entry_addr),
                        "target": hex(ptr_val),
                        "function": func.getName() if func else None,
                    },
                )
            except Exception:
                break

        return create_success_response(
            {
                "mode": "analyze",
                "vtableAddress": str(addr),
                "entries": entries,
                "count": len(entries),
                "pointerSize": ptr_size,
            },
        )

    async def _handle_callers(
        self,
        args: dict[str, Any],
        program: Any,
        listing: Any,
        memory: Any,
        fm: Any,
        addr_str: str,
        max_entries: int,
        offset: int,
        max_results: int,
    ) -> list[types.TextContent]:
        if not addr_str:
            raise ValueError("addressOrSymbol required for callers mode")

        addr = self._resolve_address(addr_str, program=program)

        # Find references to vtable entries
        ref_mgr = program.getReferenceManager()
        all_callers = []
        for ref in ref_mgr.getReferencesTo(addr):
            from_addr = ref.getFromAddress()
            func = fm.getFunctionContaining(from_addr)
            all_callers.append(
                {
                    "fromAddress": str(from_addr),
                    "function": func.getName() if func else None,
                    "refType": str(ref.getReferenceType()),
                },
            )
        paginated, has_more = self._paginate_results(all_callers, offset, max_results)
        return self._create_paginated_response(paginated, offset, max_results, total=len(all_callers), mode="callers", vtableAddress=str(addr))
