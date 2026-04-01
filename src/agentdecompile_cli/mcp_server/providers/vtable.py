"""Vtable Tool Provider - analyze-vtables.

- mode=analyze: List function pointers in a specific vtable (addressOrSymbol + maxEntries).
- mode=containing: Scan the program for arrays that look like vtables.
- mode=callers: Find code that references a given vtable.
- _handle builds shared kwargs (listing, memory, fm, addr_str, offset, max_results) and dispatches to _handle_containing / _handle_analyze / _handle_callers.
"""

from __future__ import annotations

import logging

from typing import TYPE_CHECKING, Any

from mcp import types

from agentdecompile_cli.mcp_server.tool_providers import (
    DEFAULT_MAX_ENTRIES,
    DEFAULT_PAGE_LIMIT,
    ToolProvider,
    create_success_response,
)
from agentdecompile_cli.registry import Tool

if TYPE_CHECKING:
    from ghidra.program.model.listing import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        FunctionManager as GhidraFunctionManager,
        Listing as GhidraListing,
        Program as GhidraProgram,
    )
    from ghidra.program.model.mem import Memory as GhidraMemory  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]

logger = logging.getLogger(__name__)


class VtableToolProvider(ToolProvider):
    HANDLERS = {"analyzevtables": "_handle"}

    def list_tools(self) -> list[types.Tool]:
        logger.debug("diag.enter %s", "mcp_server/providers/vtable.py:VtableToolProvider.list_tools")
        return [
            types.Tool(
                name=Tool.ANALYZE_VTABLES.value,
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
                        "limit": {
                            "type": "integer",
                            "default": 100,
                            "description": "Number of vtable results to return. Typical values are 100–500.",
                        },
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/vtable.py:VtableToolProvider._handle")
        self._require_program()
        mode = self._get_str(args, "mode", default="analyze")
        addr_str = self._get_address_or_symbol(args)
        logger.info("analyze-vtables mode=%s addressOrSymbol=%s", mode, addr_str or "(none)")
        assert self.program_info is not None  # for type checker
        # Shared context for all mode handlers: program, listing, memory, fm, address string, pagination
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
        program: GhidraProgram,
        listing: GhidraListing,
        memory: GhidraMemory,
        fm: GhidraFunctionManager,
        addr_str: str,
        max_entries: int,
        offset: int,
        max_results: int,
    ) -> list[types.TextContent]:
        # Scan all defined data; keep items whose type name suggests a vtable (user- or analyzer-named)
        logger.debug("diag.enter %s", "mcp_server/providers/vtable.py:VtableToolProvider._handle_containing")
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
        paginated, _ = self._paginate_results(all_results, offset, max_results)
        return self._create_paginated_response(paginated, offset, max_results, total=len(all_results), mode="containing")

    async def _handle_analyze(
        self,
        args: dict[str, Any],
        program: GhidraProgram,
        listing: GhidraListing,
        memory: GhidraMemory,
        fm: GhidraFunctionManager,
        addr_str: str,
        max_entries: int,
        offset: int,
        max_results: int,
    ) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/vtable.py:VtableToolProvider._handle_analyze")
        if not addr_str:
            raise ValueError("addressOrSymbol required for analyze mode")

        addr = self._resolve_address(addr_str, program=program)

        # Walk vtable slot-by-slot: read pointer-sized bytes, resolve to address, look up function
        entries = []
        ptr_size = program.getDefaultPointerSize()
        for i in range(max_entries):
            entry_addr = addr.add(i * ptr_size)
            try:
                buf = bytearray(ptr_size)
                memory.getBytes(entry_addr, buf)
                ptr_val = int.from_bytes(buf, byteorder="little")
                target_addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(ptr_val)
                func = fm.getFunctionAt(target_addr)
                # First slot can be null (e.g. offset-to-top); after that, null usually means end of vtable
                if func is None and i > 0:
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

        logger.debug("vtable analyze: vtableAddress=%s entries=%s", addr, len(entries))
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
        program: GhidraProgram,
        listing: GhidraListing,
        memory: GhidraMemory,
        fm: GhidraFunctionManager,
        addr_str: str,
        max_entries: int,
        offset: int,
        max_results: int,
    ) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/vtable.py:VtableToolProvider._handle_callers")
        if not addr_str:
            raise ValueError("addressOrSymbol required for callers mode")

        addr = self._resolve_address(addr_str, program=program)

        # Who references this vtable address? (code that loads or uses the vtable pointer)
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
        logger.debug("vtable callers: vtableAddress=%s refs=%s", addr, len(all_callers))
        paginated, _ = self._paginate_results(all_callers, offset, max_results)
        return self._create_paginated_response(paginated, offset, max_results, total=len(all_callers), mode="callers", vtableAddress=str(addr))
