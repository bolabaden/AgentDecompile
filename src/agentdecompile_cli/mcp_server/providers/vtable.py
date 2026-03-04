"""Vtable Tool Provider - analyze-vtables.

Modes: analyze, callers, containing.
"""

from __future__ import annotations

import logging

from typing import Any

from mcp import types

from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
    n,
)

logger = logging.getLogger(__name__)


class VtableToolProvider(ToolProvider):
    HANDLERS = {"analyzevtables": "_handle"}

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="analyze-vtables",
                description="Analyze virtual function tables at an address",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "addressOrSymbol": {"type": "string", "description": "Address of vtable or class"},
                        "mode": {"type": "string", "enum": ["analyze", "callers", "containing"], "default": "analyze"},
                        "maxEntries": {"type": "integer", "default": 200},
                        "limit": {"type": "integer", "default": 100},
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        mode = self._get_str(args, "mode", default="analyze")
        addr_str = self._get_address_or_symbol(args)
        max_entries = self._get_int(args, "maxentries", default=200)
        offset, max_results = self._get_pagination_params(args, default_limit=100)

        program = self.program_info.program
        listing = self._get_listing(program)
        memory = self._get_memory(program)
        fm = self._get_function_manager(program)

        mode_n = n(mode)

        if mode_n == "containing":
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

        if not addr_str:
            raise ValueError("addressOrSymbol required for analyze/callers mode")

        addr = self._resolve_address(addr_str, program=program)

        if mode_n == "analyze":
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

        if mode_n == "callers":
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

        raise ValueError(f"Unknown mode: {mode}")
