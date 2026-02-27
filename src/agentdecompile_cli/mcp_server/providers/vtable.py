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
                        "maxResults": {"type": "integer", "default": 100},
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        mode = self._get_str(args, "mode", default="analyze")
        addr_str = self._get_str(args, "addressorsymbol", "address", "addr", "symbol")
        max_entries = self._get_int(args, "maxentries", default=200)
        max_results = self._get_int(args, "maxresults", "limit", default=100)

        program = self.program_info.program
        listing = program.getListing()
        memory = program.getMemory()
        fm = program.getFunctionManager()

        from agentdecompile_cli.registry import normalize_identifier as n

        mode_n = n(mode)

        if mode_n == "containing":
            # Find vtables in the program by scanning for pointer arrays
            results = []
            for data in listing.getDefinedData(True):
                if len(results) >= max_results:
                    break
                dt = data.getDataType()
                dt_name = dt.getName().lower() if dt else ""
                if "vtable" in dt_name or "vftable" in dt_name:
                    results.append(
                        {
                            "address": str(data.getAddress()),
                            "name": str(data.getLabel()) if hasattr(data, "getLabel") and data.getLabel() else dt_name,
                            "type": str(dt),
                            "size": data.getLength(),
                        }
                    )
            return create_success_response({"mode": "containing", "vtables": results, "count": len(results)})

        if not addr_str:
            raise ValueError("addressOrSymbol required for analyze/callers mode")

        from agentdecompile_cli.mcp_utils.address_util import AddressUtil

        addr = AddressUtil.resolve_address_or_symbol(program, addr_str)

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
                        }
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
                }
            )

        if mode_n == "callers":
            # Find references to vtable entries
            ref_mgr = program.getReferenceManager()
            callers = []
            refs = list(ref_mgr.getReferencesTo(addr))
            for ref in refs[:max_results]:
                from_addr = ref.getFromAddress()
                func = fm.getFunctionContaining(from_addr)
                callers.append(
                    {
                        "fromAddress": str(from_addr),
                        "function": func.getName() if func else None,
                        "refType": str(ref.getReferenceType()),
                    }
                )
            return create_success_response(
                {
                    "mode": "callers",
                    "vtableAddress": str(addr),
                    "callers": callers,
                    "count": len(callers),
                }
            )

        raise ValueError(f"Unknown mode: {mode}")
