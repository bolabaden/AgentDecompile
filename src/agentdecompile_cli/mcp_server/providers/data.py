"""Data Tool Provider - get-data, apply-data-type.

Handles raw data viewing and type application at addresses.
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


class DataToolProvider(ToolProvider):
    HANDLERS = {
        "getdata": "_handle_get",
        "applydatatype": "_handle_apply",
    }

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="get-data",
                description="Get data at an address",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "addressOrSymbol": {"type": "string", "description": "Address or symbol"},
                        "length": {"type": "integer", "default": 16},
                        "format": {"type": "string", "enum": ["hex", "ascii", "both"], "default": "both"},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="apply-data-type",
                description="Apply a data type at an address",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "addressOrSymbol": {"type": "string"},
                        "dataType": {"type": "string", "description": "Data type name (e.g., int, char*, struct_name)"},
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle_get(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        addr_str = self._require_str(args, "addressorsymbol", "address", "addr", "symbol", name="addressOrSymbol")
        length = self._get_int(args, "length", "size", "len", default=16)
        fmt = self._get_str(args, "format", default="both")

        program = self.program_info.program
        from agentdecompile_cli.mcp_utils.address_util import AddressUtil

        addr = AddressUtil.resolve_address_or_symbol(program, addr_str)

        memory = program.getMemory()
        buf = bytearray(min(length, 10000))
        actual = memory.getBytes(addr, buf)

        result: dict[str, Any] = {"address": str(addr), "length": actual}
        if fmt in ("hex", "both"):
            result["hex"] = " ".join(f"{b:02x}" for b in buf[:actual])
        if fmt in ("ascii", "both"):
            result["ascii"] = "".join(chr(b) if 32 <= b < 127 else "." for b in buf[:actual])

        # Also check for defined data at address
        listing = program.getListing()
        data = listing.getDataAt(addr)
        if data is not None:
            result["definedType"] = str(data.getDataType())
            try:
                result["value"] = str(data.getValue())
            except Exception:
                pass
        return create_success_response(result)

    async def _handle_apply(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        addr_str = self._require_str(args, "addressorsymbol", "address", "addr", "symbol", name="addressOrSymbol")
        dt_name = self._require_str(args, "datatype", "datatypestring", "type", "typename", name="dataType")

        program = self.program_info.program
        from agentdecompile_cli.mcp_utils.address_util import AddressUtil

        addr = AddressUtil.resolve_address_or_symbol(program, addr_str)

        # Parse data type
        from ghidra.util.data import DataTypeParser

        dtm = program.getDataTypeManager()
        parser = DataTypeParser(dtm, dtm, None, DataTypeParser.AllowedDataTypes.ALL)
        dt = parser.parse(dt_name)

        tx = program.startTransaction("apply-data-type")
        try:
            listing = program.getListing()
            listing.clearCodeUnits(addr, addr.add(dt.getLength() - 1), False)
            listing.createData(addr, dt)
            program.endTransaction(tx, True)
        except Exception:
            program.endTransaction(tx, False)
            raise
        return create_success_response({"address": str(addr), "dataType": dt_name, "success": True})
