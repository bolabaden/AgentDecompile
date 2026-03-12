"""Data Tool Provider - get-data, apply-data-type.

Handles raw data viewing and type application at addresses.
"""

from __future__ import annotations

import logging

from typing import Any

from mcp import types

from agentdecompile_cli.registry import ToolName
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
                name=ToolName.GET_DATA.value,
                description="View raw bytes or structured data at a specific memory address. Use this to inspect what is stored in memory (e.g., checking if an address contains an integer, a string, or uninitialized padding).",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {
                            "type": "string",
                            "description": "Path to the binary project file in Ghidra.",
                        },
                        "addressOrSymbol": {
                            "type": "string",
                            "description": "The exact address or known symbol name where the data is located.",
                        },
                        "length": {
                            "type": "integer",
                            "default": 16,
                            "description": "How many bytes of data to read from this address.",
                        },
                        "format": {
                            "type": "string",
                            "enum": ["hex", "ascii", "both"],
                            "default": "both",
                            "description": "How to format the output. 'hex' shows hexadecimal bytes, 'ascii' shows printable characters, 'both' shows both.",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name=ToolName.APPLY_DATA_TYPE.value,
                description="Label a specific memory address as containing a certain data type (like 'int', 'char*', or a custom struct). This helps the decompiler produce cleaner code by understanding how the memory is being used.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {
                            "type": "string",
                            "description": "Path to the binary project file in Ghidra.",
                        },
                        "addressOrSymbol": {
                            "type": "string",
                            "description": "The exact address or known symbol name to label.",
                        },
                        "dataType": {
                            "type": "string",
                            "description": "The name of the data type to apply (e.g., 'int', 'char*', 'my_struct_t'). The type must already exist in the program's type manager.",
                        },
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle_get(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        addr_str = self._require_address_or_symbol(args)
        length = self._get_int(args, "length", "size", "len", default=16)
        fmt = self._get_str(args, "format", default="both")

        program = self.program_info.program
        addr = self._resolve_address(addr_str, program=program)

        memory = self._get_memory(program)
        buf = bytearray(min(length, 10000))
        actual = memory.getBytes(addr, buf)

        result: dict[str, Any] = {"address": str(addr), "length": actual}
        if fmt in ("hex", "both"):
            result["hex"] = " ".join(f"{b:02x}" for b in buf[:actual])
        if fmt in ("ascii", "both"):
            result["ascii"] = "".join(chr(b) if 32 <= b < 127 else "." for b in buf[:actual])

        # Also check for defined data at address
        listing = self._get_listing(program)
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
        addr_str = self._require_address_or_symbol(args)
        dt_name = self._require_str(args, "datatype", "datatypestring", "type", "typename", name="dataType")

        program = self.program_info.program
        addr = self._resolve_address(addr_str, program=program)

        # Parse data type
        from ghidra.util.data import DataTypeParser

        dtm = program.getDataTypeManager()
        parser = DataTypeParser(dtm, dtm, None, DataTypeParser.AllowedDataTypes.ALL)
        dt = parser.parse(dt_name)

        def _apply_data_type() -> None:
            listing = self._get_listing(program)
            listing.clearCodeUnits(addr, addr.add(dt.getLength() - 1), False)
            listing.createData(addr, dt)

        self._run_program_transaction(program, "apply-data-type", _apply_data_type)
        return create_success_response({"address": str(addr), "dataType": dt_name, "success": True})
