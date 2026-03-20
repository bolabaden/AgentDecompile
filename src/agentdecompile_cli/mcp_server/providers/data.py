"""Data Tool Provider - get-data, apply-data-type.

- get-data: Read raw bytes or interpreted data at an address (with optional length).
  Returns hex dump and/or structured view depending on existing data type.
- apply-data-type: Set or change the data type at an address (e.g. define as string,
  struct, pointer). Used to improve listing and decompilation accuracy.
"""

from __future__ import annotations

import logging
import uuid

from typing import Any

from mcp import types

from agentdecompile_cli.mcp_server.tool_providers import (
    FORCE_APPLY_CONFLICT_ID_KEY,
    ToolProvider,
    create_conflict_response,
    create_success_response,
    n,
)
from agentdecompile_cli.registry import Tool

logger = logging.getLogger(__name__)


class DataToolProvider(ToolProvider):
    """Provides get-data (read bytes/typed data at address) and apply-data-type (set type at address for listing/decompiler)."""

    HANDLERS = {
        "getdata": "_handle_get",
        "applydatatype": "_handle_apply",
    }

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name=Tool.GET_DATA.value,
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
                name=Tool.APPLY_DATA_TYPE.value,
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
        """Read raw bytes at address; include hex/ascii/both per format. Cap length at 10000."""
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

        # If Ghidra has already defined data at this address, include type and value in the response
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
        """Apply a data type at the given address: clear existing code units there, then createData with the parsed type."""
        self._require_program()
        addr_str = self._require_address_or_symbol(args)
        dt_name = self._require_str(args, "datatype", "datatypestring", "type", "typename", name="dataType")

        program = self.program_info.program
        addr = self._resolve_address(addr_str, program=program)
        listing = self._get_listing(program)

        from ghidra.util.data import DataTypeParser

        dtm = program.getDataTypeManager()
        parser = DataTypeParser(dtm, dtm, None, DataTypeParser.AllowedDataTypes.ALL)
        dt = parser.parse(dt_name)

        if not args.get(FORCE_APPLY_CONFLICT_ID_KEY):
            existing_data = listing.getDataAt(addr)
            if existing_data is not None:
                existing_type = str(existing_data.getDataType() or "").strip()
                if existing_type and existing_type != dt_name:
                    from agentdecompile_cli.mcp_server.conflict_store import store as conflict_store_store
                    from agentdecompile_cli.mcp_server.session_context import get_current_mcp_session_id

                    conflict_id = str(uuid.uuid4())
                    conflict_summary = (
                        "Apply data type would overwrite existing data at address:\n\n"
                        "```diff\n"
                        f"- {existing_type}\n"
                        f"+ {dt_name}\n"
                        "```"
                    )
                    next_step = (
                        f'To apply this change, call `resolve-modification-conflict` with `conflictId` = "{conflict_id}" and `resolution` = "overwrite". '
                        'To discard, use `resolution` = "skip".'
                    )
                    program_path = args.get(n("programPath")) or getattr(self.program_info, "path", None) or getattr(self.program_info, "file_path", None)
                    conflict_store_store(
                        get_current_mcp_session_id(),
                        conflict_id,
                        tool=Tool.APPLY_DATA_TYPE.value,
                        arguments=dict(args),
                        program_path=str(program_path) if program_path else None,
                        summary=conflict_summary,
                    )
                    return create_conflict_response(conflict_id, Tool.APPLY_DATA_TYPE.value, conflict_summary, next_step)

        def _apply_data_type() -> None:
            listing.clearCodeUnits(addr, addr.add(dt.getLength() - 1), False)
            listing.createData(addr, dt)

        self._run_program_transaction(program, "apply-data-type", _apply_data_type)
        return create_success_response({"address": str(addr), "dataType": dt_name, "success": True})
