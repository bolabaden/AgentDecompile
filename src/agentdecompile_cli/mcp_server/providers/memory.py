"""Memory Tool Provider - inspect-memory, read-bytes.

- inspect-memory: mode = blocks (memory map), read (raw bytes at address), data_at
  (typed data at address), data_items (list of defined data), segments (alias for blocks).
- read-bytes: Convenience handler that delegates to inspect-memory with mode=read.
"""

from __future__ import annotations

import logging

from typing import TYPE_CHECKING, Any

from mcp import types

from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
)
from agentdecompile_cli.registry import Tool

if TYPE_CHECKING:
    from ghidra.program.model.listing import Program as GhidraProgram  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
    from ghidra.program.model.mem import Memory as GhidraMemory  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]

logger = logging.getLogger(__name__)


class MemoryToolProvider(ToolProvider):
    """Provides inspect-memory (blocks/read/data_at/data_items) and read-bytes (delegates to inspect-memory mode=read)."""

    HANDLERS = {"inspectmemory": "_handle", "readbytes": "_handle_read_bytes"}

    @staticmethod
    def _set_forwarded_if_missing(forwarded: dict[str, Any], key: str, value: Any) -> None:
        """Set ``key`` in forwarded when it is absent and ``value`` is non-empty (for read-bytes→inspect-memory param mapping)."""
        logger.debug("diag.enter %s", "mcp_server/providers/memory.py:MemoryToolProvider._set_forwarded_if_missing")
        if key in forwarded and forwarded.get(key) is not None:
            return
        if value is None:
            return
        text = str(value).strip()
        if text:
            forwarded[key] = text

    def list_tools(self) -> list[types.Tool]:
        logger.debug("diag.enter %s", "mcp_server/providers/memory.py:MemoryToolProvider.list_tools")
        return [
            types.Tool(
                name=Tool.INSPECT_MEMORY.value,
                description="Look at how the binary's memory is divided up and what data it contains. Use this to find segments like '.text' (code) or '.data' (global variables), or to read chunks of raw bytes to inspect what's inside.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The path to the program containing the memory."},
                        "mode": {
                            "type": "string",
                            "enum": ["blocks", "read", "data_at", "data_items", "segments"],
                            "default": "blocks",
                            "description": "What to inspect: 'blocks' retrieves the high-level maps of sections (like headers vs text), 'read' dumps a block of raw binary data from an address, 'data_at' interprets what data is precisely at an address, and 'data_items' lists memory locations that have known types applied to them.",
                        },
                        "addressOrSymbol": {"type": "string", "description": "If mode is 'read' or 'data_at', you must supply the start address."},
                        "length": {"type": "integer", "default": 256, "description": "If mode is 'read', how many bytes to pull back."},
                        "maxResults": {"type": "integer", "default": 100, "description": "Number of memory items to return. Typical values are 100–500."},
                        "offset": {"type": "integer", "default": 0, "description": "Pagination offset tracking."},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name=Tool.READ_BYTES.value,
                description="Easier shortcut for 'inspect-memory mode=read'. Directly reads raw binary bytes starting from a memory address.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The path to the program containing the bytes."},
                        "binaryName": {"type": "string", "description": "Alternative parameter for programPath."},
                        "address": {"type": "string", "description": "The starting memory address (e.g. 0x08041000)."},
                        "addressOrSymbol": {"type": "string", "description": "Alternative parameter for the target address."},
                        "size": {"type": "integer", "default": 32, "description": "How many binary bytes to fetch."},
                        "length": {"type": "integer", "description": "Alternative parameter for size."},
                    },
                    "required": ["address"],
                },
            ),
        ]

    async def _handle_read_bytes(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Normalize read-bytes params (binaryName→programPath, address→addressOrSymbol, size→length) and delegate to inspect-memory mode=read."""
        logger.debug("diag.enter %s", "mcp_server/providers/memory.py:MemoryToolProvider._handle_read_bytes")
        forwarded = dict(args)
        forwarded.setdefault("mode", "read")
        # Map read-bytes-specific param names to what _handle expects
        self._set_forwarded_if_missing(forwarded, "programpath", forwarded.get("binaryname"))
        self._set_forwarded_if_missing(forwarded, "addressorsymbol", forwarded.get("address"))
        if forwarded.get("length") is None and forwarded.get("size") is not None:
            forwarded["length"] = forwarded.get("size")

        return await self._handle(forwarded)

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Dispatch to blocks/read/data_at/data_items handler; segments is an alias for blocks."""
        logger.debug("diag.enter %s", "mcp_server/providers/memory.py:MemoryToolProvider._handle")
        self._require_program()
        mode = self._get_str(args, "mode", default="blocks")
        assert self.program_info is not None, "program_info should be set after _require_program()"
        program = self.program_info.program
        memory = self._get_memory(program)

        return await self._dispatch_handler(
            args,
            mode,
            {
                "blocks": "_handle_blocks",
                "segments": "_handle_blocks",  # alias
                "read": "_handle_read",
                "data_at": "_handle_data_at",
                "data": "_handle_data_at",  # alias
                "data_items": "_handle_data_items",
            },
            program=program,
            memory=memory,
        )

    async def _handle_blocks(self, args: dict[str, Any], program: GhidraProgram, memory: GhidraMemory) -> list[types.TextContent]:
        """Return memory map: each block has name, start, end, size, r/w/x permissions, initialized flag.

        Blocks are the program's memory regions (e.g. .text, .data, .rdata); useful to find
        where code vs data lives before reading bytes or applying types.
        """
        logger.debug("diag.enter %s", "mcp_server/providers/memory.py:MemoryToolProvider._handle_blocks")
        blocks = []
        for blk in memory.getBlocks():
            blocks.append(
                {
                    "name": blk.getName(),
                    "start": str(blk.getStart()),
                    "end": str(blk.getEnd()),
                    "size": blk.getSize(),
                    "permissions": f"{'r' if blk.isRead() else '-'}{'w' if blk.isWrite() else '-'}{'x' if blk.isExecute() else '-'}",
                    "initialized": blk.isInitialized(),
                    "type": str(blk.getType()) if hasattr(blk, "getType") else "DEFAULT",
                },
            )
        return create_success_response({"mode": "blocks", "blocks": blocks, "count": len(blocks)})

    async def _handle_read(self, args: dict[str, Any], program: GhidraProgram, memory: GhidraMemory) -> list[types.TextContent]:
        """Read raw bytes at address; return hex dump and ASCII view. Cap length at 10000 to avoid huge responses."""
        logger.debug("diag.enter %s", "mcp_server/providers/memory.py:MemoryToolProvider._handle_read")
        addr_str = self._require_address_or_symbol(args)
        length = self._get_int(args, "length", "size", "len", default=256)
        length = min(length, 10000)
        addr = self._resolve_address(addr_str, program=program)

        import jpype  # noqa: PLC0415

        # Must use a JPype Java primitive byte[] array — passing Python bytearray to getBytes gives a
        # temporary Java copy that is never written back to the Python object, causing all-zero results.
        buf = jpype.JByte[length]
        actual = 0
        try:
            actual = memory.getBytes(addr, buf)
        except Exception:
            # Some Ghidra versions or address spaces don't support getBytes; fall back to byte-by-byte read
            for i in range(length):
                try:
                    buf[i] = memory.getByte(addr.add(i))  # signed Java byte; mask only on output
                    actual = i + 1
                except Exception:
                    break

        # Java bytes are signed (-128..127); mask with 0xFF for unsigned hex/ASCII display
        hex_str = " ".join(f"{b & 0xFF:02x}" for b in buf[:actual])
        ascii_str = "".join(chr(b & 0xFF) if 32 <= (b & 0xFF) < 127 else "." for b in buf[:actual])

        return create_success_response(
            {
                "mode": "read",
                "address": str(addr),
                "length": actual,
                "hex": hex_str,
                "ascii": ascii_str,
            },
        )

    async def _handle_data_at(self, args: dict[str, Any], program: GhidraProgram, memory: GhidraMemory) -> list[types.TextContent]:
        """Return the defined data at this address: type, length, value, label. Exact address first, then containing."""
        logger.debug("diag.enter %s", "mcp_server/providers/memory.py:MemoryToolProvider._handle_data_at")
        addr_str = self._require_address_or_symbol(args)
        addr = self._resolve_address(addr_str, program=program)

        listing = self._get_listing(program)
        data = listing.getDataAt(addr)
        if data is None:
            # Address might be inside a larger structure; getDataContaining finds the parent data
            data = listing.getDataContaining(addr)

        if data is not None:
            return create_success_response(
                {
                    "mode": "data_at",
                    "address": str(addr),
                    "dataType": str(data.getDataType()),
                    "length": data.getLength(),
                    "value": str(data.getValue()) if data.getValue() else None,
                    "label": str(data.getLabel()) if hasattr(data, "getLabel") and data.getLabel() else None,
                },
            )
        return create_success_response(
            {
                "mode": "data_at",
                "address": str(addr),
                "note": "No defined data at this address",
            },
        )

    async def _handle_data_items(self, args: dict[str, Any], program: GhidraProgram, memory: GhidraMemory) -> list[types.TextContent]:
        """List all memory locations that have a data type applied (getDefinedData), paginated.

        getDefinedData(True) walks the listing forward; each item has address, dataType, length, label.
        """
        logger.debug("diag.enter %s", "mcp_server/providers/memory.py:MemoryToolProvider._handle_data_items")
        offset, max_results = self._get_pagination_params(args, default_limit=100)

        listing = self._get_listing(program)
        all_items = []
        for data in listing.getDefinedData(True):
            all_items.append(
                {
                    "address": str(data.getAddress()),
                    "dataType": str(data.getDataType()),
                    "length": data.getLength(),
                    "label": str(data.getLabel()) if hasattr(data, "getLabel") and data.getLabel() else None,
                },
            )
        paginated, has_more = self._paginate_results(all_items, offset, max_results)
        return self._create_paginated_response(paginated, offset, max_results, total=len(all_items), mode="data_items")
