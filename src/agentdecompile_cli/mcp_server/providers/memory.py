"""Memory Tool Provider - inspect-memory, read-bytes.

- inspect-memory: mode = blocks (memory map), read (raw bytes at address), data_at
  (typed data at address), data_items (list of defined data), segments (alias for blocks).
- read-bytes: Convenience handler that delegates to inspect-memory with mode=read.
"""

from __future__ import annotations

import logging

from typing import TYPE_CHECKING, Any, cast

from mcp import types

from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
)
from agentdecompile_cli.registry import Tool

if TYPE_CHECKING:
    from ghidra.program.model.address import Address as GhidraAddress  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]  # noqa: F401
    from ghidra.program.model.data import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]  # noqa: F401
        Category as GhidraCategory,
        DataType as GhidraDataType,
        DataTypeManager as GhidraDataTypeManager,
        DataUtilities as GhidraDataUtilities,
    )
    from ghidra.program.model.listing import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]  # noqa: F401
        Data as GhidraData,
        Listing as GhidraListing,
        Program as GhidraProgram,
    )
    from ghidra.program.model.mem import Memory as GhidraMemory  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]  # noqa: F401

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
        forwarded: dict[str, Any] = dict(args)
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
        mode: str = self._get_str(args, "mode", default="blocks")
        assert self.program_info is not None, "program_info should be set after _require_program()"
        program: GhidraProgram | None = self.program_info.program
        memory: GhidraMemory | None = self._get_memory(program)
        assert program is not None and memory is not None, "program and memory should be set after _require_program()"

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
        blocks: list[dict[str, Any]] = []
        for blk in memory.getBlocks():
            blocks.append(
                {
                    "name": str(blk.getName()),
                    "start": str(blk.getStart()),
                    "end": str(blk.getEnd()),
                    "size": int(blk.getSize()),
                    "permissions": f"{'r' if blk.isRead() else '-'}{'w' if blk.isWrite() else '-'}{'x' if blk.isExecute() else '-'}",
                    "initialized": blk.isInitialized(),
                    "type": str(blk.getType()) if hasattr(blk, "getType") else "DEFAULT",  # pyright: ignore[reportOptionalMemberAccess]
                },
            )
        return create_success_response({"mode": "blocks", "blocks": blocks, "count": len(blocks)})

    async def _handle_read(self, args: dict[str, Any], program: GhidraProgram, memory: GhidraMemory) -> list[types.TextContent]:
        """Read raw bytes at address; return hex dump and ASCII view. Cap length at 10000 to avoid huge responses."""
        logger.debug("diag.enter %s", "mcp_server/providers/memory.py:MemoryToolProvider._handle_read")
        addr_str: str | None = self._require_address_or_symbol(args)
        assert addr_str is not None, "addr_str should be set after _require_address_or_symbol()"
        length: int | None = self._get_int(args, "length", "size", "len", default=256)
        assert length is not None, "length should be set after _require_address_or_symbol()"
        length = min(length, 10000)
        addr: GhidraAddress | None = self._resolve_address(addr_str, program=program)
        assert addr is not None, "addr should be set after _resolve_address()"

        import jpype  # noqa: PLC0415

        # Must use a JPype Java primitive byte[] array — passing Python bytearray to getBytes gives a
        # temporary Java copy that is never written back to the Python object, causing all-zero results.
        # JByte[length] is valid at runtime but typed as the JByte class, not JArray[JByte]; use JArray().
        # Stubs type JArray(JByte) as a non-callable generic; cast so (length) is accepted and slots are assignable.
        buf: Any = cast(Any, jpype.JArray(jpype.JByte))(length)
        actual: int = 0
        try:
            actual = memory.getBytes(addr, buf)
        except Exception:
            # Some Ghidra versions or address spaces don't support getBytes; fall back to byte-by-byte read
            for i in range(length):
                try:
                    # getByte may be typed as JByte (generic class); coerce to int for JPype array assignment
                    buf[i] = int(memory.getByte(addr.add(i)))
                    actual = i + 1
                except Exception:
                    break

        # Java bytes are signed (-128..127); mask with 0xFF for unsigned hex/ASCII display
        hex_str: str = " ".join(f"{int(b) & 0xFF:02x}" for b in buf[:actual])
        ascii_str: str = "".join(chr(int(b) & 0xFF) if 32 <= (int(b) & 0xFF) < 127 else "." for b in buf[:actual])

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
        addr_str: str | None = self._require_address_or_symbol(args)
        assert addr_str is not None, "addr_str should be set after _require_address_or_symbol()"
        addr: GhidraAddress | None = self._resolve_address(addr_str, program=program)
        assert addr is not None, "addr should be set after _resolve_address()"

        listing: GhidraListing | None = self._get_listing(program)
        assert listing is not None, "listing should be set after _get_listing()"
        data: GhidraData | None = listing.getDataAt(addr)
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
        offset: int | None = None
        max_results: int | None = None
        offset, max_results = self._get_pagination_params(args, default_limit=100)
        assert offset is not None and max_results is not None, "offset and max_results should be set after _get_pagination_params()"

        listing: GhidraListing | None = self._get_listing(program)
        assert listing is not None, "listing should be set after _get_listing()"
        all_items: list[dict[str, Any]] = []
        data: GhidraData | None
        for data in listing.getDefinedData(True):
            assert data is not None, "data should be set after getDefinedData()"
            all_items.append(
                {
                    "address": str(data.getAddress()),  # pyright: ignore[reportCallIssue]
                    "dataType": str(data.getDataType()),
                    "length": data.getLength(),
                    "label": str(data.getLabel()) if hasattr(data, "getLabel") and data.getLabel() else None,
                },
            )
        paginated, has_more = self._paginate_results(all_items, offset, max_results)
        return self._create_paginated_response(paginated, offset, max_results, total=len(all_items), mode="data_items")
