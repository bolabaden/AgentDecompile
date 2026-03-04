"""Memory Tool Provider - inspect-memory.

Modes: blocks, read, data_at, data_items, segments.
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


class MemoryToolProvider(ToolProvider):
    HANDLERS = {"inspectmemory": "_handle", "readbytes": "_handle_read_bytes"}

    @staticmethod
    def _set_forwarded_if_missing(forwarded: dict[str, Any], key: str, value: Any) -> None:
        """Set ``key`` when absent and ``value`` is non-empty."""
        if key in forwarded and forwarded.get(key) is not None:
            return
        if value is None:
            return
        text = str(value).strip()
        if text:
            forwarded[key] = text

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="inspect-memory",
                description="Inspect memory: list blocks, read bytes, view data at address",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "mode": {"type": "string", "enum": ["blocks", "read", "data_at", "data_items", "segments"], "default": "blocks"},
                        "addressOrSymbol": {"type": "string"},
                        "length": {"type": "integer", "default": 256},
                        "maxResults": {"type": "integer", "default": 100},
                        "offset": {"type": "integer", "default": 0},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="read-bytes",
                description="Read bytes from memory at an address (compat alias for inspect-memory mode=read)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "binaryName": {"type": "string"},
                        "address": {"type": "string"},
                        "addressOrSymbol": {"type": "string"},
                        "size": {"type": "integer", "default": 32},
                        "length": {"type": "integer"},
                    },
                    "required": ["address"],
                },
            ),
        ]

    async def _handle_read_bytes(self, args: dict[str, Any]) -> list[types.TextContent]:
        forwarded = dict(args)
        forwarded.setdefault("mode", "read")

        self._set_forwarded_if_missing(forwarded, "programpath", forwarded.get("binaryname"))
        self._set_forwarded_if_missing(forwarded, "addressorsymbol", forwarded.get("address"))
        if forwarded.get("length") is None and forwarded.get("size") is not None:
            forwarded["length"] = forwarded.get("size")

        return await self._handle(forwarded)

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Inspect memory blocks, read raw bytes, or list data items at addresses.
        
        **Modes**:
        - blocks/segments: List all memory blocks (names, addresses, permissions)
        - read: Read raw bytes from a specific address, with length clamping
        - data_items: List defined data objects with type and length information
        
        **Memory Block Permissions**: Represented as unix-style rwx notation:
            'rwx' = readable, writable, executable
            'r-x' = readable and executable (code), not writable
            'r--' = readable only (read-only data)
        
        **Design Notes**:
        - Byte reading clamps length to 10KB to prevent memory allocation issues
        - Gracefully handles partially-readable memory regions (byte-by-byte fallback)
        - Data items are paginated to handle large binaries with many defined data objects
        - Uses Ghidra API directly for memory access (DefinedDataIterator)
        
        Parameters
        ----------
        mode : str, default='blocks'
            Operation mode (blocks, read, data_items, or segments alias)
        addressOrSymbol : str  (required for read/data_items modes)
            Memory address or symbol name to read from
        length/size : int, default=256 (for read mode)
            Bytes to read, clamped to max 10000
        offset/startindex : int, default=0 (for data_items mode)
            Pagination offset
        limit/maxresults : int, default=100 (for data_items mode)
            Maximum data items to return
            
        Returns
        -------
        Response with memory information:
        - blocks mode: list of memory blocks
        - read mode: hex/ascii bytes at address
        - data_items mode: paginated list of defined data objects
        """
        self._require_program()
        mode = self._get_str(args, "mode", default="blocks")
        program = self.program_info.program
        memory = self._get_memory(program)

        mode_n = n(mode)

        if mode_n in ("blocks", "segments"):
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
            return create_success_response({"mode": mode, "blocks": blocks, "count": len(blocks)})

        if mode_n == "read":
            addr_str = self._require_address_or_symbol(args)
            length = self._get_int(args, "length", "size", "len", default=256)
            length = min(length, 10000)
            addr = self._resolve_address(addr_str, program=program)

            buf = bytearray(length)
            try:
                actual = memory.getBytes(addr, buf)
            except Exception:
                actual = 0
                for i in range(length):
                    try:
                        buf[i] = memory.getByte(addr.add(i)) & 0xFF
                        actual = i + 1
                    except Exception:
                        break

            hex_str = " ".join(f"{b:02x}" for b in buf[:actual])
            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in buf[:actual])

            return create_success_response(
                {
                    "mode": "read",
                    "address": str(addr),
                    "length": actual,
                    "hex": hex_str,
                    "ascii": ascii_str,
                },
            )

        if mode_n in ("dataat", "data"):
            addr_str = self._require_address_or_symbol(args)
            addr = self._resolve_address(addr_str, program=program)

            listing = self._get_listing(program)
            data = listing.getDataAt(addr)
            if data is None:
                # Try getDataContaining
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

        if mode_n == "dataitems":
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

        raise ValueError(f"Unknown mode: {mode}")
