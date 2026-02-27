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
)

logger = logging.getLogger(__name__)


class MemoryToolProvider(ToolProvider):
    HANDLERS = {"inspectmemory": "_handle"}

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
        ]

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        mode = self._get_str(args, "mode", default="blocks")
        program = self.program_info.program
        memory = program.getMemory()

        from agentdecompile_cli.registry import normalize_identifier as n

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
                    }
                )
            return create_success_response({"mode": mode, "blocks": blocks, "count": len(blocks)})

        if mode_n == "read":
            addr_str = self._require_str(args, "addressorsymbol", "address", "addr", "symbol", name="addressOrSymbol")
            length = self._get_int(args, "length", "size", "len", default=256)
            length = min(length, 10000)

            from agentdecompile_cli.mcp_utils.address_util import AddressUtil

            addr = AddressUtil.resolve_address_or_symbol(program, addr_str)

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
                }
            )

        if mode_n in ("dataat", "data"):
            addr_str = self._require_str(args, "addressorsymbol", "address", "addr", "symbol", name="addressOrSymbol")
            from agentdecompile_cli.mcp_utils.address_util import AddressUtil

            addr = AddressUtil.resolve_address_or_symbol(program, addr_str)

            listing = program.getListing()
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
                    }
                )
            return create_success_response(
                {
                    "mode": "data_at",
                    "address": str(addr),
                    "note": "No defined data at this address",
                }
            )

        if mode_n == "dataitems":
            max_results = self._get_int(args, "maxresults", "limit", default=100)
            offset = self._get_int(args, "offset", "startindex", default=0)

            listing = program.getListing()
            items = []
            count = 0
            for data in listing.getDefinedData(True):
                if count < offset:
                    count += 1
                    continue
                if len(items) >= max_results:
                    break
                items.append(
                    {
                        "address": str(data.getAddress()),
                        "dataType": str(data.getDataType()),
                        "length": data.getLength(),
                        "label": str(data.getLabel()) if hasattr(data, "getLabel") and data.getLabel() else None,
                    }
                )
                count += 1

            return create_success_response(
                {
                    "mode": "data_items",
                    "items": items,
                    "count": len(items),
                    "hasMore": count > offset + len(items),
                }
            )

        raise ValueError(f"Unknown mode: {mode}")
