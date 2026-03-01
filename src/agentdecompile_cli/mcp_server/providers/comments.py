"""Comment Tool Provider - manage-comments.

Actions: set, get, remove, search, search_decomp.
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

# Ghidra comment type constants
_COMMENT_TYPES = {
    "eol": 0,  # CodeUnit.EOL_COMMENT
    "pre": 1,  # CodeUnit.PRE_COMMENT
    "post": 2,  # CodeUnit.POST_COMMENT
    "plate": 3,  # CodeUnit.PLATE_COMMENT
    "repeatable": 4,  # CodeUnit.REPEATABLE_COMMENT
}


class CommentToolProvider(ToolProvider):
    HANDLERS = {"managecomments": "_handle"}

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="manage-comments",
                description="Manage comments in the program (EOL, PRE, POST, PLATE, REPEATABLE)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "mode": {"type": "string", "description": "Operation mode", "enum": ["set", "get", "remove", "search", "search_decomp"]},
                        "addressOrSymbol": {"type": "string", "description": "Address or symbol for comment"},
                        "comment": {"type": "string", "description": "Comment text"},
                        "type": {"type": "string", "enum": ["eol", "pre", "post", "plate", "repeatable"], "default": "eol"},
                        "comments": {"type": "array", "description": "Batch comments", "items": {"type": "object"}},
                        "query": {"type": "string", "description": "Search text or regex in comments"},
                        "limit": {"type": "integer", "default": 100},
                        "offset": {"type": "integer", "default": 0},
                    },
                    "required": [],
                },
            ),
        ]

    def _resolve_comment_type(self, type_str: str) -> int:
        return _COMMENT_TYPES.get(n(type_str), 0)

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        action = self._get_str(args, "mode", "action", "operation", default="get")

        dispatch = {
            "set": self._set,
            "add": self._set,
            "get": self._get_comments,
            "list": self._get_comments,
            "remove": self._remove,
            "delete": self._remove,
            "search": self._search,
            "searchdecomp": self._search_decomp,
        }
        handler = dispatch.get(n(action))
        if handler is None:
            raise ValueError(f"Unknown action: {action}. Valid: {list(dispatch.keys())}")
        return await handler(args)

    async def _set(self, args: dict[str, Any]) -> list[types.TextContent]:
        program = self.program_info.program
        listing = program.getListing()

        # Batch support
        batch = self._get_list(args, "comments")
        if batch:
            results = []
            tx = program.startTransaction("batch-set-comments")
            try:
                for item in batch:
                    ni = {n(k): v for k, v in item.items()}
                    addr_str = self._get_str(ni, "addressorsymbol", "address", "addr")
                    text = self._get_str(ni, "comment", "text")
                    ctype = self._get_str(ni, "type", "commenttype", default="eol")
                    try:
                        from agentdecompile_cli.mcp_utils.address_util import AddressUtil

                        addr = AddressUtil.resolve_address_or_symbol(program, addr_str)
                        listing.setComment(addr, self._resolve_comment_type(ctype), text)
                        results.append({"address": addr_str, "success": True})
                    except Exception as e:
                        results.append({"address": addr_str, "success": False, "error": str(e)})
                program.endTransaction(tx, True)
            except Exception:
                program.endTransaction(tx, False)
                raise
            return create_success_response({"action": "set", "batch": True, "results": results, "count": len(results)})

        # Single
        addr_str = self._require_str(args, "addressorsymbol", "address", "addr", "symbol", name="addressOrSymbol")
        text = self._require_str(args, "comment", "text", name="comment")
        ctype = self._get_str(args, "type", "commenttype", default="eol")

        from agentdecompile_cli.mcp_utils.address_util import AddressUtil

        addr = AddressUtil.resolve_address_or_symbol(program, addr_str)
        tx = program.startTransaction("set-comment")
        try:
            listing.setComment(addr, self._resolve_comment_type(ctype), text)
            program.endTransaction(tx, True)
        except Exception:
            program.endTransaction(tx, False)
            raise
        return create_success_response({"action": "set", "address": str(addr), "type": ctype, "comment": text, "success": True})

    async def _get_comments(self, args: dict[str, Any]) -> list[types.TextContent]:
        program = self.program_info.program
        listing = program.getListing()
        addr_str = self._require_str(args, "addressorsymbol", "address", "addr", "symbol", "function", name="addressOrSymbol")

        from agentdecompile_cli.mcp_utils.address_util import AddressUtil

        addr = AddressUtil.resolve_address_or_symbol(program, addr_str)
        comments = {}
        for name, code in _COMMENT_TYPES.items():
            c = listing.getComment(code, addr)
            if c:
                comments[name] = c
        return create_success_response({"action": "get", "address": str(addr), "comments": comments})

    async def _remove(self, args: dict[str, Any]) -> list[types.TextContent]:
        program = self.program_info.program
        listing = program.getListing()
        addr_str = self._require_str(args, "addressorsymbol", "address", "addr", "symbol", "function", name="addressOrSymbol")
        ctype = self._get_str(args, "type", "commenttype", default="eol")

        from agentdecompile_cli.mcp_utils.address_util import AddressUtil

        addr = AddressUtil.resolve_address_or_symbol(program, addr_str)
        tx = program.startTransaction("remove-comment")
        try:
            listing.setComment(addr, self._resolve_comment_type(ctype), None)
            program.endTransaction(tx, True)
        except Exception:
            program.endTransaction(tx, False)
            raise
        return create_success_response({"action": "remove", "address": str(addr), "type": ctype, "success": True})

    async def _search(self, args: dict[str, Any]) -> list[types.TextContent]:
        program = self.program_info.program
        listing = program.getListing()
        query = self._get_str(args, "searchtext", "query", "search", "text", "pattern")
        max_results = self._get_int(args, "maxresults", "limit", "max", "maxcount", default=100)
        offset = self._get_int(args, "offset", "startindex", default=0)
        query_lower = query.lower() if query else ""

        results = []
        count = 0
        mem = program.getMemory()
        addr_iter = mem.getAddresses(True) if hasattr(mem, "getAddresses") else None
        if addr_iter is None:
            return create_success_response({"action": "search", "results": [], "note": "Memory address iteration unavailable"})

        # Iterate code units looking for comments
        cu_iter = listing.getCodeUnits(program.getMemory(), True)
        while cu_iter.hasNext():
            cu = cu_iter.next()
            for name, code in _COMMENT_TYPES.items():
                c = cu.getComment(code)
                if c and (not query_lower or query_lower in c.lower()):
                    if count >= offset:
                        results.append({"address": str(cu.getAddress()), "type": name, "comment": c})
                    count += 1
                    if len(results) >= max_results:
                        return create_success_response(
                            {
                                "action": "search",
                                "query": query,
                                "results": results,
                                "count": len(results),
                                "hasMore": True,
                            },
                        )
        return create_success_response(
            {
                "action": "search",
                "query": query,
                "results": results,
                "count": len(results),
                "hasMore": False,
            },
        )

    async def _search_decomp(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Search comments in decompiled output."""
        program = self.program_info.program
        query = self._get_str(args, "searchtext", "query", "search", "text", "pattern")
        max_results = self._get_int(args, "maxresults", "limit", "maxcount", default=50)

        results = []
        try:
            from ghidra.app.decompiler import DecompInterface

            decomp = DecompInterface()
            decomp.openProgram(program)
            fm = program.getFunctionManager()
            for func in fm.getFunctions(True):
                if len(results) >= max_results:
                    break
                try:
                    dr = decomp.decompileFunction(func, 30, None)
                    if dr and dr.depiledFunction():
                        code = dr.getDecompiledFunction().getC()
                        if code and query.lower() in code.lower():
                            results.append(
                                {
                                    "function": func.getName(),
                                    "address": str(func.getEntryPoint()),
                                    "snippet": code[:500],
                                },
                            )
                except Exception:
                    continue
            decomp.dispose()
        except Exception as e:
            logger.warning(f"Decompiler search failed: {e}")
            return create_success_response({"action": "search_decomp", "results": [], "note": str(e)})

        return create_success_response({"action": "search_decomp", "query": query, "results": results, "count": len(results)})
