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
        mode = self._get_str(args, "mode", "action", "operation", default="get")
        
        return await self._dispatch_handler(args, mode, {
            "set": "_handle_set",
            "add": "_handle_set",  # alias
            "get": "_handle_get",
            "list": "_handle_get",  # alias
            "remove": "_handle_remove",
            "delete": "_handle_remove",  # alias
            "search": "_handle_search",
            "search_decomp": "_handle_search_decomp",
            "searchdecomp": "_handle_search_decomp",  # alias
        })

    async def _handle_set(self, args: dict[str, Any]) -> list[types.TextContent]:
        assert self.program_info is not None, "Program info is required to set comments"
        program = self.program_info.program
        listing = self._get_listing(program)

        # Batch support
        batch = self._get_list(args, "comments")
        if batch:
            results = []
            def _set_batch_comments() -> None:
                for item in batch:
                    ni = {n(k): v for k, v in item.items()}
                    addr_str = self._get_str(ni, "addressorsymbol", "address", "addr")
                    text = self._get_str(ni, "comment", "text")
                    ctype = self._get_str(ni, "type", "commenttype", default="eol")
                    try:
                        addr = self._resolve_address(addr_str, program=program)
                        listing.setComment(addr, self._resolve_comment_type(ctype), text)
                        results.append({"address": addr_str, "success": True})
                    except Exception as e:
                        results.append({"address": addr_str, "success": False, "error": str(e)})
            self._run_program_transaction(program, "batch-set-comments", _set_batch_comments)
            return create_success_response({"action": "set", "batch": True, "results": results, "count": len(results)})

        # Single
        addr_str = self._require_str(args, "addressorsymbol", "address", "addr", "symbol", name="addressOrSymbol")
        text = self._require_str(args, "comment", "text", name="comment")
        ctype = self._get_str(args, "type", "commenttype", default="eol")

        addr = self._resolve_address(addr_str, program=program)
        def _set_comment() -> None:
            listing.setComment(addr, self._resolve_comment_type(ctype), text)
        self._run_program_transaction(program, "set-comment", _set_comment)
        return create_success_response({"action": "set", "address": str(addr), "type": ctype, "comment": text, "success": True})

    async def _handle_get(self, args: dict[str, Any]) -> list[types.TextContent]:
        assert self.program_info is not None, "Program info is required to get comments"
        program = self.program_info.program
        listing = self._get_listing(program)
        addr_str = self._require_str(args, "addressorsymbol", "address", "addr", "symbol", "function", name="addressOrSymbol")
        addr = self._resolve_address(addr_str, program=program)
        comments = {}
        for name, code in _COMMENT_TYPES.items():
            c = listing.getComment(code, addr)
            if c:
                comments[name] = c
        return create_success_response({"action": "get", "address": str(addr), "comments": comments})

    async def _handle_remove(self, args: dict[str, Any]) -> list[types.TextContent]:
        assert self.program_info is not None, "Program info is required to remove comments"
        program = self.program_info.program
        listing = self._get_listing(program)
        addr_str = self._require_str(args, "addressorsymbol", "address", "addr", "symbol", "function", name="addressOrSymbol")
        ctype = self._get_str(args, "type", "commenttype", default="eol")

        addr = self._resolve_address(addr_str, program=program)
        def _remove_comment() -> None:
            listing.setComment(addr, self._resolve_comment_type(ctype), None)
        self._run_program_transaction(program, "remove-comment", _remove_comment)
        return create_success_response({"action": "remove", "address": str(addr), "type": ctype, "success": True})

    async def _handle_search(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Search for comments in the program by text content.
        
        Iterates through all code units in the program, checking all comment types
        (EOL, plate, pre, post, repeatable) and matching against search text.
        Results are paginated to handle large binaries.
        
        **Design Notes**:
        - Searches all comment types (EOL, plate, pre, post, repeatable) simultaneously
        - Case-insensitive substring matching on comment text
        - Uses code unit iteration which handles all address spaces correctly
        - Gracefully handles programs that don't support address iteration
        
        Parameters
        ----------
        searchtext/query/search : str, optional
            Text to search for (case-insensitive substring match)
        offset/startindex : int, default=0
            Pagination offset
        limit/maxresults : int, default=100
            Maximum results to return
            
        Returns
        -------
        Paginated response with matching comments
        """
        assert self.program_info is not None, "Program info is required to search comments"
        program = self.program_info.program
        listing = self._get_listing(program)
        query = self._get_str(args, "searchtext", "query", "search", "text", "pattern")
        offset, max_results = self._get_pagination_params(args, default_limit=100)
        query_lower = query.lower() if query else ""

        mem = self._get_memory(program)
        addr_iter = mem.getAddresses(True) if hasattr(mem, "getAddresses") else None
        if addr_iter is None:
            return create_success_response({"action": "search", "results": [], "note": "Memory address iteration unavailable"})

        # Iterate code units looking for comments
        all_results: list[dict[str, str]] = []
        cu_iter: Any = listing.getCodeUnits(mem, True)
        while cu_iter.hasNext():
            cu = cu_iter.next()
            for name, code in _COMMENT_TYPES.items():
                c = cu.getComment(code)
                if c and (not query_lower or query_lower in c.lower()):
                    all_results.append({"address": str(cu.getAddress()), "type": name, "comment": c})

        paginated, has_more = self._paginate_results(all_results, offset, max_results)
        return self._create_paginated_response(paginated, offset, max_results, total=len(all_results), mode="search", query=query)

    async def _handle_search_decomp(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Search comments in decompiled output."""
        assert self.program_info is not None, "Program info is required for decomp search"
        program = self.program_info.program
        query = self._get_str(args, "searchtext", "query", "search", "text", "pattern")
        max_results = self._get_int(args, "maxresults", "limit", "maxcount", default=50)

        results = []
        try:
            from ghidra.app.decompiler import DecompInterface # pyright: ignore[reportMissingModuleSource]

            decomp = DecompInterface()
            decomp.openProgram(program)
            fm = self._get_function_manager(program)
            from ghidra.util.task import ConsoleTaskMonitor # pyright: ignore[reportMissingModuleSource]

            monitor = ConsoleTaskMonitor()
            for func in fm.getFunctions(True):
                if len(results) >= max_results:
                    break
                try:
                    dr = decomp.decompileFunction(func, 30, monitor)
                    if dr and dr.decompileCompleted():
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
