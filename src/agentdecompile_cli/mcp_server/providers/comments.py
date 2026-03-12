"""Comment Tool Provider - manage-comments.

Actions: set, get, remove, search, search_decomp.
"""

from __future__ import annotations

import logging

from typing import Any

from mcp import types

from agentdecompile_cli.mcp_server.providers._collectors import collect_comments
from agentdecompile_cli.registry import ToolName
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
                name=ToolName.MANAGE_COMMENTS.value,
                description="Read, write, search, or delete notes left for other analysts (or yourself) at specific lines of assembly or decompiled pseudo-code. Use this to document what complicated logic means as you figure it out.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The path to the program containing the comments."},
                        "mode": {
                            "type": "string",
                            "description": "What to do: 'get' (read comments at an address), 'set' (write a new comment), 'remove' (delete a comment), 'search' (find text inside all comments globally), or 'search_decomp' (same as search, but limits to functions, triggering decompilation if needed).",
                            "enum": ["set", "get", "remove", "search", "search_decomp"],
                        },
                        "addressOrSymbol": {"type": "string", "description": "The exact memory address or symbol where the comment belongs."},
                        "comment": {"type": "string", "description": "The plain text content of the annotation to save."},
                        "type": {
                            "type": "string",
                            "enum": ["eol", "pre", "post", "plate", "repeatable"],
                            "default": "eol",
                            "description": "Where the comment physically appears: 'eol' (at the end of a line, normal right-side), 'pre' (block above the line), 'post' (block below the line), 'plate' (large boxed header comment), or 'repeatable' (appears everywhere the data is referenced).",
                        },
                        "comments": {"type": "array", "description": "Batch creation parameter for multiple comments at once.", "items": {"type": "object"}},
                        "query": {"type": "string", "description": "If searching, the word, phrase, or regular expression you are looking for."},
                        "limit": {"type": "integer", "default": 100, "description": "Number of comment search results to return. Typical values are 100–500. Do not set this below 50 unless the user explicitly asks for only a handful of results."},
                        "offset": {"type": "integer", "default": 0, "description": "Pagination tracking index."},
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

        return await self._dispatch_handler(
            args,
            mode,
            {
                "set": "_handle_set",
                "add": "_handle_set",  # alias
                "get": "_handle_get",
                "list": "_handle_get",  # alias
                "remove": "_handle_remove",
                "delete": "_handle_remove",  # alias
                "search": "_handle_search",
                "search_decomp": "_handle_search_decomp",
                "searchdecomp": "_handle_search_decomp",  # alias
            },
        )

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

        Returns:
        -------
        Paginated response with matching comments
        """
        assert self.program_info is not None, "Program info is required to search comments"
        program = self.program_info.program
        query = self._get_str(args, "searchtext", "query", "search", "text", "pattern")
        offset, max_results = self._get_pagination_params(args, default_limit=100)
        query_lower = query.lower() if query else ""

        all_results = [
            {
                "address": row.get("address", ""),
                "type": row.get("commentType", ""),
                "comment": row.get("comment", ""),
            }
            for row in collect_comments(program)
            if not query_lower or query_lower in str(row.get("comment", "")).lower()
        ]

        paginated, has_more = self._paginate_results(all_results, offset, max_results)
        return self._create_paginated_response(paginated, offset, max_results, total=len(all_results), mode="search", query=query)

    async def _handle_search_decomp(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Search comments in decompiled output."""
        assert self.program_info is not None, "Program info is required for decomp search"
        program = self.program_info.program
        query = self._get_str(args, "searchtext", "query", "search", "text", "pattern")
        max_results = self._get_int(args, "maxresults", "limit", "maxcount", default=50)

        results: list[dict[str, str]] = []
        try:
            from ghidra.app.decompiler import DecompInterface  # pyright: ignore[reportMissingModuleSource]

            decomp = DecompInterface()
            decomp.openProgram(program)
            fm = self._get_function_manager(program)
            from ghidra.util.task import ConsoleTaskMonitor  # pyright: ignore[reportMissingModuleSource]

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
            logger.warning(f"Decompiler search failed: {e.__class__.__name__}: {e}")
            return create_success_response({"action": "search_decomp", "results": [], "note": {e.__class__.__name__: str(e)}, "query": query})

        return create_success_response({"action": "search_decomp", "query": query, "results": results, "count": len(results)})
