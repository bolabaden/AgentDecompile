"""Comment Tool Provider - manage-comments.

Single tool, mode = set|get|remove|search|search_decomp. Ghidra comment types
(EOL, pre, post, plate, repeatable) are mapped to the _COMMENT_TYPES dict.
set/write at an address; get at address; search globally or search_decomp
(limit to decompiled function bodies). Uses _collectors.collect_comments for listing.
"""

from __future__ import annotations

import logging
import uuid

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ghidra.program.model.address import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        Address as GhidraAddress,
    )
    from ghidra.program.model.listing import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        Listing as GhidraListing,
    )

from mcp import types

from agentdecompile_cli.mcp_server.providers._collectors import collect_comments
from agentdecompile_cli.mcp_server.tool_providers import (
    FORCE_APPLY_CONFLICT_ID_KEY,
    ToolProvider,
    create_conflict_response,
    create_success_response,
    n,
)
from agentdecompile_cli.registry import Tool

logger = logging.getLogger(__name__)

# Ghidra comment type constants (int codes for Listing.getComment(int, Address))
_COMMENT_TYPES = {
    "eol": 0,  # CodeUnit.EOL_COMMENT
    "pre": 1,  # CodeUnit.PRE_COMMENT
    "post": 2,  # CodeUnit.POST_COMMENT
    "plate": 3,  # CodeUnit.PLATE_COMMENT
    "repeatable": 4,  # CodeUnit.REPEATABLE_COMMENT
}


def _get_listing_comment(listing: GhidraListing, comment_type_code: int, addr: GhidraAddress) -> str | None:
    """Get comment at address for the given type. Supports both Listing overloads:
    getComment(int, Address) and getComment(CommentType, Address).
    """
    logger.debug("diag.enter %s", "mcp_server/providers/comments.py:_get_listing_comment")
    try:
        return listing.getComment(comment_type_code, addr)
    except Exception as e:
        err_msg = str(e).lower()
        if "no matching overloads" not in err_msg and "getcomment" not in err_msg:
            raise
        try:
            from ghidra.program.model.listing import CommentType as GhidraCommentType  # pyright: ignore[reportMissingModuleSource]

            # CommentType enum order: EOL=0, PRE=1, POST=2, PLATE=3, REPEATABLE=4
            _by_code = (
                GhidraCommentType.EOL,
                GhidraCommentType.PRE,
                GhidraCommentType.POST,
                GhidraCommentType.PLATE,
                GhidraCommentType.REPEATABLE,
            )
            ctype_enum = _by_code[comment_type_code] if 0 <= comment_type_code < 5 else GhidraCommentType.EOL
            return listing.getComment(ctype_enum, addr)
        except Exception:
            raise e


class CommentToolProvider(ToolProvider):
    HANDLERS = {"managecomments": "_handle"}

    def list_tools(self) -> list[types.Tool]:
        logger.debug("diag.enter %s", "mcp_server/providers/comments.py:CommentToolProvider.list_tools")
        return [
            types.Tool(
                name=Tool.MANAGE_COMMENTS.value,
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
                        "limit": {
                            "type": "integer",
                            "default": 100,
                            "description": "Number of comment search results to return. Typical values are 100–500.",
                        },
                        "offset": {"type": "integer", "default": 0, "description": "Pagination tracking index."},
                    },
                    "required": [],
                },
            ),
        ]

    def _resolve_comment_type(self, type_str: str) -> int:
        logger.debug("diag.enter %s", "mcp_server/providers/comments.py:CommentToolProvider._resolve_comment_type")
        return _COMMENT_TYPES.get(n(type_str), 0)

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/comments.py:CommentToolProvider._handle")
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
        logger.debug("diag.enter %s", "mcp_server/providers/comments.py:CommentToolProvider._handle_set")
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
        comment_type_code = self._resolve_comment_type(ctype)

        if not args.get(FORCE_APPLY_CONFLICT_ID_KEY):
            existing = _get_listing_comment(listing, comment_type_code, addr)
            if existing is not None and str(existing).strip() and str(existing).strip() != text.strip():
                from agentdecompile_cli.mcp_server.conflict_store import store as conflict_store_store
                from agentdecompile_cli.mcp_server.session_context import get_current_mcp_session_id

                conflict_id = str(uuid.uuid4())
                conflict_summary = f"Set comment would overwrite existing comment at (address, type):\n\n```diff\n- {existing}\n+ {text}\n```"
                next_step = f'To apply this change, call `resolve-modification-conflict` with `conflictId` = "{conflict_id}" and `resolution` = "overwrite". To discard, use `resolution` = "skip".'
                program_path = args.get(n("programPath")) or getattr(self.program_info, "path", None) or getattr(self.program_info, "file_path", None)
                conflict_store_store(
                    get_current_mcp_session_id(),
                    conflict_id,
                    tool=Tool.MANAGE_COMMENTS.value,
                    arguments=dict(args),
                    program_path=str(program_path) if program_path else None,
                    summary=conflict_summary,
                )
                return create_conflict_response(conflict_id, Tool.MANAGE_COMMENTS.value, conflict_summary, next_step)

        def _set_comment() -> None:
            listing.setComment(addr, comment_type_code, text)

        self._run_program_transaction(program, "set-comment", _set_comment)
        return create_success_response({"action": "set", "address": str(addr), "type": ctype, "comment": text, "success": True})

    async def _handle_get(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/comments.py:CommentToolProvider._handle_get")
        assert self.program_info is not None, "Program info is required to get comments"
        program = self.program_info.program
        listing = self._get_listing(program)
        addr_str = self._require_str(args, "addressorsymbol", "address", "addr", "symbol", "function", name="addressOrSymbol")
        addr = self._resolve_address(addr_str, program=program)
        comments = {}
        for name, code in _COMMENT_TYPES.items():
            c = _get_listing_comment(listing, code, addr)
            if c:
                comments[name] = c
        return create_success_response({"action": "get", "address": str(addr), "comments": comments})

    async def _handle_remove(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/comments.py:CommentToolProvider._handle_remove")
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
        logger.debug("diag.enter %s", "mcp_server/providers/comments.py:CommentToolProvider._handle_search")
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
        logger.debug("diag.enter %s", "mcp_server/providers/comments.py:CommentToolProvider._handle_search_decomp")
        assert self.program_info is not None, "Program info is required for decomp search"
        program = self.program_info.program
        query = self._get_str(args, "searchtext", "query", "search", "text", "pattern")
        max_results = self._get_int(args, "maxresults", "limit", "maxcount", default=50)

        results: list[dict[str, str]] = []
        try:
            from ghidra.app.decompiler import DecompInterface  # pyright: ignore[reportMissingModuleSource]

            from agentdecompile_cli.mcp_utils.decompiler_util import get_decompiled_function_from_results

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
                        df = get_decompiled_function_from_results(dr)
                        code = df.getC() if df else ""
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
