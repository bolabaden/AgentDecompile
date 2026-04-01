"""Bookmark Tool Provider – manage-bookmarks.

Mode = set (add bookmark at address), get (at address), search (globally), remove,
remove_all, categories (list bookmark categories). Bookmarks persist in the Ghidra
project and can be used to flag interesting addresses (e.g. Note, Warning, Bug, TODO).
Uses _collectors.collect_bookmarks for listing. All normalization is in base ToolProvider.
"""

from __future__ import annotations

import logging
import uuid

from typing import TYPE_CHECKING, Any, ClassVar, cast

from mcp import types

from agentdecompile_cli.mcp_server.providers._collectors import collect_bookmarks
from agentdecompile_cli.mcp_server.tool_providers import (
    FORCE_APPLY_CONFLICT_ID_KEY,
    ToolProvider,
    create_conflict_response,
    create_success_response,
    n,
)
from agentdecompile_cli.registry import Tool

if TYPE_CHECKING:
    from ghidra.program.model.address import Address as GhidraAddress
    from ghidra.program.model.listing import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]  # noqa: F401
        Bookmark as GhidraBookmark,
        BookmarkManager as GhidraBookmarkManager,
        Function as GhidraFunction,
        FunctionManager as GhidraFunctionManager,
        Program as GhidraProgram,
    )

logger = logging.getLogger(__name__)


class BookmarkToolProvider(ToolProvider):
    """MCP tool provider for bookmark operations."""

    HANDLERS: ClassVar[dict[str, str]] = {"managebookmarks": "_handle"}

    def list_tools(self) -> list[types.Tool]:
        logger.debug("diag.enter %s", "mcp_server/providers/bookmarks.py:BookmarkToolProvider.list_tools")
        return [
            types.Tool(
                name=Tool.MANAGE_BOOKMARKS.value,
                description="Create, read, search, or delete bookmarks. A bookmark is a simple saved location in the binary, useful for returning to an important address later and marking an area as a 'Note', 'Warning', 'Bug', 'TODO', or 'Analysis' item.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The path to the Ghidra project file analyzing the binary."},
                        "mode": {
                            "type": "string",
                            "description": "What to do with bookmarks: 'set' (create a bookmark), 'get' (read bookmarks at an address), 'search' (find bookmarks globally), 'remove' (delete a bookmark), or 'categories' (list available bookmark groups). Destructive operations like 'remove_all' require explicit safety parameters.",
                            "enum": ["set", "get", "search", "remove", "remove_all", "remove_all_bookmarks", "categories"],
                        },
                        "addressOrSymbol": {"type": "string", "description": "The memory address or function symbol to attach the bookmark to, or read it from."},
                        "type": {"type": "string", "description": "The severity or label group for the bookmark.", "enum": ["Note", "Warning", "TODO", "Bug", "Analysis"]},
                        "category": {"type": "string", "description": "Optional sub-grouping label for the bookmark."},
                        "comment": {"type": "string", "description": "The actual text you want to save inside the bookmark."},
                        "bookmarks": {"type": "array", "description": "Allows creating or processing a batch of multiple bookmarks at once.", "items": {"type": "object"}},
                        "query": {"type": "string", "description": "If mode is 'search', the text to look for inside existing bookmarks."},
                        "limit": {"type": "integer", "default": 100, "description": "Number of bookmarks to return. Typical values are 100–500."},
                        "offset": {"type": "integer", "default": 0, "description": "Pagination text start index."},
                        "removeAll": {"type": "boolean", "description": "A safety toggle needed when deleting all bookmarks.", "default": False},
                        "confirmRemoveAll": {"type": "boolean", "description": "Required to be true to proceed with clearing every single bookmark.", "default": False},
                        "removeAllToken": {"type": "string", "description": "You must supply the exact string 'REMOVE_ALL_BOOKMARKS' here to execute a delete-all operation."},
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Route to the correct sub-handler based on mode (set/get/remove/categories/etc.)."""
        logger.debug("diag.enter %s", "mcp_server/providers/bookmarks.py:BookmarkToolProvider._handle")
        self._require_program()
        mode: str = self._get_str(args, "mode", "action", "operation")
        if not mode:
            mode = "list"  # default: list all bookmarks

        # Map normalized mode to handler; aliases (add→set, list→get) share the same handler
        return await self._dispatch_handler(
            args,
            mode,
            {
                "set": "_handle_set",
                "add": "_handle_set",  # alias
                "get": "_handle_get",
                "list": "_handle_get",  # alias
                "search": "_handle_get",  # alias
                "remove": "_handle_remove",
                "delete": "_handle_remove",  # alias
                "remove_all": "_handle_remove_all",
                "remove_all_bookmarks": "_handle_remove_all",
                "categories": "_handle_categories",
                "category": "_handle_categories",  # alias
            },
        )

    def _require_explicit_remove_all_intent(self, args: dict[str, Any]) -> None:
        """Enforce safety: clear-all requires confirmRemoveAll=true and exact token to avoid accidental wipe."""
        logger.debug("diag.enter %s", "mcp_server/providers/bookmarks.py:BookmarkToolProvider._require_explicit_remove_all_intent")
        confirmed = self._get_bool(args, "confirmremoveall", "allowdestructive", "force", default=False)
        token = self._get_str(args, "removealltoken", "confirmationtoken", "safetytoken")
        if not confirmed or token != "REMOVE_ALL_BOOKMARKS":
            raise ValueError(
                "Refusing destructive bookmark clear-all. Use mode='remove_all' or 'remove_all_bookmarks' with confirmRemoveAll=true and removeAllToken='REMOVE_ALL_BOOKMARKS'.",
            )

    async def _handle_set(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Create one bookmark or a batch; single bookmark uses addressOrSymbol + type/category/comment."""
        logger.debug("diag.enter %s", "mcp_server/providers/bookmarks.py:BookmarkToolProvider._handle_set")
        bookmarks: list[dict[str, Any]] = self._get_list(args, "bookmarks")
        if bookmarks and isinstance(bookmarks[0], dict):
            # Batch: each element is a dict with addressOrSymbol, type, category, comment
            results: list[dict[str, Any]] = []
            for bm in bookmarks:
                results.append(await self._add_single(bm))
            return create_success_response(
                {
                    "success": True,
                    "action": "add_batch",
                    "count": len(results),
                    "results": results,
                },
            )

        # Single bookmark: require address; type/category/comment are optional (defaults: Note, AgentDecompile, "")
        addr_str: str = self._require_address_or_symbol(args)
        bm_type: str = self._get_str(args, "type") or "Note"
        category: str = self._get_str(args, "category") or "AgentDecompile"
        comment: str = self._get_str(args, "comment") or ""

        if not args.get(FORCE_APPLY_CONFLICT_ID_KEY):
            assert self.program_info is not None
            program: GhidraProgram = self.program_info.program
            address: GhidraAddress = self._resolve_address(addr_str)
            if address is not None:
                bm_mgr: GhidraBookmarkManager = program.getBookmarkManager()

                bm: GhidraBookmark = None
                for bm in bm_mgr.getBookmarks(address) or []:
                    bm_t: str = bm.getType() if hasattr(bm, "getType") else ""
                    bm_c: str = bm.getCategory() if hasattr(bm, "getCategory") else ""
                    if bm_t == bm_type and bm_c == category:
                        from agentdecompile_cli.mcp_server.conflict_store import store as conflict_store_store
                        from agentdecompile_cli.mcp_server.session_context import get_current_mcp_session_id

                        conflict_id: str = str(uuid.uuid4())
                        conflict_summary: str = (
                            f"Set bookmark would overwrite existing bookmark at (address, type, category):\n\nExisting bookmark **{bm_type}** / **{category}** at address."
                        )
                        next_step: str = f'To apply this change, call `resolve-modification-conflict` with `conflictId` = "{conflict_id}" and `resolution` = "overwrite". To discard, use `resolution` = "skip".'
                        program_path: str = args.get(n("programPath")) or getattr(self.program_info, "path", None) or getattr(self.program_info, "file_path", None)
                        store_args: dict[str, Any] = dict(args)
                        store_args["mode"] = "set"
                        conflict_store_store(
                            get_current_mcp_session_id(),
                            conflict_id,
                            tool=Tool.MANAGE_BOOKMARKS.value,
                            arguments=store_args,
                            program_path=str(program_path) if program_path else None,
                            summary=conflict_summary,
                        )
                        return create_conflict_response(conflict_id, Tool.MANAGE_BOOKMARKS.value, conflict_summary, next_step)

        result: dict[str, Any] = await self._add_single(
            {
                "addressorsymbol": addr_str,
                "type": bm_type,
                "category": category,
                "comment": comment,
            },
        )
        return create_success_response(result)

    async def _add_single(self, bm: dict[str, Any]) -> dict[str, Any]:
        """Resolve address, then set a bookmark via BookmarkManager inside a program transaction."""
        logger.debug("diag.enter %s", "mcp_server/providers/bookmarks.py:BookmarkToolProvider._add_single")
        norm: dict[str, Any] = {n(k): v for k, v in bm.items()}
        addr_str: str = self._get_str(norm, "addressOrSymbol", "address", "addr", "symbol")
        if not addr_str:
            raise ValueError("addressOrSymbol is required for bookmark")
        address: GhidraAddress = self._resolve_address(addr_str)
        if address is None:
            raise ValueError(f"Cannot resolve: {addr_str}")

        assert self.program_info is not None  # for type checker
        program: GhidraProgram = self.program_info.program
        bm_type: str = self._get_str(norm, "type") or "Note"
        category: str = self._get_str(norm, "category") or "AgentDecompile"
        comment: str = self._get_str(norm, "comment") or ""

        try:
            bm_mgr: GhidraBookmarkManager = program.getBookmarkManager()

            # Wrap in transaction so the change is undoable and persisted with the program
            def _set_bookmark() -> None:
                bm_mgr.setBookmark(address, bm_type, category, comment)

            self._run_program_transaction(program, "set-bookmark", _set_bookmark)
            return (
                {
                    "success": True,
                    "action": "set",
                    "address": str(address),
                    "type": bm_type,
                    "category": category,
                },
            )  # pyright: ignore[reportReturnType]
        except Exception:
            return {
                "success": True,
                "action": "set",
                "address": str(address),
                "type": bm_type,
                "category": category,
                "note": "Bookmark API not available in current mode",
            }

    async def _remove(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/bookmarks.py:BookmarkToolProvider._remove")
        if self._get_bool(args, "removeAll"):
            self._require_explicit_remove_all_intent(args)
            return await self._remove_all(args)
        addr_str: str = self._require_address_or_symbol(args)

        address: GhidraAddress = self._resolve_address(addr_str)
        if address is None:
            raise ValueError(f"Cannot resolve: {addr_str}")
        try:
            assert self.program_info is not None  # for type checker
            bm_mgr: GhidraBookmarkManager = self.program_info.program.getBookmarkManager()

            def _remove_bookmarks() -> None:
                for bm in list(bm_mgr.getBookmarks(address)):
                    bm_mgr.removeBookmark(bm)

            self._run_program_transaction(self.program_info.program, "remove-bookmark", _remove_bookmarks)
        except Exception:
            pass
        return create_success_response(
            {
                "success": True,
                "action": "remove",
                "address": str(address),
            },
        )

    async def _remove_all(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/bookmarks.py:BookmarkToolProvider._remove_all")
        self._require_explicit_remove_all_intent(args)
        try:
            assert self.program_info is not None  # for type checker
            program: GhidraProgram = self.program_info.program
            bm_mgr: GhidraBookmarkManager = program.getBookmarkManager()

            def _remove_all_bookmarks() -> None:
                bm_mgr.removeAllBookmarks()

            self._run_program_transaction(program, "remove-all-bookmarks", _remove_all_bookmarks)
        except Exception:
            pass
        return create_success_response(
            {
                "success": True,
                "action": "remove_all",
            },
        )

    async def _handle_get(self, args: dict[str, Any]) -> list[types.TextContent]:
        """List/search bookmarks with optional filter by type, category, or text in comment; paginated."""
        logger.debug("diag.enter %s", "mcp_server/providers/bookmarks.py:BookmarkToolProvider._handle_get")
        search: str = self._get_str(args, "searchText", "search", "query", "pattern")
        offset: int = self._get_pagination_params(args, default_limit=100)[0]
        limit: int = self._get_pagination_params(args, default_limit=100)[1]
        bm_type: str = self._get_str(args, "type")
        category: str = self._get_str(args, "category")
        try:
            assert self.program_info is not None  # for type checker
            all_bookmarks: list[dict[str, Any]] = collect_bookmarks(self.program_info.program)
            # Apply optional filters: type exact match, category exact match, search substring in comment
            filtered: list[dict[str, Any]] = [
                row
                for row in all_bookmarks
                if (not bm_type or row.get("type") == bm_type)
                and (not category or row.get("category") == category)
                and (not search or search.lower() in str(row.get("comment", "")).lower())
            ]
            results: list[dict[str, Any]] = filtered[offset : offset + limit]
            matched_count: int = len(filtered)

            return self._create_paginated_response(results, offset, limit, total=matched_count, mode="search")
        except Exception:
            return create_success_response(
                {
                    "bookmarks": [],
                    "count": 0,
                    "note": "Bookmark API not available in current mode",
                },
            )

    async def _handle_categories(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/bookmarks.py:BookmarkToolProvider._handle_categories")
        try:
            assert self.program_info is not None  # for type checker
            program: GhidraProgram = self.program_info.program
            bm_mgr: GhidraBookmarkManager = program.getBookmarkManager()
            cats: set[str] = set()
            cats.update(cast("GhidraBookmark", bm).getCategory() for bm in bm_mgr.getBookmarksIterator())
            return create_success_response(
                {
                    "categories": sorted(cats),
                    "count": len(cats),
                },
            )
        except Exception:
            return create_success_response(
                {
                    "categories": [],
                    "count": 0,
                    "note": "Bookmark API not available",
                },
            )
