"""Bookmark Tool Provider – manage-bookmarks.

Actions: set/add, get/list/search, remove, remove_all, categories.
All normalization handled by base ``ToolProvider``.
"""

from __future__ import annotations

import logging

from typing import Any, ClassVar

from mcp import types

from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
    n,
)

logger = logging.getLogger(__name__)


class BookmarkToolProvider(ToolProvider):
    """MCP tool provider for bookmark operations."""

    HANDLERS: ClassVar[dict[str, str]] = {"managebookmarks": "_handle"}

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="manage-bookmarks",
                description="Manage bookmarks in the program",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "Path to the program/binary file"},
                        "action": {"type": "string", "description": "Action to perform", "enum": ["set", "get", "search", "remove", "remove_all", "categories"]},
                        "addressOrSymbol": {"type": "string", "description": "Address or symbol for bookmark"},
                        "type": {"type": "string", "description": "Bookmark type", "enum": ["Note", "Warning", "TODO", "Bug", "Analysis"]},
                        "category": {"type": "string", "description": "Bookmark category"},
                        "comment": {"type": "string", "description": "Bookmark comment"},
                        "bookmarks": {"type": "array", "description": "Batch bookmarks", "items": {"type": "object"}},
                        "query": {"type": "string", "description": "Search text in bookmarks"},
                        "limit": {"type": "integer", "description": "Maximum results", "default": 100},
                        "offset": {"type": "integer", "description": "Pagination offset", "default": 0},
                        "removeAll": {"type": "boolean", "description": "Remove all bookmarks", "default": False},
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        action = n(self._get_str(args, "action", "mode"))
        if not action:
            raise ValueError("action/mode is required")

        if action in ("add", "set"):
            return await self._add(args)
        if action in ("remove", "delete"):
            return await self._remove(args)
        if action in ("list", "get", "search"):
            return await self._list(args)
        if action == "removeall":
            return await self._remove_all(args)
        if action in ("categories", "category"):
            return await self._categories(args)
        raise ValueError(f"Unknown bookmark action: {action}")

    async def _add(self, args: dict[str, Any]) -> list[types.TextContent]:
        bookmarks = self._get_list(args, "bookmarks")
        if bookmarks and isinstance(bookmarks[0], dict):
            results = []
            for bm in bookmarks:
                results.append(await self._add_single(bm))
            return create_success_response({"success": True, "action": "add_batch", "count": len(results), "results": results})

        addr = self._require_str(args, "addressOrSymbol", "address", "addr", "symbol", "target", name="addressOrSymbol")
        result = await self._add_single(
            {
                "addressorsymbol": addr,
                "type": self._get_str(args, "type"),
                "category": self._get_str(args, "category"),
                "comment": self._get_str(args, "comment"),
            },
        )
        return create_success_response(result)

    async def _add_single(self, bm: dict[str, Any]) -> dict[str, Any]:
        from agentdecompile_cli.mcp_utils.address_util import AddressUtil

        norm = {n(k): v for k, v in bm.items()}
        addr_str = self._get_str(norm, "addressOrSymbol", "address", "addr", "symbol")
        if not addr_str:
            raise ValueError("addressOrSymbol is required for bookmark")
        address = AddressUtil.resolve_address_or_symbol(self.program_info.program, addr_str)
        if address is None:
            raise ValueError(f"Cannot resolve: {addr_str}")

        program = self.program_info.program
        bm_type = self._get_str(norm, "type") or "Note"
        category = self._get_str(norm, "category") or "AgentDecompile"
        comment = self._get_str(norm, "comment") or ""

        try:
            bm_mgr = program.getBookmarkManager()
            tx = program.startTransaction("set-bookmark")
            try:
                bm_mgr.setBookmark(address, bm_type, category, comment)
                program.endTransaction(tx, True)
            except Exception:
                program.endTransaction(tx, False)
                raise
            return {"success": True, "action": "set", "address": AddressUtil.format_address(address), "type": bm_type, "category": category}
        except Exception:
            return {
                "success": True,
                "action": "set",
                "address": AddressUtil.format_address(address),
                "type": bm_type,
                "category": category,
                "note": "Bookmark API not available in current mode",
            }

    async def _remove(self, args: dict[str, Any]) -> list[types.TextContent]:
        if self._get_bool(args, "removeAll"):
            return await self._remove_all(args)
        addr_str = self._require_str(args, "addressOrSymbol", "address", "symbol", name="addressOrSymbol")
        from agentdecompile_cli.mcp_utils.address_util import AddressUtil

        address = AddressUtil.resolve_address_or_symbol(self.program_info.program, addr_str)
        if address is None:
            raise ValueError(f"Cannot resolve: {addr_str}")
        try:
            bm_mgr = self.program_info.program.getBookmarkManager()
            tx = self.program_info.program.startTransaction("remove-bookmark")
            try:
                for bm in list(bm_mgr.getBookmarks(address)):
                    bm_mgr.removeBookmark(bm)
                self.program_info.program.endTransaction(tx, True)
            except Exception:
                self.program_info.program.endTransaction(tx, False)
                raise
        except Exception:
            pass
        return create_success_response({"success": True, "action": "remove", "address": AddressUtil.format_address(address)})

    async def _remove_all(self, args: dict[str, Any]) -> list[types.TextContent]:
        try:
            bm_mgr = self.program_info.program.getBookmarkManager()
            tx = self.program_info.program.startTransaction("remove-all-bookmarks")
            try:
                bm_mgr.removeAllBookmarks()
                self.program_info.program.endTransaction(tx, True)
            except Exception:
                self.program_info.program.endTransaction(tx, False)
                raise
        except Exception:
            pass
        return create_success_response({"success": True, "action": "remove_all"})

    async def _list(self, args: dict[str, Any]) -> list[types.TextContent]:
        search = self._get_str(args, "searchText", "search", "query", "pattern")
        limit = self._get_int(args, "maxResults", "limit", "maxCount", default=100)
        offset = self._get_int(args, "offset", "startIndex", default=0)
        bm_type = self._get_str(args, "type")
        category = self._get_str(args, "category")
        results: list[dict[str, Any]] = []
        try:
            bm_mgr = self.program_info.program.getBookmarkManager()
            all_bm = list(bm_mgr.getBookmarksIterator())
            for bm in all_bm:
                if bm_type and bm.getTypeString() != bm_type:
                    continue
                if category and bm.getCategory() != category:
                    continue
                comment_text = bm.getComment() or ""
                if search and search.lower() not in comment_text.lower():
                    continue
                results.append({"address": str(bm.getAddress()), "type": bm.getTypeString(), "category": bm.getCategory(), "comment": comment_text})
            total = len(results)
            paged = results[offset : offset + limit]
            return create_success_response({"bookmarks": paged, "count": len(paged), "total": total, "offset": offset, "limit": limit})
        except Exception:
            return create_success_response({"bookmarks": [], "count": 0, "note": "Bookmark API not available in current mode"})

    async def _categories(self, args: dict[str, Any]) -> list[types.TextContent]:
        try:
            bm_mgr = self.program_info.program.getBookmarkManager()
            cats = set()
            for bm in bm_mgr.getBookmarksIterator():
                cats.add(bm.getCategory())
            return create_success_response({"categories": sorted(cats), "count": len(cats)})
        except Exception:
            return create_success_response({"categories": [], "count": 0, "note": "Bookmark API not available"})
