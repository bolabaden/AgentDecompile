"""Strings Tool Provider - manage-strings.

Modes: list, regex, count, similarity.
"""

from __future__ import annotations

import logging
import re

from typing import Any

from mcp import types

from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
)

logger = logging.getLogger(__name__)


class StringToolProvider(ToolProvider):
    HANDLERS = {
        "managestrings": "_handle",
        "liststrings": "_handle_list_strings",
        "searchstrings": "_handle_search_strings",
    }

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="manage-strings",
                description="Search and manage string data in the program",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "mode": {"type": "string", "enum": ["list", "regex", "count", "similarity"], "default": "list"},
                        "query": {"type": "string", "description": "Search query or regex pattern"},
                        "minLength": {"type": "integer", "default": 4},
                        "limit": {"type": "integer", "default": 100},
                        "offset": {"type": "integer", "default": 0},
                        "includeReferencingFunctions": {"type": "boolean", "default": False},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="list-strings",
                description="List strings (alias for manage-strings mode=list)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "minLength": {"type": "integer", "default": 4},
                        "limit": {"type": "integer", "default": 100},
                        "offset": {"type": "integer", "default": 0},
                        "includeReferencingFunctions": {"type": "boolean", "default": False},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="search-strings",
                description="Search strings (alias for manage-strings mode=regex/similarity/list)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "query": {"type": "string"},
                        "mode": {"type": "string", "enum": ["regex", "similarity", "list"], "default": "list"},
                        "limit": {"type": "integer", "default": 100},
                        "offset": {"type": "integer", "default": 0},
                        "includeReferencingFunctions": {"type": "boolean", "default": False},
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle_list_strings(self, args: dict[str, Any]) -> list[types.TextContent]:
        updated = dict(args)
        updated["mode"] = "list"
        return await self._handle(updated)

    async def _handle_search_strings(self, args: dict[str, Any]) -> list[types.TextContent]:
        updated = dict(args)
        if not self._get_str(updated, "mode"):
            updated["mode"] = "list"
        return await self._handle(updated)

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        mode = self._get_str(args, "mode", default="list")
        pattern = self._get_str(args, "pattern", "query", "search", "text", "regex", "searchstring", "filter")
        min_len = self._get_int(args, "minlength", "minlen", default=4)
        max_results = self._get_int(args, "maxresults", "limit", "max", "maxcount", default=100)
        offset = self._get_int(args, "offset", "startindex", default=0)
        include_refs = self._get_bool(args, "includereferencingfunctions", "includerefs", default=False)

        # Try GhidraTools first
        if self.ghidra_tools is not None:
            try:
                all_strings = self.ghidra_tools.get_all_strings()
                return self._filter_strings(all_strings, mode, pattern, min_len, max_results, offset, include_refs)
            except Exception as e:
                logger.warning(f"GhidraTools.get_all_strings failed: {e}")

        # Direct Ghidra API
        program = self.program_info.program
        strings = []
        try:
            from ghidra.program.util import DefinedDataIterator

            for data in DefinedDataIterator.definedStrings(program):
                val = str(data.getValue()) if data.getValue() else ""
                if len(val) < min_len:
                    continue
                strings.append(
                    {
                        "address": str(data.getAddress()),
                        "value": val,
                        "length": len(val),
                        "dataType": str(data.getDataType()),
                    }
                )
        except Exception as e:
            logger.warning(f"String iteration error: {e}")

        return self._filter_strings(strings, mode, pattern, min_len, max_results, offset, include_refs)

    def _filter_strings(self, strings: list, mode: str, pattern: str, min_len: int, max_results: int, offset: int, include_refs: bool) -> list[types.TextContent]:
        from agentdecompile_cli.registry import normalize_identifier as n

        mode_n = n(mode)

        if mode_n == "count":
            return create_success_response({"mode": "count", "totalStrings": len(strings)})

        if mode_n == "regex" and pattern:
            try:
                pat = re.compile(pattern, re.IGNORECASE)
                strings = [s for s in strings if pat.search(s.get("value", ""))]
            except re.error as e:
                raise ValueError(f"Invalid regex pattern: {e}")

        elif mode_n == "similarity" and pattern:
            query_lower = pattern.lower()
            scored = []
            for s in strings:
                val = s.get("value", "").lower()
                if query_lower in val:
                    score = len(query_lower) / max(len(val), 1)
                    scored.append((score, s))
            scored.sort(key=lambda x: x[0], reverse=True)
            strings = [s for _, s in scored]

        elif pattern:
            p_lower = pattern.lower()
            strings = [s for s in strings if p_lower in s.get("value", "").lower()]

        total = len(strings)
        strings = strings[offset : offset + max_results]

        if include_refs and self.program_info:
            try:
                program = self.program_info.program
                ref_mgr = program.getReferenceManager()
                fm = program.getFunctionManager()
                for s in strings:
                    try:
                        from agentdecompile_cli.mcp_utils.address_util import AddressUtil

                        addr = AddressUtil.resolve_address_or_symbol(program, s["address"])
                        refs = list(ref_mgr.getReferencesTo(addr))
                        funcs = set()
                        for ref in refs[:20]:
                            f = fm.getFunctionContaining(ref.getFromAddress())
                            if f:
                                funcs.add(f.getName())
                        s["referencingFunctions"] = sorted(funcs)
                    except Exception:
                        pass
            except Exception:
                pass

        return create_success_response(
            {
                "mode": mode,
                "results": strings,
                "count": len(strings),
                "total": total,
                "offset": offset,
                "hasMore": offset + len(strings) < total,
            }
        )
