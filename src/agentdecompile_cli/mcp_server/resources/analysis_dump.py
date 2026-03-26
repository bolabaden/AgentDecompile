"""Analysis Dump Resource - ghidra://analysis-dump.

Returns all bookmarks, programs, labels (symbols), comments, functions, data types,
and related analysis data in one JSON document. Optimized for large projects (~100k+ items):
single-pass iteration per category, minimal dicts, compact JSON (no indent).
"""

from __future__ import annotations

import json
import logging

from typing import Any

from mcp import types
from pydantic import AnyUrl

from agentdecompile_cli.mcp_server.providers._collectors import (
    _COMMENT_TYPES,
    iter_items,
)
from agentdecompile_cli.mcp_server.resource_providers import ResourceProvider
from agentdecompile_cli.mcp_server.session_context import (
    SESSION_CONTEXTS,
    get_current_mcp_session_id,
)

logger = logging.getLogger(__name__)

_URI = "ghidra://analysis-dump"


def _collect_bookmarks_fast(program: Any) -> list[dict[str, Any]]:
    """Single-pass bookmark iteration. Keys a/t/c/m match keyLegend (address, type, category, comment)."""
    logger.debug("diag.enter %s", "mcp_server/resources/analysis_dump.py:_collect_bookmarks_fast")
    out: list[dict[str, Any]] = []
    try:
        bm_mgr = program.getBookmarkManager()
        it = bm_mgr.getBookmarksIterator() if hasattr(bm_mgr, "getBookmarksIterator") else None
        if it is None:
            return out
        for bm in iter_items(it):
            out.append(
                {
                    "a": str(bm.getAddress()),
                    "t": str(bm.getTypeString()),
                    "c": str(bm.getCategory()),
                    "m": str(bm.getComment() or ""),
                },
            )
    except Exception as e:
        logger.debug("analysis_dump bookmarks: %s", e)
    return out


def _collect_symbols_fast(program: Any) -> list[dict[str, Any]]:
    """Single-pass symbol/label iteration."""
    logger.debug("diag.enter %s", "mcp_server/resources/analysis_dump.py:_collect_symbols_fast")
    out: list[dict[str, Any]] = []
    try:
        st = program.getSymbolTable()
        it = st.getAllSymbols(True) if hasattr(st, "getAllSymbols") else st.getSymbolIterator()
        for sym in iter_items(it):
            out.append(
                {
                    "n": str(sym.getName()),
                    "a": str(sym.getAddress()),
                    "y": str(sym.getSymbolType()),
                    "p": str(sym.getParentNamespace()),
                    "s": str(sym.getSource()),
                },
            )
    except Exception as e:
        logger.debug("analysis_dump symbols: %s", e)
    return out


def _collect_comments_fast(program: Any) -> list[dict[str, Any]]:
    """Single-pass comment iteration over code units."""
    logger.debug("diag.enter %s", "mcp_server/resources/analysis_dump.py:_collect_comments_fast")
    out: list[dict[str, Any]] = []
    try:
        listing = program.getListing()
        mem = program.getMemory()
        fm = program.getFunctionManager()
        cu_iter = listing.getCodeUnits(mem, True)
        while cu_iter.hasNext():
            cu = cu_iter.next()
            addr = cu.getAddress()
            container = fm.getFunctionContaining(addr)
            fn_name = str(container.getName()) if container else ""
            fn_addr = str(container.getEntryPoint()) if container else ""
            for ctype_name, ctype_code in _COMMENT_TYPES:
                txt = cu.getComment(ctype_code)
                if not txt:
                    continue
                out.append(
                    {
                        "a": str(addr),
                        "k": ctype_name,
                        "t": str(txt),
                        "f": fn_name,
                        "fa": fn_addr,
                    },
                )
    except Exception as e:
        logger.debug("analysis_dump comments: %s", e)
    return out


def _collect_functions_fast(program: Any) -> list[dict[str, Any]]:
    """Single-pass function iteration, minimal fields."""
    logger.debug("diag.enter %s", "mcp_server/resources/analysis_dump.py:_collect_functions_fast")
    out: list[dict[str, Any]] = []
    try:
        fm = program.getFunctionManager()
        for func in fm.getFunctions(True):
            body = func.getBody()
            naddr = body.getNumAddresses() if body else 0
            out.append(
                {
                    "n": str(func.getName()),
                    "a": str(func.getEntryPoint()),
                    "s": str(func.getSignature()),
                    "z": int(naddr),
                    "e": bool(func.isExternal()),
                    "k": bool(func.isThunk()),
                    "p": int(func.getParameterCount()),
                    "r": str(func.getReturnType()),
                },
            )
    except Exception as e:
        logger.debug("analysis_dump functions: %s", e)
    return out


def _collect_data_types_fast(program: Any) -> list[dict[str, Any]]:
    """Single-pass data type names (path + name only). Recursively walks category tree."""
    logger.debug("diag.enter %s", "mcp_server/resources/analysis_dump.py:_collect_data_types_fast")
    out: list[dict[str, Any]] = []
    try:
        dtm = program.getDataTypeManager()
        root = dtm.getRootCategory()

        def walk(cat: Any, path: str) -> None:
            # Each category: emit its data types, then recurse into subcategories
            for dt in iter_items(cat.getDataTypes()):
                out.append({"n": str(dt.getName()), "p": path or "/"})
            for sub in iter_items(cat.getCategories()):
                name = str(sub.getName())
                subpath = f"{path}/{name}" if path else f"/{name}"
                walk(sub, subpath)

        walk(root, "")
    except Exception as e:
        logger.debug("analysis_dump data types: %s", e)
    return out


def _collect_strings_fast(program: Any, limit: int = 50000) -> list[dict[str, Any]]:
    """Bounded string iteration; stops at limit to avoid huge dumps in string-heavy binaries."""
    logger.debug("diag.enter %s", "mcp_server/resources/analysis_dump.py:_collect_strings_fast")
    out: list[dict[str, Any]] = []
    try:
        from ghidra.program.util import DefinedDataIterator  # pyright: ignore[reportMissingModuleSource]

        for data in DefinedDataIterator.definedStrings(program):
            v = str(data.getValue() or "")
            if v:
                out.append({"a": str(data.getAddress()), "v": v[:500]})
            if len(out) >= limit:
                break
    except Exception as e:
        logger.debug("analysis_dump strings: %s", e)
    return out


def _collect_programs_from_session(session_id: str) -> list[dict[str, Any]]:
    """Program paths from session (open + project binaries)."""
    logger.debug("diag.enter %s", "mcp_server/resources/analysis_dump.py:_collect_programs_from_session")
    out: list[dict[str, Any]] = []
    try:
        session = SESSION_CONTEXTS.get_or_create(session_id)
        for path_key in session.open_programs or {}:
            out.append({"path": path_key})
        binaries = SESSION_CONTEXTS.get_project_binaries(session_id, fallback_to_latest=False)
        if binaries:
            seen = {p["path"] for p in out}
            for item in binaries:
                p = item.get("path") or item.get("programPath") or item.get("name") or ""
                if p and p not in seen:
                    seen.add(p)
                    out.append({"path": p, "name": item.get("name")})
    except Exception as e:
        logger.debug("analysis_dump programs: %s", e)
    return out


class AnalysisDumpResource(ResourceProvider):
    """MCP resource that returns all analysis data as one JSON document."""

    def list_resources(self) -> list[types.Resource]:
        logger.debug("diag.enter %s", "mcp_server/resources/analysis_dump.py:AnalysisDumpResource.list_resources")
        return [
            types.Resource(
                uri=AnyUrl(url=_URI),
                name="Analysis Dump",
                description="All bookmarks, programs, labels, comments, functions, data types, and strings in one JSON (compact, fast, for large projects)",
                mimeType="application/json",
            ),
        ]

    async def read_resource(self, uri: str) -> str:
        logger.debug("diag.enter %s", "mcp_server/resources/analysis_dump.py:AnalysisDumpResource.read_resource")
        if str(uri) != _URI:
            raise NotImplementedError(f"Unknown resource: {uri}")

        # No program loaded: return programs list + empty categories + keyLegend so clients can parse future dumps
        if self.program_info is None or getattr(self.program_info, "program", None) is None:
            logger.info("analysis-dump read: no program loaded, returning programs list only")
            session_id = get_current_mcp_session_id()
            programs = _collect_programs_from_session(session_id)
            payload = {
                "keyLegend": {
                    "a": "address",
                    "n": "name",
                    "t": "type/comment",
                    "c": "category",
                    "m": "comment",
                    "y": "symbolType",
                    "p": "path/params/parentNamespace",
                    "s": "signature/source",
                    "z": "size",
                    "e": "isExternal",
                    "k": "kind/isThunk",
                    "r": "returnType",
                    "v": "value",
                    "f": "function",
                    "fa": "functionAddress",
                },
                "programs": programs,
                "bookmarks": [],
                "symbols": [],
                "comments": [],
                "functions": [],
                "dataTypes": [],
                "strings": [],
                "summary": {"message": "No program loaded", "programs": len(programs)},
            }
            return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)

        program = self.program_info.program
        session_id = get_current_mcp_session_id()

        # Single-pass per category to keep memory and time predictable on large projects
        bookmarks = _collect_bookmarks_fast(program)
        symbols = _collect_symbols_fast(program)
        comments = _collect_comments_fast(program)
        functions = _collect_functions_fast(program)
        data_types = _collect_data_types_fast(program)
        strings = _collect_strings_fast(program)
        programs = _collect_programs_from_session(session_id)
        logger.info(
            "analysis-dump read: bookmarks=%s symbols=%s comments=%s functions=%s dataTypes=%s strings=%s",
            len(bookmarks),
            len(symbols),
            len(comments),
            len(functions),
            len(data_types),
            len(strings),
        )

        payload = {
            "keyLegend": {"a": "address", "n": "name", "t": "type/comment", "c": "category", "m": "comment", "y": "symbolType", "p": "path/params/parentNamespace", "s": "signature/source", "z": "size", "e": "isExternal", "k": "kind/isThunk", "r": "returnType", "v": "value", "f": "function", "fa": "functionAddress"},
            "programs": programs,
            "bookmarks": bookmarks,
            "symbols": symbols,
            "comments": comments,
            "functions": functions,
            "dataTypes": data_types,
            "strings": strings,
            "summary": {
                "bookmarks": len(bookmarks),
                "symbols": len(symbols),
                "comments": len(comments),
                "functions": len(functions),
                "dataTypes": len(data_types),
                "strings": len(strings),
                "programs": len(programs),
            },
        }
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
