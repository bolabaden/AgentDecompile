"""Cross References Tool Provider - get-references, list-cross-references.

- get-references: Find references to/from an address. Mode = to (who references this),
  from (what this references), both, function (refs within a function), referencers_decomp,
  import, thunk. Paginated via limit/offset.
- list-cross-references: Alias that delegates to get-references with same semantics.
- When the target is in the .rsrc section, refs "to" also include LoadStringA/LoadStringW call sites,
  since resource strings are referenced indirectly via those APIs rather than direct code xrefs.
"""

from __future__ import annotations

import logging

from typing import Any

from mcp import types

from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
)
from agentdecompile_cli.registry import Tool

logger = logging.getLogger(__name__)

# APIs that load resource strings; .rsrc strings have no direct code xrefs.
_LOADSTRING_NAMES = ("LoadStringA", "LoadStringW", "LoadString")


class CrossReferencesToolProvider(ToolProvider):
    HANDLERS = {
        "getreferences": "_handle",
        "listcrossreferences": "_handle_list_cross_references",
    }

    def list_tools(self) -> list[types.Tool]:
        logger.debug("diag.enter %s", "mcp_server/providers/xrefs.py:CrossReferencesToolProvider.list_tools")
        return [
            types.Tool(
                name=Tool.GET_REFERENCES.value,
                description="Find all locations in the code that point to (call/read) or are pointed to by (called/written) a specific memory address. For targets in the .rsrc section, also includes LoadStringA/LoadStringW call sites (resource strings are referenced indirectly).",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The active program project."},
                        "addressOrSymbol": {"type": "string", "description": "The target hex address or symbol name. Supports both thunk addresses (e.g. CreateFileA @ 0x004011fc) and IAT addresses (e.g. 0x48f1fc); IAT is resolved to the thunk for consistent results."},
                        "target": {"type": "string", "description": "Alternative parameter for addressOrSymbol."},
                        "importName": {"type": "string", "description": "Import or external symbol name (e.g. RegOpenKeyExA). Alternative to addressOrSymbol when the target is an external."},
                        "mode": {
                            "type": "string",
                            "description": "Which direction the cross-references should be tracked. 'to' means finding who refers to this address. 'from' means finding what this address refers out to.",
                            "enum": ["to", "from", "both", "function", "referencers_decomp", "import", "thunk"],
                            "default": "to",
                        },
                        "limit": {"type": "integer", "default": 100, "description": "Number of cross-references to return. Typical values are 100\u2013500. Do not set this below 50 unless the user explicitly asks for only a handful of results."},
                        "offset": {"type": "integer", "default": 0, "description": "Pagination offset."},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name=Tool.LIST_CROSS_REFERENCES.value,
                description="Extract every interaction mapping to and from a specific target address simultaneously. For .rsrc targets, refs-to include LoadStringA/LoadStringW call sites.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The active program project."},
                        "addressOrSymbol": {"type": "string", "description": "The target address or symbol. Supports both thunk addresses (e.g. 0x004011fc) and IAT addresses (e.g. 0x48f1fc); IAT is resolved to the thunk."},
                        "target": {"type": "string", "description": "Alternative parameter for address."},
                        "importName": {"type": "string", "description": "Import or external symbol name. Alternative to addressOrSymbol."},
                        "limit": {"type": "integer", "default": 100, "description": "Number of cross-references to return. Typical values are 100\u2013500. Do not set this below 50 unless the user explicitly asks for only a handful of results."},
                        "offset": {"type": "integer", "default": 0, "description": "Pagination offset."},
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle_list_cross_references(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Alias for get-references with mode=both (refs to and from the address)."""
        logger.debug("diag.enter %s", "mcp_server/providers/xrefs.py:CrossReferencesToolProvider._handle_list_cross_references")
        updated = dict(args)
        updated.setdefault("mode", "both")
        return await self._handle(updated)

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/xrefs.py:CrossReferencesToolProvider._handle")
        self._require_program()
        addr_str = self._require_str(args, "addressorsymbol", "address", "addr", "target", "symbol", "importname", name="addressOrSymbol")
        mode = self._get_str(args, "mode", "direction", default="to")
        offset, max_results = self._get_pagination_params(args, default_limit=100)

        assert self.program_info is not None  # for type checker
        program = self.program_info.program
        addr = self._resolve_address(addr_str, program=program)
        if addr is None:
            raise ValueError(f"Could not resolve address or symbol: {addr_str!r}. Check format (e.g. 0x401000) and that the program is loaded.")
        ref_mgr = program.getReferenceManager()
        fm = self._get_function_manager(program)

        return await self._dispatch_handler(
            args,
            mode,
            {
                "to": "_handle_to",
                "from": "_handle_from",
                "both": "_handle_both",
                "function": "_handle_function",
                "referencers_decomp": "_handle_referencers_decomp",
                "referencersdecomp": "_handle_referencers_decomp",  # alias
                "referencerdecomp": "_handle_referencers_decomp",  # alias
                "import": "_handle_import",
                "thunk": "_handle_thunk",
            },
            program=program,
            addr=addr,
            addr_str=addr_str,
            ref_mgr=ref_mgr,
            fm=fm,
            offset=offset,
            max_results=max_results,
        )

    def _is_address_in_rsrc(self, program: Any, addr: Any) -> bool:
        """True if the address lies in a memory block that looks like the PE .rsrc section."""
        logger.debug("diag.enter %s", "mcp_server/providers/xrefs.py:CrossReferencesToolProvider._is_address_in_rsrc")
        try:
            block = program.getMemory().getBlock(addr)
            if block is None:
                return False
            name = (block.getName() or "").lower()
            return "rsrc" in name or ".rsrc" in name
        except Exception:
            return False

    def _get_loadstring_indirect_refs(
        self, program: Any, ref_mgr: Any, fm: Any, seen_from: set[str], max_results: int
    ) -> list[dict[str, Any]]:
        """Collect call sites of LoadStringA/LoadStringW for .rsrc string referencers (indirect refs)."""
        logger.debug("diag.enter %s", "mcp_server/providers/xrefs.py:CrossReferencesToolProvider._get_loadstring_indirect_refs")
        indirect: list[dict[str, Any]] = []
        try:
            st = program.getSymbolTable()
            for name in _LOADSTRING_NAMES:
                if len(indirect) >= max_results:
                    break
                symbols = st.getSymbols(name)
                sym = None
                if hasattr(symbols, "hasNext") and symbols.hasNext():
                    sym = symbols.next()
                else:
                    for s in symbols:
                        sym = s
                        break
                if sym is None:
                    continue
                sym_addr = sym.getAddress()
                for ref in ref_mgr.getReferencesTo(sym_addr):
                    if len(indirect) >= max_results:
                        break
                    from_addr = ref.getFromAddress()
                    from_str = str(from_addr)
                    if from_str in seen_from:
                        continue
                    seen_from.add(from_str)
                    func = fm.getFunctionContaining(from_addr)
                    indirect.append(
                        {
                            "fromAddress": from_str,
                            "toAddress": str(sym_addr),
                            "type": str(ref.getReferenceType()),
                            "function": func.getName() if func else None,
                            "indirect": True,
                            "via": name,
                            "note": "Resource strings in .rsrc are loaded via LoadStringA/LoadStringW; match resource ID at call site to confirm.",
                        },
                    )
        except Exception as e:
            logger.debug("LoadString indirect refs failed: %s", e)
        return indirect

    async def _handle_to(self, args: dict[str, Any], program: Any, addr: Any, addr_str: str, ref_mgr: Any, fm: Any, offset: int, max_results: int) -> list[types.TextContent]:
        # Use ref_mgr with already-resolved addr so raw addresses (e.g. 0x004a2a62) and
        # symbol names both work; avoid ghidra_tools.list_cross_references(addr_str)
        # which looks up by symbol name only and fails for addresses with no symbol.
        logger.debug("diag.enter %s", "mcp_server/providers/xrefs.py:CrossReferencesToolProvider._handle_to")
        refs_to: list[dict[str, Any]] = []
        seen_from: set[str] = set()
        for ref in ref_mgr.getReferencesTo(addr):
            if len(refs_to) >= max_results:
                break
            from_addr = ref.getFromAddress()
            from_str = str(from_addr)
            seen_from.add(from_str)
            func = fm.getFunctionContaining(from_addr)
            refs_to.append(
                {
                    "fromAddress": from_str,
                    "toAddress": str(ref.getToAddress()),
                    "type": str(ref.getReferenceType()),
                    "function": func.getName() if func else None,
                },
            )
        # Resource strings (.rsrc) are referenced via LoadStringA/LoadStringW, not direct xrefs.
        if self._is_address_in_rsrc(program, addr):
            remaining = max(0, max_results - len(refs_to))
            indirect = self._get_loadstring_indirect_refs(program, ref_mgr, fm, seen_from, remaining)
            refs_to.extend(indirect)
        return create_success_response({"mode": "to", "target": str(addr), "references": refs_to, "count": len(refs_to)})

    async def _handle_from(self, args: dict[str, Any], program: Any, addr: Any, addr_str: str, ref_mgr: Any, fm: Any, offset: int, max_results: int) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/xrefs.py:CrossReferencesToolProvider._handle_from")
        refs_from: list[dict[str, Any]] = []
        for ref in ref_mgr.getReferencesFrom(addr):
            if len(refs_from) >= max_results:
                break
            refs_from.append(
                {
                    "fromAddress": str(ref.getFromAddress()),
                    "toAddress": str(ref.getToAddress()),
                    "type": str(ref.getReferenceType()),
                },
            )
        return create_success_response({"mode": "from", "target": str(addr), "references": refs_from, "count": len(refs_from)})

    async def _handle_both(self, args: dict[str, Any], program: Any, addr: Any, addr_str: str, ref_mgr: Any, fm: Any, offset: int, max_results: int) -> list[types.TextContent]:
        # Use ref_mgr with already-resolved addr (see _handle_to).
        logger.debug("diag.enter %s", "mcp_server/providers/xrefs.py:CrossReferencesToolProvider._handle_both")
        refs_to: list[dict[str, Any]] = []
        seen_from: set[str] = set()
        for ref in ref_mgr.getReferencesTo(addr):
            if len(refs_to) >= max_results:
                break
            from_addr = ref.getFromAddress()
            from_str = str(from_addr)
            seen_from.add(from_str)
            func = fm.getFunctionContaining(from_addr)
            refs_to.append(
                {
                    "fromAddress": from_str,
                    "toAddress": str(ref.getToAddress()),
                    "type": str(ref.getReferenceType()),
                    "function": func.getName() if func else None,
                },
            )
        if self._is_address_in_rsrc(program, addr):
            remaining = max(0, max_results - len(refs_to))
            refs_to.extend(self._get_loadstring_indirect_refs(program, ref_mgr, fm, seen_from, remaining))

        refs_from: list[dict[str, Any]] = []
        for ref in ref_mgr.getReferencesFrom(addr):
            if len(refs_from) >= max_results:
                break
            refs_from.append(
                {
                    "fromAddress": str(ref.getFromAddress()),
                    "toAddress": str(ref.getToAddress()),
                    "type": str(ref.getReferenceType()),
                },
            )

        return create_success_response({"mode": "both", "target": str(addr), "referencesTo": refs_to, "referencesFrom": refs_from})

    async def _handle_function(self, args: dict[str, Any], program: Any, addr: Any, addr_str: str, ref_mgr: Any, fm: Any, offset: int, max_results: int) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/xrefs.py:CrossReferencesToolProvider._handle_function")
        func = fm.getFunctionContaining(addr)
        if func is None:
            func = fm.getFunctionAt(addr)
        if func is None:
            raise ValueError(f"No function at {addr_str}")
        # All refs within function body
        body = func.getBody()
        refs = []
        if body:
            for rng in body:
                cur = rng.getMinAddress()
                while cur is not None and cur.compareTo(rng.getMaxAddress()) <= 0:
                    for ref in ref_mgr.getReferencesFrom(cur):
                        refs.append(
                            {
                                "fromAddress": str(ref.getFromAddress()),
                                "toAddress": str(ref.getToAddress()),
                                "type": str(ref.getReferenceType()),
                            },
                        )
                        if len(refs) >= max_results:
                            break
                    if len(refs) >= max_results:
                        break
                    cur = cur.next()
        return create_success_response({"mode": "function", "function": func.getName(), "references": refs, "count": len(refs)})

    async def _handle_referencers_decomp(self, args: dict[str, Any], program: Any, addr: Any, addr_str: str, ref_mgr: Any, fm: Any, offset: int, max_results: int) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/xrefs.py:CrossReferencesToolProvider._handle_referencers_decomp")
        results = []
        try:
            from ghidra.app.decompiler import DecompInterface  # pyright: ignore[reportMissingModuleSource]
            from ghidra.util.task import ConsoleTaskMonitor  # pyright: ignore[reportMissingModuleSource]

            from agentdecompile_cli.mcp_utils.decompiler_util import get_decompiled_function_from_results

            decomp = DecompInterface()
            decomp.openProgram(program)
            monitor = ConsoleTaskMonitor()
            seen_funcs: set[str] = set()
            refs_seen = 0
            for ref in ref_mgr.getReferencesTo(addr):
                if refs_seen >= max_results:
                    break
                refs_seen += 1
                func = fm.getFunctionContaining(ref.getFromAddress())
                if func and func.getName() not in seen_funcs:
                    seen_funcs.add(func.getName())
                    try:
                        dr = decomp.decompileFunction(func, 30, monitor)
                        code = ""
                        if dr and dr.decompileCompleted():
                            df = get_decompiled_function_from_results(dr)
                            code = df.getC() if df else ""
                        results.append(
                            {
                                "function": func.getName(),
                                "address": str(func.getEntryPoint()),
                                "decompilation": code[:2000],
                            },
                        )
                    except Exception:
                        results.append({"function": func.getName(), "decompilation": "// error"})
                    if len(results) >= 50:
                        break
            # When target is in .rsrc, also decompile referencers via LoadStringA/LoadStringW.
            if self._is_address_in_rsrc(program, addr) and len(results) < 50:
                from agentdecompile_cli.mcp_utils.address_util import AddressUtil

                seen_from_refs: set[str] = set()
                indirect = self._get_loadstring_indirect_refs(program, ref_mgr, fm, seen_from_refs, max_results)
                for entry in indirect:
                    if len(results) >= 50:
                        break
                    func_name = entry.get("function")
                    if not func_name or func_name in seen_funcs:
                        continue
                    seen_funcs.add(func_name)
                    raw = (entry["fromAddress"] or "").strip()
                    if ":" in raw:
                        raw = raw.split(":")[-1].strip()
                    from_addr = AddressUtil.parse_address(program, raw)
                    if from_addr is None:
                        continue
                    func = fm.getFunctionContaining(from_addr) or fm.getFunctionAt(from_addr)
                    if func is not None:
                        try:
                            dr = decomp.decompileFunction(func, 30, monitor)
                            code = ""
                            if dr and dr.decompileCompleted():
                                df = get_decompiled_function_from_results(dr)
                                code = df.getC() if df else ""
                            results.append(
                                {
                                    "function": func.getName(),
                                    "address": str(func.getEntryPoint()),
                                    "decompilation": code[:2000],
                                    "indirect": True,
                                    "via": entry.get("via", "LoadString"),
                                },
                            )
                        except Exception:
                            results.append({"function": func.getName(), "decompilation": "// error", "indirect": True})
            decomp.dispose()
        except ImportError:
            pass
        return create_success_response({"mode": "referencers_decomp", "target": str(addr), "referencers": results, "count": len(results)})

    async def _handle_import(self, args: dict[str, Any], program: Any, addr: Any, addr_str: str, ref_mgr: Any, fm: Any, offset: int, max_results: int) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/xrefs.py:CrossReferencesToolProvider._handle_import")
        refs = []
        st = self._get_symbol_table(program)
        for sym in st.getExternalSymbols():
            for ref in ref_mgr.getReferencesTo(sym.getAddress()):
                func = fm.getFunctionContaining(ref.getFromAddress())
                refs.append(
                    {
                        "importName": sym.getName(),
                        "fromAddress": str(ref.getFromAddress()),
                        "function": func.getName() if func else None,
                    },
                )
                if len(refs) >= max_results:
                    break
            if len(refs) >= max_results:
                break
        return create_success_response({"mode": "import", "references": refs, "count": len(refs)})

    async def _handle_thunk(self, args: dict[str, Any], program: Any, addr: Any, addr_str: str, ref_mgr: Any, fm: Any, offset: int, max_results: int) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/xrefs.py:CrossReferencesToolProvider._handle_thunk")
        func = fm.getFunctionAt(addr)
        if func is None:
            func = fm.getFunctionContaining(addr)
        results = []
        if func and func.isThunk():
            thunked = func.getThunkedFunction(True)
            results.append(
                {
                    "thunk": func.getName(),
                    "thunkAddress": str(func.getEntryPoint()),
                    "target": thunked.getName() if thunked else "unknown",
                    "targetAddress": str(thunked.getEntryPoint()) if thunked else "unknown",
                },
            )
        return create_success_response({"mode": "thunk", "results": results, "count": len(results)})
