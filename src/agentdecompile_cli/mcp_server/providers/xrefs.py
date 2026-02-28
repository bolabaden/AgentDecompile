"""Cross References Tool Provider - get-references.

Modes: to, from, both, function, referencers_decomp, import, thunk.
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


class CrossReferencesToolProvider(ToolProvider):
    HANDLERS = {
        "getreferences": "_handle",
        "listcrossreferences": "_handle_list_cross_references",
    }

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="get-references",
                description="Get cross-references to/from an address or symbol",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "addressOrSymbol": {"type": "string"},
                        "target": {"type": "string"},
                        "mode": {"type": "string", "enum": ["to", "from", "both", "function", "referencers_decomp", "import", "thunk"], "default": "to"},
                        "limit": {"type": "integer", "default": 100},
                        "offset": {"type": "integer", "default": 0},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="list-cross-references",
                description="List cross references to/from target (alias for get-references mode=both)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "addressOrSymbol": {"type": "string"},
                        "target": {"type": "string"},
                        "limit": {"type": "integer", "default": 100},
                        "offset": {"type": "integer", "default": 0},
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle_list_cross_references(self, args: dict[str, Any]) -> list[types.TextContent]:
        updated = dict(args)
        updated.setdefault("mode", "both")
        return await self._handle(updated)

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        addr_str = self._require_str(args, "addressorsymbol", "address", "addr", "target", "symbol", name="addressOrSymbol")
        mode = self._get_str(args, "mode", "direction", default="to")
        max_results = self._get_int(args, "maxresults", "limit", "max", default=100)
        offset = self._get_int(args, "offset", "startindex", default=0)

        program = self.program_info.program

        from agentdecompile_cli.registry import normalize_identifier as n

        mode_n = n(mode)

        # Try GhidraTools first
        if self.ghidra_tools and mode_n in ("to", "from", "both"):
            try:
                results = self.ghidra_tools.list_cross_references(addr_str)
                paginated = results[offset : offset + max_results]
                return create_success_response(
                    {
                        "mode": mode,
                        "target": addr_str,
                        "results": paginated,
                        "count": len(paginated),
                        "total": len(results),
                        "hasMore": offset + len(paginated) < len(results),
                    },
                )
            except Exception:
                pass

        from agentdecompile_cli.mcp_utils.address_util import AddressUtil

        addr = AddressUtil.resolve_address_or_symbol(program, addr_str)
        ref_mgr = program.getReferenceManager()
        fm = program.getFunctionManager()

        if mode_n in ("to", "both"):
            refs_to = []
            for ref in ref_mgr.getReferencesTo(addr):
                if len(refs_to) >= max_results:
                    break
                from_addr = ref.getFromAddress()
                func = fm.getFunctionContaining(from_addr)
                refs_to.append(
                    {
                        "fromAddress": str(from_addr),
                        "toAddress": str(ref.getToAddress()),
                        "type": str(ref.getReferenceType()),
                        "function": func.getName() if func else None,
                    },
                )

        if mode_n in ("from", "both"):
            refs_from = []
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

        if mode_n == "to":
            return create_success_response({"mode": "to", "target": str(addr), "references": refs_to, "count": len(refs_to)})
        if mode_n == "from":
            return create_success_response({"mode": "from", "target": str(addr), "references": refs_from, "count": len(refs_from)})
        if mode_n == "both":
            return create_success_response({"mode": "both", "target": str(addr), "referencesTo": refs_to, "referencesFrom": refs_from})

        if mode_n == "function":
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

        if mode_n in ("referencersdecomp", "referencerdecomp"):
            refs = list(ref_mgr.getReferencesTo(addr))[:max_results]
            results = []
            try:
                from ghidra.app.decompiler import DecompInterface

                decomp = DecompInterface()
                decomp.openProgram(program)
                seen_funcs = set()
                for ref in refs:
                    func = fm.getFunctionContaining(ref.getFromAddress())
                    if func and func.getName() not in seen_funcs:
                        seen_funcs.add(func.getName())
                        try:
                            dr = decomp.decompileFunction(func, 30, None)
                            code = ""
                            if dr and dr.decompileCompleted():
                                df = dr.getDecompiledFunction()
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
                decomp.dispose()
            except ImportError:
                pass
            return create_success_response({"mode": "referencers_decomp", "target": str(addr), "referencers": results, "count": len(results)})

        if mode_n == "import":
            refs = []
            st = program.getSymbolTable()
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

        if mode_n == "thunk":
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

        raise ValueError(f"Unknown mode: {mode}")
