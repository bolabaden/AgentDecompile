"""Function Tool Provider - list-functions, get-functions.

Lists and retrieves function information with pagination, filtering.
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


class FunctionToolProvider(ToolProvider):
    HANDLERS = {
        "listfunctions": "_handle_list",
        "getfunctions": "_handle_get",
    }

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="list-functions",
                description="List all functions in the program",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "namePattern": {"type": "string", "description": "Regex filter on function name"},
                        "includeExternals": {"type": "boolean", "default": True},
                        "limit": {"type": "integer", "default": 100},
                        "offset": {"type": "integer", "default": 0},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="get-functions",
                description="Get detailed function info (decompile, disassemble, info, calls)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "function": {"type": "string"},
                        "addressOrSymbol": {"type": "string"},
                        "functionIdentifier": {"type": "string"},
                        "view": {"type": "string", "enum": ["decompile", "disassemble", "info", "calls"], "default": "info"},
                        "limit": {"type": "integer", "default": 100},
                        "offset": {"type": "integer", "default": 0},
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle_list(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        pattern = self._get_str(args, "namepattern", "pattern", "filter", "regex")
        include_ext = self._get_bool(args, "includeexternals", "externals", default=True)
        max_results = self._get_int(args, "limit", "maxresults", "max", default=100)
        offset = self._get_int(args, "offset", "startindex", default=0)

        program = getattr(self.program_info, "program", None)
        if program is None or not hasattr(program, "getFunctionManager"):
            raise ValueError("No program loaded")
        fm = program.getFunctionManager()

        pat = re.compile(pattern, re.IGNORECASE) if pattern else None
        functions = []
        count = 0

        for func in fm.getFunctions(True):
            if not include_ext and func.isExternal():
                continue
            if pat and not pat.search(func.getName()):
                continue
            if count < offset:
                count += 1
                continue
            if len(functions) >= max_results:
                count += 1
                continue

            functions.append(
                {
                    "name": func.getName(),
                    "address": str(func.getEntryPoint()),
                    "size": func.getBody().getNumAddresses() if func.getBody() else 0,
                    "isExternal": func.isExternal(),
                    "isThunk": func.isThunk(),
                    "parameterCount": func.getParameterCount(),
                }
            )
            count += 1

        return create_success_response(
            {
                "functions": functions,
                "count": len(functions),
                "totalMatched": count,
                "offset": offset,
                "hasMore": count > offset + len(functions),
            }
        )

    async def _handle_get(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        func_id = self._get_str(args, "function", "addressorsymbol", "functionidentifier", "identifier", "name", "addr", "symbol")
        from agentdecompile_cli.registry import normalize_identifier as _n
        view = _n(self._get_str(args, "view", "mode", default="info"))
        max_results = self._get_int(args, "limit", "maxresults", default=100)

        program = getattr(self.program_info, "program", None)
        if program is None or not hasattr(program, "getFunctionManager"):
            raise ValueError("No program loaded")
        fm = program.getFunctionManager()

        # If no function specified, list all
        if not func_id:
            return await self._handle_list(args)

        # Find function
        target_func = None
        for f in fm.getFunctions(True):
            if f.getName() == func_id or str(f.getEntryPoint()) == func_id:
                target_func = f
                break

        if target_func is None:
            try:
                from agentdecompile_cli.mcp_utils.address_util import AddressUtil

                addr = AddressUtil.resolve_address_or_symbol(program, func_id)
                target_func = fm.getFunctionContaining(addr)
            except Exception:
                pass

        if target_func is None:
            raise ValueError(f"Function not found: {func_id}")

        result: dict[str, Any] = {
            "name": target_func.getName(),
            "address": str(target_func.getEntryPoint()),
            "signature": str(target_func.getSignature()),
            "view": view,
        }

        if view in ("info",):
            result.update(
                {
                    "size": target_func.getBody().getNumAddresses() if target_func.getBody() else 0,
                    "isExternal": target_func.isExternal(),
                    "isThunk": target_func.isThunk(),
                    "parameterCount": target_func.getParameterCount(),
                    "parameters": [{"name": p.getName(), "type": str(p.getDataType()), "ordinal": p.getOrdinal()} for p in target_func.getParameters()],
                    "returnType": str(target_func.getReturnType()),
                    "callingConvention": target_func.getCallingConventionName(),
                    "hasVarArgs": target_func.hasVarArgs(),
                }
            )
        elif view in ("calls",):
            callers = [{"name": c.getName(), "address": str(c.getEntryPoint())} for c in target_func.getCallingFunctions(None)]
            callees = [{"name": c.getName(), "address": str(c.getEntryPoint())} for c in target_func.getCalledFunctions(None)]
            result.update({"callers": callers, "callees": callees, "callerCount": len(callers), "calleeCount": len(callees)})
        elif view in ("decompile",):
            try:
                from ghidra.app.decompiler import DecompInterface

                decomp = DecompInterface()
                decomp.openProgram(program)
                dr = decomp.decompileFunction(target_func, 60, None)
                if dr and dr.decompileCompleted():
                    df = dr.getDecompiledFunction()
                    result["decompilation"] = df.getC() if df else "// No output"
                else:
                    result["decompilation"] = "// Decompilation failed"
                decomp.dispose()
            except Exception as e:
                result["decompilation"] = f"// Error: {e}"
        elif view in ("disassemble",):
            instructions = []
            listing = program.getListing()
            body = target_func.getBody()
            if body:
                instr_iter = listing.getInstructions(body, True)
                while instr_iter.hasNext() and len(instructions) < max_results:
                    instr = instr_iter.next()
                    instructions.append(
                        {
                            "address": str(instr.getAddress()),
                            "mnemonic": instr.getMnemonicString(),
                            "operands": str(instr),
                            "bytes": " ".join(f"{b:02x}" for b in instr.getBytes()),
                        }
                    )
            result["instructions"] = instructions
            result["instructionCount"] = len(instructions)

        return create_success_response(result)
