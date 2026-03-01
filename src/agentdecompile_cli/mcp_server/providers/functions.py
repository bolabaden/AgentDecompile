"""Function Tool Provider - list-functions, get-functions.

Lists and retrieves function information with pagination, filtering.
"""

from __future__ import annotations

import logging
import re
from typing import Any, ClassVar

from mcp import types

from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
    n,
)

logger = logging.getLogger(__name__)


class FunctionToolProvider(ToolProvider):
    HANDLERS: ClassVar[dict[str, str]] = {
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
                        "timeout": {"type": "integer", "default": 60},
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
                },
            )
            count += 1

        return create_success_response(
            {
                "functions": functions,
                "count": len(functions),
                "totalMatched": count,
                "offset": offset,
                "hasMore": count > offset + len(functions),
            },
        )

    async def _handle_get(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        func_id: str = self._get_str(args, "function", "addressorsymbol", "functionidentifier", "identifier", "name", "addr", "symbol")
        view: str = n(self._get_str(args, "view", "mode", default="info"))
        max_results: int = self._get_int(args, "limit", "maxresults", default=100)

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
                },
            )
        elif view in ("calls",):
            callers = [{"name": c.getName(), "address": str(c.getEntryPoint())} for c in target_func.getCallingFunctions(None)]
            callees = [{"name": c.getName(), "address": str(c.getEntryPoint())} for c in target_func.getCalledFunctions(None)]
            result.update({"callers": callers, "callees": callees, "callerCount": len(callers), "calleeCount": len(callees)})
        elif view in ("decompile",):
            try:
                from ghidra.app.decompiler import DecompInterface, DecompileOptions
                from ghidra.util.task import ConsoleTaskMonitor

                timeout = self._get_int(args, "timeout", "decompiletimeout", default=60)
                monitor = ConsoleTaskMonitor()

                session_decomp = getattr(self.program_info, "decompiler", None)
                decomp = session_decomp
                owns_decomp = False

                if decomp is None:
                    decomp = DecompInterface()
                    options = DecompileOptions()
                    options.grabFromProgram(program)
                    decomp.setOptions(options)
                    decomp.openProgram(program)
                    owns_decomp = True
                else:
                    try:
                        options = DecompileOptions()
                        options.grabFromProgram(program)
                        decomp.setOptions(options)
                    except Exception:
                        pass

                dr = decomp.decompileFunction(target_func, timeout, monitor)
                if dr and dr.decompileCompleted():
                    df = dr.getDecompiledFunction()
                    result["decompilation"] = df.getC() if df else "// No output"
                else:
                    err_msg = ""
                    if dr is not None:
                        try:
                            err_msg = dr.getErrorMessage() or ""
                        except Exception:
                            err_msg = ""

                    # Retry once with a fresh interface if the shared/session
                    # decompiler failed, to recover from stale interface state.
                    if session_decomp is not None:
                        retry = DecompInterface()
                        retry_options = DecompileOptions()
                        retry_options.grabFromProgram(program)
                        retry.setOptions(retry_options)
                        retry.openProgram(program)
                        retry_dr = retry.decompileFunction(target_func, timeout, monitor)
                        if retry_dr and retry_dr.decompileCompleted():
                            retry_df = retry_dr.getDecompiledFunction()
                            result["decompilation"] = retry_df.getC() if retry_df else "// No output"
                            retry.dispose()
                            return create_success_response(result)
                        try:
                            retry_err = retry_dr.getErrorMessage() if retry_dr else ""
                        except Exception:
                            retry_err = ""
                        retry.dispose()
                        if retry_err:
                            err_msg = retry_err

                    if not err_msg:
                        try:
                            err_msg = decomp.getLastMessage() or ""
                        except Exception:
                            err_msg = ""

                    result["decompilation"] = self._build_decompile_fallback(
                        program,
                        target_func,
                        err_msg,
                    )

                if owns_decomp:
                    decomp.dispose()
            except Exception as e:
                result["decompilation"] = self._build_decompile_fallback(program, target_func, str(e))
        elif view in ("disassemble",):
            instructions: list[dict[str, Any]] = []
            listing: Any = program.getListing()
            body: Any = target_func.getBody()
            if body:
                instr_iter: Any = listing.getInstructions(body, True)
                while instr_iter.hasNext() and len(instructions) < max_results:
                    instr = instr_iter.next()
                    instructions.append(
                        {
                            "address": str(instr.getAddress()),
                            "mnemonic": instr.getMnemonicString(),
                            "operands": str(instr),
                            "bytes": " ".join(f"{b:02x}" for b in instr.getBytes()),
                        },
                    )
            result["instructions"] = instructions
            result["instructionCount"] = len(instructions)

        return create_success_response(result)

    def _build_decompile_fallback(self, program: Any, target_func: Any, reason: str | None = None) -> str:
        listing = program.getListing()
        body = target_func.getBody()
        lines: list[str] = []
        max_instructions = 400

        if body:
            instr_iter = listing.getInstructions(body, True)
            count = 0
            while instr_iter.hasNext() and count < max_instructions:
                instr = instr_iter.next()
                lines.append(f"{instr.getAddress()}: {instr}")
                count += 1

        reason_text = reason.strip() if reason else "native decompiler unavailable"
        signature = str(target_func.getSignature())
        fallback = [
            f"/* Fallback decompilation ({reason_text}) */",
            f"/* Function: {target_func.getName()} @ {target_func.getEntryPoint()} */",
            f"/* Signature: {signature} */",
            "",
            "/* Disassembly */",
        ]

        if lines:
            fallback.extend(lines)
        else:
            fallback.append("<no instructions available>")

        return "\n".join(fallback)
