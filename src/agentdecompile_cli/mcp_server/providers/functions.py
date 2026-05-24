"""Function Tool Provider - list-functions, get-functions.

- list-functions: Enumerate functions in the program with optional name-pattern filter,
  includeExternals flag, and pagination (offset/limit). Uses collect_functions from
  _collectors for a single pass over the function manager.
- get-functions: Detailed view of one or more functions. Accepts a single 'function'
  or a 'functions' array for batch. Modes: info, decompile, disassemble, calls (or
  all). Decompilation goes through the program's DecompInterface; results are
  formatted for MCP consumption.
"""

from __future__ import annotations

import json
import logging
import re

from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from ghidra.program.model.address import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        AddressSetView as GhidraAddressSetView,
    )
    from ghidra.program.model.listing import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        Function as GhidraFunction,
        Listing as GhidraListing,
        Program as GhidraProgram,
    )

from mcp import types

from agentdecompile_cli.mcp_server.providers._collectors import collect_functions, make_task_monitor
from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
)

logger = logging.getLogger(__name__)


class FunctionToolProvider(ToolProvider):
    HANDLERS: ClassVar[dict[str, str]] = {
        "listfunctions": "_handle_list",
        "getfunctions": "_handle_get",
    }

    async def _handle_list(self, args: dict[str, Any]) -> list[types.TextContent]:
        """List functions in the current program, with optional filtering and pagination.

        Iterates through all functions in the active program, optionally filtering by regex
        name pattern and including/excluding external functions. Results are paginated for
        efficient handling of large binaries.

        **Performance Note**: Uses two-pass approach for efficiency:
            1. Single iteration to collect matching functions (O(n))
            2. Slice matching list for pagination (O(1) offset lookup)
        This avoids offset tracking during iteration and simplifies logic.

        Parameters
        ----------
        namepattern/pattern/filter/regex : str, optional
            Regex pattern to match function names (case-insensitive)
        includeexternals : bool, default=True
            Include external/imported functions
        offset/startindex : int, default=0
            Pagination offset
        limit/maxresults : int, default=100
            Maximum results to return

        Returns:
        -------
        Paginated response with functions, count, total, hasMore
        """
        logger.debug("diag.enter %s", "mcp_server/providers/functions.py:FunctionToolProvider._handle_list")
        self._require_program()
        pattern = self._get_str(args, "namepattern", "pattern", "filter", "regex")
        include_ext = self._get_bool(args, "includeexternals", "externals", default=True)
        offset, max_results = self._get_pagination_params(args, default_limit=100)

        program = self.program_info.program
        if program is None or not hasattr(program, "getFunctionManager"):
            raise ValueError("No program loaded")

        # Compile regex once; None if no pattern.
        pat = re.compile(pattern, re.IGNORECASE) if pattern else None

        all_functions = collect_functions(program)
        all_matching = [
            {
                "name": row["name"],
                "address": row["address"],
                "size": row["size"],
                "isExternal": row["isExternal"],
                "isThunk": row["isThunk"],
                "parameterCount": row["parameterCount"],
            }
            for row in all_functions
            if (include_ext or not row.get("isExternal")) and (not pat or pat.search(str(row.get("name", ""))))
        ]

        paginated, has_more = self._paginate_results(all_matching, offset, max_results)
        return self._create_paginated_response(paginated, offset, max_results, total=len(all_matching), mode="list")

    @staticmethod
    def _response_to_payload(response: list[types.TextContent]) -> dict[str, Any]:
        logger.debug("diag.enter %s", "mcp_server/providers/functions.py:FunctionToolProvider._response_to_payload")
        if not response:
            return {}
        text = getattr(response[0], "text", "")
        if not text:
            return {}
        try:
            data = json.loads(text)
        except Exception:
            return {}
        return data if isinstance(data, dict) else {}

    async def _handle_get(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Get detailed views (info/decompile/disassemble/calls) for one or more functions. Batch via 'functions' array."""
        logger.debug("diag.enter %s", "mcp_server/providers/functions.py:FunctionToolProvider._handle_get")
        self._require_program()

        # Collect all function identifiers: 'functions' array, or single 'function' / 'addressOrSymbol' / etc.
        func_ids: list[str] = []
        raw_functions = self._get_list(args, "functions")
        if raw_functions:
            for v in raw_functions:
                if isinstance(v, str) and v.strip():
                    func_ids.append(v.strip())
        if not func_ids:
            raw_functions_str = self._get_str(args, "functions")
            if raw_functions_str and raw_functions_str.strip():
                func_ids = [raw_functions_str.strip()]
        if not func_ids:
            single = self._get_str(args, "function", "addressorsymbol", "functionidentifier", "identifier", "name", "addr", "symbol")
            if single:
                func_ids = [single.strip()]

        view: str = self._get_str(args, "mode", "view", "action", "operation", default="")
        max_results: int = self._get_int(args, "limit", "maxresults", default=100)
        timeout: int = self._get_int(args, "timeout", "decompiletimeout", default=60)

        program = self.program_info.program
        if program is None or not hasattr(program, "getFunctionManager"):
            raise ValueError("No program loaded")

        # If no function specified, list all
        if not func_ids:
            return await self._handle_list(args)

        # Single function path (existing behavior)
        if len(func_ids) == 1:
            func_id = func_ids[0]
            target_func = self._resolve_function(func_id, program=program)
            if target_func is None:
                raise ValueError(f"Function not found: {func_id}")

            if not view:
                info_resp = await self._handle_info(args, target_func=target_func, program=program, max_results=max_results, timeout=timeout)
                calls_resp = await self._handle_calls(args, target_func=target_func, program=program, max_results=max_results, timeout=timeout)
                decompile_resp = await self._handle_decompile(args, target_func=target_func, program=program, max_results=max_results, timeout=timeout)
                disassemble_resp = await self._handle_disassemble(args, target_func=target_func, program=program, max_results=max_results, timeout=timeout)

                return create_success_response(
                    {
                        "name": target_func.getName(),
                        "address": str(target_func.getEntryPoint()),
                        "signature": str(target_func.getSignature()),
                        "view": "all",
                        "views": {
                            "info": self._response_to_payload(info_resp),
                            "calls": self._response_to_payload(calls_resp),
                            "decompile": self._response_to_payload(decompile_resp),
                            "disassemble": self._response_to_payload(disassemble_resp),
                        },
                    },
                )

            return await self._dispatch_handler(
                args,
                view,
                {
                    "info": "_handle_info",
                    "calls": "_handle_calls",
                    "decompile": "_handle_decompile",
                    "disassemble": "_handle_disassemble",
                },
                target_func=target_func,
                program=program,
                max_results=max_results,
                timeout=timeout,
            )

        # Batch path: multiple functions requested
        batch_results: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        for func_id in func_ids:
            try:
                target_func = self._resolve_function(func_id, program=program)
                if target_func is None:
                    errors.append({"identifier": func_id, "error": "Function not found"})
                    continue
                if not view:
                    info_resp = await self._handle_info(args, target_func=target_func, program=program, max_results=max_results, timeout=timeout)
                    calls_resp = await self._handle_calls(args, target_func=target_func, program=program, max_results=max_results, timeout=timeout)
                    decompile_resp = await self._handle_decompile(args, target_func=target_func, program=program, max_results=max_results, timeout=timeout)
                    disassemble_resp = await self._handle_disassemble(args, target_func=target_func, program=program, max_results=max_results, timeout=timeout)
                    batch_results.append(
                        {
                            "identifier": func_id,
                            "name": target_func.getName(),
                            "address": str(target_func.getEntryPoint()),
                            "signature": str(target_func.getSignature()),
                            "view": "all",
                            "views": {
                                "info": self._response_to_payload(info_resp),
                                "calls": self._response_to_payload(calls_resp),
                                "decompile": self._response_to_payload(decompile_resp),
                                "disassemble": self._response_to_payload(disassemble_resp),
                            },
                        },
                    )
                else:
                    single_resp = await self._dispatch_handler(
                        args,
                        view,
                        {
                            "info": "_handle_info",
                            "calls": "_handle_calls",
                            "decompile": "_handle_decompile",
                            "disassemble": "_handle_disassemble",
                        },
                        target_func=target_func,
                        program=program,
                        max_results=max_results,
                        timeout=timeout,
                    )
                    payload = self._response_to_payload(single_resp)
                    payload["identifier"] = func_id
                    batch_results.append(payload)
            except Exception as e:
                errors.append({"identifier": func_id, "error": str(e)})

        return create_success_response(
            {
                "mode": "batch",
                "view": view or "all",
                "count": len(batch_results),
                "results": batch_results,
                "errors": errors,
            },
        )

    async def _handle_info(self, args: dict[str, Any], target_func: GhidraFunction, program: GhidraProgram, max_results: int, timeout: int) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/functions.py:FunctionToolProvider._handle_info")
        result: dict[str, Any] = {
            "name": target_func.getName(),
            "address": str(target_func.getEntryPoint()),
            "signature": str(target_func.getSignature()),
            "view": "info",
            "size": target_func.getBody().getNumAddresses() if target_func.getBody() else 0,
            "isExternal": target_func.isExternal(),
            "isThunk": target_func.isThunk(),
            "parameterCount": target_func.getParameterCount(),
            "parameters": [{"name": p.getName(), "type": str(p.getDataType()), "ordinal": p.getOrdinal()} for p in target_func.getParameters()],
            "returnType": str(target_func.getReturnType()),
            "callingConvention": target_func.getCallingConventionName(),
            "hasVarArgs": target_func.hasVarArgs(),
        }
        return create_success_response(result)

    async def _handle_calls(self, args: dict[str, Any], target_func: GhidraFunction, program: GhidraProgram, max_results: int, timeout: int) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/functions.py:FunctionToolProvider._handle_calls")
        _monitor = make_task_monitor()
        callers = [{"name": c.getName(), "address": str(c.getEntryPoint())} for c in target_func.getCallingFunctions(_monitor)]
        callees = [{"name": c.getName(), "address": str(c.getEntryPoint())} for c in target_func.getCalledFunctions(_monitor)]
        result: dict[str, Any] = {
            "name": target_func.getName(),
            "address": str(target_func.getEntryPoint()),
            "signature": str(target_func.getSignature()),
            "view": "calls",
            "callers": callers,
            "callees": callees,
            "callerCount": len(callers),
            "calleeCount": len(callees),
        }
        return create_success_response(result)

    async def _handle_decompile(self, args: dict[str, Any], target_func: GhidraFunction, program: GhidraProgram, max_results: int, timeout: int) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/functions.py:FunctionToolProvider._handle_decompile")
        result: dict[str, Any] = {
            "name": target_func.getName(),
            "address": str(target_func.getEntryPoint()),
            "signature": str(target_func.getSignature()),
            "view": "decompile",
        }
        try:
            from agentdecompile_cli.mcp_utils.decompiler_util import (
                acquire_decompiler_for_program,
                get_decompiled_function_from_results,
                merge_decompile_dict_keys,
                open_decompiler_for_program,
            )
            from ghidra.util.task import ConsoleTaskMonitor  # pyright: ignore[reportMissingModuleSource]

            monitor = ConsoleTaskMonitor()

            session_decomp = getattr(self.program_info, "decompiler", None)
            with acquire_decompiler_for_program(session_decomp, program) as lease:
                decomp = lease.decompiler
                dr = decomp.decompileFunction(target_func, timeout, monitor)
                if dr and dr.decompileCompleted():
                    df = get_decompiled_function_from_results(dr)
                    if df is None:
                        raise RuntimeError("Decompilation completed but Ghidra returned no DecompiledFunction")
                    c_out = df.getC()
                    if not (c_out or "").strip():
                        raise RuntimeError("Decompilation completed but C output was empty")
                    result["decompilation"] = c_out
                else:
                    err_msg = ""
                    if dr is not None:
                        try:
                            err_msg = dr.getErrorMessage() or ""
                        except Exception:
                            err_msg = ""

                    if session_decomp is not None and lease.reused_session:
                        retry = open_decompiler_for_program(program)
                        retry_dr = retry.decompileFunction(target_func, timeout, monitor)
                        if retry_dr and retry_dr.decompileCompleted():
                            retry_df = get_decompiled_function_from_results(retry_dr)
                            if retry_df is None:
                                retry.dispose()
                                raise RuntimeError("Decompilation completed but Ghidra returned no DecompiledFunction")
                            c_retry = retry_df.getC()
                            if not (c_retry or "").strip():
                                retry.dispose()
                                raise RuntimeError("Decompilation completed but C output was empty")
                            result["decompilation"] = c_retry
                            retry.dispose()
                            return create_success_response(merge_decompile_dict_keys(result))
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

                    extras: list[str] = []
                    if dr is not None:
                        try:
                            if not dr.decompileCompleted():
                                extras.append("decompileCompleted=false")
                        except Exception:
                            pass
                    detail = "; ".join([p for p in [err_msg, " ".join(extras)] if p]) or "no error message from DecompInterface"
                    raise RuntimeError(f"Decompilation failed for {target_func.getName()}: {detail}")
        except Exception:
            raise

        return create_success_response(merge_decompile_dict_keys(result))

    async def _handle_disassemble(self, args: dict[str, Any], target_func: GhidraFunction, program: GhidraProgram, max_results: int, timeout: int) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/functions.py:FunctionToolProvider._handle_disassemble")
        instructions: list[dict[str, Any]] = []
        listing: GhidraListing = self._get_listing(program)
        body: GhidraAddressSetView = target_func.getBody()
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
                    },
                )
        result: dict[str, Any] = {
            "name": target_func.getName(),
            "address": str(target_func.getEntryPoint()),
            "signature": str(target_func.getSignature()),
            "view": "disassemble",
            "instructions": instructions,
            "instructionCount": len(instructions),
        }
        return create_success_response(result)
