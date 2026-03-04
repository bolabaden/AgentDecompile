"""Decompiler Tool Provider - decompile (get-functions with decompile view).

Provides decompilation of functions via DecompInterface or DecompileTool.
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


class DecompilerToolProvider(ToolProvider):
    HANDLERS = {
        "decompile": "_handle",
        "decompilefunction": "_handle",
    }

    def __init__(self, program_info=None):
        super().__init__(program_info)
        self._decomp_tool = None

    def _get_decomp_tool(self):
        if self._decomp_tool is None:
            try:
                from agentdecompile_cli.tools.decompile_tool import DecompileTool

                self._decomp_tool = DecompileTool(
                    self.program_info,
                    getattr(self.program_info, "decompiler", None),
                )
            except Exception:
                pass
        return self._decomp_tool

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="decompile-function",
                description="Decompile a function to C pseudocode",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "function": {"type": "string", "description": "Function name or address"},
                        "addressOrSymbol": {"type": "string"},
                        "functionIdentifier": {"type": "string"},
                        "timeout": {"type": "integer", "default": 60},
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        func_id = self._get_address_or_symbol(args)
        if not func_id:
            raise ValueError("function or addressOrSymbol required")

        timeout = self._get_int(args, "timeout", default=60)

        # Try DecompileTool first
        dt = self._get_decomp_tool()
        if dt is not None:
            try:
                result = dt.decompile_function_for_mcp(func_id, timeout=timeout)
                if hasattr(result, "model_dump"):
                    result = result.model_dump()
                return create_success_response(result)
            except Exception as e:
                logger.warning(f"DecompileTool failed: {e}")

        # Fallback: use Ghidra API directly
        program = self.program_info.program
        target_func = self._resolve_function(func_id, program=program)

        if target_func is None:
            raise ValueError(f"Function not found: {func_id}")

        try:
            from ghidra.app.decompiler import DecompInterface
            from ghidra.app.decompiler import DecompileOptions
            from ghidra.util.task import ConsoleTaskMonitor

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

            completed = bool(dr and dr.decompileCompleted())
            err_msg = ""
            if dr is not None:
                try:
                    err_msg = dr.getErrorMessage() or ""
                except Exception:
                    err_msg = ""

            # Retry once with a fresh interface if the session decompiler failed.
            if not completed and session_decomp is not None:
                retry = DecompInterface()
                retry_options = DecompileOptions()
                retry_options.grabFromProgram(program)
                retry.setOptions(retry_options)
                retry.openProgram(program)
                retry_dr = retry.decompileFunction(target_func, timeout, monitor)
                if retry_dr and retry_dr.decompileCompleted():
                    retry_df = retry_dr.getDecompiledFunction()
                    c_code = retry_df.getC() if retry_df else "// Decompilation produced no output"
                    sig = retry_df.getSignature() if retry_df else str(target_func.getSignature())
                    retry.dispose()
                    if owns_decomp:
                        decomp.dispose()
                    return create_success_response(
                        {
                            "function": target_func.getName(),
                            "address": str(target_func.getEntryPoint()),
                            "signature": sig,
                            "decompilation": c_code,
                        },
                    )
                try:
                    retry_err = retry_dr.getErrorMessage() if retry_dr else ""
                except Exception:
                    retry_err = ""
                if retry_err:
                    err_msg = retry_err
                retry.dispose()

            if completed:
                df = dr.getDecompiledFunction()
                c_code = df.getC() if df else "// Decompilation produced no output"
                sig = df.getSignature() if df else str(target_func.getSignature())
            else:
                if not err_msg:
                    try:
                        err_msg = decomp.getLastMessage() or ""
                    except Exception:
                        err_msg = ""
                c_code = self._build_decompile_fallback(program, target_func, err_msg)
                sig = str(target_func.getSignature())

            if owns_decomp:
                decomp.dispose()

            return create_success_response(
                {
                    "function": target_func.getName(),
                    "address": str(target_func.getEntryPoint()),
                    "signature": sig,
                    "decompilation": c_code,
                },
            )
        except ImportError:
            return create_success_response(
                {
                    "function": target_func.getName(),
                    "address": str(target_func.getEntryPoint()),
                    "note": "DecompInterface not available in this environment",
                },
            )
