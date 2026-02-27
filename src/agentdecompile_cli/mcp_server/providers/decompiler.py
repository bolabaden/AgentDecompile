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

                self._decomp_tool = DecompileTool(self.program_info)
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
        func_id = self._get_str(args, "function", "addressorsymbol", "functionidentifier", "addr", "symbol", "name")
        if not func_id:
            raise ValueError("function or addressOrSymbol required")

        timeout = self._get_int(args, "timeout", default=60)

        # Try DecompileTool first
        dt = self._get_decomp_tool()
        if dt is not None:
            try:
                result = dt.decompile_function_for_mcp(func_id, timeout=timeout)
                return create_success_response(result)
            except Exception as e:
                logger.warning(f"DecompileTool failed: {e}")

        # Fallback: use Ghidra API directly
        program = self.program_info.program
        fm = program.getFunctionManager()

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

        try:
            from ghidra.app.decompiler import DecompInterface

            decomp = DecompInterface()
            decomp.openProgram(program)
            dr = decomp.decompileFunction(target_func, timeout, None)

            if dr and dr.decompileCompleted():
                df = dr.getDecompiledFunction()
                c_code = df.getC() if df else "// Decompilation produced no output"
                sig = df.getSignature() if df else str(target_func.getSignature())
            else:
                c_code = "// Decompilation failed or timed out"
                sig = str(target_func.getSignature())

            decomp.dispose()

            return create_success_response(
                {
                    "function": target_func.getName(),
                    "address": str(target_func.getEntryPoint()),
                    "signature": sig,
                    "decompilation": c_code,
                }
            )
        except ImportError:
            return create_success_response(
                {
                    "function": target_func.getName(),
                    "address": str(target_func.getEntryPoint()),
                    "note": "DecompInterface not available in this environment",
                }
            )
