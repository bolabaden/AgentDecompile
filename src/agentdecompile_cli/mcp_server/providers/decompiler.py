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
    DEFAULT_TIMEOUT_SECONDS,
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
                description="Convert machine code representing a function into high-level, human-readable C-like pseudocode. Use this tool to easily read and understand what a function does without having to read assembly instructions.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The path to the program containing the function to be decompiled."},
                        "function": {"type": "string", "description": "The name or address of the function you want to decompile (e.g. 'main', '0x1000')."},
                        "addressOrSymbol": {"type": "string", "description": "Alternative way to specify the function by its exact address or symbol name."},
                        "functionIdentifier": {"type": "string", "description": "Another alternative to specify the target function's identifier."},
                        "timeout": {"type": "integer", "default": 60, "description": "Maximum time in seconds to wait for the decompiler to finish before aborting."},
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

        timeout = self._get_int(args, "timeout", default=DEFAULT_TIMEOUT_SECONDS)

        # Try DecompileTool first
        dt = self._get_decomp_tool()
        if dt is not None:
            try:
                result = dt.decompile_function_for_mcp(func_id, timeout=timeout)
                if hasattr(result, "model_dump"):
                    result = result.model_dump()
                return create_success_response(result)
            except Exception as e:
                logger.warning(f"DecompileTool failed: {e.__class__.__name__}: {e}")

        # Fallback: use Ghidra API directly
        assert self.program_info is not None  # for type checker
        program = self.program_info.program
        target_func = self._resolve_function(func_id, program=program)

        if target_func is None:
            raise ValueError(f"Function not found: {func_id}")

        return await self._decompile_with_ghidra_api(target_func, program, timeout)

    async def _decompile_with_ghidra_api(self, target_func, program, timeout: int) -> list[types.TextContent]:
        """Decompile a function using Ghidra's DecompInterface."""
        try:
            from ghidra.util.task import ConsoleTaskMonitor

            monitor = ConsoleTaskMonitor()
            session_decomp = getattr(self.program_info, "decompiler", None)
            
            decomp, owns_decomp = self._setup_decompiler(session_decomp, program)
            
            try:
                result = self._perform_decompilation(decomp, target_func, timeout, monitor, session_decomp, program)
                return create_success_response(result)
            finally:
                if owns_decomp:
                    decomp.dispose()
                    
        except ImportError:
            return create_success_response(
                {
                    "function": target_func.getName(),
                    "address": str(target_func.getEntryPoint()),
                    "note": "DecompInterface not available in this environment",
                },
            )

    def _setup_decompiler(self, session_decomp, program):
        """Set up the decompiler interface, returning (decomp, owns_decomp)."""
        from ghidra.app.decompiler import DecompInterface, DecompileOptions

        if session_decomp is None:
            decomp = DecompInterface()
            options = DecompileOptions()
            options.grabFromProgram(program)
            decomp.setOptions(options)
            decomp.openProgram(program)
            owns_decomp = True
        else:
            decomp = session_decomp
            owns_decomp = False
            try:
                options = DecompileOptions()
                options.grabFromProgram(program)
                decomp.setOptions(options)
            except Exception:
                pass
        
        return decomp, owns_decomp

    def _perform_decompilation(self, decomp, target_func, timeout: int, monitor, session_decomp, program=None):
        """Perform the actual decompilation with retry logic."""
        dr = decomp.decompileFunction(target_func, timeout, monitor)
        
        if dr and dr.decompileCompleted():
            return self._extract_successful_decompilation(dr, target_func)
        
        # Try retry with fresh interface if session decomp failed
        if session_decomp is not None:
            retry_result = self._try_retry_decompilation(target_func, timeout, monitor, decomp, program)
            if retry_result:
                return retry_result
        
        # Fallback to error handling
        return self._handle_decompilation_failure(dr, decomp, target_func, program)

    def _extract_successful_decompilation(self, dr, target_func):
        """Extract results from a successful decompilation."""
        df = dr.getDecompiledFunction()
        c_code = df.getC() if df else "// Decompilation produced no output"
        sig = df.getSignature() if df else str(target_func.getSignature())
        
        return {
            "function": target_func.getName(),
            "address": str(target_func.getEntryPoint()),
            "signature": sig,
            "decompilation": c_code,
        }

    def _try_retry_decompilation(self, target_func, timeout: int, monitor, original_decomp, program=None):
        """Try decompilation again with a fresh DecompInterface."""
        from ghidra.app.decompiler import DecompInterface, DecompileOptions
        
        try:
            retry = DecompInterface()
            if program is None:
                program = original_decomp.getProgram()
            
            # If we still don't have a program, we can't retry
            if program is None:
                return None
            
            retry_options = DecompileOptions()
            retry_options.grabFromProgram(program)
            retry.setOptions(retry_options)
            retry.openProgram(program)
            
            retry_dr = retry.decompileFunction(target_func, timeout, monitor)
            if retry_dr and retry_dr.decompileCompleted():
                result = self._extract_successful_decompilation(retry_dr, target_func)
                retry.dispose()
                return result
            
            retry.dispose()
        except Exception:
            pass
        
        return None

    def _handle_decompilation_failure(self, dr, decomp, target_func, program=None):
        """Handle failed decompilation by extracting error and providing fallback."""
        err_msg = self._extract_error_message(dr, decomp)
        if program is None:
            program = decomp.getProgram()
        
        # If we still don't have a program, build minimal error response
        if program is None:
            return {
                "function": target_func.getName(),
                "address": str(target_func.getEntryPoint()),
                "signature": str(target_func.getSignature()),
                "decompilation": f"// Decompilation failed: {err_msg or 'Program unavailable'}",
            }
        
        c_code = self._build_decompile_fallback(program, target_func, err_msg)
        sig = str(target_func.getSignature())
        
        return {
            "function": target_func.getName(),
            "address": str(target_func.getEntryPoint()),
            "signature": sig,
            "decompilation": c_code,
        }

    def _extract_error_message(self, dr, decomp):
        """Extract error message from decompilation result."""
        err_msg = ""
        if dr is not None:
            try:
                err_msg = dr.getErrorMessage() or ""
            except Exception:
                err_msg = ""
        
        if not err_msg:
            try:
                err_msg = decomp.getLastMessage() or ""
            except Exception:
                err_msg = ""
        
        return err_msg
