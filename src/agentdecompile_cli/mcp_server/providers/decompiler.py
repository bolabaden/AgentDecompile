"""Decompiler Tool Provider - decompile-function.

Single tool: decompile-function. Resolves the function by name or address, then
decompiles via DecompileTool (if available) or the program's DecompInterface.
Returns C-like pseudocode and metadata. Timeout is configurable; default 60s.
"""

from __future__ import annotations

import logging

from typing import TYPE_CHECKING, Any

from mcp import types

from agentdecompile_cli.mcp_server.constants import DEFAULT_TIMEOUT_SECONDS  # pyright: ignore[reportMissingImports]
from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
)
from agentdecompile_cli.mcp_utils.decompiler_util import (
    get_decompiled_function_from_results,
    merge_decompile_dict_keys,
    open_decompiler_for_program,
    resolve_decompiler_for_program,
)
from agentdecompile_cli.registry import Tool

if TYPE_CHECKING:
    from ghidra.app.decompiler import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        DecompInterface as GhidraDecompInterface,
        DecompileResults as GhidraDecompileResults,
    )
    from ghidra.program.model.listing import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        Function as GhidraFunction,
        Program as GhidraProgram,
    )
    from ghidra.util.task import TaskMonitor as GhidraTaskMonitor  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]

    from agentdecompile_cli.launcher import ProgramInfo
    from agentdecompile_cli.tools.decompile_tool import DecompileTool

logger = logging.getLogger(__name__)


class DecompilerToolProvider(ToolProvider):
    HANDLERS = {
        "decompile": "_handle",
        "decompilefunction": "_handle",
    }

    def __init__(self, program_info: ProgramInfo | None = None):  # noqa: F821
        logger.debug("diag.enter %s", "mcp_server/providers/decompiler.py:DecompilerToolProvider.__init__")
        super().__init__(program_info)
        self._decomp_tool: DecompileTool | None = None  # noqa: F821

    def _get_decomp_tool(self) -> DecompileTool | None:  # noqa: F821
        """Lazy-init DecompileTool so we only load it when decompile-function is actually called."""
        logger.debug("diag.enter %s", "mcp_server/providers/decompiler.py:DecompilerToolProvider._get_decomp_tool")
        if self._decomp_tool is None:
            try:
                from agentdecompile_cli.tools.decompile_tool import DecompileTool

                self._decomp_tool = DecompileTool(
                    self.program_info,
                    getattr(self.program_info, "decompiler", None),
                )
            except Exception as exc:
                logger.warning("DecompileTool lazy init failed: %s: %s", exc.__class__.__name__, exc)
                self._decomp_tool = None
        return self._decomp_tool

    def list_tools(self) -> list[types.Tool]:
        logger.debug("diag.enter %s", "mcp_server/providers/decompiler.py:DecompilerToolProvider.list_tools")
        return [
            types.Tool(
                name=Tool.DECOMPILE_FUNCTION.value,
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
        logger.debug("diag.enter %s", "mcp_server/providers/decompiler.py:DecompilerToolProvider._handle")
        self._require_program()
        func_id = self._get_address_or_symbol(args)
        if not func_id:
            raise ValueError("function or addressOrSymbol required")

        timeout: int = self._get_int(args, "timeout", default=DEFAULT_TIMEOUT_SECONDS)  # pyright: ignore[reportAssignmentType]

        # Prefer unified DecompileTool (opens DecompInterface on demand if session has none)
        dt = self._get_decomp_tool()
        if dt is not None:
            try:
                result = dt.decompile_function_for_mcp(func_id, timeout=timeout)
                if hasattr(result, "model_dump"):
                    result = result.model_dump()
                if isinstance(result, dict):
                    result = merge_decompile_dict_keys(result)
                return create_success_response(result)  # pyright: ignore[reportArgumentType]
            except Exception as e:
                logger.warning("DecompileTool failed: %s: %s", e.__class__.__name__, e)

        # Direct DecompInterface path when DecompileTool could not be constructed
        assert self.program_info is not None  # for type checker
        program = self.program_info.program
        target_func = self._resolve_function(func_id, program=program)

        if target_func is None:
            raise ValueError(f"Function not found: {func_id}")

        return await self._decompile_with_ghidra_api(target_func, program, timeout)

    async def _decompile_with_ghidra_api(
        self,
        target_func: GhidraFunction,
        program: GhidraProgram,
        timeout: int,
    ) -> list[types.TextContent]:
        """Decompile a function using Ghidra's DecompInterface."""
        logger.debug("diag.enter %s", "mcp_server/providers/decompiler.py:DecompilerToolProvider._decompile_with_ghidra_api")
        try:
            from ghidra.util.task import ConsoleTaskMonitor  # pyright: ignore[reportMissingModuleSource]

            monitor = ConsoleTaskMonitor()
            session_decomp = getattr(self.program_info, "decompiler", None)

            decomp, owns_decomp = self._setup_decompiler(session_decomp, program)

            try:
                result = self._perform_decompilation(decomp, target_func, timeout, monitor, session_decomp, program)
                if isinstance(result, dict):
                    result = merge_decompile_dict_keys(result)
                return create_success_response(result)
            finally:
                if owns_decomp:
                    decomp.dispose()

        except ImportError as exc:
            raise RuntimeError("Ghidra DecompInterface is not available (PyGhidra / Ghidra classpath)") from exc

    def _setup_decompiler(
        self,
        session_decomp: GhidraDecompInterface | None,
        program: GhidraProgram,
    ) -> tuple[GhidraDecompInterface, bool]:
        """Set up the decompiler interface, returning (decomp, owns_decomp). When owns_decomp is True, caller must dispose decomp."""
        logger.debug("diag.enter %s", "mcp_server/providers/decompiler.py:DecompilerToolProvider._setup_decompiler")
        return resolve_decompiler_for_program(session_decomp, program)

    def _perform_decompilation(
        self,
        decomp: GhidraDecompInterface,
        target_func: GhidraFunction,
        timeout: int,
        monitor: GhidraTaskMonitor,
        session_decomp: GhidraDecompInterface | None,
        program: GhidraProgram | None = None,
    ) -> dict[str, Any]:  # pyright: ignore[reportReturnType]
        """Perform the actual decompilation with retry logic."""
        logger.debug("diag.enter %s", "mcp_server/providers/decompiler.py:DecompilerToolProvider._perform_decompilation")
        dr: GhidraDecompileResults = decomp.decompileFunction(target_func, timeout, monitor)

        if dr and dr.decompileCompleted():
            return self._extract_successful_decompilation(dr, target_func)

        # Try retry with fresh interface if session decomp failed
        if session_decomp is not None:
            retry_result = self._try_retry_decompilation(target_func, timeout, monitor, decomp, program)
            if retry_result:
                return retry_result

        self._handle_decompilation_failure(dr, decomp, target_func, program)

    def _extract_successful_decompilation(
        self,
        dr: GhidraDecompileResults,
        target_func: GhidraFunction,
    ) -> dict[str, Any]:
        """Extract results from a successful decompilation."""
        logger.debug("diag.enter %s", "mcp_server/providers/decompiler.py:DecompilerToolProvider._extract_successful_decompilation")
        df = get_decompiled_function_from_results(dr)
        if df is None:
            raise RuntimeError("Decompilation completed but Ghidra returned no DecompiledFunction")
        c_code = df.getC()
        if not (c_code or "").strip():
            raise RuntimeError("Decompilation completed but C output was empty")
        sig = df.getSignature()

        return merge_decompile_dict_keys(
            {
                "function": target_func.getName(),
                "address": str(target_func.getEntryPoint()),
                "signature": sig,
                "decompilation": c_code,
            },
        )

    def _try_retry_decompilation(
        self,
        target_func: GhidraFunction,
        timeout: int,
        monitor: GhidraTaskMonitor,
        original_decomp: GhidraDecompInterface,
        program: GhidraProgram | None = None,
    ) -> dict[str, Any] | None:
        """Try decompilation again with a fresh DecompInterface."""
        logger.debug("diag.enter %s", "mcp_server/providers/decompiler.py:DecompilerToolProvider._try_retry_decompilation")
        try:
            if program is None:
                program = original_decomp.getProgram()

            # If we still don't have a program, we can't retry
            if program is None:
                return None

            retry = open_decompiler_for_program(program)

            retry_dr = retry.decompileFunction(target_func, timeout, monitor)
            if retry_dr and retry_dr.decompileCompleted():
                result = self._extract_successful_decompilation(retry_dr, target_func)
                retry.dispose()
                return result

            retry.dispose()
        except Exception:
            pass

        return None

    def _handle_decompilation_failure(
        self,
        dr: GhidraDecompileResults | None,
        decomp: GhidraDecompInterface,
        target_func: GhidraFunction,
        program: GhidraProgram | None = None,
    ) -> None:
        """Raise with Ghidra decompiler diagnostics when decompilation does not complete."""
        logger.debug("diag.enter %s", "mcp_server/providers/decompiler.py:DecompilerToolProvider._handle_decompilation_failure")
        err_msg: str = self._extract_error_message(dr, decomp)
        if program is None:
            try:
                program = decomp.getProgram()
            except Exception:
                program = None

        extras: list[str] = []
        if dr is not None:
            for attr in ("timedOut", "isTimedOut", "wasCancelled", "isCancelled"):
                if hasattr(dr, attr):
                    try:
                        fn = getattr(dr, attr)
                        flag = fn() if callable(fn) else fn
                        if bool(flag):
                            extras.append(f"{attr}=true")
                            break
                    except Exception:
                        pass
            try:
                if not dr.decompileCompleted():
                    extras.append("decompileCompleted=false")
            except Exception:
                pass

        name = target_func.getName()
        addr = str(target_func.getEntryPoint())
        parts = [p for p in [err_msg, " ".join(extras)] if p]
        detail = "; ".join(parts) if parts else "no error message from DecompInterface"
        if program is None:
            detail = f"{detail} (program handle unavailable on DecompInterface)"
        raise RuntimeError(f"Decompilation failed for {name} @ {addr}: {detail}")

    def _extract_error_message(self, dr: GhidraDecompileResults | None, decomp: GhidraDecompInterface) -> str:
        """Extract error message from decompilation result."""
        logger.debug("diag.enter %s", "mcp_server/providers/decompiler.py:DecompilerToolProvider._extract_error_message")
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

        return str(err_msg)
