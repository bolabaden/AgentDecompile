"""Unified Decompile Tool - Handles both MCP provider and CLI interfaces.

This tool consolidates the duplicated decompilation functionality from:
- tools/wrappers.py (MCP provider usage)
- ghidrecomp/decompile.py (CLI tool usage)

Provides a single, consistent interface for function decompilation.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

from typing import TYPE_CHECKING, Any

from agentdecompile_cli.models import DecompiledFunction

if TYPE_CHECKING:
    import argparse

    from agentdecompile_cli.context import ProgramInfo
    from ghidra.app.decompiler import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        DecompInterface as GhidraDecompInterface,
    )
    from ghidra.program.model.listing import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        Function as GhidraFunction,
    )
    from ghidra.program.model.symbol import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        Symbol as GhidraSymbol,
    )
    from ghidra.util.task import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        TaskMonitor as GhidraTaskMonitor,
    )

    Symbol = GhidraSymbol


class DecompileTool:
    """Unified Decompile tool handling both MCP and CLI interfaces.

    MCP path: decompile_function_for_mcp(name_or_addr, timeout) → DecompiledFunction.
    CLI path: decompile_function_for_cli(func, decompilers, thread_id, timeout, monitor) for batch runs.
    Both use the same program + decompiler; the decompiler may come from program_info or be passed in.
    """

    def __init__(self, program_info: ProgramInfo | None = None, decompiler: GhidraDecompInterface | None = None):
        logger.debug("diag.enter %s", "tools/decompile_tool.py:DecompileTool.__init__")
        self.program_info = program_info
        self.program = getattr(program_info, "program", None) if program_info else None
        self.decompiler = decompiler if decompiler is not None else (program_info.get_decompiler() if program_info and hasattr(program_info, "get_decompiler") else getattr(program_info, "decompiler", None) if program_info else None)

    @classmethod
    def add_cli_args(cls, parser: argparse.ArgumentParser) -> None:
        """Add decompilation arguments to CLI parser."""
        logger.debug("diag.enter %s", "tools/decompile_tool.py:DecompileTool.add_cli_args")
        group = parser.add_argument_group("Decompilation Options")
        group.add_argument(
            "--decompile-timeout",
            help="Timeout for decompilation in seconds",
            default=30,
            type=int,
        )
        group.add_argument(
            "--decompile-threads",
            help="Number of threads for batch decompilation",
            default=1,
            type=int,
        )

    def decompile_function_for_mcp(
        self,
        function_name_or_address: str,
        timeout: int = 30,
        include_signature: bool = True,
    ) -> DecompiledFunction:
        """Decompile a function for MCP provider interface.

        Args:
            function_name_or_address: Function name or address to decompile
            timeout: Decompilation timeout in seconds
            include_signature: Whether to include function signature

        Returns:
            DecompiledFunction with name, code, and signature
        """
        logger.debug("diag.enter %s", "tools/decompile_tool.py:DecompileTool.decompile_function_for_mcp")
        if not self.program:
            raise ValueError("Program must be set")

        func = self._resolve_function(function_name_or_address)
        if not func:
            raise ValueError(f"Function not found: {function_name_or_address}")

        return self._decompile_single_function(func, timeout)

    def decompile_function_for_cli(
        self,
        func: GhidraFunction,
        decompilers: dict[int, GhidraDecompInterface],
        thread_id: int = 0,
        timeout: int = 30,
        monitor: GhidraTaskMonitor | None = None,
    ) -> list[str | None]:
        """Decompile a function for CLI interface.

        Args:
            func: Ghidra function to decompile
            decompilers: Dictionary of decompilers by thread ID
            thread_id: Thread ID for decompiler selection
            timeout: Decompilation timeout
            monitor: Optional monitor for progress

        Returns:
            List of [function_name, decompiled_code, signature]
        """
        logger.debug("diag.enter %s", "tools/decompile_tool.py:DecompileTool.decompile_function_for_cli")
        if thread_id not in decompilers:
            raise ValueError(f"No decompiler available for thread {thread_id}")

        result = self._decompile_with_decompiler(func, decompilers[thread_id], timeout, monitor)

        return [
            self._get_function_name(func),
            result["code"],
            result["signature"] if result["signature"] else None,
        ]

    def _decompile_single_function(
        self,
        func: GhidraFunction,
        timeout: int = 30,
    ) -> DecompiledFunction:
        """Core single function decompilation logic."""
        logger.debug("diag.enter %s", "tools/decompile_tool.py:DecompileTool._decompile_single_function")
        from agentdecompile_cli.mcp_utils.decompiler_util import resolve_decompiler_for_program

        if not self.program:
            raise ValueError("Program must be set")

        decompiler, owns_ephemeral = resolve_decompiler_for_program(self.decompiler, self.program)
        try:
            result = self._decompile_with_decompiler(func, decompiler, timeout)
            return DecompiledFunction(
                name=self._get_function_name(func),
                code=result["code"],
                signature=result["signature"],
            )
        finally:
            if owns_ephemeral:
                try:
                    decompiler.dispose()
                except Exception:
                    logger.debug("ephemeral_decompiler_dispose_failed", exc_info=True)

    def _decompile_with_decompiler(
        self,
        func: GhidraFunction,
        decompiler: GhidraDecompInterface,
        timeout: int = 30,
        monitor: GhidraTaskMonitor | None = None,
    ) -> dict[str, Any]:
        """Core decompilation logic with a specific decompiler instance."""
        logger.debug("diag.enter %s", "tools/decompile_tool.py:DecompileTool._decompile_with_decompiler")
        from ghidra.util.task import ConsoleTaskMonitor

        from agentdecompile_cli.mcp_utils.decompiler_util import get_decompiled_function_from_results

        if monitor is None:
            monitor = ConsoleTaskMonitor()

        # Perform the decompilation
        decompile_result = decompiler.decompileFunction(func, timeout, monitor)

        err = ""
        try:
            err = decompile_result.getErrorMessage() or ""
        except Exception:
            err = ""

        completed = False
        try:
            completed = bool(decompile_result.decompileCompleted())
        except Exception:
            completed = False

        df = get_decompiled_function_from_results(decompile_result) if completed else None

        if completed and df is not None:
            code = df.getC()
            signature = df.getSignature()
            if (code or "").strip():
                if err:
                    logger.debug("decompile_completed_with_nonempty_error_message: %s", err[:500])
                return {
                    "code": code,
                    "signature": signature,
                    "error_message": err or "",
                }
            raise RuntimeError("Decompilation completed but C output was empty")

        extra = ""
        for attr in ("timedOut", "isTimedOut", "wasCancelled", "isCancelled"):
            if hasattr(decompile_result, attr):
                try:
                    if bool(getattr(decompile_result, attr)()):
                        extra = f"{attr}=true"
                        break
                except Exception:
                    pass
        msg = err or decompiler.getLastMessage() or "decompileCompleted() is false"
        if extra:
            msg = f"{msg} ({extra})" if msg else extra
        raise RuntimeError(msg or "Decompilation failed")

    def _resolve_function(self, name_or_address: str) -> GhidraFunction | None:
        """Resolve function by name or address. Address strings: 0x = hex, else decimal (AddressUtil)."""
        logger.debug("diag.enter %s", "tools/decompile_tool.py:DecompileTool._resolve_function")
        if not self.program:
            return None

        from agentdecompile_cli.mcp_utils.address_util import AddressUtil

        # Try AddressUtil first so "0x48b17c" is parsed as hex, not base-10
        addr = AddressUtil.parse_address(self.program, name_or_address)
        if addr is not None:
            fm = self.program.getFunctionManager()
            func = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
            if func is not None:
                return func
        try:
            addr = self.program.getAddressFactory().getAddress(name_or_address)
            if addr:
                func = self.program.getFunctionManager().getFunctionAt(addr) or self.program.getFunctionManager().getFunctionContaining(addr)
                if func:
                    return func
        except Exception:
            pass

        # Try to find by name
        funcs = list(self.program.getFunctionManager().getFunctions(True))
        for func in funcs:
            if func.getName(True) == name_or_address:
                return func

        return None

    def _get_function_name(self, func: GhidraFunction) -> str:
        """Get a standardized function name."""
        logger.debug("diag.enter %s", "tools/decompile_tool.py:DecompileTool._get_function_name")
        MAX_PATH_LEN = 50
        return f"{func.getName()[:MAX_PATH_LEN]}-{func.entryPoint}"
