"""Unified Decompile Tool - Handles both MCP provider and CLI interfaces.

This tool consolidates the duplicated decompilation functionality from:
- tools/wrappers.py (MCP provider usage)
- ghidrecomp/decompile.py (CLI tool usage)

Provides a single, consistent interface for function decompilation.
"""

from __future__ import annotations

import argparse

from typing import TYPE_CHECKING, Any

from agentdecompile_cli.models import DecompiledFunction

if TYPE_CHECKING:
    from agentdecompile_cli.launcher import ProgramInfo
    from ghidra.app.decompiler import (  # pyright: ignore[reportMissingImports, reportMissingTypeStubs, reportMissingModuleSource]
        DecompInterface as GhidraDecompInterface,
    )
    from ghidra.program.model.listing import (  # pyright: ignore[reportMissingTypeStubs, reportMissingImports, reportMissingModuleSource]
        Function as GhidraFunction,
    )
    from ghidra.program.model.symbol import (  # pyright: ignore[reportMissingModuleSource, reportMissingImports, reportMissingTypeStubs]
        Symbol as GhidraSymbol,
    )

    # Type alias for convenience
    Symbol = GhidraSymbol


class DecompileTool:
    """Unified Decompile tool handling both MCP and CLI interfaces."""

    def __init__(self, program_info: ProgramInfo | None = None, decompiler: GhidraDecompInterface | None = None):
        self.program_info = program_info
        self.program = program_info.current_program if program_info else None
        self.decompiler = decompiler

    @classmethod
    def add_cli_args(cls, parser: argparse.ArgumentParser) -> None:
        """Add decompilation arguments to CLI parser."""
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
        if not self.program or not self.decompiler:
            raise ValueError("Program and decompiler must be set")

        # Find the function
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
        monitor: Any | None = None,
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
        if not self.decompiler:
            raise ValueError("Decompiler not available")

        result = self._decompile_with_decompiler(func, self.decompiler, timeout)

        return DecompiledFunction(
            name=self._get_function_name(func),
            code=result["code"],
            signature=result["signature"],
        )

    def _decompile_with_decompiler(
        self,
        func: GhidraFunction,
        decompiler: GhidraDecompInterface,
        timeout: int = 30,
        monitor: Any | None = None,
    ) -> dict[str, Any]:
        """Core decompilation logic with a specific decompiler instance."""
        from ghidra.util.task import ConsoleTaskMonitor

        if monitor is None:
            monitor = ConsoleTaskMonitor()

        # Perform the decompilation
        decompile_result = decompiler.decompileFunction(func, timeout, monitor)

        # Extract results
        if decompile_result.getErrorMessage() == "":
            code = decompile_result.decompiledFunction.getC()
            signature = decompile_result.decompiledFunction.getSignature()
        else:
            code = decompile_result.getErrorMessage()
            signature = None

        return {
            "code": code,
            "signature": signature,
            "error_message": decompile_result.getErrorMessage(),
        }

    def _resolve_function(self, name_or_address: str) -> GhidraFunction | None:
        """Resolve function by name or address."""
        if not self.program:
            return None

        # Try to find by address first
        try:
            addr = self.program.getAddressFactory().getAddress(name_or_address)
            if addr:
                func = self.program.getFunctionManager().getFunctionAt(addr)
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
        MAX_PATH_LEN = 50
        return f"{func.getName()[:MAX_PATH_LEN]}-{func.entryPoint}"
