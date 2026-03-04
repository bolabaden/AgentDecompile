"""Data Flow Tool Provider - analyze-data-flow.

Directions: backward, forward, variable_accesses.
Uses DecompInterface with P-code analysis.
"""

from __future__ import annotations

import logging

from typing import Any

from mcp import types

from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
    n,
)

logger = logging.getLogger(__name__)


class DataFlowToolProvider(ToolProvider):
    HANDLERS = {"analyzedataflow": "_handle"}

    @staticmethod
    def _empty_response(
        direction: str,
        addr: Any,
        *,
        func_name: str | None = None,
        note: str | None = None,
        error: str | None = None,
    ) -> list[types.TextContent]:
        """Create a standardized empty-result response payload."""
        payload: dict[str, Any] = {
            "direction": direction,
            "address": str(addr),
            "pcode": [],
        }
        if func_name is not None:
            payload["function"] = func_name
        if note is not None:
            payload["note"] = note
        if error is not None:
            payload["error"] = error
        return create_success_response(payload)

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="analyze-data-flow",
                description="Analyze data flow at an address (backward slice, forward slice, variable accesses)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "addressOrSymbol": {"type": "string"},
                        "functionIdentifier": {"type": "string"},
                        "direction": {"type": "string", "enum": ["backward", "forward", "variable_accesses"], "default": "backward"},
                        "maxOps": {"type": "integer", "default": 500},
                        "maxDepth": {"type": "integer", "default": 10},
                        "timeout": {"type": "integer", "default": 30},
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Analyze data flow at a specific address using P-code decompilation.
        
        Uses Ghidra's DecompInterface to analyze data dependence at a given address.
        Supports three analysis modes:
        - backward: Find inputs that affect this address (data dependencies)
        - forward: Find outputs affected by this address (transitive dependents)
        - variable_accesses: Map high-level variable accesses and storage
        
        **Performance Considerations**:
        - Decompilation is expensive; limit maxOps and timeout for large functions
        - P-code analysis respects SSA form for accurate dependency tracking
        - Variable mode requires high-function representation (not always available)
        
        Parameters
        ----------
        addressOrSymbol : str
            Address or symbol where analysis begins
        direction : str
            Analysis direction: 'backward', 'forward', or 'variable_accesses'
        maxOps : int, default=500
            Maximum P-code operations to analyze
        timeout : int, default=30
            Decompilation timeout in seconds
            
        Returns
        -------
        response with P-code operations and metadata
        """
        self._require_program()
        addr_str = self._get_address_or_symbol(args)
        if not addr_str:
            raise ValueError("addressOrSymbol or functionIdentifier required")

        direction = n(self._get_str(args, "direction", "mode", default="backward"))
        max_ops = self._get_int(args, "maxops", default=500)
        timeout_s = self._get_int(args, "timeout", default=30)

        program = self.program_info.program
        addr = self._resolve_address(addr_str, program=program)

        fm = self._get_function_manager(program)
        func = fm.getFunctionContaining(addr)
        if func is None:
            raise ValueError(f"No function found containing {addr_str}")

        decomp = None
        try:
            from ghidra.app.decompiler import DecompInterface
            from ghidra.util.task import ConsoleTaskMonitor

            decomp = DecompInterface()
            decomp.openProgram(program)
            result = decomp.decompileFunction(func, timeout_s, ConsoleTaskMonitor())

            if result is None or not result.decompileCompleted():
                return self._empty_response(
                    direction,
                    addr,
                    func_name=func.getName(),
                    note="Decompilation failed or timed out",
                )

            hfunc = result.getHighFunction()
            if hfunc is None:
                return self._empty_response(
                    direction,
                    addr,
                    func_name=func.getName(),
                    note="No high-level function available",
                )

            pcode_ops = []
            op_iter = hfunc.getPcodeOps()
            count = 0
            while op_iter.hasNext() and count < max_ops:
                op = op_iter.next()
                pcode_ops.append(
                    {
                        "address": str(op.getSeqnum().getTarget()),
                        "mnemonic": str(op.getMnemonic()),
                        "output": str(op.getOutput()) if op.getOutput() else None,
                        "inputs": [str(inp) for inp in op.getInputs()],
                    },
                )
                count += 1

            if direction in ("variableaccesses", "variable_accesses"):
                # Gather variable info from high function
                variables = []
                for sym in hfunc.getLocalSymbolMap().getSymbols():
                    hv = sym.getHighVariable()
                    if hv:
                        variables.append(
                            {
                                "name": sym.getName(),
                                "dataType": str(hv.getDataType()),
                                "storage": str(hv.getRepresentative()),
                                "size": hv.getSize(),
                            },
                        )
                return create_success_response(
                    {
                        "direction": direction,
                        "address": str(addr),
                        "function": func.getName(),
                        "variables": variables,
                        "count": len(variables),
                    },
                )

            return create_success_response(
                {
                    "direction": direction,
                    "address": str(addr),
                    "function": func.getName(),
                    "pcode": pcode_ops,
                    "count": len(pcode_ops),
                    "hasMore": count >= max_ops,
                },
            )

        except ImportError:
            return self._empty_response(direction, addr, note="DecompInterface not available in this environment")
        except Exception as e:
            logger.error(f"Data flow analysis error: {e}")
            return self._empty_response(direction, addr, error=str(e))
        finally:
            if decomp is not None:
                try:
                    decomp.dispose()
                except Exception:
                    pass
