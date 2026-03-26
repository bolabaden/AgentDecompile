"""Data Flow Tool Provider - analyze-data-flow.

- direction=backward: Where a value at the given address came from (e.g. user input → vulnerability).
- direction=forward: Where a value at the given address flows to.
- direction=variable_accesses: Reads/writes to a variable at the given address.
- Uses Ghidra DecompInterface and P-code analysis; _empty_response builds a consistent empty-result payload for errors or no-data cases.
"""

from __future__ import annotations

import logging

from typing import Any

from mcp import types

from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
)
from agentdecompile_cli.registry import Tool

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
        logger.debug("diag.enter %s", "mcp_server/providers/dataflow.py:DataFlowToolProvider._empty_response")
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
        logger.debug("diag.enter %s", "mcp_server/providers/dataflow.py:DataFlowToolProvider.list_tools")
        return [
            types.Tool(
                name=Tool.ANALYZE_DATA_FLOW.value,
                description="Track the flow of data through registers and memory starting from a specific address. Use 'backward' to see where a value came from (e.g. tracking user input to a vulnerability), 'forward' to see where a value goes, or 'variable_accesses' to find reads/writes to a variable.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {
                            "type": "string",
                            "description": "Path to the program in the Ghidra project.",
                        },
                        "addressOrSymbol": {
                            "type": "string",
                            "description": "The target address or symbol name to start tracking data flow from.",
                        },
                        "functionIdentifier": {
                            "type": "string",
                            "description": "Name or address of the function containing the data to track.",
                        },
                        "direction": {
                            "type": "string",
                            "enum": ["backward", "forward", "variable_accesses"],
                            "default": "backward",
                            "description": "Whether to track where the data came from (backward), where it goes (forward), or how a variable is accessed.",
                        },
                        "maxOps": {
                            "type": "integer",
                            "default": 500,
                            "description": "Maximum number of operations (P-code ops) to analyze. Prevents infinite loops.",
                        },
                        "maxDepth": {
                            "type": "integer",
                            "default": 10,
                            "description": "Maximum path depth when tracing through data flow graphs.",
                        },
                        "timeout": {
                            "type": "integer",
                            "default": 30,
                            "description": "Maximum time in seconds to allow the analysis to run.",
                        },
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/dataflow.py:DataFlowToolProvider._handle")
        self._require_program()
        addr_str = self._get_address_or_symbol(args)
        if not addr_str:
            raise ValueError("addressOrSymbol or functionIdentifier required")

        direction = self._get_str(args, "direction", "mode", default="backward")
        max_ops = self._get_int(args, "maxops", default=500)
        timeout_s = self._get_int(args, "timeout", default=30)

        program = self.program_info.program
        addr = self._resolve_address(addr_str, program=program)

        fm = self._get_function_manager(program)
        func = fm.getFunctionContaining(addr)
        if func is None:
            raise ValueError(f"No function found containing {addr_str}")

        return await self._dispatch_handler(
            args,
            direction,
            {
                "backward": "_handle_backward",
                "forward": "_handle_forward",
                "variable_accesses": "_handle_variable_accesses",
                "variableaccesses": "_handle_variable_accesses",  # alias
            },
            program=program,
            addr=addr,
            func=func,
            max_ops=max_ops,
            timeout_s=timeout_s,
        )

    async def _handle_backward(self, args: dict[str, Any], program: Any, addr: Any, func: Any, max_ops: int, timeout_s: int) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/dataflow.py:DataFlowToolProvider._handle_backward")
        return await self._analyze_data_flow("backward", program, addr, func, max_ops, timeout_s)

    async def _handle_forward(self, args: dict[str, Any], program: Any, addr: Any, func: Any, max_ops: int, timeout_s: int) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/dataflow.py:DataFlowToolProvider._handle_forward")
        return await self._analyze_data_flow("forward", program, addr, func, max_ops, timeout_s)

    async def _handle_variable_accesses(self, args: dict[str, Any], program: Any, addr: Any, func: Any, max_ops: int, timeout_s: int) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/dataflow.py:DataFlowToolProvider._handle_variable_accesses")
        return await self._analyze_data_flow("variable_accesses", program, addr, func, max_ops, timeout_s)

    async def _analyze_data_flow(self, direction: str, program: Any, addr: Any, func: Any, max_ops: int, timeout_s: int) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/dataflow.py:DataFlowToolProvider._analyze_data_flow")
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

            if direction in ("variable_accesses", "variableaccesses"):
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

            # backward/forward: collect P-code operations
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
            logger.error("Data flow analysis error: %s", e)
            return self._empty_response(direction, addr, error=str(e))
        finally:
            if decomp is not None:
                try:
                    decomp.dispose()
                except Exception:
                    pass
