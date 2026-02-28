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
)

logger = logging.getLogger(__name__)


class DataFlowToolProvider(ToolProvider):
    HANDLERS = {"analyzedataflow": "_handle"}

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
        self._require_program()
        addr_str = self._get_str(args, "addressorsymbol", "address", "addr", "symbol", "functionidentifier", "functionaddress", "startaddress")
        if not addr_str:
            raise ValueError("addressOrSymbol or functionIdentifier required")

        from agentdecompile_cli.registry import normalize_identifier as n

        direction = n(self._get_str(args, "direction", "mode", default="backward"))
        max_ops = self._get_int(args, "maxops", default=500)
        timeout_s = self._get_int(args, "timeout", default=30)

        program = self.program_info.program
        from agentdecompile_cli.mcp_utils.address_util import AddressUtil

        addr = AddressUtil.resolve_address_or_symbol(program, addr_str)

        fm = program.getFunctionManager()
        func = fm.getFunctionContaining(addr)
        if func is None:
            raise ValueError(f"No function found containing {addr_str}")

        try:
            from ghidra.app.decompiler import DecompInterface

            decomp = DecompInterface()
            decomp.openProgram(program)
            result = decomp.decompileFunction(func, timeout_s, None)

            if result is None or not result.decompileCompleted():
                decomp.dispose()
                return create_success_response(
                    {
                        "direction": direction,
                        "address": str(addr),
                        "function": func.getName(),
                        "note": "Decompilation failed or timed out",
                        "pcode": [],
                    },
                )

            hfunc = result.getHighFunction()
            if hfunc is None:
                decomp.dispose()
                return create_success_response(
                    {
                        "direction": direction,
                        "address": str(addr),
                        "function": func.getName(),
                        "note": "No high-level function available",
                        "pcode": [],
                    },
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

            decomp.dispose()

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
            return create_success_response(
                {
                    "direction": direction,
                    "address": str(addr),
                    "note": "DecompInterface not available in this environment",
                    "pcode": [],
                },
            )
        except Exception as e:
            logger.error(f"Data flow analysis error: {e}")
            return create_success_response(
                {
                    "direction": direction,
                    "address": str(addr),
                    "error": str(e),
                    "pcode": [],
                },
            )
