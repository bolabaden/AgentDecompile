"""Data Flow Tool Provider - analyze-data-flow.

- direction=backward: Where a value at the given address came from (e.g. user input → vulnerability).
- direction=forward: Where a value at the given address flows to.
- direction=variable_accesses: Reads/writes to a variable at the given address.
- Uses Ghidra DecompInterface and P-code analysis; _empty_response builds a consistent empty-result payload for errors or no-data cases.
"""

from __future__ import annotations

import logging

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ghidra.program.model.address import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        Address as GhidraAddress,
    )
    from ghidra.program.model.listing import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        Function as GhidraFunction,
        Program as GhidraProgram,
    )

from mcp import types

from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
)
from agentdecompile_cli.mcp_server.providers._collectors import collect_function_data_flow
from agentdecompile_cli.registry import Tool

logger = logging.getLogger(__name__)


class DataFlowToolProvider(ToolProvider):
    HANDLERS = {"analyzedataflow": "_handle"}

    @staticmethod
    def _empty_response(
        direction: str,
        addr: GhidraAddress,
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
        max_depth = self._get_int(args, "maxdepth", default=10)
        timeout_s = self._get_int(args, "timeout", default=30)

        assert self.program_info is not None, "program_info should be set by _require_program()"
        program = self.program_info.program
        assert program is not None, "program should be loaded after _require_program()"
        fm = self._get_function_manager(program)
        assert fm is not None, "function manager should be available for loaded program"
        addr = self._resolve_address(addr_str, program=program)
        func = None
        if addr is not None:
            func = fm.getFunctionContaining(addr)
        if func is None:
            func = self._resolve_function(addr_str, program=program)
            if func is not None:
                addr = func.getEntryPoint()
        assert addr is not None, "addr should be set after resolving address or function"
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
            max_depth=max_depth,
            timeout_s=timeout_s,
        )

    async def _handle_backward(self, args: dict[str, Any], program: GhidraProgram, addr: GhidraAddress, func: GhidraFunction, max_ops: int, max_depth: int, timeout_s: int) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/dataflow.py:DataFlowToolProvider._handle_backward")
        return await self._analyze_data_flow("backward", program, addr, func, max_ops, max_depth, timeout_s)

    async def _handle_forward(self, args: dict[str, Any], program: GhidraProgram, addr: GhidraAddress, func: GhidraFunction, max_ops: int, max_depth: int, timeout_s: int) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/dataflow.py:DataFlowToolProvider._handle_forward")
        return await self._analyze_data_flow("forward", program, addr, func, max_ops, max_depth, timeout_s)

    async def _handle_variable_accesses(self, args: dict[str, Any], program: GhidraProgram, addr: GhidraAddress, func: GhidraFunction, max_ops: int, max_depth: int, timeout_s: int) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/dataflow.py:DataFlowToolProvider._handle_variable_accesses")
        return await self._analyze_data_flow("variable_accesses", program, addr, func, max_ops, max_depth, timeout_s)

    async def _analyze_data_flow(self, direction: str, program: GhidraProgram, addr: GhidraAddress, func: GhidraFunction, max_ops: int, max_depth: int, timeout_s: int) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/dataflow.py:DataFlowToolProvider._analyze_data_flow")
        try:
            payload = collect_function_data_flow(
                program,
                func,
                addr,
                direction=direction,
                max_ops=max_ops,
                max_depth=max_depth,
                timeout_s=timeout_s,
                session_decompiler=getattr(self.program_info, "decompiler", None) if self.program_info is not None else None,
            )
            return create_success_response(payload)
        except Exception as e:
            logger.error("Data flow analysis error: %s", e)
            return self._empty_response(direction, addr, error=str(e))
