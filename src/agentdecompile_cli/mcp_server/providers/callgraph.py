"""Call Graph Tool Provider - get-call-graph.

Modes: graph, tree, callers, callees, callers_decomp, common_callers.
"""

from __future__ import annotations

import logging
from itertools import islice

from typing import Any

from mcp import types

from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
    n,
)

logger = logging.getLogger(__name__)


class CallGraphToolProvider(ToolProvider):
    HANDLERS = {
        "getcallgraph": "_handle",
        "gencallgraph": "_handle",
    }

    def __init__(self, program_info=None):
        super().__init__(program_info)
        self._callgraph_tool = None

    def _get_callgraph_tool(self):
        if self._callgraph_tool is None:
            try:
                from agentdecompile_cli.tools.callgraph_tool import CallGraphTool

                self._callgraph_tool = CallGraphTool(self.program_info)
            except Exception:
                pass
        return self._callgraph_tool

    def list_tools(self) -> list[types.Tool]:
        schema = {
            "type": "object",
            "properties": {
                "programPath": {"type": "string", "description": "Path to the program/binary"},
                "function": {"type": "string", "description": "Function name or address"},
                "addressOrSymbol": {"type": "string", "description": "Address or symbol (alt)"},
                "functionIdentifier": {"type": "string", "description": "Function identifier (alt)"},
                "mode": {"type": "string", "enum": ["graph", "tree", "callers", "callees", "callers_decomp", "common_callers"]},
                "direction": {"type": "string", "enum": ["calling", "called"], "default": "calling"},
                "displayType": {"type": "string", "enum": ["flow", "flow_ends", "mind"], "default": "flow"},
                "includeRefs": {"type": "boolean", "default": True},
                "maxDepth": {"type": "integer"},
                "maxRunTime": {"type": "integer", "default": 60},
                "condenseThreshold": {"type": "integer", "default": 50},
                "topLayers": {"type": "integer", "default": 5},
                "bottomLayers": {"type": "integer", "default": 5},
                "maxNodes": {"type": "integer", "default": 250},
                "secondFunction": {"type": "string", "description": "Second function for common_callers mode"},
            },
            "required": [],
        }

        return [
            types.Tool(
                name="get-call-graph",
                description="Generate a call graph for a function",
                inputSchema=schema,
            ),
            types.Tool(
                name="gen-callgraph",
                description="Generate a call graph (alias for get-call-graph)",
                inputSchema=schema,
            ),
        ]

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        func = self._get_address_or_symbol(args)
        if not func:
            raise ValueError("function or addressOrSymbol is required")

        mode = self._get_str(args, "mode", default="graph")
        direction = self._get_str(args, "direction", default="calling")
        display_type = self._get_str(args, "displaytype", "displayType", default="flow")
        include_refs = self._get_bool(args, "includerefs", default=True)
        max_depth = self._get(args, "maxdepth")
        if max_depth is not None:
            max_depth = int(max_depth)
        max_run_time = self._get_int(args, "maxruntime", default=60)
        condense = self._get_int(args, "condensethreshold", default=50)
        top = self._get_int(args, "toplayers", default=5)
        bottom = self._get_int(args, "bottomlayers", default=5)
        max_nodes = self._get_int(args, "maxnodes", default=250)
        second = self._get_str(args, "secondfunction")

        # Try the real CallGraphTool first
        cg = self._get_callgraph_tool()
        if cg is not None:
            try:
                result = cg.generate_for_mcp(
                    function_name_or_address=func,
                    direction=direction,
                    display_type=display_type,
                    include_refs=include_refs,
                    max_depth=max_depth,
                    max_run_time=max_run_time,
                    condense_threshold=condense,
                    top_layers=top,
                    bottom_layers=bottom,
                )
                return create_success_response(
                    {
                        "functionName": result.function_name,
                        "direction": result.direction.value if hasattr(result.direction, "value") else str(result.direction),
                        "displayType": result.display_type.value if hasattr(result.display_type, "value") else str(result.display_type),
                        "graph": result.graph if hasattr(result, "graph") else {},
                        "mermaidUrl": getattr(result, "mermaid_url", None),
                    },
                )
            except Exception as e:
                logger.warning(f"CallGraphTool failed, using Ghidra API: {e}")

        # Fallback: use Ghidra API directly
        try:
            assert self.program_info is not None, "Program info is not available"
            program = self.program_info.program
            fm = self._get_function_manager(program)

            target_func: Any = self._resolve_function(func, program=program)

            if target_func is None:
                raise ValueError(f"Function not found: {func}")

            # Use dispatch table to map modes to handlers for clarity
            return await self._dispatch_handler(args, mode, {
                "callers": "_handle_callers",
                "callers_decomp": "_handle_callers",
                "callersdecomp": "_handle_callers",
                "common_callers": "_handle_callers",
                "commoncallers": "_handle_callers",
                "callees": "_handle_callees",
                "graph": "_handle_graph",
                "tree": "_handle_graph",
            }, program=program, target_func=target_func, func=func, second=second, max_nodes=max_nodes)
        except ValueError:
            raise
        except Exception as e:
            return create_success_response(
                {
                    "function": func,
                    "mode": mode,
                    "note": f"Call graph generation incomplete: {e}",
                    "graph": {},
                },
            )

    async def _handle_callers(self, args: dict[str, Any], program: Any, target_func: Any, func: str, second: str | None, max_nodes: int) -> list[types.TextContent]:
        callers = list(islice(target_func.getCallingFunctions(None), max_nodes))
        caller_info = [{"name": c.getName(), "address": str(c.getEntryPoint())} for c in callers]

        mode = self._get_str(args, "mode", default="callers")
        mode_n = n(mode)
        if mode_n in ("commoncallers", "common_callers") and second:
            second_func = self._resolve_function(second, program=program)
            if second_func:
                second_callers = {c.getName() for c in second_func.getCallingFunctions(None)}
                common = [c for c in caller_info if c["name"] in second_callers]
                return create_success_response({"function": func, "secondFunction": second, "mode": mode, "commonCallers": common, "count": len(common)})

        return create_success_response({"function": func, "mode": mode, "callers": caller_info, "count": len(caller_info)})

    async def _handle_callees(self, args: dict[str, Any], program: Any, target_func: Any, func: str, second: str | None, max_nodes: int) -> list[types.TextContent]:
        callees = list(islice(target_func.getCalledFunctions(None), max_nodes))
        callee_info = [{"name": c.getName(), "address": str(c.getEntryPoint())} for c in callees]
        mode = self._get_str(args, "mode", default="callees")
        return create_success_response({"function": func, "mode": mode, "callees": callee_info, "count": len(callee_info)})

    async def _handle_graph(self, args: dict[str, Any], program: Any, target_func: Any, func: str, second: str | None, max_nodes: int) -> list[types.TextContent]:
        callers = list(islice(target_func.getCallingFunctions(None), max_nodes))
        callees = list(islice(target_func.getCalledFunctions(None), max_nodes))
        return create_success_response(
            {
                "function": func,
                "mode": self._get_str(args, "mode", default="graph"),
                "callers": [{"name": c.getName(), "address": str(c.getEntryPoint())} for c in callers],
                "callees": [{"name": c.getName(), "address": str(c.getEntryPoint())} for c in callees],
                "callerCount": len(callers),
                "calleeCount": len(callees),
            },
        )
