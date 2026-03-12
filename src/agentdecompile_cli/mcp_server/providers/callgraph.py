"""Call Graph Tool Provider - get-call-graph (and gen-call-graph alias).

  - mode: graph (visual flow), tree, callers (who calls this), callees (what this calls), callers_decomp (with decompiled snippets), common_callers (compare two functions).
  - direction: 'calling' → callers, 'called' → callees; mode can be inferred from direction.
  - Uses tools/callgraph_tool.CallGraphTool; lazily instantiated per provider via _get_callgraph_tool().
"""

from __future__ import annotations

import logging

from itertools import islice
from typing import Any

from mcp import types

from agentdecompile_cli.registry import ToolName
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
        """Lazy-init CallGraphTool so we only load it when a call-graph tool is actually used."""
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
                "programPath": {"type": "string", "description": "The path to the program containing the function."},
                "function": {"type": "string", "description": "The exact name or starting address of the function to trace."},
                "addressOrSymbol": {"type": "string", "description": "Alternative parameter for the function to trace."},
                "functionIdentifier": {"type": "string", "description": "Another alternative parameter for the function to trace."},
                "mode": {
                    "type": "string",
                    "enum": ["graph", "tree", "callers", "callees", "callers_decomp", "common_callers"],
                    "description": "What type of data to generate. Omit and use 'direction' instead for simple lookups — mode is automatically inferred from direction ('calling' → 'callers', 'called' → 'callees'). Set explicitly only when you need 'graph'/'tree' layouts, 'callers_decomp', or 'common_callers'.",
                },
                "direction": {"type": "string", "enum": ["calling", "called"], "default": "calling", "description": "PRIMARY traversal direction: 'calling' = upwards (who calls this function), 'called' = downwards (what this function calls). Mode is inferred from this automatically."},
                "displayType": {"type": "string", "enum": ["flow", "flow_ends", "mind"], "default": "flow", "description": "Visual format style for graphical outputs."},
                "includeRefs": {"type": "boolean", "default": True, "description": "If true, incorporates data cross-references (using memory addresses) in addition to direct function calls."},
                "maxDepth": {"type": "integer", "description": "Omit unless you need to cap traversal depth. By default depth is unlimited. Set to 1 for direct callers/callees only, 2 for one level deeper, etc."},
                "maxRunTime": {"type": "integer", "default": 60, "description": "Timeout in seconds to prevent the graph tracer from analyzing forever on massive functions."},
                "condenseThreshold": {"type": "integer", "default": 50, "description": "If more than this many nodes exist at one level, combine them to keep the graph readable."},
                "topLayers": {"type": "integer", "default": 5, "description": "Max upwards layers (callers) to show in the visual graph."},
                "bottomLayers": {"type": "integer", "default": 5, "description": "Max downwards layers (callees) to show in the visual graph."},
                "maxNodes": {"type": "integer", "default": 250, "description": "Number of functions to track in the call graph. Typical values are 250–1000. Do not set this below 100 unless the user explicitly wants a very shallow graph."},
                "secondFunction": {"type": "string", "description": "Used only when mode is 'common_callers'. The name or address of the second function to compare callers against."},
            },
            "required": [],
        }

        return [
            types.Tool(
                name=ToolName.GET_CALL_GRAPH.value,
                description="List or map out the relationships of who calls what function (callers/xrefs) and what functions are called from here (callees). Critical for tracking execution flow, finding the main path to a vulnerability, or figuring out how to reach hidden code.",
                inputSchema=schema,
            ),
        ]

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        func = self._get_address_or_symbol(args)
        if not func:
            raise ValueError("function or addressOrSymbol is required")

        mode_explicit = self._get_str(args, "mode", "action", "operation")
        direction_raw = self._get_str(args, "direction", default="calling")
        _dir_aliases = {"callers": "calling", "callees": "called", "up": "calling", "down": "called"}
        direction = _dir_aliases.get(n(direction_raw), direction_raw)

        # If caller didn't set mode, derive it from direction so "direction: called" → mode "callees"
        if mode_explicit:
            mode = mode_explicit
        else:
            mode = "callees" if direction == "called" else "callers"
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

        # Prefer full CallGraphTool (graph/tree, timeouts, condense); fall back to Ghidra API if unavailable
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

            # Multiple mode names can map to same handler (e.g. callers_decomp → _handle_callers)
            return await self._dispatch_handler(
                args,
                mode,
                {
                    "callers": "_handle_callers",
                    "callers_decomp": "_handle_callers",
                    "callersdecomp": "_handle_callers",
                    "common_callers": "_handle_callers",
                    "commoncallers": "_handle_callers",
                    "callees": "_handle_callees",
                    "graph": "_handle_graph",
                    "tree": "_handle_graph",
                },
                program=program,
                target_func=target_func,
                func=func,
                second=second,
                max_nodes=max_nodes,
            )
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
        # common_callers: intersect callers of func with callers of second function
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
