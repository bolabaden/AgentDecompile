"""Call Graph Tool Provider - get-call-graph (and gen-call-graph alias).

- mode: graph (visual flow), tree, callers (who calls this), callees (what this calls), callers_decomp (with decompiled snippets), common_callers (compare two functions).
- direction: 'calling' → callers, 'called' → callees; mode can be inferred from direction.
- Uses tools/callgraph_tool.CallGraphTool; lazily instantiated per provider via _get_callgraph_tool().
"""

from __future__ import annotations

import logging

from itertools import islice
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ghidra.program.model.listing import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        Function as GhidraFunction,
        FunctionManager as GhidraFunctionManager,
        Program as GhidraProgram,
    )

from mcp import types

from agentdecompile_cli.mcp_server.providers._collectors import make_task_monitor
from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
    n,
)
from agentdecompile_cli.registry import Tool

logger = logging.getLogger(__name__)


class CallGraphToolProvider(ToolProvider):
    HANDLERS = {
        "getcallgraph": "_handle",
        "gencallgraph": "_handle",
    }

    def __init__(self, program_info=None):
        logger.debug("diag.enter %s", "mcp_server/providers/callgraph.py:CallGraphToolProvider.__init__")
        super().__init__(program_info)
        self._callgraph_tool = None

    def _get_callgraph_tool(self):
        """Lazy-init CallGraphTool so we only load it when a call-graph tool is actually used."""
        logger.debug("diag.enter %s", "mcp_server/providers/callgraph.py:CallGraphToolProvider._get_callgraph_tool")
        if self._callgraph_tool is None:
            try:
                from agentdecompile_cli.tools.callgraph_tool import CallGraphTool

                self._callgraph_tool = CallGraphTool(self.program_info)
            except Exception:
                pass
        return self._callgraph_tool

    def list_tools(self) -> list[types.Tool]:
        logger.debug("diag.enter %s", "mcp_server/providers/callgraph.py:CallGraphToolProvider.list_tools")
        schema = {
            "type": "object",
            "properties": {
                "programPath": {"type": "string", "description": "The path to the program containing the function."},
                "function": {"type": "string", "description": "The exact name or starting address of the function to trace. Supports both thunk addresses (e.g. CreateFileA @ 0x004011fc) and IAT addresses (e.g. 0x48f1fc); IAT is resolved to the thunk. Omit to get a whole-program overview (all functions with caller/callee counts, sorted by most-called)."},
                "addressOrSymbol": {"type": "string", "description": "Alternative parameter for the function. Supports both thunk and IAT addresses; IAT is resolved to the thunk. Omit to get the whole-program overview."},
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
                name=Tool.GET_CALL_GRAPH.value,
                description="List or map out the relationships of who calls what function (callers/xrefs) and what functions are called from here (callees). Critical for tracking execution flow, finding the main path to a vulnerability, or figuring out how to reach hidden code. Call with no arguments to get a whole-program overview (all functions sorted by caller count, entry points flagged).",
                inputSchema=schema,
            ),
        ]

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/callgraph.py:CallGraphToolProvider._handle")
        self._require_program()
        # function/addressOrSymbol: resolved via AddressUtil (0x=hex, else decimal) in CallGraphTool or _resolve_function
        func = self._get_address_or_symbol(args)

        # No function specified → return whole-program call graph overview
        if not func:
            return await self._handle_overview(args)

        mode_explicit = self._get_str(args, "mode", "action", "operation")
        direction_raw = self._get_str(args, "direction", default="calling")
        logger.info("get-call-graph function=%s direction=%s", func, direction_raw)
        _dir_aliases = {"callers": "calling", "callees": "called", "up": "calling", "down": "called"}
        direction = _dir_aliases.get(n(direction_raw), direction_raw)

        # If caller didn't set mode, derive it from direction so "direction: called" → mode "callees"
        if mode_explicit:
            mode = mode_explicit
        else:
            mode = "callees" if direction == "called" else "callers"
        display_type = self._get_str(args, "displaytype", "displayType", default="flow")
        include_refs = self._get_bool(args, "includerefs", default=True)
        max_depth_raw = self._get(args, "maxdepth")
        max_depth = None
        if max_depth_raw is not None:
            try:
                max_depth = int(max_depth_raw)
            except (ValueError, TypeError):
                pass
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
                logger.debug("get-call-graph completed via CallGraphTool function=%s", func)
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
                logger.warning("CallGraphTool failed, using Ghidra API fallback: %s", e)

        # Fallback: use Ghidra API directly
        try:
            assert self.program_info is not None, "Program info is not available"
            program: GhidraProgram = self.program_info.program
            fm: GhidraFunctionManager = self._get_function_manager(program)  # noqa: F841

            target_func: GhidraFunction = self._resolve_function(func, program=program)

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

    async def _handle_overview(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Whole-program call graph overview when no function is specified.

        Returns all functions with their caller/callee counts, sorted by callerCount
        descending (hotspots first).  Functions with 0 callers are flagged as entry
        points (likely root functions or dead code).  Respects maxNodes.
        """
        logger.debug("diag.enter %s", "mcp_server/providers/callgraph.py:CallGraphToolProvider._handle_overview")
        max_nodes = self._get_int(args, "maxnodes", default=250)
        assert self.program_info is not None, "Program info is not available"
        program = self.program_info.program
        fm = program.getFunctionManager()

        entries: list[dict[str, Any]] = []
        _monitor = make_task_monitor()
        for func in fm.getFunctions(True):
            caller_count = func.getCallingFunctions(_monitor).size() if hasattr(func.getCallingFunctions(_monitor), "size") else len(list(func.getCallingFunctions(_monitor)))
            callee_count = func.getCalledFunctions(_monitor).size() if hasattr(func.getCalledFunctions(_monitor), "size") else len(list(func.getCalledFunctions(_monitor)))
            entries.append({
                "name": str(func.getName()),
                "address": str(func.getEntryPoint()),
                "callerCount": int(caller_count),
                "calleeCount": int(callee_count),
                "isExternal": bool(func.isExternal()),
                "isThunk": bool(func.isThunk()),
                "isEntryPoint": int(caller_count) == 0,
            })

        entries.sort(key=lambda x: x["callerCount"], reverse=True)
        truncated = len(entries) > max_nodes
        entries = entries[:max_nodes]

        return create_success_response({
            "mode": "overview",
            "totalFunctions": len(entries),
            "truncated": truncated,
            "maxNodes": max_nodes,
            "functions": entries,
            "note": "Sorted by callerCount descending. isEntryPoint=true means no callers found (likely root/entry/dead-code). Pass function= to get a specific function's call graph.",
        })

    async def _handle_callers(self, args: dict[str, Any], program: GhidraProgram, target_func: GhidraFunction, func: str, second: str | None, max_nodes: int) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/callgraph.py:CallGraphToolProvider._handle_callers")
        callers = list(islice(target_func.getCallingFunctions(make_task_monitor()), max_nodes))
        caller_info = [{"name": c.getName(), "address": str(c.getEntryPoint())} for c in callers]

        mode = self._get_str(args, "mode", default="callers")
        mode_n = n(mode)
        # common_callers: intersect callers of func with callers of second function
        if mode_n in ("commoncallers", "common_callers") and second:
            second_func = self._resolve_function(second, program=program)
            if second_func:
                second_callers = {c.getName() for c in second_func.getCallingFunctions(make_task_monitor())}
                common = [c for c in caller_info if c["name"] in second_callers]
                return create_success_response({"function": func, "secondFunction": second, "mode": mode, "commonCallers": common, "count": len(common)})

        return create_success_response({"function": func, "mode": mode, "callers": caller_info, "count": len(caller_info)})

    async def _handle_callees(self, args: dict[str, Any], program: GhidraProgram, target_func: GhidraFunction, func: str, second: str | None, max_nodes: int) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/callgraph.py:CallGraphToolProvider._handle_callees")
        callees = list(islice(target_func.getCalledFunctions(make_task_monitor()), max_nodes))
        callee_info = [{"name": c.getName(), "address": str(c.getEntryPoint())} for c in callees]
        mode = self._get_str(args, "mode", default="callees")
        return create_success_response({"function": func, "mode": mode, "callees": callee_info, "count": len(callee_info)})

    async def _handle_graph(self, args: dict[str, Any], program: GhidraProgram, target_func: GhidraFunction, func: str, second: str | None, max_nodes: int) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/callgraph.py:CallGraphToolProvider._handle_graph")
        callers = list(islice(target_func.getCallingFunctions(make_task_monitor()), max_nodes))
        callees = list(islice(target_func.getCalledFunctions(make_task_monitor()), max_nodes))
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
