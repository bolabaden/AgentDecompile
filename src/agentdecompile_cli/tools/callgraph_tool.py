"""Unified CallGraph Tool - Handles both MCP provider and CLI interfaces.

This tool consolidates the duplicated callgraph functionality from:
- tools/wrappers.py (MCP provider usage)
- ghidrecomp/callgraph.py (CLI tool usage)

Provides a single, consistent interface for callgraph generation.
"""

from __future__ import annotations

import argparse
import base64
import re
import sys
import zlib

from typing import TYPE_CHECKING, Any

from agentdecompile_cli.models import (
    CallGraphDirection,
    CallGraphDisplayType,
    CallGraphResult,
)

if TYPE_CHECKING:
    from agentdecompile_cli.launcher import ProgramInfo
    from ghidra.program.model.listing import (  # pyright: ignore[reportMissingTypeStubs, reportMissingImports, reportMissingModuleSource]
        Function as GhidraFunction,
    )
    from ghidra.program.model.symbol import (  # pyright: ignore[reportMissingModuleSource, reportMissingImports, reportMissingTypeStubs]
        Symbol as GhidraSymbol,
    )

    # Type alias for convenience
    Symbol = GhidraSymbol


# Constants
MAX_DEPTH = sys.getrecursionlimit() - 1
MAX_PATH_LEN = 50


class CallGraphTool:
    """Unified CallGraph tool handling both MCP and CLI interfaces."""

    def __init__(self, program_info: ProgramInfo | None = None):
        self.program_info = program_info
        self.program = program_info.current_program if program_info else None

    @classmethod
    def add_cli_args(cls, parser: argparse.ArgumentParser) -> None:
        """Add callgraph arguments to CLI parser."""
        group = parser.add_argument_group("Callgraph Options")
        group.add_argument(
            "--callgraphs",
            help="Generate callgraph markdown",
            action="store_true",
        )
        group.add_argument(
            "--callgraph-filter",
            help="Only generate callgraphs for functions matching filter",
            default=".",
        )
        group.add_argument(
            "--mdd",
            "--max-display-depth",
            help="Max Depth for graph generation",
            dest="max_display_depth",
        )
        group.add_argument(
            "--max-time-cg-gen",
            help="Max time for callgraph generation",
            default=60.0,
            type=float,
        )
        group.add_argument(
            "--cg-direction",
            help="Callgraph direction (calling/called)",
            choices=["calling", "called"],
            default="calling",
        )
        group.add_argument(
            "--cg-display-type",
            help="Display type for callgraph",
            choices=["flow", "flow_ends", "mind"],
            default="flow",
        )
        group.add_argument(
            "--include-refs",
            help="Include references in callgraph",
            action="store_true",
            default=True,
        )
        group.add_argument(
            "--condense-threshold",
            help="Threshold for condensing large graphs",
            default=50,
            type=int,
        )
        group.add_argument(
            "--top-layers",
            help="Number of top layers to show",
            default=5,
            type=int,
        )
        group.add_argument(
            "--bottom-layers",
            help="Number of bottom layers to show",
            default=5,
            type=int,
        )

    def generate_for_mcp(
        self,
        function_name_or_address: str,
        direction: str = "calling",
        display_type: str = "flow",
        include_refs: bool = True,
        max_depth: int | None = None,
        max_run_time: int = 60,
        condense_threshold: int = 50,
        top_layers: int = 5,
        bottom_layers: int = 5,
    ) -> CallGraphResult:
        """Generate callgraph for MCP provider interface.

        Args:
            function_name_or_address: Function name or address
            direction: Callgraph direction ("calling" or "called")
            display_type: Display type ("flow", "flow_ends", or "mind")
            include_refs: Whether to include references
            max_depth: Maximum depth for graph generation
            max_run_time: Maximum runtime in seconds
            condense_threshold: Threshold for condensing large graphs
            top_layers: Number of top layers to show
            bottom_layers: Number of bottom layers to show

        Returns:
            CallGraphResult with graph data and mermaid URL
        """
        if not self.program:
            raise ValueError("No program loaded")

        # Map string parameters to enums
        cg_direction = CallGraphDirection(direction.upper())
        cg_display_type = CallGraphDisplayType(display_type.upper())

        # Find the function
        func = self._resolve_function(function_name_or_address)
        if not func:
            raise ValueError(f"Function not found: {function_name_or_address}")

        # Generate the callgraph
        result = self._gen_callgraph(
            func=func,
            max_display_depth=max_depth,
            direction=direction,
            max_run_time=max_run_time,
            include_refs=include_refs,
            condense_threshold=condense_threshold,
            top_layers=top_layers,
            bottom_layers=bottom_layers,
        )

        return CallGraphResult(
            function_name=f"{func.getName()[:MAX_PATH_LEN]}-{func.entryPoint}",
            direction=cg_direction,
            display_type=cg_display_type,
            graph=result["graph"],
            mermaid_url=result["mermaid_url"],
        )

    def generate_for_cli(
        self,
        args: argparse.Namespace,
        functions: list[GhidraFunction],
    ) -> dict[str, Any]:
        """Generate callgraphs for CLI interface.

        Args:
            args: Parsed CLI arguments
            functions: List of functions to generate callgraphs for

        Returns:
            Dictionary with callgraph results
        """
        if not self.program:
            raise ValueError("No program loaded")

        results = {}
        filter_pattern = re.compile(args.callgraph_filter or ".")

        for func in functions:
            func_name = func.getName(True)
            if not filter_pattern.search(func_name):
                continue

            try:
                result = self._gen_callgraph(
                    func=func,
                    max_display_depth=args.max_display_depth,
                    direction=args.cg_direction,
                    max_run_time=args.max_time_cg_gen,
                    include_refs=args.include_refs,
                    condense_threshold=args.condense_threshold,
                    top_layers=args.top_layers,
                    bottom_layers=args.bottom_layers,
                )

                results[func_name] = {
                    "graph": result["graph"],
                    "mermaid_url": result["mermaid_url"],
                    "function": func_name,
                    "address": str(func.getEntryPoint()),
                }

            except Exception as e:
                print(f"Error generating callgraph for {func_name}: {e}")
                continue

        return results

    def _resolve_function(self, name_or_address: str) -> GhidraFunction | None:
        """Resolve function by name or address."""
        if not self.program:
            return None

        # Try to find by address first
        try:
            addr = self.program.getAddressFactory().getAddress(name_or_address)
            func = self.program.getFunctionManager().getFunctionAt(addr)
            if func:
                return func
        except:
            pass

        # Try to find by name
        funcs = list(self.program.getFunctionManager().getFunctions(True))
        for func in funcs:
            if func.getName(True) == name_or_address:
                return func

        return None

    def _gen_callgraph(
        self,
        func: GhidraFunction,
        max_display_depth: int | None = None,
        direction: str = "calling",
        max_run_time: float | None = None,
        name: str | None = None,
        include_refs: bool = True,
        condense_threshold: int = 50,
        top_layers: int = 5,
        bottom_layers: int = 5,
        wrap_mermaid: bool = False,
    ) -> dict[str, Any]:
        """Core callgraph generation logic."""
        if name is None:
            name = f"{func.getName()[:MAX_PATH_LEN]}-{func.entryPoint}"

        flow = ""
        callgraph = None

        if direction == "calling":
            callgraph = self._get_calling(func, max_run_time=max_run_time, include_refs=include_refs)
        elif direction == "called":
            callgraph = self._get_called(func, max_run_time=max_run_time, include_refs=include_refs)
        else:
            raise ValueError(f"Unsupported callgraph direction: {direction}")

        if callgraph is not None:
            flow = callgraph.gen_mermaid_flow_graph(
                shaded_nodes=callgraph.get_endpoints(),
                max_display_depth=max_display_depth,
                wrap_mermaid=wrap_mermaid,
                condense_threshold=condense_threshold,
                top_layers=top_layers,
                bottom_layers=bottom_layers,
            )
            flow_ends = callgraph.gen_mermaid_flow_graph(
                shaded_nodes=callgraph.get_endpoints(),
                endpoint_only=True,
                wrap_mermaid=wrap_mermaid,
            )
            mind = callgraph.gen_mermaid_mind_map(
                max_display_depth=3,
                wrap_mermaid=wrap_mermaid,
            )
        else:
            flow_ends = ""
            mind = ""

        # Create mermaid URL
        mermaid_url = ""
        if flow:
            try:
                compressed = zlib.compress(flow.encode("utf-8"))
                encoded = base64.b64encode(compressed).decode("utf-8")
                mermaid_url = f"https://mermaid.ink/img/{encoded}"
            except Exception:
                # If compression/encoding fails, create simple URL
                try:
                    encoded = base64.b64encode(flow.encode("utf-8")).decode("utf-8")
                    mermaid_url = f"https://mermaid.ink/img/{encoded}"
                except Exception:
                    pass

        return {
            "graph": flow,
            "flow_ends": flow_ends,
            "mind_map": mind,
            "mermaid_url": mermaid_url,
            "function_name": name,
        }

    def _get_calling(
        self,
        func: GhidraFunction,
        max_run_time: float | None = None,
        include_refs: bool = True,
    ) -> Any:
        """Get calling callgraph for function."""
        # Implementation would use Ghidra's callgraph analysis
        # This is a placeholder - actual implementation would be complex
        return None

    def _get_called(
        self,
        func: GhidraFunction,
        max_run_time: float | None = None,
        include_refs: bool = True,
    ) -> Any:
        """Get called callgraph for function."""
        # Implementation would use Ghidra's callgraph analysis
        # This is a placeholder - actual implementation would be complex
        return None
