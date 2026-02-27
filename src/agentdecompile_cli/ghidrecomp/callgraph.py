from __future__ import annotations

import argparse
import json
import re
import sys

from functools import lru_cache
from typing import TYPE_CHECKING, Any

from agentdecompile_cli.tools.callgraph_tool import CallGraphTool

# Constants from unified tool
MAX_DEPTH = sys.getrecursionlimit() - 1
MAX_PATH_LEN = 50

# needed for ghidra python vscode autocomplete
if TYPE_CHECKING:
    from ghidra.program.model.address import AddressRange as GhidraAddressRange, AddressRangeIterator as GhidraAddressRangeIterator
    from ghidra.program.model.listing import Function as GhidraFunction, Program as GhidraProgram
    from ghidra.program.model.symbol import (
        FunctionManager as GhidraFunctionManager,
        Reference as GhidraReference,
        ReferenceIterator as GhidraReferenceIterator,
        ReferenceManager as GhidraReferenceManager,
    )
    from ghidra_builtins import *


def add_cg_args_to_parser(parser: argparse.ArgumentParser) -> None:
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
        help="Max time in seconds to wait for callgraph gen.",
        default=5,
    )
    group.add_argument(
        "--cg-direction",
        help="Direction for callgraph.",
        choices=["calling", "called", "both"],
        default="calling",
    )
    group.add_argument(
        "--no-call-refs",
        action="store_true",
        help="Do not include non-call references in callgraph",
    )
    group.add_argument(
        "--condense-threshold",
        help="Number of edges to trigger graph condensation.",
        type=int,
        default=50,
    )
    group.add_argument(
        "--top-layers",
        help="Number of top layers to show in condensed graph.",
        type=int,
        default=None,
    )
    group.add_argument(
        "--bottom-layers",
        help="Number of bottom layers to show in condensed graph.",
        type=int,
        default=None,
    )


class CallGraph:
    def __init__(self, root: str | None = None):
        self.graph: dict[str, list[tuple[str, int, int, str]]] = {}
        self.title: str | None = None
        self.count: int = 0
        self.max_depth: int = 0
        self.root: str | None = root

    def set_root(self, root: str) -> None:
        self.graph.setdefault(root, [])
        self.root = root if root is not None else None

    def add_edge(self, node1: str, node2: str, depth: int, ref_type: str) -> None:
        if self.root is None:
            raise ValueError("root node must be set prior to adding an edge")

        self.graph.setdefault(node1, [])
        self.graph.setdefault(node2, [])

        self.graph[node1].append((node2, depth, self.count, ref_type))
        self.count += 1

        # update max depth
        self.max_depth = max(self.max_depth, depth)

    def print_graph(self) -> None:
        for src, dst in self.graph.items():
            print(f"{src}-->{dst}")

    def root_at_end(self) -> bool:
        """Determines the direction of the graph"""
        # if the root has no links, the root is at the end
        return len(self.graph.get(self.root or "", []) or []) == 0

    def get_direction(self) -> str | None:
        """Reports calling or called if known"""
        direction: str | None = None

        if len(self.graph) == 1:
            direction = "unknown"
        elif self.root_at_end():
            direction = "calling"
        else:
            direction = "called"

        return direction

    def get_endpoints(self) -> list[str]:
        end_nodes: set[str] = set()

        if not self.root_at_end():
            for src in list(self.graph):
                dst = self.graph[src]
                # special case of loop
                if len(dst) == 0 or (len(dst) == 1 and dst[0] == src):
                    end_nodes.add(src)
        else:
            destinations: list[str] = []

            for src in list(self.graph):
                dst = self.graph[src]
                # special case of loop
                if len(dst) == 1 and dst[0] == src:
                    # don't append to destinations in this case
                    continue

                for d in dst:
                    destinations.append(d[0])

            end_nodes = set(self.graph.keys()).difference(set(destinations))

        return list(end_nodes)

    def get_count_at_depth(self, depth: int) -> int:
        """Returns count for nodes at a specific depth"""
        count: int = 0
        for src in list(self.graph):
            dst = self.graph[src]
            for d in dst:
                if d[1] == depth:
                    count += 1

        return count

    def links_count(self) -> int:
        """Returns count of edges"""
        count: int = 0
        for src in list(self.graph):
            dst = self.graph[src]

            for d in dst:
                count += 1

        return count

    def is_reachable(self, source_func: str, dest_func: str) -> bool:
        """Determines if dest_func is reachable from source_func by traversing the callgraph."""
        if source_func not in self.graph or dest_func not in self.graph:
            raise ValueError("Source function does not exist in callgraph")

        if source_func == dest_func:
            return True

        queue: list[str] = [source_func]
        visited: set[str] = {source_func}

        while queue:
            current_func = queue.pop(0)

            # In this graph, an edge (u, v) means u calls v.
            # self.graph[current_func] is a list of (neighbor, depth, count, ref_type)
            for neighbor, _, _, _ in self.graph.get(current_func, []):
                if neighbor == dest_func:
                    return True
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)

        return False

    def get_all_paths_graph(self, source_func: str, dest_func: str) -> CallGraph:
        """Generates a new CallGraph containing only the edges that form paths
        between source_func and dest_func.
        """

        def find_all_paths_dfs(start_node: str, end_node: str) -> list[list[str]]:
            paths: list[list[str]] = []

            def dfs_recursive(current_node: str, current_path: list[str]) -> None:
                current_path.append(current_node)

                if current_node == end_node:
                    paths.append(list(current_path))
                else:
                    for neighbor_tuple in self.graph.get(current_node, []):
                        neighbor = neighbor_tuple[0]
                        if neighbor not in current_path:
                            dfs_recursive(neighbor, current_path)

                current_path.pop()

            if start_node in self.graph:
                dfs_recursive(start_node, [])
            return paths

        if source_func not in self.graph or dest_func not in self.graph:
            return CallGraph(root=source_func)

        all_paths: list[list[str]] = find_all_paths_dfs(source_func, dest_func)

        path_graph: CallGraph = CallGraph(root=source_func)

        if not all_paths:
            return path_graph

        added_edges: set[tuple[str, str]] = set()

        for path in all_paths:
            for i in range(len(path) - 1):
                u, v = path[i], path[i + 1]

                if (u, v) in added_edges:
                    continue

                for neighbor_tuple in self.graph.get(u, []):
                    if neighbor_tuple[0] == v:
                        # Original tuple: (node2, depth, self.count, ref_type)
                        depth = neighbor_tuple[1]
                        ref_type = neighbor_tuple[3]
                        path_graph.add_edge(u, v, depth, ref_type)
                        added_edges.add((u, v))
                        break

        return path_graph

    @staticmethod
    def remove_bad_mermaid_chars(text: str) -> str:
        return re.sub(r"`", "", text)

    def gen_mermaid_flow_graph(
        self,
        direction: str | None = None,
        shaded_nodes: list[str] | None = None,
        shade_color="#339933",
        max_display_depth: int | None = None,
        endpoint_only: bool = False,
        wrap_mermaid: bool = False,
        condense_threshold: int | None = 50,
        top_layers: int | None = None,
        bottom_layers: int | None = None,
        preserve_root_layers: int = 2,
        preserve_leaf_layers: int = 2,
    ) -> str:
        """Generate MermaidJS flowchart from self.graph"""
        used_condensed = False
        condensed_cg: CallGraph | None = None

        # Condense only if graph is large enough and not endpoint-only
        if condense_threshold is not None and self.links_count() > condense_threshold and not endpoint_only:
            import collections

            # --- Step 1: Collect nodes and edges ---
            # Build a list of all nodes and edges, and record depth from root.
            all_nodes: set[str] = set(self.graph.keys())
            edges_raw: list[tuple[str, str, int]] = []
            node_depths: dict[str, int] = {self.root or "": 0}
            for src, edge_list in self.graph.items() if self.root is not None else {"": []}:
                for dst, depth_val, _, _ in edge_list:
                    all_nodes.add(dst)
                    edges_raw.append((src, dst, int(depth_val)))
                    if dst not in node_depths or int(depth_val) < node_depths.get(dst, float("inf")):
                        node_depths[dst] = int(depth_val)

            # --- Step 2: Build reverse adjacency ---
            # Reverse adjacency lets us walk upward (toward parents).
            rev_adj: dict[str, list[str]] = {n: [] for n in all_nodes}
            for src, dst, _ in edges_raw:
                rev_adj[dst].append(src)

            # --- Step 3: Compute heights ---
            # Heights measure distance from leaves (callee graph) or entry points (calling graph).
            graph_direction = self.get_direction()
            if graph_direction and str(graph_direction).upper() == "CALLING":
                # In a calling graph, root is a leaf (like printf).
                # So compute heights from entry points (nodes with no parents).
                entry_points = {n for n in all_nodes if not rev_adj.get(n)}
                heights: dict[str, int] = dict.fromkeys(entry_points, 0)
                q: collections.deque[tuple[str, int]] = collections.deque([(ep, 0) for ep in entry_points])
                visited: set[str] = set(entry_points)
                while q:
                    node, h = q.popleft()
                    for child in self.graph.get(node, []):
                        dst = child[0]
                        if dst not in visited:
                            visited.add(dst)
                            heights[dst] = h + 1
                            q.append((dst, h + 1))
            else:
                # In a callee graph, root is entry point (like main).
                # Compute heights from leaves upward.
                leaves: set[str] = {n for n in all_nodes if not self.graph.get(n)}
                heights = dict.fromkeys(leaves, 0)
                q = collections.deque([(leaf, 0) for leaf in leaves])
                visited = set(leaves)
                while q:
                    node, h = q.popleft()
                    for parent in rev_adj.get(node, []):
                        if parent not in visited:
                            visited.add(parent)
                            heights[parent] = h + 1
                            q.append((parent, h + 1))

            # --- Step 4: Auto-calc top/bottom layer thresholds ---
            # Decide how many layers to keep at the top and bottom before condensing.
            if top_layers is None:
                current_top_layers = 0
                current_total_edges_top = 0
                for d in range(self.max_depth + 1):
                    edges_at_depth = sum(1 for _, _, depth_val in edges_raw if depth_val == d)
                    if (current_total_edges_top + edges_at_depth) > (condense_threshold // 2):
                        break
                    current_total_edges_top += edges_at_depth
                    current_top_layers = d
                top_layers = current_top_layers

            if bottom_layers is None:
                current_bottom_layers = 0
                current_total_nodes_bottom = 0
                max_height_val = max(heights.values()) if heights else 0
                for h in range(max_height_val + 1):
                    nodes_at_height = sum(1 for _, ht in heights.items() if ht == h)
                    if (current_total_nodes_bottom + nodes_at_height) > (condense_threshold // 2):
                        if h == max_height_val:
                            current_total_nodes_bottom += nodes_at_height
                            current_bottom_layers = h + 1
                        break
                    current_total_nodes_bottom += nodes_at_height
                    current_bottom_layers = h + 1
                bottom_layers = current_bottom_layers

            # --- Step 5: Enforce minimum preservation ---
            # Always keep at least N root layers and N leaf layers.
            top_layers = max(preserve_root_layers, top_layers)
            bottom_layers = max(preserve_leaf_layers, bottom_layers)

            # --- Step 6: Select nodes to keep ---
            # Top nodes: near root (callee) or entry points (calling).
            # Bottom nodes: near leaves (callee) or near root leaf (calling).
            if graph_direction and str(graph_direction).upper() == "CALLING":
                top_nodes = {n for n, h in heights.items() if h <= top_layers}
                bottom_nodes = {n for n, d in node_depths.items() if d <= (bottom_layers) and n not in top_nodes}
                condensed_depth = max(node_depths.get(self.root or "", 0), top_layers + 1)
            else:
                top_nodes = {n for n, d in node_depths.items() if d <= top_layers}
                bottom_nodes = {n for n, h in heights.items() if h <= (bottom_layers) and n not in top_nodes}
                condensed_depth = top_layers + 1

            kept_nodes: set[str] = top_nodes | bottom_nodes
            if self.root:
                kept_nodes.add(self.root)

            num_hidden_nodes = len(all_nodes) - len(kept_nodes)

            # --- Step 7: Build condensed graph ---
            # Replace middle of graph with a single placeholder node summarizing hidden nodes/edges.
            condensed_cg = CallGraph(root=self.root)
            visible_edges: list[tuple[str, str, int, str]] = []
            edges_to_condensed: set[str] = set()
            edges_from_condensed: set[str] = set()

            # Separate visible edges from those that collapse into condensed node
            for src, edge_list in self.graph.items():
                for dst, depth, count, ref_type in edge_list:
                    src_kept = src in kept_nodes
                    dst_kept = dst in kept_nodes
                    if src_kept and dst_kept:
                        visible_edges.append((src, dst, depth, ref_type))
                    elif src_kept and not dst_kept:
                        edges_to_condensed.add(src)
                    elif not src_kept and dst_kept:
                        edges_from_condensed.add(dst)

            # Add visible edges directly
            for src, dst, depth, ref_type in visible_edges:
                condensed_cg.add_edge(src, dst, depth, ref_type)

            # Add condensed placeholder node if needed
            if num_hidden_nodes > 0:
                hidden_links_count = self.links_count() - len(visible_edges)
                condensed_node_name = f"... {hidden_links_count} hidden links across {num_hidden_nodes} nodes ..."
                for src in edges_to_condensed:
                    condensed_cg.add_edge(
                        src,
                        condensed_node_name,
                        condensed_depth,
                        "call",
                    )
                for dst in edges_from_condensed:
                    dst_depth = node_depths.get(dst, condensed_depth + 1)
                    condensed_cg.add_edge(condensed_node_name, dst, dst_depth, "call")

            used_condensed = True

        # --- Step 8: Mermaid chart construction ---
        # Build the flowchart text from either the condensed graph (if used) or the original graph.
        node_keys: dict[str, int] = {}  # Maps node names to numeric IDs for Mermaid
        node_count: int = 0  # Counter for assigning IDs
        existing_base_links: set[str] = set()  # Tracks links already added to avoid duplicates
        shade_key: str = "sh"  # Style key for shaded nodes
        links: dict[str, int] = {}  # Dictionary of Mermaid link strings

        # Choose chart direction: TD (top-down) for small graphs, LR (left-right) for large ones
        if direction is None:
            direction = "TD" if len(self.graph) < 350 else "LR"

        mermaid_flow: str = """flowchart {direction}\n{style}\n{links}\n"""
        style: str = f"classDef {shade_key} fill:{shade_color}" if shaded_nodes else ""

        # Decide which graph to render: condensed or original
        graph_to_use: dict[str, list[tuple[str, int, int, str]]] = condensed_cg.graph if used_condensed and condensed_cg is not None else self.graph

        # --- Step 9: Handle trivial case (single root node) ---
        if len(graph_to_use) == 1 and self.root in graph_to_use:
            links[self.root] = 1
        elif endpoint_only:
            # --- Step 10: Endpoint-only mode ---
            # Show only root and endpoints, skipping intermediate nodes
            endpoints: list[str] = self.get_endpoints()
            for i, end in enumerate(endpoints):
                end_style_class = f":::{shade_key}" if shaded_nodes and end in shaded_nodes else ""
                root_style_class = f":::{shade_key}" if shaded_nodes and self.root in shaded_nodes else ""
                if self.root_at_end():
                    link = f'{i}["{end}"]{end_style_class} --> root["{self.root}"]{root_style_class}'
                else:
                    link = f'root["{self.root}"]{root_style_class} --> {i}["{end}"]{end_style_class}'
                links[link] = 1
        else:
            # --- Step 11: Full graph rendering ---
            # Iterate through nodes and edges, building Mermaid links
            for src in list(graph_to_use):
                src_style_class = f":::{shade_key}" if shaded_nodes and src in shaded_nodes else ""
                for node in list(graph_to_use[src]):
                    depth = node[1]
                    fname = node[0]
                    ref_type = node[3]

                    # Skip edges deeper than max_display_depth if specified
                    if max_display_depth is not None and depth > max_display_depth:
                        continue

                    dst_style_class = f":::{shade_key}" if shaded_nodes and fname in shaded_nodes else ""

                    # Assign numeric IDs for Mermaid nodes if not already assigned
                    if node_keys.get(src) is None:
                        node_keys[src] = node_count
                        node_count += 1
                        src_node = f'{node_keys[src]}["{src}"]{src_style_class}'
                    else:
                        src_node = f"{node_keys[src]}{src_style_class}"

                    if node_keys.get(fname) is None:
                        node_keys[fname] = node_count
                        node_count += 1
                        dst_node = f'{node_keys[fname]}["{fname}"]{dst_style_class}'
                    else:
                        dst_node = f"{node_keys[fname]}{dst_style_class}"

                    # Avoid duplicate links
                    current_base_link = f"{src} --> {node[0]}"
                    if current_base_link not in existing_base_links:
                        if ref_type == "ref":
                            link = f"{src_node} -- ref --> {dst_node}"
                        else:
                            link = f"{src_node} --> {dst_node}"
                        links[link] = 1
                        existing_base_links.add(current_base_link)

        # --- Step 12: Finalize Mermaid chart ---
        mermaid_chart = mermaid_flow.format(
            links="\n".join(links.keys()),
            direction=direction,
            style=style,
        )

        # Clean up invalid characters for Mermaid syntax
        mermaid_chart = self.remove_bad_mermaid_chars(mermaid_chart)

        # Optionally wrap chart in embedding markup
        if wrap_mermaid:
            mermaid_chart = _wrap_mermaid(mermaid_chart)

        return mermaid_chart

    def gen_mermaid_mind_map(self, max_display_depth: int | None = None, wrap_mermaid: bool = False) -> str:
        """Generate MermaidJS mindmap from self.graph
        See https://mermaid.js.org/syntax/mindmap.html
        """
        rows: list[str] = []

        mermaid_mind = """mindmap\nroot(({root}))\n{rows}\n"""

        destinations: list[tuple[str, int, int, str]] = []

        for src in list(self.graph):
            dst = self.graph[src]
            for d in dst:
                destinations.append(d)

        last_depth = 0
        current_level_names: list[str] = []
        for i, row in enumerate(sorted(destinations, key=lambda x: x[2])):
            depth = row[1]

            # skip root row
            if depth < 2 or (max_display_depth is not None and depth > max_display_depth):
                continue

            if depth < last_depth:
                # reset level names
                current_level_names = []

            if row[0] not in current_level_names:
                spaces = (depth + 1) * "  "
                rows.append(f"{spaces}{row[0]}")
                last_depth = depth
                current_level_names.append(row[0])

        mermaid_chart = mermaid_mind.format(rows="\n".join(rows), root=self.root)

        mermaid_chart = self.remove_bad_mermaid_chars(mermaid_chart)

        if wrap_mermaid:
            mermaid_chart = _wrap_mermaid(mermaid_chart)

        return mermaid_chart


@lru_cache(None)
def get_calling_funcs_memo(
    func: GhidraFunction | None,
    include_refs: bool = True,
) -> list[tuple[GhidraFunction, str]]:
    """Given a GhidraFunction, return a set of Functions that call it.
    Only call references are included (non-call references are skipped).
    """
    callers: dict[GhidraFunction, bool] = {}
    if func is None:
        return []

    program = func.getProgram()
    ref_manager = program.getReferenceManager()
    func_manager = program.getFunctionManager()

    entry_point = func.getEntryPoint()
    ref_iter = ref_manager.getReferencesTo(entry_point)

    while ref_iter.hasNext():
        ref = ref_iter.next()
        is_call = ref.getReferenceType().isCall()
        if not is_call and not include_refs:
            continue

        from_addr = ref.getFromAddress()
        caller_func = func_manager.getFunctionContaining(from_addr)
        if caller_func:
            # If we already have an entry for this caller,
            # we only update it if the new reference is a 'call'.
            if caller_func not in callers or not callers[caller_func]:
                callers[caller_func] = is_call

    return [(f, "call" if is_call else "ref") for f, is_call in callers.items()]


@lru_cache(None)
def get_called_funcs_memo(
    func: GhidraFunction | None,
    include_refs: bool = True,
) -> list[tuple[GhidraFunction, str]]:
    """Given a GhidraFunction, return a list of Functions that it calls.
    Only call references are included (non-call references are skipped unless include_refs=True).
    """
    callees: dict[GhidraFunction, bool] = {}
    if not func:
        return []

    program: GhidraProgram = func.getProgram()
    ref_manager: GhidraReferenceManager = program.getReferenceManager()
    func_manager: GhidraFunctionManager = program.getFunctionManager()

    # Iterate through all address ranges in the function body
    range_iter: GhidraAddressRangeIterator = func.getBody().getAddressRanges()

    while range_iter.hasNext():
        addr_range: GhidraAddressRange = range_iter.next()
        ref_iter: GhidraReferenceIterator = ref_manager.getReferenceIterator(addr_range.getMinAddress())

        while ref_iter.hasNext():
            ref: GhidraReference = ref_iter.next()

            # Stop if we've moved outside the current address range
            if not addr_range.contains(ref.getFromAddress()):
                break

            is_call = ref.getReferenceType().isCall()
            # Skip non-call references unless include_refs=True
            if not is_call and not include_refs:
                continue

            # Look up the callee function at the reference's destination
            callee = func_manager.getFunctionAt(ref.getToAddress())
            if callee:
                if callee not in callees or not callees[callee]:
                    callees[callee] = is_call

    return [(f, "call" if is_call else "ref") for f, is_call in callees.items()]


# Recursively calling to build calling graph
def get_calling(
    f: GhidraFunction,
    cgraph: CallGraph | None = None,
    depth: int = 0,
    visited: tuple[str, ...] | None = None,
    verbose: bool = False,
    include_ns: bool = True,
    start_time: float | None = None,
    max_run_time: float | None = None,
    max_depth: int = MAX_DEPTH,
    include_refs: bool = True,
) -> CallGraph | None:
    """Build a call graph of all calling functions
    Traverses depth first
    """
    if f is None:
        return None

    if cgraph is None:
        cgraph = CallGraph()

    if depth == 0:
        if verbose:
            print(f"root({f.getName(include_ns)})")
        cgraph.set_root(f.getName(include_ns))
        visited = tuple()
        start_time = time.time()

    if visited is None:
        visited = tuple()

    if depth == MAX_DEPTH:
        cgraph.add_edge(
            f.getName(include_ns),
            f"MAX_DEPTH_HIT - {depth}",
            depth,
            "call",
        )
        return cgraph

    if max_run_time is not None and start_time is not None and (time.time() - start_time) > max_run_time:
        # raise TimeoutError(f'time expired for {clean_func(f,include_ns)}')
        cgraph.add_edge(
            f.getName(include_ns),
            f"MAX_TIME_HIT - time: {max_run_time} depth: {depth}",
            depth,
            "call",
        )
        print(
            f"\nWarn: cg : {cgraph.root} edges: {cgraph.links_count()} depth: {depth} name: {f.name} did not complete. max_run_time: {max_run_time} Increase timeout with --max-time-cg-gen MAX_TIME_CG_GEN",
        )
        return cgraph

    space = (depth + 2) * "  "

    # loop check
    if f.getName(True) in visited:
        # calling loop
        if verbose:
            print(f"{space} - LOOOOP {f.getName(include_ns)}")

        return cgraph

    calling = get_calling_funcs_memo(f, include_refs=include_refs)

    visited = visited + tuple([f.getName(True)])

    if len(calling) > 0:
        depth = depth + 1

        for c, ref_type in calling:
            if verbose:
                print(f"{space} - {c.getName(include_ns)}")

            # Add calling edge
            if cgraph is not None:
                cgraph.add_edge(
                    c.getName(include_ns),
                    f.getName(include_ns),
                    depth,
                    ref_type,
                )

            # Parse further functions
            cgraph = get_calling(
                c,
                cgraph,
                depth,
                visited=visited,
                start_time=start_time,
                max_run_time=max_run_time,
                max_depth=max_depth,
                include_refs=include_refs,
            )
    elif verbose:
        print(f"{space} - END for {f.name}")

    return cgraph


def func_is_external(f: GhidraFunction) -> bool:
    # sometimwa f.exExternal() failes (like with ls binary)
    return f.isExternal() or "<EXTERNAL>" in f.getName(True)


# Recursively calling to build called graph


def get_called(
    f: GhidraFunction,
    cgraph: CallGraph | None = None,
    depth: int = 0,
    visited: tuple[str, ...] | None = None,
    verbose: bool = False,
    include_ns: bool = True,
    start_time: float | None = None,
    max_run_time: float | None = None,
    max_depth: int = MAX_DEPTH,
    include_refs: bool = True,
) -> CallGraph | None:
    """Build a call graph of all called functions
    Traverses depth first
    """
    if f is None:
        return None

    if cgraph is None:
        cgraph = CallGraph()

    if depth == 0:
        if verbose:
            print(f"root({f.getName(include_ns)})")
        cgraph.set_root(f.getName(include_ns))
        visited = tuple()
        start_time = time.time()

    if visited is None:
        visited = tuple()

    if depth == max_depth:
        cgraph.add_edge(
            f.getName(include_ns),
            f"MAX_DEPTH_HIT - {depth}",
            depth,
            "call",
        )
        return cgraph

    if max_run_time is not None and start_time is not None and (time.time() - start_time) > max_run_time:
        cgraph.add_edge(
            f.getName(include_ns),
            f"MAX_TIME_HIT - time: {max_run_time} depth: {depth}",
            depth,
            "call",
        )
        print(
            f"\nWarn: cg : {cgraph.root} edges: {cgraph.links_count()} depth: {depth} name: {f.name} did not complete. max_run_time: {max_run_time} Increase timeout with --max-time-cg-gen MAX_TIME_CG_GEN",
        )
        return cgraph

    space = (depth + 2) * "  "

    # loop check
    if f.getName(True) in visited:
        # calling loop
        if verbose:
            print(f"{space} - LOOOOP {f.getName(include_ns)}")

        return cgraph

    visited = visited + tuple([f.getName(True)])

    called = get_called_funcs_memo(f, include_refs=include_refs)

    if len(called) > 0:
        # this check handles special case when get_called(f) is external but returns called func of itself
        # in that case ignore it
        if not (func_is_external(f) and len(called) == 1):
            depth = depth + 1

            for c, ref_type in called:
                c: GhidraFunction = c

                if verbose:
                    print(f"{space} - {c.getName(include_ns)}")

                # Add called edge
                if func_is_external(c):
                    # force external to show namespace lib with sendind param True
                    if cgraph is not None:
                        cgraph.add_edge(
                            f.getName(include_ns),
                            f"{c.getName(True)}",
                            depth,
                            ref_type,
                        )

                else:
                    if cgraph is not None:
                        cgraph.add_edge(
                            f.getName(include_ns),
                            c.getName(include_ns),
                            depth,
                            ref_type,
                        )

                    # Parse further functions
                    cgraph = get_called(
                        c,
                        cgraph,
                        depth,
                        visited=visited,
                        start_time=start_time,
                        max_run_time=max_run_time,
                        max_depth=max_depth,
                        include_refs=include_refs,
                    )

    elif verbose:
        print(f"{space} - END for {f.name}")

    return cgraph


def _wrap_mermaid(text: str) -> str:
    return f"""```mermaid\n{text}\n```"""


def _unwrap_mermaid(wrapped: str) -> str:
    prefix = "```mermaid\n"
    suffix = "\n```"
    if wrapped.startswith(prefix) and wrapped.endswith(suffix):
        return wrapped[len(prefix) : -len(suffix)]
    return wrapped


def gen_mermaid_url_old(graph: str, edit: bool = False) -> str:
    """MermaidInkSvg

    Generate valid mermaid live edit and image links
    # based on serialize func  https://github.com/mermaid-js/mermaid-live-editor/blob/b5978e6faf7635e39452855fb4d062d1452ab71b/src/lib/util/serde.ts#L19-L24
    """
    mm_json: dict[str, Any] = {
        "code": graph,
        "mermaid": {"theme": "dark"},
        "updateEditor": True,
        "autoSync": True,
        "updateDiagram": True,
        "editorMode": "code",
        "panZoom": True,
    }
    base64_string = base64.urlsafe_b64encode(
        zlib.compress(json.dumps(mm_json).encode("utf-8"), 9),
    ).decode("ascii")

    if edit:
        url = f"https://mermaid.live/edit#pako:{base64_string}"
    else:
        url = f"https://mermaid.ink/img/svg/pako:{base64_string}"

    return url


def gen_mermaid_url(
    graph: str,
    edit: bool = False,
    # Optional State params
    mermaid_config_json: dict[str, Any] | None = None,
    updateDiagram: bool = True,
    rough: bool = False,
    renderCount: int | None = None,
    panZoom: bool | None = True,
    grid: bool | None = True,
    editorMode: str | None = "code",
    pan: dict[str, float] | None = None,
    zoom: float | None = None,
    loader: dict[str, Any] | None = None,
    autoSync: bool = True,
    updateEditor: bool = True,
) -> str:
    """Generate valid Mermaid live edit and image links.

    Updated to match new State interface with optional params.
    # based on serialize func  https://github.com/mermaid-js/mermaid-live-editor/blob/b5978e6faf7635e39452855fb4d062d1452ab71b/src/lib/util/serde.ts#L19-L24
    """
    mm_state = {
        "code": graph,
        "mermaid": json.dumps(
            mermaid_config_json or {"theme": "dark"},
        ),  # stringified JSON
        "updateDiagram": updateDiagram,
        "rough": rough,
        "updateEditor": updateEditor,
        "autoSync": autoSync,
    }

    # Add optional fields only if provided
    if renderCount is not None:
        mm_state["renderCount"] = renderCount
    if panZoom is not None:
        mm_state["panZoom"] = panZoom
    if grid is not None:
        mm_state["grid"] = grid
    if editorMode is not None:
        mm_state["editorMode"] = editorMode
    if pan is not None:
        mm_state["pan"] = pan
    if zoom is not None:
        mm_state["zoom"] = zoom
    if loader is not None:
        mm_state["loader"] = loader

    # Compress + encode
    base64_string = base64.urlsafe_b64encode(
        zlib.compress(json.dumps(mm_state).encode("utf-8"), 9),
    ).decode("ascii")

    if edit:
        url = f"https://mermaid.live/edit#pako:{base64_string}"
    else:
        url = f"https://mermaid.ink/svg/pako:{base64_string}"  # updated endpoint

    return url


def gen_callgraph_md(
    f: GhidraFunction,
    called: str,
    calling: str,
    calling_entrypoints: str,
    called_endpoints: str,
    called_mind: str,
    calling_mind: str,
) -> str:
    fname = f.getName(True)

    calling_mind_url = f"[Edit calling Mindmap]({gen_mermaid_url(calling_mind, edit=True)})"
    called_mind_url = f"![Edit called Mindmap]({gen_mermaid_url(called_mind, edit=True)})"

    md_template = f"""
# {fname}

## Calling

Functions that call `{fname}`.

### Flowchart

[Edit on mermaid live]({gen_mermaid_url(calling, edit=True)})

{_wrap_mermaid(calling)}

### Entrypoints

A condensed view, showing only entrypoints to the callgraph.

{_wrap_mermaid(calling_entrypoints)}

### Mindmap

{calling_mind_url}

## Called

Functions that `{fname}` calls

### Flowchart

[Edit on mermaid live]({gen_mermaid_url(called, edit=True)})

{_wrap_mermaid(called)}

### Endpoints

A condensed view, showing only endpoints of the callgraph.

{_wrap_mermaid(called_endpoints)}

### Mindmap

{called_mind_url}

"""

    return md_template


def gen_callgraph(
    func: GhidraFunction,
    max_display_depth: int | None = None,
    direction: str = "calling",
    max_run_time: float | None = None,
    name: str | None = None,
    include_refs: bool = True,
    condense_threshold: int | None = 50,
    top_layers: int | None = 5,
    bottom_layers: int | None = 5,
    wrap_mermaid: bool = False,
) -> list[Any]:
    """Generate callgraph using unified CallGraphTool.

    This function now delegates to the unified CallGraphTool for consistency
    between MCP provider and CLI interfaces.
    """
    try:
        # Create a mock program info for the unified tool
        from agentdecompile_cli.launcher import create_program_info

        # Try to get current program from Ghidra context
        current_program = func.getProgram()
        program_info = create_program_info(current_program)
        callgraph_tool = CallGraphTool(program_info)

        # Use unified tool's internal method
        result = callgraph_tool._gen_callgraph(
            func=func,
            max_display_depth=max_display_depth,
            direction=direction,
            max_run_time=max_run_time,
            name=name,
            include_refs=include_refs,
            condense_threshold=condense_threshold or 50,
            top_layers=top_layers or 5,
            bottom_layers=bottom_layers or 5,
            wrap_mermaid=wrap_mermaid,
        )

        # Format return value to match original interface
        cg_mermaid_url = result["mermaid_url"]
        if cg_mermaid_url and not cg_mermaid_url.endswith("\n"):
            # Add edit URL like original
            cg_mermaid_url += "\n" + cg_mermaid_url.replace("ink/img/", "ink/edit/")

        return [
            result["function_name"],
            direction,
            None,  # callgraph object (not available in unified tool)
            [
                ["flow", result["graph"]],
                ["flow_ends", result["flow_ends"]],
                ["mind", result["mind_map"]],
                ["mermaid_url", cg_mermaid_url],
            ],
            None,  # Placeholder for additional data
        ]

    except Exception as e:
        print(f"Error using unified callgraph tool: {e}")
        # Fallback to original implementation if unified tool fails
        return _gen_callgraph_fallback(func, max_display_depth, direction, max_run_time, name, include_refs, condense_threshold, top_layers, bottom_layers, wrap_mermaid)


def _gen_callgraph_fallback(
    func: GhidraFunction,
    max_display_depth: int | None = None,
    direction: str = "calling",
    max_run_time: float | None = None,
    name: str | None = None,
    include_refs: bool = True,
    condense_threshold: int | None = 50,
    top_layers: int | None = 5,
    bottom_layers: int | None = 5,
    wrap_mermaid: bool = False,
) -> list[Any]:
    """Fallback implementation for backward compatibility."""
    if name is None:
        name = f"{func.getName()[:MAX_PATH_LEN]}-{func.entryPoint}"

    flow = ""
    flow_ends = ""
    mind = ""
    cg_mermaid_url = ""
    callgraph = None

    if direction == "calling":
        callgraph = get_calling(
            func,
            max_run_time=max_run_time,
            include_refs=include_refs,
        )
    elif direction == "called":
        callgraph = get_called(
            func,
            max_run_time=max_run_time,
            include_refs=include_refs,
        )
    else:
        raise Exception(f"Unsupported callgraph direction {direction}")

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
        cg_mermaid_url = gen_mermaid_url(_unwrap_mermaid(flow)) + "\n" + gen_mermaid_url(_unwrap_mermaid(flow), edit=True)

    return [
        name,
        direction,
        callgraph,
        [
            ["flow", flow],
            ["flow_ends", flow_ends],
            ["mind", mind],
            ["mermaid_url", cg_mermaid_url],
        ],
        None,  # Placeholder for additional data
    ]
