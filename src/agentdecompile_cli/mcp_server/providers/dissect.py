"""Get Function Tool Provider – get-function (file named dissect for “deep dissection”).

All-in-one deep inspection of a single function. Returns decompilation,
disassembly, comments, labels, callers, callees, cross-references, tags,
bookmarks, stack frame / local variables, namespace, and memory block info
in a single MCP tool call. MCP tool name is get-function; this module implements it.
"""

from __future__ import annotations

import logging

from itertools import islice
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from ghidra.app.decompiler import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        DecompileResults as GhidraDecompileResults,
    )
    from ghidra.program.model.address import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        Address as GhidraAddress,
        AddressSetView as GhidraAddressSetView,
    )
    from ghidra.program.model.listing import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        Bookmark as GhidraBookmark,
        BookmarkManager as GhidraBookmarkManager,
        CodeUnit as GhidraCodeUnit,
        Function as GhidraFunction,
        Program as GhidraProgram,
    )
    from ghidra.program.model.symbol import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        ReferenceManager as GhidraReferenceManager,
    )

from mcp import types

from agentdecompile_cli.mcp_server.constants import DEFAULT_TIMEOUT_SECONDS  # pyright: ignore[reportMissingImports]
from agentdecompile_cli.mcp_server.providers._collectors import (
    collect_function_comments,
    collect_function_data_flow,
    collect_function_tags,
    make_task_monitor,
)
from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
)
from agentdecompile_cli.registry import Tool

logger = logging.getLogger(__name__)


class GetFunctionAioToolProvider(ToolProvider):
    """AIO provider that returns everything knowable about a single function."""

    HANDLERS: ClassVar[dict[str, str]] = {
        "getfunction": "_handle",
    }

    def list_tools(self) -> list[types.Tool]:
        logger.debug("diag.enter %s", "mcp_server/providers/dissect.py:GetFunctionAioToolProvider.list_tools")
        return [
            types.Tool(
                name=Tool.GET_FUNCTION.value,
                description=(
                    "Deep, all-in-one inspection of a single function. "
                    "Returns every available detail in one call: decompiled C code, "
                    "disassembly with raw bytes, all comment types (EOL/pre/post/plate/repeatable), "
                    "labels and symbols inside the function body, callers (who calls it), "
                    "callees (what it calls), inbound cross-references, function tags, "
                    "bookmarks, stack frame with local variables, namespace path, "
                    "and the memory block the function resides in. "
                    "Use this instead of chaining multiple tools when you need a complete "
                    "picture of what a function is, does, and how it connects to the rest "
                    "of the binary."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {
                            "type": "string",
                            "description": "Path to the program in the project.",
                        },
                        "function": {
                            "type": "string",
                            "description": "Name or hex address of the function to dissect (e.g. 'main', '0x401000').",
                        },
                        "addressOrSymbol": {
                            "type": "string",
                            "description": "Alternative way to identify the function by address or symbol.",
                        },
                        "functionIdentifier": {
                            "type": "string",
                            "description": "Another alternative for the function identifier.",
                        },
                        "functions": {
                            "oneOf": [
                                {"type": "string"},
                                {"type": "array", "items": {"type": "string"}},
                            ],
                            "description": "Compatibility input from legacy get-functions. If multiple identifiers are provided, get-function uses the first one.",
                        },
                        "mode": {
                            "type": "string",
                            "description": "Compatibility selector accepted from legacy decompile/get-functions/get-call-graph calls. get-function still returns the unified full view.",
                        },
                        "view": {
                            "type": "string",
                            "description": "Compatibility alias for legacy get-functions view selection. get-function still returns the unified full view.",
                        },
                        "dataFlowDirection": {
                            "type": "string",
                            "enum": ["backward", "forward", "variable_accesses"],
                            "description": "Optional function-local data-flow slice to include in the response.",
                        },
                        "dataFlowAddress": {
                            "type": "string",
                            "description": "Address or symbol inside the target function to seed data-flow from. Defaults to the function entry point.",
                        },
                        "dataFlowMaxOps": {
                            "type": "integer",
                            "default": 150,
                            "description": "Maximum number of P-code operations to include in the data-flow section.",
                        },
                        "dataFlowMaxDepth": {
                            "type": "integer",
                            "default": 10,
                            "description": "Maximum dependency depth for the data-flow slice.",
                        },
                        "timeout": {
                            "type": "integer",
                            "default": 60,
                            "description": "Maximum seconds for the decompiler before aborting, default 60; omit unless needed.",
                        },
                        "maxInstructions": {
                            "type": "integer",
                            "default": 2000,
                            "description": "Cap on disassembly instructions returned, default 2000; omit unless needed.",
                        },
                        "maxRefs": {
                            "type": "integer",
                            "default": 200,
                            "description": "Cap on cross-references returned, default 200; omit unless needed.",
                        },
                        "maxCallers": {
                            "type": "integer",
                            "description": "Cap on callers returned; omit for no limit.",
                        },
                        "maxCallees": {
                            "type": "integer",
                            "description": "Cap on callees returned; omit for no limit.",
                        },
                        "callerDepth": {
                            "type": "integer",
                            "default": 2,
                            "description": "Depth of recursive caller expansion for full related-function details, default 2. Set to 0 to disable caller expansion.",
                        },
                        "calleeDepth": {
                            "type": "integer",
                            "default": 2,
                            "description": "Depth of recursive callee expansion for full related-function details, default 2. Set to 0 to disable callee expansion.",
                        },
                        "callerBranching": {
                            "type": "integer",
                            "default": 3,
                            "description": "Maximum callers to follow at each expansion step, default 3.",
                        },
                        "calleeBranching": {
                            "type": "integer",
                            "default": 3,
                            "description": "Maximum callees to follow at each expansion step, default 3.",
                        },
                        "maxRelatedCallers": {
                            "type": "integer",
                            "default": 9,
                            "description": "Maximum number of expanded caller detail blocks to include, default 9.",
                        },
                        "maxRelatedCallees": {
                            "type": "integer",
                            "default": 9,
                            "description": "Maximum number of expanded callee detail blocks to include, default 9.",
                        },
                    },
                    "required": [],
                },
            ),
        ]

    # ------------------------------------------------------------------
    # Main handler
    # ------------------------------------------------------------------

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/dissect.py:GetFunctionAioToolProvider._handle")
        self._require_program()

        func_id = self._get_address_or_symbol(args)
        if not func_id:
            function_list = self._get_list(args, "functions") or []
            if function_list:
                first_identifier = function_list[0]
                if isinstance(first_identifier, str) and first_identifier.strip():
                    func_id = first_identifier.strip()
        if not func_id:
            functions_csv = self._get_str(args, "functions")
            if functions_csv:
                first_identifier = functions_csv.split(",", 1)[0].strip()
                if first_identifier:
                    func_id = first_identifier
        if not func_id:
            func_id = self._get_str(args, "function", "functionidentifier", "identifier", "name", "symbol")
        if not func_id:
            raise ValueError("function, addressOrSymbol, or functionIdentifier required")

        timeout = self._get_int(args, "timeout", default=DEFAULT_TIMEOUT_SECONDS)
        max_instructions = self._get_int(args, "maxinstructions", "maxinsns", default=2000)
        max_refs = self._get_int(args, "maxrefs", "maxreferences", default=200)
        max_callers = self._get_int(args, "maxcallers", default=None)
        max_callees = self._get_int(args, "maxcallees", default=None)
        data_flow_direction = self._get_str(args, "dataflowdirection", default="")
        data_flow_address = self._get_str(args, "dataflowaddress", default="")
        data_flow_max_ops = self._get_int(args, "dataflowmaxops", default=150) or 150
        data_flow_max_depth = self._normalize_non_negative(self._get_int(args, "dataflowmaxdepth", default=10), default=10)
        legacy_depth = self._get_int(args, "maxdepth", "depth", default=None)
        caller_depth = self._normalize_non_negative(self._get_int(args, "callerdepth", "relatedcallerdepth", default=legacy_depth if legacy_depth is not None else 2), default=2)
        callee_depth = self._normalize_non_negative(self._get_int(args, "calleedepth", "relatedcalleedepth", default=legacy_depth if legacy_depth is not None else 2), default=2)
        caller_branching = self._normalize_non_negative(self._get_int(args, "callerbranching", "relatedcallerbranching", default=3), default=3)
        callee_branching = self._normalize_non_negative(self._get_int(args, "calleebranching", "relatedcalleebranching", default=3), default=3)
        legacy_max_nodes = self._get_int(args, "maxnodes", default=None)
        max_related_callers = self._normalize_non_negative(self._get_int(args, "maxrelatedcallers", "maxcallerdetails", default=legacy_max_nodes if legacy_max_nodes is not None else 9), default=9)
        max_related_callees = self._normalize_non_negative(self._get_int(args, "maxrelatedcallees", "maxcalleedetails", default=legacy_max_nodes if legacy_max_nodes is not None else 9), default=9)

        assert self.program_info is not None, "program_info should be set by _require_program()"
        program = self.program_info.program
        if program is None:
            raise ValueError("No program loaded")

        target = self._resolve_function(func_id, program=program)
        if target is None:
            program_path = getattr(self.program_info, "file_path", None) or getattr(self.program_info, "path", None)
            if not program_path and program is not None:
                try:
                    df = program.getDomainFile()
                    if df is not None:
                        program_path = str(df.getPathname())
                except Exception:
                    pass
            program_path = str(program_path) if program_path else "current program"

            # --- Diagnostic: collect what IS at this address ---
            from agentdecompile_cli.mcp_utils.address_util import AddressUtil  # pyright: ignore[reportMissingImports]

            addr = None
            try:
                addr = AddressUtil.resolve_address_or_symbol(program, func_id)
            except Exception:
                pass

            diag: dict[str, Any] = {
                "found": False,
                "requestedIdentifier": func_id,
                "programPath": program_path,
            }

            if addr is not None:
                diag["resolvedAddress"] = str(addr)

                # What memory block is this in?
                try:
                    mem = program.getMemory()
                    block = mem.getBlock(addr)
                    if block is not None:
                        diag["memoryBlock"] = {
                            "name": str(block.getName()),
                            "start": str(block.getStart()),
                            "end": str(block.getEnd()),
                            "readable": bool(block.isRead()),
                            "writable": bool(block.isWrite()),
                            "executable": bool(block.isExecute()),
                        }
                except Exception:
                    pass

                # Data / defined type at this address
                try:
                    listing = program.getListing()
                    data = listing.getDataAt(addr)
                    if data is not None:
                        dt = data.getDataType()
                        diag["dataAtAddress"] = {
                            "dataType": str(dt.getName()) if dt is not None else "unknown",
                            "length": int(data.getLength()),
                            "value": str(data.getValue()) if not isinstance(data.getValue(), type(None)) else None,
                        }
                except Exception:
                    pass

                # All comments at this address
                try:
                    listing = program.getListing()
                    cmt_types = {
                        "plateComment": 0,
                        "preComment": 1,
                        "postComment": 2,
                        "eolComment": 3,
                        "repeatableComment": 4,
                    }
                    comments: dict[str, str] = {}
                    for cname, ctype in cmt_types.items():
                        try:
                            cval = listing.getComment(ctype, addr)
                            if cval:
                                comments[cname] = str(cval)
                        except Exception:
                            pass
                    if comments:
                        diag["commentsAtAddress"] = comments
                except Exception:
                    pass

                # Labels / symbols at this address
                try:
                    sym_table = program.getSymbolTable()
                    syms = list(sym_table.getSymbols(addr))
                    if syms:
                        diag["labelsAtAddress"] = [
                            {
                                "name": str(s.getName()),
                                "namespace": str(s.getParentNamespace()) if hasattr(s, "getParentNamespace") else "",
                                "source": str(s.getSource()),
                                "isPrimary": bool(s.isPrimary()),
                            }
                            for s in syms[:20]
                        ]
                except Exception:
                    pass

                # Cross-references TO this address
                try:
                    ref_mgr = program.getReferenceManager()
                    refs_to = list(islice(ref_mgr.getReferencesTo(addr), 20))
                    if refs_to:
                        diag["referencesToAddress"] = [{"from": str(r.getFromAddress()), "type": str(r.getReferenceType())} for r in refs_to]
                except Exception:
                    pass

                # Nearest functions before/after this address
                try:
                    fm = program.getFunctionManager()
                    nearby: list[dict[str, str]] = []
                    f_before = fm.getFunctionBefore(addr)
                    f_after = fm.getFunctionAfter(addr)
                    if f_before is not None:
                        nearby.append(
                            {
                                "direction": "before",
                                "name": str(f_before.getName()),
                                "address": str(f_before.getEntryPoint()),
                            }
                        )
                    if f_after is not None:
                        nearby.append(
                            {
                                "direction": "after",
                                "name": str(f_after.getName()),
                                "address": str(f_after.getEntryPoint()),
                            }
                        )
                    if nearby:
                        diag["nearbyFunctions"] = nearby
                except Exception:
                    pass

                # Function count
                try:
                    fm2 = program.getFunctionManager()
                    count = int(fm2.getFunctionCount()) if hasattr(fm2, "getFunctionCount") else 0
                    diag["programFunctionCount"] = count
                    if count == 0:
                        diag["hint"] = "Program has no functions yet; run analyze-program first."
                    else:
                        diag["hint"] = "No function is defined at this address. Use nearbyFunctions above or list-functions to find addressable functions."
                except Exception:
                    pass
            else:
                diag["hint"] = f"Could not resolve {func_id!r} to an address in this program. Check the address format or use list-functions to browse available functions."

            return create_success_response(diag)

        target_details = self._collect_function_details(
            target,
            program,
            timeout=timeout,
            max_instructions=max_instructions,
            max_refs=max_refs,
            max_callers=max_callers,
            max_callees=max_callees,
            data_flow_direction=data_flow_direction,
            data_flow_address=data_flow_address,
            data_flow_max_ops=data_flow_max_ops,
            data_flow_max_depth=data_flow_max_depth,
        )
        caller_tree, caller_funcs = self._collect_related_tree(
            target,
            direction="callers",
            depth=caller_depth,
            branching=caller_branching,
            max_details=max_related_callers,
        )
        callee_tree, callee_funcs = self._collect_related_tree(
            target,
            direction="callees",
            depth=callee_depth,
            branching=callee_branching,
            max_details=max_related_callees,
        )
        caller_details = [
            self._collect_function_details(
                func,
                program,
                timeout=timeout,
                max_instructions=max_instructions,
                max_refs=max_refs,
                max_callers=max_callers,
                max_callees=max_callees,
                data_flow_direction="",
                data_flow_address="",
                data_flow_max_ops=0,
                data_flow_max_depth=0,
                relationship="caller",
                include_code=False,
            )
            for func in caller_funcs
        ]
        callee_details = [
            self._collect_function_details(
                func,
                program,
                timeout=timeout,
                max_instructions=max_instructions,
                max_refs=max_refs,
                max_callers=max_callers,
                max_callees=max_callees,
                data_flow_direction="",
                data_flow_address="",
                data_flow_max_ops=0,
                data_flow_max_depth=0,
                relationship="callee",
                include_code=False,
            )
            for func in callee_funcs
        ]

        result: dict[str, Any] = {
            "tool": Tool.GET_FUNCTION.value,
            **target_details,
            "targetFunction": target_details,
            "callGraphTree": {
                "callers": caller_tree,
                "callees": callee_tree,
                "callerDepth": caller_depth,
                "calleeDepth": callee_depth,
                "callerBranching": caller_branching,
                "calleeBranching": callee_branching,
                "expandedCallerCount": len(caller_details),
                "expandedCalleeCount": len(callee_details),
            },
            "callerDetails": caller_details,
            "calleeDetails": callee_details,
        }
        result["sectionsIncluded"] = [
            "metadata",
            "namespace",
            "decompilation",
            "disassembly",
            "comments",
            "labels",
            "callers",
            "callees",
            "crossReferences",
            "outboundReferences",
            "tags",
            "bookmarks",
            "stackFrame",
            "memoryBlock",
            "dataFlow",
            "callGraphTree",
            "callerDetails",
            "calleeDetails",
        ]
        return create_success_response(result)

    # ------------------------------------------------------------------
    # Collectors (private)
    # ------------------------------------------------------------------

    def _collect_function_details(
        self,
        func: GhidraFunction,
        program: GhidraProgram,
        *,
        timeout: int | None,
        max_instructions: int | None,
        max_refs: int | None,
        max_callers: int | None,
        max_callees: int | None,
        data_flow_direction: str,
        data_flow_address: str,
        data_flow_max_ops: int,
        data_flow_max_depth: int,
        relationship: str | None = None,
        include_code: bool = True,
    ) -> dict[str, Any]:
        logger.debug("diag.enter %s", "mcp_server/providers/dissect.py:GetFunctionAioToolProvider._collect_function_details")
        entry = func.getEntryPoint()
        body = func.getBody()
        metadata = self._collect_metadata(func)
        callers_list = self._collect_callers(func, max_callers)
        callees_list = self._collect_callees(func, max_callees)
        metadata["callerCount"] = len(callers_list)
        metadata["calleeCount"] = len(callees_list)

        if include_code:
            try:
                _decompilation = self._decompile(func, program, timeout or DEFAULT_TIMEOUT_SECONDS)
            except RuntimeError as _decompile_err:
                _decompilation = f"[decompilation unavailable: {_decompile_err}]"
            _disassembly = self._disassemble(func, program, max_instructions)
        else:
            _decompilation = ""
            _disassembly: dict[str, Any] = {"instructions": [], "count": 0, "truncated": False}

        data_flow: dict[str, Any] | None = None
        if data_flow_direction:
            seed_address = entry
            if data_flow_address:
                try:
                    resolved_seed_address = self._resolve_address(data_flow_address, program=program)
                    if resolved_seed_address is not None:
                        seed_address = resolved_seed_address
                except Exception:
                    seed_address = entry
            data_flow = collect_function_data_flow(
                program,
                func,
                seed_address,
                direction=data_flow_direction,
                max_ops=data_flow_max_ops,
                max_depth=data_flow_max_depth,
                timeout_s=timeout or DEFAULT_TIMEOUT_SECONDS,
                session_decompiler=getattr(self.program_info, "decompiler", None) if self.program_info is not None else None,
            )

        details: dict[str, Any] = {
            "name": func.getName(),
            "address": str(entry),
            "signature": str(func.getSignature()),
            "metadata": metadata,
            "namespace": self._collect_namespace(func),
            "decompilation": _decompilation,
            "disassembly": _disassembly,
            "comments": self._collect_all_comments(func, program, body),
            "labels": self._collect_labels(program, body),
            "callers": callers_list,
            "callees": callees_list,
            "crossReferences": self._collect_xrefs(program, entry, max_refs),
            "outboundReferences": self._collect_outbound_refs(program, body, max_refs),
            "tags": collect_function_tags(func),
            "bookmarks": self._collect_bookmarks(program, body),
            "stackFrame": self._collect_stack_frame(func),
            "memoryBlock": self._collect_memory_block(program, entry) or {},
        }
        if data_flow is not None:
            details["dataFlow"] = data_flow
        if relationship and relationship.strip():
            details["relationship"] = relationship
        return details

    @staticmethod
    def _normalize_non_negative(value: int | None, *, default: int) -> int:
        logger.debug("diag.enter %s", "mcp_server/providers/dissect.py:GetFunctionAioToolProvider._normalize_non_negative")
        if value is None:
            return default
        return max(0, int(value))

    @staticmethod
    def _summarize_function(func: GhidraFunction) -> dict[str, Any]:
        logger.debug("diag.enter %s", "mcp_server/providers/dissect.py:GetFunctionAioToolProvider._summarize_function")
        return {
            "name": func.getName(),
            "address": str(func.getEntryPoint()),
            "signature": str(func.getSignature()),
        }

    def _iter_related_functions(self, func: GhidraFunction, direction: str) -> Any:
        logger.debug("diag.enter %s", "mcp_server/providers/dissect.py:GetFunctionAioToolProvider._iter_related_functions")
        monitor = make_task_monitor()
        if direction == "callers":
            return func.getCallingFunctions(monitor)
        return func.getCalledFunctions(monitor)

    def _collect_related_tree(
        self,
        func: GhidraFunction,
        *,
        direction: str,
        depth: int,
        branching: int,
        max_details: int,
    ) -> tuple[list[dict[str, Any]], list[GhidraFunction]]:
        logger.debug("diag.enter %s", "mcp_server/providers/dissect.py:GetFunctionAioToolProvider._collect_related_tree")
        if depth <= 0 or branching <= 0 or max_details <= 0:
            return [], []

        ordered_funcs: list[GhidraFunction] = []
        seen_addresses: set[str] = set()

        def walk(current: GhidraFunction, remaining_depth: int, path: set[str]) -> list[dict[str, Any]]:
            nodes: list[dict[str, Any]] = []
            if remaining_depth <= 0 or len(ordered_funcs) >= max_details:
                return nodes

            for related in islice(self._iter_related_functions(current, direction), branching):
                addr = str(related.getEntryPoint())
                if addr in path:
                    continue
                if addr not in seen_addresses:
                    if len(ordered_funcs) >= max_details:
                        break
                    seen_addresses.add(addr)
                    ordered_funcs.append(related)

                node = self._summarize_function(related)
                child_path = set(path)
                child_path.add(addr)
                children = walk(related, remaining_depth - 1, child_path)
                if children:
                    node["children"] = children
                nodes.append(node)

                if len(ordered_funcs) >= max_details:
                    break

            return nodes

        root_path = {str(func.getEntryPoint())}
        return walk(func, depth, root_path), ordered_funcs

    @staticmethod
    def _collect_metadata(func: GhidraFunction) -> dict[str, Any]:
        logger.debug("diag.enter %s", "mcp_server/providers/dissect.py:GetFunctionAioToolProvider._collect_metadata")
        body = func.getBody()
        return {
            "size": int(body.getNumAddresses()) if body else 0,
            "isExternal": bool(func.isExternal()),
            "isThunk": bool(func.isThunk()),
            "parameterCount": int(func.getParameterCount()),
            "parameters": [
                {
                    "name": str(p.getName()),
                    "type": str(p.getDataType()),
                    "ordinal": int(p.getOrdinal()),
                    "storage": str(p.getVariableStorage()) if hasattr(p, "getVariableStorage") else "",
                }
                for p in func.getParameters()
            ],
            "returnType": str(func.getReturnType()),
            "callingConvention": str(func.getCallingConventionName() or ""),
            "hasVarArgs": bool(func.hasVarArgs()),
            "hasCustomStorage": bool(func.hasCustomVariableStorage()) if hasattr(func, "hasCustomVariableStorage") else False,
            "isInline": bool(func.isInline()) if hasattr(func, "isInline") else False,
            "isNoReturn": bool(func.hasNoReturn()) if hasattr(func, "hasNoReturn") else False,
        }

    @staticmethod
    def _collect_namespace(func: GhidraFunction) -> dict[str, Any]:
        logger.debug("diag.enter %s", "mcp_server/providers/dissect.py:GetFunctionAioToolProvider._collect_namespace")
        ns = func.getParentNamespace()
        parts: list[str] = []
        while ns is not None and hasattr(ns, "getName"):
            name = str(ns.getName() or "")
            if name and name.lower() != "global":
                parts.append(name)
            parent = getattr(ns, "getParentNamespace", None)
            ns = parent() if parent else None
        parts.reverse()
        return {
            "path": "::".join(parts) if parts else "(global)",
            "segments": parts,
        }

    def _decompile(self, func: GhidraFunction, program: GhidraProgram, timeout: int | None = None) -> str:
        logger.debug("diag.enter %s", "mcp_server/providers/dissect.py:GetFunctionAioToolProvider._decompile")
        try:
            from ghidra.util.task import ConsoleTaskMonitor  # pyright: ignore[reportMissingModuleSource]

            from agentdecompile_cli.mcp_utils.decompiler_util import (
                get_decompiled_function_from_results,
                open_decompiler_for_program,
                resolve_decompiler_for_program,
            )

            monitor = ConsoleTaskMonitor()

            session_decomp = getattr(self.program_info, "decompiler", None)
            decomp, owns = resolve_decompiler_for_program(session_decomp, program)

            dr: GhidraDecompileResults = decomp.decompileFunction(func, timeout or 60, monitor)
            if dr and dr.decompileCompleted():
                df = get_decompiled_function_from_results(dr)
                if df is None:
                    raise RuntimeError("Decompilation completed but Ghidra returned no DecompiledFunction")
                code = df.getC()
                if code is not None and code.strip():
                    if owns:
                        decomp.dispose()
                    return str(code)

            # Retry with fresh interface if session decomp failed
            if session_decomp is not None:
                retry = open_decompiler_for_program(program)
                try:
                    retry_dr = retry.decompileFunction(func, timeout or 60, monitor)
                    if retry_dr and retry_dr.decompileCompleted():
                        retry_df = get_decompiled_function_from_results(retry_dr)
                        if retry_df is None:
                            if owns:
                                decomp.dispose()
                            raise RuntimeError("Decompilation completed but Ghidra returned no DecompiledFunction")
                        code = retry_df.getC()
                        if code is not None and code.strip():
                            if owns:
                                decomp.dispose()
                            return str(code)
                finally:
                    try:
                        retry.dispose()
                    except Exception:
                        pass

            extras: list[str] = []
            if dr is not None:
                try:
                    if not dr.decompileCompleted():
                        extras.append("decompileCompleted=false")
                except Exception:
                    pass
            err_tail = ""
            try:
                err_tail = dr.getErrorMessage() or "" if dr is not None else ""
            except Exception:
                err_tail = ""
            if not err_tail:
                try:
                    err_tail = decomp.getLastMessage() or ""
                except Exception:
                    err_tail = ""
            if owns:
                decomp.dispose()
            detail = "; ".join([p for p in [err_tail, " ".join(extras)] if p]) or "no error message from DecompInterface"
            raise RuntimeError(f"Decompilation failed for {func.getName()}: {detail}")

        except ImportError as exc:
            raise RuntimeError("Ghidra DecompInterface is not available (PyGhidra / Ghidra classpath)") from exc

    @staticmethod
    def _disassemble(func: GhidraFunction, program: GhidraProgram, max_insns: int | None = None) -> dict[str, Any]:
        logger.debug("diag.enter %s", "mcp_server/providers/dissect.py:GetFunctionAioToolProvider._disassemble")
        listing = program.getListing()
        body = func.getBody()
        instructions: list[dict[str, Any]] = []
        if body:
            it = listing.getInstructions(body, True)
            while it.hasNext() and (max_insns is None or len(instructions) < max_insns):
                instr = it.next()
                instructions.append(
                    {
                        "address": str(instr.getAddress()),  # pyright: ignore[reportCallIssue]
                        "mnemonic": str(instr.getMnemonicString()),
                        "operands": str(instr),
                        "bytes": " ".join(f"{b & 0xff:02x}" for b in instr.getBytes()),
                    },
                )
        return {
            "instructions": instructions,
            "count": len(instructions),
            "truncated": max_insns is not None and len(instructions) >= max_insns,
        }

    @staticmethod
    def _collect_all_comments(func: GhidraFunction, program: GhidraProgram, body: GhidraAddressSetView) -> dict[str, Any]:
        """Collect entry-point comments + inline comments across the function body."""
        logger.debug("diag.enter %s", "mcp_server/providers/dissect.py:GetFunctionAioToolProvider._collect_all_comments")
        listing = program.getListing()
        _TYPES = (
            ("eol", 0),
            ("pre", 1),
            ("post", 2),
            ("plate", 3),
            ("repeatable", 4),
        )

        # Entry-point comments
        entry_comments = collect_function_comments(program, func)

        # Inline comments at every code unit in the function body
        inline: list[dict[str, Any]] = []
        if body:
            cu_iter = listing.getCodeUnits(body, True)
            while cu_iter.hasNext():
                cu = cu_iter.next()
                addr = str(cu.getAddress())  # pyright: ignore[reportCallIssue]
                for label, code in _TYPES:
                    val = cu.getComment(code)
                    if val:
                        inline.append(
                            {
                                "address": addr,
                                "type": label,
                                "text": str(val),
                            },
                        )

        return {
            "entryPoint": entry_comments,
            "inline": inline,
            "inlineCount": len(inline),
        }

    @staticmethod
    def _collect_labels(program: GhidraProgram, body: GhidraAddressSetView) -> list[dict[str, Any]]:
        """Collect all symbols/labels within the function address range."""
        logger.debug("diag.enter %s", "mcp_server/providers/dissect.py:GetFunctionAioToolProvider._collect_labels")
        st = program.getSymbolTable()
        labels: list[dict[str, Any]] = []
        if body is None:
            return labels
        min_addr = body.getMinAddress()
        if min_addr is None:
            return labels
        sym_iter = st.getSymbolIterator(min_addr, True)
        while sym_iter.hasNext():
            sym = sym_iter.next()
            addr = sym.getAddress()
            if body.contains(addr):
                labels.append(
                    {
                        "name": str(sym.getName()),
                        "address": str(addr),
                        "type": str(sym.getSymbolType()),
                        "isPrimary": bool(sym.isPrimary()),
                        "source": str(sym.getSource()) if hasattr(sym, "getSource") else "",
                    },
                )
            else:
                break  # past the body
        return labels

    @staticmethod
    def _collect_callers(func: GhidraFunction, max_callers: int | None = None) -> list[dict[str, Any]]:
        logger.debug("diag.enter %s", "mcp_server/providers/dissect.py:GetFunctionAioToolProvider._collect_callers")
        return [{"name": c.getName(), "address": str(c.getEntryPoint())} for c in islice(func.getCallingFunctions(make_task_monitor()), max_callers)]

    @staticmethod
    def _collect_callees(func: GhidraFunction, max_callees: int | None = None) -> list[dict[str, Any]]:
        logger.debug("diag.enter %s", "mcp_server/providers/dissect.py:GetFunctionAioToolProvider._collect_callees")
        return [{"name": c.getName(), "address": str(c.getEntryPoint())} for c in islice(func.getCalledFunctions(make_task_monitor()), max_callees)]

    @staticmethod
    def _collect_xrefs(program: GhidraProgram, entry: GhidraAddress, max_refs: int | None = None) -> list[dict[str, Any]]:
        """Inbound cross-references to the function entry point."""
        logger.debug("diag.enter %s", "mcp_server/providers/dissect.py:GetFunctionAioToolProvider._collect_xrefs")
        ref_mgr: GhidraReferenceManager = program.getReferenceManager()
        refs: list[dict[str, Any]] = []
        for ref in islice(ref_mgr.getReferencesTo(entry), max_refs):
            if max_refs is not None and len(refs) >= max_refs:
                break
            refs.append(
                {
                    "fromAddress": str(ref.getFromAddress()),
                    "toAddress": str(ref.getToAddress()),
                    "type": str(ref.getReferenceType()),
                    "isCall": bool(ref.getReferenceType().isCall()) if hasattr(ref.getReferenceType(), "isCall") else False,
                    "isData": bool(ref.getReferenceType().isData()) if hasattr(ref.getReferenceType(), "isData") else False,
                },
            )
        return refs

    @staticmethod
    def _collect_outbound_refs(program: GhidraProgram, body: GhidraAddressSetView, max_refs: int | None = None) -> list[dict[str, Any]]:
        """Outbound cross-references from code inside the function body to other addresses."""
        logger.debug("diag.enter %s", "mcp_server/providers/dissect.py:GetFunctionAioToolProvider._collect_outbound_refs")
        if body is None:
            return []
        ref_mgr: GhidraReferenceManager = program.getReferenceManager()
        listing = program.getListing()
        refs: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        it = listing.getCodeUnits(body, True)
        while it.hasNext() and (max_refs is None or len(refs) < max_refs):
            cu: GhidraCodeUnit = it.next()
            from_addr = cu.getAddress()  # pyright: ignore[reportCallIssue]
            for ref in ref_mgr.getReferencesFrom(from_addr):
                if max_refs is not None and len(refs) >= max_refs:
                    return refs
                key = (str(from_addr), str(ref.getToAddress()))
                if key in seen:
                    continue
                seen.add(key)
                refs.append(
                    {
                        "fromAddress": str(ref.getFromAddress()),
                        "toAddress": str(ref.getToAddress()),
                        "type": str(ref.getReferenceType()),
                        "isCall": bool(ref.getReferenceType().isCall()) if hasattr(ref.getReferenceType(), "isCall") else False,
                        "isData": bool(ref.getReferenceType().isData()) if hasattr(ref.getReferenceType(), "isData") else False,
                    },
                )
        return refs

    @staticmethod
    def _collect_bookmarks(program: GhidraProgram, body: GhidraAddressSetView) -> list[dict[str, Any]]:
        """Bookmarks within the function's address range."""
        logger.debug("diag.enter %s", "mcp_server/providers/dissect.py:GetFunctionAioToolProvider._collect_bookmarks")
        bm_mgr: GhidraBookmarkManager = program.getBookmarkManager()
        bookmarks: list[dict[str, Any]] = []
        if body is None:
            return bookmarks
        min_addr = body.getMinAddress()
        if min_addr is None:
            return bookmarks
        it = bm_mgr.getBookmarksIterator(min_addr, True)
        while it.hasNext():
            bm: GhidraBookmark = it.next()
            addr = bm.getAddress()
            if body.contains(addr):
                bookmarks.append(
                    {
                        "address": str(addr),
                        "type": str(bm.getTypeString()),
                        "category": str(bm.getCategory()),
                        "comment": str(bm.getComment() or ""),
                    },
                )
            else:
                break
        return bookmarks

    @staticmethod
    def _collect_stack_frame(func: Any, max_variables: int | None = None) -> dict[str, Any]:
        """Stack frame layout: local variables, parameters, and frame size."""
        logger.debug("diag.enter %s", "mcp_server/providers/dissect.py:GetFunctionAioToolProvider._collect_stack_frame")
        frame: Any = func.getStackFrame()
        if frame is None:
            return {
                "variables": [],
                "frameSize": 0,
                "parameterOffset": None,
                "returnAddressOffset": None,
                "localSize": None,
                "parameterSize": None,
            }
        variables: list[dict[str, Any]] = []
        for var in islice(frame.getStackVariables(), max_variables):
            if max_variables is not None and len(variables) >= max_variables:
                break
            variables.append(
                {
                    "name": str(var.getName()),
                    "offset": int(var.getStackOffset()),
                    "size": int(var.getLength()),
                    "dataType": str(var.getDataType()),
                    "comment": str(var.getComment() or ""),
                    "isParameter": var.getStackOffset() >= 0,  # heuristic: positive offsets = params on many ABIs
                },
            )
        return {
            "variables": variables,
            "frameSize": int(frame.getFrameSize()),
            "parameterOffset": int(frame.getParameterOffset()),
            "returnAddressOffset": int(frame.getReturnAddressOffset()) if hasattr(frame, "getReturnAddressOffset") else None,
            "localSize": int(frame.getLocalSize()) if hasattr(frame, "getLocalSize") else None,
            "parameterSize": int(frame.getParameterSize()) if hasattr(frame, "getParameterSize") else None,
        }

    @staticmethod
    def _collect_memory_block(program: Any, address: Any) -> dict[str, Any] | None:
        """Info about the memory block containing the function entry point."""
        logger.debug("diag.enter %s", "mcp_server/providers/dissect.py:GetFunctionAioToolProvider._collect_memory_block")
        mem: Any = program.getMemory()
        block: Any = mem.getBlock(address)
        if block is None:
            return None
        return {
            "name": str(block.getName()),
            "start": str(block.getStart()),
            "end": str(block.getEnd()),
            "size": int(block.getSize()),
            "permissions": {
                "read": bool(block.isRead()),
                "write": bool(block.isWrite()),
                "execute": bool(block.isExecute()),
            },
            "isInitialized": bool(block.isInitialized()),
            "sourceInfo": str(block.getSourceName()) if hasattr(block, "getSourceName") else "",
        }
