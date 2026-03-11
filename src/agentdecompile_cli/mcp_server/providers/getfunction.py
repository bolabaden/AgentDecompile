"""GetFunction Tool Provider - manage-function, manage-function-tags, match-function.

Covers function modification, tagging, and matching/comparison.
"""

from __future__ import annotations

import heapq
import logging

from collections import defaultdict
from dataclasses import dataclass
from itertools import islice
from typing import Any, ClassVar, cast

from mcp import types

from agentdecompile_cli.mcp_server.profiling import ProfileCapture
from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
    n,
)

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class _FunctionMatchFeature:
    function: Any
    name: str
    address: str
    signature: str
    param_count: int
    return_type: str
    callers: frozenset[str]
    callees: frozenset[str]


@dataclass(slots=True)
class _FunctionMatchIndex:
    function_count: int
    features: list[_FunctionMatchFeature]
    by_identity: dict[str, _FunctionMatchFeature]
    by_signature: dict[tuple[int, str], list[_FunctionMatchFeature]]
    by_caller: dict[str, set[str]]
    by_callee: dict[str, set[str]]


class GetFunctionToolProvider(ToolProvider):
    _MATCH_INDEX_CACHE: ClassVar[dict[int, _FunctionMatchIndex]] = {}

    HANDLERS = {
        "managefunction": "_handle_manage",
        "managefunctiontags": "_handle_tags",
        "matchfunction": "_handle_match",
    }

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="manage-function",
                description="Change attributes of an existing function to improve analysis. Use this when you understand what a function does and want to update its name, its input arguments (prototype), the type of value it returns, or its calling convention (how it receives arguments). You can also create a new function or delete an existing one.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "Path to the program containing the function."},
                        "function": {"type": "string", "description": "The current name or address of the function you want to modify."},
                        "addressOrSymbol": {"type": "string", "description": "Alternative way to specify the function's starting address."},
                        "mode": {
                            "type": "string",
                            "description": "What modification you want to make: 'rename' (change name), 'set_prototype' (change arguments), 'set_calling_convention' (how arguments are passed), 'set_return_type', 'delete', or 'create'.",
                            "enum": ["rename", "set_prototype", "set_calling_convention", "set_return_type", "delete", "create"],
                        },
                        "newName": {"type": "string", "description": "If mode is 'rename', the new name you want to give the function."},
                        "prototype": {"type": "string", "description": "If mode is 'set_prototype', the complete C-style signature you want to apply (e.g. 'int main(int argc, char** argv)')."},
                        "callingConvention": {"type": "string", "description": "If mode is 'set_calling_convention', the new convention (e.g., '__stdcall', '__fastcall')."},
                        "returnType": {"type": "string", "description": "If mode is 'set_return_type', the new return data type (e.g. 'int', 'void')."},
                        "address": {"type": "string", "description": "If mode is 'create', the memory address where the new function should start."},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="manage-function-tags",
                description="Label a function with simple string tags (like 'crypto', 'network', 'vulnerable') to easily group or find it later. Use this to organize the reverse engineering workload.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "Path to the program."},
                        "function": {"type": "string", "description": "The function name or address to tag."},
                        "addressOrSymbol": {"type": "string", "description": "Alternative way to specify the function."},
                        "mode": {"type": "string", "description": "What to do with tags: 'list' (view tags), 'add' (attach a tag), 'remove' (detach a tag), or 'search' (find functions by tag).", "enum": ["list", "add", "remove", "search"]},
                        "tag": {"type": "string", "description": "The specific tag to add, remove, or search for (e.g. 'encryption')."},
                        "tagName": {"type": "string", "description": "Alternative parameter name for 'tag'."},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="match-function",
                description="Find other functions in the binary that look or behave similarly to a target function. Use this to find cloned functions, shared library code, or to discover groups of functions that share common traits like the same number of arguments or similar callers/callees.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "Path to the program."},
                        "function": {"type": "string", "description": "The target function you want to match against."},
                        "addressOrSymbol": {"type": "string", "description": "Alternative way to specify the target function."},
                        "mode": {
                            "type": "string",
                            "enum": ["similar", "callers", "callees", "signature"],
                            "default": "similar",
                            "description": "How to evaluate similarity: 'similar' (overall heuristics), 'callers' (functions grouped by who calls them), 'callees' (functions grouped by who they call), 'signature' (functions with identical argument types).",
                        },
                        "maxResults": {"type": "integer", "default": 100, "description": "Number of matched functions to return. Typical values are 100–500. Do not set this below 50 unless the user explicitly asks for only a handful of results."},
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle_manage(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        action = self._require_str(args, "mode", "action", "operation", name="mode")
        func_id = self._get_address_or_symbol(args)
        assert self.program_info is not None, "program_info should not be None after _require_program()"
        program = self.program_info.program

        action_n = n(action)
        # Handle create early (no target function required)
        if action_n == "create":
            addr_str = self._require_address_or_symbol(args)
            addr = self._resolve_address(addr_str, program=program)
            name = self._get_str(args, "newname", "name", "functionname", default="")

            def _create_function():
                fm = self._get_function_manager(program)
                from ghidra.program.model.symbol import SourceType  # pyright: ignore[reportMissingModuleSource]

                return fm.createFunction(name or None, addr, None, SourceType.USER_DEFINED)

            func = self._run_program_transaction(program, "create-function", _create_function)
            return create_success_response({"action": "create", "address": str(addr), "name": func.getName(), "success": True})

        # For other actions, ensure function specified
        if not func_id:
            raise ValueError("function or addressOrSymbol required")
        func = self._resolve_function(func_id, program=program)
        if func is None:
            raise ValueError(f"Function not found: {func_id}")

        # Dispatch remaining actions to dedicated handlers to reduce inline branching
        return await self._dispatch_handler(
            args,
            action,
            {
                "rename": "_handle_rename",
                "setprototype": "_handle_set_prototype",
                "setcallingconvention": "_handle_set_calling_convention",
                "callingconvention": "_handle_set_calling_convention",
                "setreturntype": "_handle_set_return_type",
                "returntype": "_handle_set_return_type",
                "delete": "_handle_delete",
            },
            program=program,
            func=func,
            func_id=func_id,
        )

    async def _handle_rename(self, args: dict[str, Any], program: Any, func: Any, func_id: str) -> list[types.TextContent]:
        new_name = self._require_str(args, "newname", "name", name="newName")

        def _rename_function() -> None:
            from ghidra.program.model.symbol import SourceType  # pyright: ignore[reportMissingModuleSource]

            func.setName(new_name, SourceType.USER_DEFINED)

        self._run_program_transaction(program, "rename-function", _rename_function)
        return create_success_response(
            {
                "action": "rename",
                "oldName": func_id,
                "newName": new_name,
                "success": True,
            },
        )

    async def _handle_set_prototype(self, args: dict[str, Any], program: Any, func: Any, func_id: str) -> list[types.TextContent]:
        proto = self._require_str(args, "prototype", "signature", name="prototype")

        def _set_prototype() -> None:
            func.setSignature(proto)

        self._run_program_transaction(program, "set-prototype", _set_prototype)
        return create_success_response(
            {
                "action": "set_prototype",
                "function": func.getName(),
                "prototype": proto,
                "success": True,
            },
        )

    async def _handle_set_calling_convention(self, args: dict[str, Any], program: Any, func: Any, func_id: str) -> list[types.TextContent]:
        cc = self._require_str(args, "callingconvention", "convention", name="callingConvention")

        def _set_calling_convention() -> None:
            func.setCallingConvention(cc)

        self._run_program_transaction(program, "set-calling-convention", _set_calling_convention)
        return create_success_response(
            {
                "action": "set_calling_convention",
                "function": func.getName(),
                "callingConvention": cc,
                "success": True,
            },
        )

    async def _handle_set_return_type(self, args: dict[str, Any], program: Any, func: Any, func_id: str) -> list[types.TextContent]:
        rt_str = self._require_str(args, "returntype", "newtype", "type", name="returnType")
        from ghidra.util.data import DataTypeParser  # pyright: ignore[reportMissingModuleSource]

        dtm = program.getDataTypeManager()
        parser = DataTypeParser(dtm, dtm, cast("Any", None), DataTypeParser.AllowedDataTypes.ALL)
        rt = parser.parse(rt_str)

        def _set_return_type() -> None:
            from ghidra.program.model.symbol import SourceType  # pyright: ignore[reportMissingModuleSource]

            func.setReturnType(rt, SourceType.USER_DEFINED)

        self._run_program_transaction(program, "set-return-type", _set_return_type)
        return create_success_response(
            {
                "action": "set_return_type",
                "function": func.getName(),
                "returnType": rt_str,
                "success": True,
            },
        )

    async def _handle_delete(self, args: dict[str, Any], program: Any, func: Any, func_id: str) -> list[types.TextContent]:
        def _delete_function() -> None:
            self._get_function_manager(program).removeFunction(func.getEntryPoint())

        self._run_program_transaction(program, "delete-function", _delete_function)
        return create_success_response(
            {
                "action": "delete",
                "function": func_id,
                "success": True,
            },
        )

    async def _handle_tags(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        action = self._get_str(args, "mode", "action", "operation", default="list")
        func_id = self._get_address_or_symbol(args)
        tag_name = self._get_str(args, "tag", "tagname", "tags", "name")
        assert self.program_info is not None, "program_info should not be None after _require_program()"
        program = self.program_info.program

        action_n = n(action)

        if action_n == "search":
            # Search for functions with a specific tag
            fm = self._get_function_manager(program)
            results = []
            for func in fm.getFunctions(True):
                tags = list(func.getTags())
                tag_names = [t.getName() for t in tags]
                if tag_name and tag_name.lower() in [tn.lower() for tn in tag_names]:
                    results.append({"name": func.getName(), "address": str(func.getEntryPoint()), "tags": tag_names})
            return create_success_response({"action": "search", "tag": tag_name, "functions": results, "count": len(results)})

        if not func_id:
            # List all known tags
            fm = self._get_function_manager(program)
            all_tags = set()
            for func in fm.getFunctions(True):
                for t in func.getTags():
                    all_tags.add(t.getName())
            return create_success_response({"action": "list", "tags": sorted(all_tags), "count": len(all_tags)})

        func = self._resolve_function(func_id, program=program)
        if func is None:
            raise ValueError(f"Function not found: {func_id}")

        if action_n == "list":
            tags = [t.getName() for t in func.getTags()]
            return create_success_response(
                {
                    "function": func.getName(),
                    "tags": tags,
                    "count": len(tags),
                },
            )

        if action_n in ("add", "set"):
            if not tag_name:
                raise ValueError("tag or tagName required")

            def _add_function_tag() -> None:
                func.addTag(tag_name)

            self._run_program_transaction(program, "add-function-tag", _add_function_tag)
            return create_success_response(
                {
                    "action": "add",
                    "function": func.getName(),
                    "tag": tag_name,
                    "success": True,
                },
            )

        if action_n in ("remove", "delete"):
            if not tag_name:
                raise ValueError("tag or tagName required")

            def _remove_function_tag() -> None:
                func.removeTag(tag_name)

            self._run_program_transaction(program, "remove-function-tag", _remove_function_tag)
            return create_success_response(
                {
                    "action": "remove",
                    "function": func.getName(),
                    "tag": tag_name,
                    "success": True,
                },
            )

        raise ValueError(f"Unknown tag action: {action}")

    def _get_match_index(self, program: Any, fm: Any) -> tuple[_FunctionMatchIndex, bool]:
        cache_key = id(program)
        function_count = int(fm.getFunctionCount()) if hasattr(fm, "getFunctionCount") else -1
        cached = self._MATCH_INDEX_CACHE.get(cache_key)
        if cached is not None and cached.function_count == function_count:
            return cached, True

        with ProfileCapture(
            "match-function-index-build",
            target=getattr(program, "getName", lambda: "")(),
            metadata={"functionCount": function_count},
        ) as capture:
            features: list[_FunctionMatchFeature] = []
            by_identity: dict[str, _FunctionMatchFeature] = {}
            by_signature: dict[tuple[int, str], list[_FunctionMatchFeature]] = defaultdict(list)
            by_caller: dict[str, set[str]] = defaultdict(set)
            by_callee: dict[str, set[str]] = defaultdict(set)

            for func in fm.getFunctions(True):
                callers = frozenset(c.getName() for c in func.getCallingFunctions(None))
                callees = frozenset(c.getName() for c in func.getCalledFunctions(None))
                addr_str = str(func.getEntryPoint())
                feature = _FunctionMatchFeature(
                    function=func,
                    name=func.getName(),
                    address=addr_str,
                    signature=str(func.getSignature()),
                    param_count=func.getParameterCount(),
                    return_type=str(func.getReturnType()),
                    callers=callers,
                    callees=callees,
                )
                features.append(feature)
                by_identity[addr_str] = feature
                by_signature[(feature.param_count, feature.return_type)].append(feature)
                for caller in callers:
                    by_caller[caller].add(addr_str)
                for callee in callees:
                    by_callee[callee].add(addr_str)

            capture.add_metadata(indexedFunctions=len(features))

        index = _FunctionMatchIndex(
            function_count=function_count,
            features=features,
            by_identity=by_identity,
            by_signature=dict(by_signature),
            by_caller={name: set(addrs) for name, addrs in by_caller.items()},
            by_callee={name: set(addrs) for name, addrs in by_callee.items()},
        )
        self._MATCH_INDEX_CACHE[cache_key] = index
        return index, False

    async def _handle_match(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        raw_targets = args.get(n("targetprogrampaths"))
        if raw_targets is not None:
            if isinstance(raw_targets, list):
                has_paths = any(x and str(x).strip() for x in raw_targets)
            else:
                has_paths = bool(str(raw_targets).strip())
            if has_paths:
                raise ValueError(
                    "Cross-program matching (targetProgramPaths) is not yet implemented. "
                    "Use match-function without targetProgramPaths for single-program modes: "
                    "similar, callers, callees, or signature."
                )
        func_id = self._require_address_or_symbol(args)
        mode = self._get_str(args, "mode", default="similar")
        max_results = self._get_int(args, "maxresults", "limit", "maxfunctions", "maxcount", default=50)

        func = self._resolve_function(func_id)
        if func is None:
            raise ValueError(f"Function not found: {func_id}")

        assert self.program_info is not None, "program_info should not be None after _require_program()"
        program = self.program_info.program
        fm = self._get_function_manager(program)

        mode_n = n(mode)
        match_index: _FunctionMatchIndex | None = None
        cache_hit = False
        if mode_n in {"similar", "signature"}:
            match_index, cache_hit = self._get_match_index(program, fm)

        if mode_n == "callers":
            callers = list(islice(func.getCallingFunctions(None), max_results))
            return create_success_response(
                {
                    "function": func.getName(),
                    "mode": "callers",
                    "results": [{"name": c.getName(), "address": str(c.getEntryPoint())} for c in callers],
                    "count": len(callers),
                },
            )

        if mode_n == "callees":
            callees = list(islice(func.getCalledFunctions(None), max_results))
            return create_success_response(
                {
                    "function": func.getName(),
                    "mode": "callees",
                    "results": [{"name": c.getName(), "address": str(c.getEntryPoint())} for c in callees],
                    "count": len(callees),
                },
            )

        if mode_n == "signature":
            sig = str(func.getSignature())
            param_count = func.getParameterCount()
            ret = str(func.getReturnType())
            func_addr = str(func.getEntryPoint())
            assert match_index is not None
            candidates = [feature for feature in match_index.by_signature.get((param_count, ret), []) if feature.address != func_addr]
            similar = [
                {"name": feature.name, "address": feature.address, "signature": feature.signature}
                for feature in candidates[:max_results]
            ]
            return create_success_response(
                {
                    "function": func.getName(),
                    "mode": "signature",
                    "referenceSignature": sig,
                    "indexedFunctionCount": match_index.function_count,
                    "cacheHit": cache_hit,
                    "results": similar,
                    "count": len(similar),
                },
            )

        assert match_index is not None
        func_addr = str(func.getEntryPoint())
        target_feature = match_index.by_identity.get(func_addr)
        if target_feature is None:
            raise ValueError(f"Function not indexed for matching: {func_id}")

        candidate_addrs: set[str] = set()
        for caller in target_feature.callers:
            candidate_addrs.update(match_index.by_caller.get(caller, set()))
        for callee in target_feature.callees:
            candidate_addrs.update(match_index.by_callee.get(callee, set()))

        candidate_addrs.discard(func_addr)
        if not candidate_addrs:
            signature_candidates = match_index.by_signature.get((target_feature.param_count, target_feature.return_type), [])
            candidate_addrs.update(feature.address for feature in signature_candidates if feature.address != func_addr)

        scores: list[tuple[int, _FunctionMatchFeature]] = []
        top_k = max(max_results, 1)
        for addr in candidate_addrs:
            feature = match_index.by_identity.get(addr)
            if feature is None:
                continue
            overlap = len(target_feature.callees & feature.callees) + len(target_feature.callers & feature.callers)
            if overlap > 0:
                scores.append((overlap, feature))

        with ProfileCapture(
            "match-function-similarity",
            target=func.getName(),
            metadata={
                "mode": "similar",
                "cacheHit": cache_hit,
                "indexedFunctionCount": match_index.function_count,
                "candidateCount": len(candidate_addrs),
            },
        ):
            top_matches = heapq.nlargest(top_k, scores, key=lambda item: item[0])

        similar = [{"name": feature.name, "address": feature.address, "similarityScore": score} for score, feature in top_matches]
        return create_success_response(
            {
                "function": func.getName(),
                "mode": "similar",
                "indexedFunctionCount": match_index.function_count,
                "candidateCount": len(candidate_addrs),
                "cacheHit": cache_hit,
                "results": similar,
                "count": len(similar),
            },
        )
