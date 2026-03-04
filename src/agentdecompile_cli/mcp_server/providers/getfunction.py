"""GetFunction Tool Provider - manage-function, manage-function-tags, match-function.

Covers function modification, tagging, and matching/comparison.
"""

from __future__ import annotations

import heapq
import logging
from itertools import islice

from typing import Any, cast

from mcp import types

from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
    n,
)

logger = logging.getLogger(__name__)


class GetFunctionToolProvider(ToolProvider):
    HANDLERS = {
        "managefunction": "_handle_manage",
        "managefunctiontags": "_handle_tags",
        "matchfunction": "_handle_match",
    }

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="manage-function",
                description="Modify function properties (rename, set prototype, set calling convention, etc.)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "function": {"type": "string"},
                        "addressOrSymbol": {"type": "string"},
                        "mode": {
                            "type": "string",
                            "description": "Operation mode",
                            "enum": ["rename", "set_prototype", "set_calling_convention", "set_return_type", "delete", "create"],
                        },
                        "newName": {"type": "string"},
                        "prototype": {"type": "string"},
                        "callingConvention": {"type": "string"},
                        "returnType": {"type": "string"},
                        "address": {"type": "string", "description": "Address for create action"},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="manage-function-tags",
                description="Manage function tags",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "function": {"type": "string"},
                        "addressOrSymbol": {"type": "string"},
                        "mode": {"type": "string", "description": "Operation mode", "enum": ["list", "add", "remove", "search"]},
                        "tag": {"type": "string"},
                        "tagName": {"type": "string"},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="match-function",
                description="Match/compare functions by signature, callees, callers",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string"},
                        "function": {"type": "string"},
                        "addressOrSymbol": {"type": "string"},
                        "mode": {"type": "string", "enum": ["similar", "callers", "callees", "signature"], "default": "similar"},
                        "maxResults": {"type": "integer", "default": 50},
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
        parser = DataTypeParser(dtm, dtm, cast(Any, None), DataTypeParser.AllowedDataTypes.ALL)
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

    async def _handle_match(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
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
            similar = []
            for f in fm.getFunctions(True):
                if f == func:
                    continue
                if f.getParameterCount() == param_count and str(f.getReturnType()) == ret:
                    similar.append({"name": f.getName(), "address": str(f.getEntryPoint()), "signature": str(f.getSignature())})
                    if len(similar) >= max_results:
                        break
            return create_success_response(
                {
                    "function": func.getName(),
                    "mode": "signature",
                    "referenceSignature": sig,
                    "results": similar,
                    "count": len(similar),
                },
            )

        # similar
        # Compare by callee overlap
        my_callees = {c.getName() for c in func.getCalledFunctions(None)}
        my_callers = {c.getName() for c in func.getCallingFunctions(None)}
        scores = []
        top_k = max(max_results, 1)
        for f in fm.getFunctions(True):
            if f == func:
                continue
            f_callees = {c.getName() for c in f.getCalledFunctions(None)}
            f_callers = {c.getName() for c in f.getCallingFunctions(None)}
            overlap = len(my_callees & f_callees) + len(my_callers & f_callers)
            if overlap > 0:
                scores.append((overlap, f))
        top_matches = heapq.nlargest(top_k, scores, key=lambda item: item[0])
        similar = [{"name": f.getName(), "address": str(f.getEntryPoint()), "similarityScore": s} for s, f in top_matches]
        return create_success_response(
            {
                "function": func.getName(),
                "mode": "similar",
                "results": similar,
                "count": len(similar),
            },
        )
