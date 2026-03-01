"""GetFunction Tool Provider - manage-function, manage-function-tags, match-function.

Covers function modification, tagging, and matching/comparison.
"""

from __future__ import annotations

import logging

from typing import Any

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
                        "mode": {"type": "string", "description": "Operation mode (aliases: action, operation)", "enum": ["rename", "set_prototype", "set_calling_convention", "set_return_type", "delete", "create"]},
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
                        "mode": {"type": "string", "description": "Operation mode (aliases: action, operation)", "enum": ["list", "add", "remove", "search"]},
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

    def _find_function(self, func_id: str):
        program = self.program_info.program
        fm = program.getFunctionManager()
        for f in fm.getFunctions(True):
            if f.getName() == func_id or str(f.getEntryPoint()) == func_id:
                return f
        try:
            from agentdecompile_cli.mcp_utils.address_util import AddressUtil

            addr = AddressUtil.resolve_address_or_symbol(program, func_id)
            return fm.getFunctionContaining(addr)
        except Exception:
            return None

    async def _handle_manage(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        action = self._require_str(args, "mode", "action", "operation", name="mode")
        func_id = self._get_str(args, "function", "addressorsymbol", "functionidentifier", "name", "addr", "symbol")
        program = self.program_info.program

        action_n = n(action)

        if action_n == "create":
            addr_str = self._require_str(args, "address", "addressorsymbol", "addr", name="address")
            from agentdecompile_cli.mcp_utils.address_util import AddressUtil

            addr = AddressUtil.resolve_address_or_symbol(program, addr_str)
            name = self._get_str(args, "newname", "name", "functionname", default="")
            tx = program.startTransaction("create-function")
            try:
                fm = program.getFunctionManager()
                from ghidra.program.model.symbol import SourceType

                func = fm.createFunction(name or None, addr, None, SourceType.USER_DEFINED)
                program.endTransaction(tx, True)
                return create_success_response({"action": "create", "address": str(addr), "name": func.getName(), "success": True})
            except Exception:
                program.endTransaction(tx, False)
                raise

        if not func_id:
            raise ValueError("function or addressOrSymbol required")
        func = self._find_function(func_id)
        if func is None:
            raise ValueError(f"Function not found: {func_id}")

        if action_n == "rename":
            new_name = self._require_str(args, "newname", "name", name="newName")
            tx = program.startTransaction("rename-function")
            try:
                from ghidra.program.model.symbol import SourceType

                func.setName(new_name, SourceType.USER_DEFINED)
                program.endTransaction(tx, True)
            except Exception:
                program.endTransaction(tx, False)
                raise
            return create_success_response({"action": "rename", "oldName": func_id, "newName": new_name, "success": True})

        if action_n == "setprototype":
            proto = self._require_str(args, "prototype", "signature", name="prototype")
            tx = program.startTransaction("set-prototype")
            try:
                # Use Ghidra's function signature parser
                func.setSignature(proto)
                program.endTransaction(tx, True)
            except Exception:
                program.endTransaction(tx, False)
                raise
            return create_success_response({"action": "set_prototype", "function": func.getName(), "prototype": proto, "success": True})

        if action_n in ("setcallingconvention", "callingconvention"):
            cc = self._require_str(args, "callingconvention", "convention", name="callingConvention")
            tx = program.startTransaction("set-calling-convention")
            try:
                func.setCallingConvention(cc)
                program.endTransaction(tx, True)
            except Exception:
                program.endTransaction(tx, False)
                raise
            return create_success_response({"action": "set_calling_convention", "function": func.getName(), "callingConvention": cc, "success": True})

        if action_n in ("setreturntype", "returntype"):
            rt_str = self._require_str(args, "returntype", "type", name="returnType")
            from ghidra.util.data import DataTypeParser

            dtm = program.getDataTypeManager()
            parser = DataTypeParser(dtm, dtm, None, DataTypeParser.AllowedDataTypes.ALL)
            rt = parser.parse(rt_str)
            tx = program.startTransaction("set-return-type")
            try:
                from ghidra.program.model.symbol import SourceType

                func.setReturnType(rt, SourceType.USER_DEFINED)
                program.endTransaction(tx, True)
            except Exception:
                program.endTransaction(tx, False)
                raise
            return create_success_response({"action": "set_return_type", "function": func.getName(), "returnType": rt_str, "success": True})

        if action_n == "delete":
            tx = program.startTransaction("delete-function")
            try:
                program.getFunctionManager().removeFunction(func.getEntryPoint())
                program.endTransaction(tx, True)
            except Exception:
                program.endTransaction(tx, False)
                raise
            return create_success_response({"action": "delete", "function": func_id, "success": True})

        raise ValueError(f"Unknown action: {action}")

    async def _handle_tags(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        action = self._get_str(args, "mode", "action", "operation", default="list")
        func_id = self._get_str(args, "function", "addressorsymbol", "functionidentifier")
        tag_name = self._get_str(args, "tag", "tagname", "tags", "name")
        program = self.program_info.program

        action_n = n(action)

        if action_n == "search":
            # Search for functions with a specific tag
            fm = program.getFunctionManager()
            results = []
            for func in fm.getFunctions(True):
                tags = list(func.getTags())
                tag_names = [t.getName() for t in tags]
                if tag_name and tag_name.lower() in [tn.lower() for tn in tag_names]:
                    results.append({"name": func.getName(), "address": str(func.getEntryPoint()), "tags": tag_names})
            return create_success_response({"action": "search", "tag": tag_name, "functions": results, "count": len(results)})

        if not func_id:
            # List all known tags
            fm = program.getFunctionManager()
            all_tags = set()
            for func in fm.getFunctions(True):
                for t in func.getTags():
                    all_tags.add(t.getName())
            return create_success_response({"action": "list", "tags": sorted(all_tags), "count": len(all_tags)})

        func = self._find_function(func_id)
        if func is None:
            raise ValueError(f"Function not found: {func_id}")

        if action_n == "list":
            tags = [t.getName() for t in func.getTags()]
            return create_success_response({"function": func.getName(), "tags": tags, "count": len(tags)})

        if action_n in ("add", "set"):
            if not tag_name:
                raise ValueError("tag or tagName required")
            tx = program.startTransaction("add-function-tag")
            try:
                func.addTag(tag_name)
                program.endTransaction(tx, True)
            except Exception:
                program.endTransaction(tx, False)
                raise
            return create_success_response({"action": "add", "function": func.getName(), "tag": tag_name, "success": True})

        if action_n in ("remove", "delete"):
            if not tag_name:
                raise ValueError("tag or tagName required")
            tx = program.startTransaction("remove-function-tag")
            try:
                func.removeTag(tag_name)
                program.endTransaction(tx, True)
            except Exception:
                program.endTransaction(tx, False)
                raise
            return create_success_response({"action": "remove", "function": func.getName(), "tag": tag_name, "success": True})

        raise ValueError(f"Unknown tag action: {action}")

    async def _handle_match(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()
        func_id = self._require_str(args, "function", "addressorsymbol", "functionidentifier", name="function")
        mode = self._get_str(args, "mode", default="similar")
        max_results = self._get_int(args, "maxresults", "limit", "maxfunctions", "maxcount", default=50)

        func = self._find_function(func_id)
        if func is None:
            raise ValueError(f"Function not found: {func_id}")

        program = self.program_info.program
        fm = program.getFunctionManager()

        mode_n = n(mode)

        if mode_n == "callers":
            callers = list(func.getCallingFunctions(None))[:max_results]
            return create_success_response(
                {
                    "function": func.getName(),
                    "mode": "callers",
                    "results": [{"name": c.getName(), "address": str(c.getEntryPoint())} for c in callers],
                    "count": len(callers),
                },
            )

        if mode_n == "callees":
            callees = list(func.getCalledFunctions(None))[:max_results]
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
        for f in fm.getFunctions(True):
            if f == func:
                continue
            f_callees = {c.getName() for c in f.getCalledFunctions(None)}
            f_callers = {c.getName() for c in f.getCallingFunctions(None)}
            overlap = len(my_callees & f_callees) + len(my_callers & f_callers)
            if overlap > 0:
                scores.append((overlap, f))
        scores.sort(key=lambda x: x[0], reverse=True)
        similar = [{"name": f.getName(), "address": str(f.getEntryPoint()), "similarityScore": s} for s, f in scores[:max_results]]
        return create_success_response(
            {
                "function": func.getName(),
                "mode": "similar",
                "results": similar,
                "count": len(similar),
            },
        )
