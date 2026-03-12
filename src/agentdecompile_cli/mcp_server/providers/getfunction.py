"""GetFunction Tool Provider - manage-function, manage-function-tags, match-function.

This provider implements three tools:

  - manage-function: Rename, set prototype/return type/calling convention, create, or delete
    a function. Used when the user or agent has identified what a function does and wants
    to persist that knowledge (name, signature) into the program.
  - manage-function-tags: Attach string tags to functions (e.g. 'crypto', 'network') for
    organization and search. Modes: list, add, remove, search.
  - match-function: Cross-program or single-program function matching. Primary use: given
    a source function and target program paths, find the equivalent function in each target
    (by signature/name similarity) and optionally propagate name, tags, comments, prototype,
    bookmarks. Single-program modes: similar, callers, callees, signature (no targets).

Match-function builds an in-memory index (_FunctionMatchIndex) keyed by signature and
call graph so that candidates can be ranked by similarity; the index is cached per program
to avoid recomputing on repeated calls.
"""

from __future__ import annotations

import heapq
import json
import logging

from collections import defaultdict
from dataclasses import dataclass
from itertools import islice
from typing import Any, ClassVar, cast

from mcp import types

from agentdecompile_cli.mcp_server.profiling import ProfileCapture
from agentdecompile_cli.mcp_server.session_context import (
    SESSION_CONTEXTS,
    get_current_mcp_session_id,
)
from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
    n,
)
from agentdecompile_cli.registry import Tool

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Match-function index: per-program feature set for similarity and call-graph lookup
# ---------------------------------------------------------------------------


@dataclass(slots=True)  # pyright: ignore[reportCallIssue]
class _FunctionMatchFeature:
    """One function's extracted features for matching (signature, callers, callees)."""

    function: Any
    name: str
    address: str
    signature: str
    param_count: int
    return_type: str
    callers: frozenset[str]
    callees: frozenset[str]


@dataclass(slots=True)  # pyright: ignore[reportCallIssue]
class _FunctionMatchIndex:
    """In-memory index of all functions in a program for match-function.

    Indexed by: identity (name/addr), (param_count, return_type), caller names,
    callee names. Built once per program and cached in _MATCH_INDEX_CACHE so
    repeated match calls (e.g. same program, different source function) are fast.
    """

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
                name=Tool.MANAGE_FUNCTION.value,
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
                        "prototype": {
                            "type": "string",
                            "description": "If mode is 'set_prototype', the complete C-style signature you want to apply (e.g. 'int main(int argc, char** argv)').",
                        },
                        "callingConvention": {"type": "string", "description": "If mode is 'set_calling_convention', the new convention (e.g., '__stdcall', '__fastcall')."},
                        "returnType": {"type": "string", "description": "If mode is 'set_return_type', the new return data type (e.g. 'int', 'void')."},
                        "address": {"type": "string", "description": "If mode is 'create', the memory address where the new function should start."},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name=Tool.MANAGE_FUNCTION_TAGS.value,
                description="Label a function with simple string tags (like 'crypto', 'network', 'vulnerable') to easily group or find it later. Use this to organize the reverse engineering workload.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "Path to the program."},
                        "function": {"type": "string", "description": "The function name or address to tag."},
                        "addressOrSymbol": {"type": "string", "description": "Alternative way to specify the function."},
                        "mode": {
                            "type": "string",
                            "description": "What to do with tags: 'list' (view tags), 'add' (attach a tag), 'remove' (detach a tag), or 'search' (find functions by tag).",
                            "enum": ["list", "add", "remove", "search"],
                        },
                        "tag": {"type": "string", "description": "The specific tag to add, remove, or search for (e.g. 'encryption')."},
                        "tagName": {"type": "string", "description": "Alternative parameter name for 'tag'."},
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name=Tool.MATCH_FUNCTION.value,
                description="Match functions across different builds or versions of a binary (cross-program matching). Give a source function and target program paths to find the equivalent in each target and optionally propagate names, tags, comments, prototype, and bookmarks. If function/functionIdentifier/addressOrSymbol is omitted but targetProgramPaths is set (or targets are discoverable from the session), the tool iterates over all functions in the source (bulk migration). Use without targetProgramPaths for single-program modes: similar, callers, callees, signature. Matched results include functionDetails (get-function output) for context.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "Path to the source program containing the function to match."},
                        "function": {"type": "string", "description": "The source function name or address to match (alias: functionIdentifier, addressOrSymbol)."},
                        "addressOrSymbol": {"type": "string", "description": "Alternative way to specify the source function."},
                        "functionIdentifier": {"type": "string", "description": "Source function name or address (same as function)."},
                        "targetProgramPaths": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Paths to target programs to find the equivalent function in. When provided, cross-program matching runs (primary use). Omit for single-program modes.",
                        },
                        "minSimilarity": {
                            "type": "number",
                            "default": 0.7,
                            "description": "Minimum similarity 0–1 (or 0–100). Name match = 1.0, signature-only = 0.7. Default 0.7.",
                        },
                        "propagateNames": {
                            "type": "boolean",
                            "default": False,
                            "description": "If true, set the matched target function's name to the source function's name.",
                        },
                        "propagateTags": {"type": "boolean", "default": False, "description": "If true, copy source function's tags to the matched target function."},
                        "propagateComments": {
                            "type": "boolean",
                            "default": False,
                            "description": "If true, copy all comment types (plate, pre, post, eol, repeatable) at the source function entry to the matched target.",
                        },
                        "propagatePrototype": {
                            "type": "boolean",
                            "default": False,
                            "description": "If true, set the matched target function's signature (return type and parameters) to the source function's prototype.",
                        },
                        "propagateBookmarks": {
                            "type": "boolean",
                            "default": False,
                            "description": "If true, copy bookmarks at the source function entry to the matched target function entry.",
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["similar", "callers", "callees", "signature"],
                            "default": "similar",
                            "description": "Single-program only: 'similar', 'callers', 'callees', or 'signature'. Ignored when targetProgramPaths is provided.",
                        },
                        "maxResults": {"type": "integer", "default": 100, "description": "Single-program mode: number of matched functions to return."},
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle_manage(
        self,
        args: dict[str, Any],
    ) -> list[types.TextContent]:
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

        # All other actions need an existing function (rename, set_prototype, delete, etc.)
        if not func_id:
            raise ValueError("function or addressOrSymbol required")
        func = self._resolve_function(func_id, program=program)
        if func is None:
            raise ValueError(f"Function not found: {func_id}")

        # Dispatch to per-action handlers (rename, set_prototype, set_calling_convention, etc.)
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

    async def _handle_rename(
        self,
        args: dict[str, Any],
        program: Any,
        func: Any,
        func_id: str,
    ) -> list[types.TextContent]:
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

    async def _handle_set_prototype(
        self,
        args: dict[str, Any],
        program: Any,
        func: Any,
        func_id: str,
    ) -> list[types.TextContent]:
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

    async def _handle_set_calling_convention(
        self,
        args: dict[str, Any],
        program: Any,
        func: Any,
        func_id: str,
    ) -> list[types.TextContent]:
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

    async def _handle_set_return_type(
        self,
        args: dict[str, Any],
        program: Any,
        func: Any,
        func_id: str,
    ) -> list[types.TextContent]:
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
                all_tags.update(t.getName() for t in func.getTags())
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

    def _get_match_index(
        self,
        program: Any,
        fm: Any,
    ) -> tuple[_FunctionMatchIndex, bool]:
        """Build or return cached match index for this program.

        The index maps: identity (addr) → feature; (param_count, return_type) → list of features;
        caller name → set of addrs; callee name → set of addrs. Used to rank candidates by
        signature and call-graph similarity. Cache is keyed by program id; we invalidate when
        function count changes (e.g. after analysis or import).
        """
        cache_key: int = id(program)
        function_count: int = int(fm.getFunctionCount()) if hasattr(fm, "getFunctionCount") else -1
        cached: _FunctionMatchIndex | None = self._MATCH_INDEX_CACHE.get(cache_key)
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
                # Call graph sets used for similarity: more shared callers/callees => higher match score
                callers = frozenset(c.getName() for c in func.getCallingFunctions(None))
                callees = frozenset(c.getName() for c in func.getCalledFunctions(None))
                addr_str = str(func.getEntryPoint())
                feature = _FunctionMatchFeature(
                    function=func,  # pyright: ignore[reportCallIssue]
                    name=func.getName(),  # pyright: ignore[reportCallIssue]
                    address=addr_str,  # pyright: ignore[reportCallIssue]
                    signature=str(func.getSignature()),  # pyright: ignore[reportCallIssue]
                    param_count=func.getParameterCount(),  # pyright: ignore[reportCallIssue]
                    return_type=str(func.getReturnType()),  # pyright: ignore[reportCallIssue]
                    callers=callers,  # pyright: ignore[reportCallIssue]
                    callees=callees,  # pyright: ignore[reportCallIssue]
                )
                features.append(feature)
                by_identity[addr_str] = feature
                by_signature[feature.param_count, feature.return_type].append(feature)
                for caller in callers:
                    by_caller[caller].add(addr_str)
                for callee in callees:
                    by_callee[callee].add(addr_str)

            capture.add_metadata(indexedFunctions=len(features))

        index = _FunctionMatchIndex(
            function_count=function_count,  # pyright: ignore[reportCallIssue]
            features=features,  # pyright: ignore[reportCallIssue]
            by_identity=by_identity,  # pyright: ignore[reportCallIssue]
            by_signature=dict(by_signature),  # pyright: ignore[reportCallIssue]
            by_caller={name: set(addrs) for name, addrs in by_caller.items()},  # pyright: ignore[reportCallIssue]
            by_callee={name: set(addrs) for name, addrs in by_callee.items()},  # pyright: ignore[reportCallIssue]
        )
        self._MATCH_INDEX_CACHE[cache_key] = index
        return index, False

    def _normalize_min_similarity(self, args: dict[str, Any]) -> float:
        """Return minSimilarity in 0.0–1.0 (accepts 0–100 or 0–1)."""
        raw = self._get_str(args, "minsimilarity", "similaritythreshold", default="")
        if not raw:
            return 0.7
        try:
            v = float(raw)
            return min(1.0, max(0.0, v / 100.0 if v > 1 else v))
        except (ValueError, TypeError):
            return 0.7

    def _discover_target_paths(self, source_path: str) -> list[str]:
        """Discover target program paths from session (list-project-files style); exclude source; filter to common binaries."""
        session_id = get_current_mcp_session_id()
        binaries = SESSION_CONTEXTS.get_project_binaries(session_id, fallback_to_latest=True)
        source_norm = (source_path or "").strip().lower().replace("\\", "/")
        binary_extensions = (".exe", ".dll", ".so", ".dylib")
        paths: list[str] = []
        for item in binaries:
            if not isinstance(item, dict):
                continue
            if str(item.get("type") or "").strip() == "Folder":
                continue
            path = (item.get("path") or item.get("name") or "").strip().replace("\\", "/")
            if not path or path.lower() == source_norm:
                continue
            if not any(path.lower().endswith(ext) for ext in binary_extensions):
                continue
            paths.append(path)
        return paths

    def _list_source_function_identifiers(
        self,
        program: Any,
        include_externals: bool = True,
        limit: int | None = None,
    ) -> list[str]:
        """List function identifiers (name or address) from source program for bulk match."""
        fm = self._get_function_manager(program)
        identifiers: list[str] = []
        for func in fm.getFunctions(include_externals):
            name = func.getName() or ""
            addr = str(func.getEntryPoint())
            if name and not (name.startswith("FUN_") and len(name) > 4 and name[4:].replace(".", "").isdigit()):
                ident = name
            else:
                ident = addr
            if ident:
                identifiers.append(ident)
            if limit is not None and len(identifiers) >= limit:
                break
        return identifiers

    async def _handle_match_cross_program(
        self,
        source_func: Any,
        source_program: Any,
        target_paths: list[str],
        min_similarity: float,
        propagate_names: bool,
        propagate_tags: bool,
        propagate_comments: bool,
        propagate_prototype: bool = False,
        propagate_bookmarks: bool = False,
    ) -> list[types.TextContent]:
        """Match source function to equivalent functions in target programs; optionally propagate name, tags, comments, prototype, bookmarks."""
        session_id = get_current_mcp_session_id()
        manager = getattr(self, "_manager", None)
        if manager is None:
            raise ValueError("Cross-program matching requires a session with program resolution. Ensure open-project or import-binary has been used so target programs can be opened.")

        source_name = source_func.getName()
        source_param_count = source_func.getParameterCount()
        source_return_type = str(source_func.getReturnType())
        source_sig = str(source_func.getSignature())
        sig_key = (source_param_count, source_return_type)

        results_per_target: list[dict[str, Any]] = []
        errors: list[str] = []

        for target_path in target_paths:
            target_path = str(target_path).strip()
            if not target_path:
                continue
            try:
                target_info = await manager.get_or_open_program(session_id, target_path)
            except Exception as e:
                errors.append(f"{target_path}: {e}")
                results_per_target.append({"targetProgramPath": target_path, "matched": None, "error": str(e)})
                continue
            if target_info is None:
                errors.append(f"{target_path}: could not open program")
                results_per_target.append({"targetProgramPath": target_path, "matched": None, "error": "Could not open program"})
                continue

            target_program = target_info.program
            domain_file = target_program.getDomainFile()
            is_versioned = domain_file.isVersioned() if domain_file else False
            we_did_checkout = False
            did_propagate = False
            if is_versioned and domain_file is not None and not domain_file.isCheckedOut():
                try:
                    from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingModuleSource]

                    domain_file.checkout(False, TaskMonitor.DUMMY)
                    we_did_checkout = True
                except Exception as e:
                    errors.append(f"{target_path}: checkout failed: {e}")
                    results_per_target.append({"targetProgramPath": target_path, "matched": None, "error": f"Checkout failed: {e}"})
                    continue

            target_fm = self._get_function_manager(target_program)
            target_index, _ = self._get_match_index(target_program, target_fm)

            candidates = target_index.by_signature.get(sig_key, [])
            best_feature: _FunctionMatchFeature | None = None
            best_score = 0.0
            for feat in candidates:
                # Name match = 1.0; same signature (param_count, return_type) but different name = 0.7
                score = 1.0 if feat.name == source_name else 0.7
                if score >= min_similarity and score > best_score:
                    best_score = score
                    best_feature = feat

            if best_feature is None:
                results_per_target.append(
                    {
                        "targetProgramPath": target_path,
                        "matched": None,
                        "candidatesBySignature": len(candidates),
                        "message": "No match meeting minSimilarity",
                    },
                )
                if is_versioned and domain_file is not None and we_did_checkout:
                    try:
                        from ghidra.framework.data import CheckinHandler  # pyright: ignore[reportMissingModuleSource]
                        from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingModuleSource]

                        class _MatchCheckinHandler(CheckinHandler):  # type: ignore[misc]
                            def getComment(self) -> str:  # noqa: N802
                                return "Auto match-function propagation"

                            def keepCheckedOut(self) -> bool:  # noqa: N802
                                return False

                            def createKeepFile(self) -> bool:  # noqa: N802
                                return False

                        domain_file.checkin(_MatchCheckinHandler(), TaskMonitor.DUMMY)
                    except Exception as e:
                        logger.warning("Checkin after no-match (target %s) failed: %s", target_path, e)
                continue

            target_func = best_feature.function
            entry: dict[str, Any] = {
                "targetProgramPath": target_path,
                "matched": {
                    "name": best_feature.name,
                    "address": best_feature.address,
                    "signature": best_feature.signature,
                    "similarityScore": best_score,
                },
                "propagated": [],
            }

            if propagate_names and best_feature.name != source_name:

                def _rename() -> None:
                    from ghidra.program.model.symbol import SourceType  # pyright: ignore[reportMissingModuleSource]

                    target_func.setName(source_name, SourceType.USER_DEFINED)

                self._run_program_transaction(target_program, "match-function-rename", _rename)
                entry["propagated"].append("name")
                did_propagate = True

            if propagate_prototype:
                target_sig = str(target_func.getSignature())
                if source_sig != target_sig:
                    try:

                        def _set_proto() -> None:
                            target_func.setSignature(source_sig)

                        self._run_program_transaction(target_program, "match-function-prototype", _set_proto)
                        entry["propagated"].append("prototype")
                        did_propagate = True
                    except Exception as e:
                        logger.debug("Propagate prototype skipped for %s: %s", target_path, e)

            if propagate_tags:
                source_tags = [t.getName() for t in source_func.getTags()]
                existing = {t.getName() for t in target_func.getTags()}
                to_add = [t for t in source_tags if t not in existing]
                if to_add:

                    def _add_tags() -> None:
                        for tag in to_add:
                            target_func.addTag(tag)

                    self._run_program_transaction(target_program, "match-function-tags", _add_tags)
                    entry["propagated"].extend(to_add)
                    did_propagate = True

            if propagate_comments:
                try:
                    from ghidra.program.model.listing import CodeUnit  # pyright: ignore[reportMissingModuleSource]

                    source_listing = source_program.getListing()
                    target_listing = target_program.getListing()
                    source_entry = source_func.getEntryPoint()
                    target_entry = target_func.getEntryPoint()
                    comment_types = (
                        CodeUnit.PLATE_COMMENT,
                        CodeUnit.PRE_COMMENT,
                        CodeUnit.POST_COMMENT,
                        CodeUnit.EOL_COMMENT,
                        CodeUnit.REPEATABLE_COMMENT,
                    )
                    for ctype in comment_types:
                        try:
                            comment = source_listing.getComment(ctype, source_entry)
                            if comment and str(comment).strip():
                                _comment = comment

                                def _set_comment() -> None:
                                    target_listing.setComment(target_entry, ctype, _comment)

                                self._run_program_transaction(target_program, "match-function-comment", _set_comment)
                                entry["propagated"].append("comment")
                                did_propagate = True
                        except Exception:
                            continue
                except Exception as e:
                    logger.debug("Propagate comments skipped: %s", e)

            if propagate_bookmarks:
                try:
                    source_bm_mgr = source_program.getBookmarkManager()
                    source_entry = source_func.getEntryPoint()
                    target_entry = target_func.getEntryPoint()
                    source_bms = list(source_bm_mgr.getBookmarks(source_entry)) if hasattr(source_bm_mgr, "getBookmarks") else []
                    if not source_bms and hasattr(source_bm_mgr, "getBookmarksIterator"):
                        for bm in source_bm_mgr.getBookmarksIterator():
                            if bm.getAddress().equals(source_entry):
                                source_bms.append(bm)
                    bm_data = [(bm.getTypeString(), bm.getCategory(), bm.getComment() or "") for bm in source_bms]
                    if bm_data:

                        def _set_bookmarks() -> None:
                            tgt_mgr = target_program.getBookmarkManager()
                            for bm_type, bm_cat, bm_comment in bm_data:
                                tgt_mgr.setBookmark(target_entry, bm_type, bm_cat, bm_comment)

                        self._run_program_transaction(target_program, "match-function-bookmarks", _set_bookmarks)
                        entry["propagated"].append("bookmarks")
                        did_propagate = True
                except Exception as e:
                    logger.debug("Propagate bookmarks skipped: %s", e)

            # Enrich with get-function output for contextual details (same shape as get-function tool)
            manager = getattr(self, "_manager", None)
            if manager is not None and entry.get("matched"):
                matched_info = entry["matched"]
                gf_name = (matched_info.get("name") or matched_info.get("address") or "").strip()
                if gf_name:
                    try:
                        gf_resp = await manager.call_tool(
                            "get-function",
                            {
                                "programPath": target_path,
                                "function": gf_name,
                                "format": "json",
                            },
                        )
                        if gf_resp and isinstance(gf_resp[0], types.TextContent) and gf_resp[0].text:
                            parsed = json.loads(gf_resp[0].text)
                            if isinstance(parsed, dict):
                                entry["functionDetails"] = parsed
                    except Exception as e:
                        logger.debug("get-function enrichment for %s in %s: %s", gf_name, target_path, e)

            results_per_target.append(entry)

            if is_versioned and domain_file is not None and (we_did_checkout or did_propagate):
                try:
                    from ghidra.framework.data import CheckinHandler  # pyright: ignore[reportMissingModuleSource]
                    from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingModuleSource]

                    keep_out = not we_did_checkout and did_propagate

                    class _MatchCheckinHandler(CheckinHandler):  # type: ignore[misc]
                        def getComment(self) -> str:  # noqa: N802
                            return "Auto match-function propagation"

                        def keepCheckedOut(self) -> bool:  # noqa: N802
                            return keep_out

                        def createKeepFile(self) -> bool:  # noqa: N802
                            return False

                    domain_file.checkin(_MatchCheckinHandler(), TaskMonitor.DUMMY)
                except Exception as e:
                    logger.warning("Checkin after propagation (target %s) failed: %s", target_path, e)

        return create_success_response(
            {
                "mode": "cross-program",
                "sourceFunction": source_name,
                "sourceSignature": source_sig,
                "targetProgramPaths": target_paths,
                "minSimilarity": min_similarity,
                "results": results_per_target,
                "count": len(results_per_target),
                "errors": errors or None,
            },
        )

    async def _handle_match(self, args: dict[str, Any]) -> list[types.TextContent]:
        """Entry for match-function: cross-program (targetProgramPaths set) or single-program (similar/callers/callees/signature)."""
        self._require_program()
        raw_targets = args.get(n("targetprogrampaths"))
        target_paths: list[str] = []
        if raw_targets is not None:
            if isinstance(raw_targets, list):
                target_paths = [str(x).strip() for x in raw_targets if x and str(x).strip()]
            elif str(raw_targets).strip():
                target_paths = [str(raw_targets).strip()]
        # Cross-program: single function or all functions (when no functionIdentifier given)
        assert self.program_info is not None
        program = self.program_info.program
        source_path = (
            self._get_str(args, "programpath", "programpath", default="")
            or getattr(self.program_info, "file_path", None)
            or getattr(self.program_info, "path", None)
            or ""
        )
        source_path = str(source_path).strip() if source_path else ""
        # Resolve targets: from args or discover from session (so bulk works without targetProgramPaths)
        resolved_targets = target_paths if target_paths else self._discover_target_paths(source_path or "unknown")

        if resolved_targets:
            func_id = self._get_address_or_symbol(args)
            if func_id:
                # Single function: existing behavior
                func = self._resolve_function(func_id)
                if func is None:
                    raise ValueError(f"Function not found: {func_id}")
                min_sim = self._normalize_min_similarity(args)
                propagate_names = self._get_bool(args, "propagatenames", "propagatename", default=False)
                propagate_tags = self._get_bool(args, "propagatetags", "propagatetag", default=False)
                propagate_comments = self._get_bool(args, "propagatecomments", "propagatecomment", default=False)
                propagate_prototype = self._get_bool(args, "propagateprototype", "propagatesignature", default=False)
                propagate_bookmarks = self._get_bool(args, "propagatebookmarks", default=False)
                return await self._handle_match_cross_program(
                    func,
                    program,
                    resolved_targets,
                    min_sim,
                    propagate_names,
                    propagate_tags,
                    propagate_comments,
                    propagate_prototype,
                    propagate_bookmarks,
                )

            # No functionIdentifier: iterate all functions (bulk migration)
            targets = resolved_targets
            include_externals = self._get_bool(args, "includeexternals", "includeexternals", default=True)
            limit = self._get_int(args, "limit", "maxfunctions", "maxcount", default=None)
            # Treat limit<=0 as no limit (process all functions)
            if limit is not None and limit <= 0:
                limit = None
            identifiers = self._list_source_function_identifiers(program, include_externals, limit)
            logger.info(
                "match-function bulk: source_path=%s target_count=%d identifier_count=%d limit=%s",
                source_path,
                len(targets),
                len(identifiers),
                limit,
            )
            if not identifiers:
                return create_success_response(
                    {
                        "mode": "cross-program-bulk",
                        "sourceProgramPath": source_path,
                        "targetProgramPaths": targets,
                        "processedCount": 0,
                        "resultsByFunction": [],
                        "summary": {"processed": 0, "errors": 0, "matchesPerTarget": {t: 0 for t in targets}},
                    },
                )
            min_sim = self._normalize_min_similarity(args)
            propagate_names = self._get_bool(args, "propagatenames", "propagatename", default=True)
            propagate_tags = self._get_bool(args, "propagatetags", "propagatetag", default=True)
            propagate_comments = self._get_bool(args, "propagatecomments", "propagatecomment", default=True)
            propagate_prototype = self._get_bool(args, "propagateprototype", "propagatesignature", default=True)
            propagate_bookmarks = self._get_bool(args, "propagatebookmarks", default=True)
            results_by_function: list[dict[str, Any]] = []
            errors_count = 0
            matches_per_target: dict[str, int] = {t: 0 for t in targets}
            progress_interval = 1000
            for idx, ident in enumerate(identifiers):
                if progress_interval and (idx + 1) % progress_interval == 0:
                    logger.info("match-function bulk progress: %d/%d", idx + 1, len(identifiers))
                func = self._resolve_function(ident)
                if func is None:
                    continue
                try:
                    one_resp = await self._handle_match_cross_program(
                        func,
                        program,
                        targets,
                        min_sim,
                        propagate_names,
                        propagate_tags,
                        propagate_comments,
                        propagate_prototype,
                        propagate_bookmarks,
                    )
                except Exception as e:
                    errors_count += 1
                    logger.debug("match-function bulk %s: %s", ident, e)
                    results_by_function.append(
                        {
                            "sourceFunction": ident,
                            "error": str(e),
                            "results": [],
                        },
                    )
                    continue
                if not one_resp or not isinstance(one_resp[0], types.TextContent):
                    continue
                try:
                    data = json.loads(one_resp[0].text)
                except (json.JSONDecodeError, TypeError):
                    continue
                one_results = data.get("results") or []
                one_errors = data.get("errors") or []
                if one_errors:
                    errors_count += len(one_errors)
                for entry in one_results:
                    tpath = (entry.get("targetProgramPath") or "").strip()
                    if entry.get("matched") is not None and tpath:
                        matches_per_target[tpath] = matches_per_target.get(tpath, 0) + 1
                results_by_function.append(
                    {
                        "sourceFunction": data.get("sourceFunction") or ident,
                        "results": one_results,
                        "errors": one_errors or None,
                    },
                )
            return create_success_response(
                {
                    "mode": "cross-program-bulk",
                    "sourceProgramPath": source_path,
                    "targetProgramPaths": targets,
                    "processedCount": len(results_by_function),
                    "resultsByFunction": results_by_function,
                    "summary": {
                        "processed": len(results_by_function),
                        "errors": errors_count,
                        "matchesPerTarget": matches_per_target,
                    },
                },
            )
        # No targets: bulk was intended but session has no other binaries (or targetProgramPaths not passed)
        func_id_any = self._get_address_or_symbol(args)
        if not func_id_any and source_path:
            raise ValueError(
                "No target programs found for bulk migration. Open a project with multiple binaries, "
                "or pass targetProgramPaths (e.g. CLI: --target-paths /path/to/other.exe). "
                "For single-function match, pass function or addressOrSymbol."
            )
        # Single-program: similar (rank by signature + call graph), callers, callees, or signature-only
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
            similar = [{"name": feature.name, "address": feature.address, "signature": feature.signature} for feature in candidates[:max_results]]
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
