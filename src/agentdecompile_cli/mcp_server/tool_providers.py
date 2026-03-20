"""Base ToolProvider with centralized normalization, dispatch, and manager.

ALL normalization happens HERE, in ONE place.  The single canonical function
is ``n()`` (alias for ``registry.normalize_identifier``).  It strips everything
except lowercase ASCII letters: ``re.sub(r'[^a-z]', '', s.lower())``.

Flow:
  1. MCP Server → ToolProviderManager.call_tool(name, arguments)
  2. Manager normalizes ``name`` → looks up the owning ToolProvider
  3. Provider.call_tool() normalizes ALL argument keys, dispatches to handler.
  4. Handler uses ``self._get(args, ...)`` helpers on already-normalized dicts.

Consolidation Helpers (Phase 2b):
  - ``_dispatch_handler(dispatch, action, action_name)`` – Unified handler dispatch with error handling
    Replaces 3-4 lines of boilerplate per provider method (used in comments, structures, datatypes, symbols)
  - ``_paginate_results(all_results, offset, limit)`` – Slicing + hasMore calculation
    Replaces 2-3 lines of duplication per pagination method (used in xrefs, strings)
  - Together eliminate ~20+ lines of repeated code while improving consistency
"""

from __future__ import annotations

import json as _json
import logging
import multiprocessing
import os
import re
import time

from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from mcp import types

from agentdecompile_cli.launcher import ProgramInfo
from agentdecompile_cli.mcp_server.response_formatter import render_tool_response
from agentdecompile_cli.mcp_server.session_context import (
    SESSION_CONTEXTS,
    get_current_mcp_session_id,
    get_current_request_auto_match_propagate,
    get_current_request_auto_match_target_paths,
)
from agentdecompile_cli.registry import (
    ADVERTISED_TOOLS,
    ADVERTISED_TOOL_PARAMS,
    TOOL_ALIASES,
    TOOL_PARAM_ALIASES,
    Tool,
    is_tool_advertised,
    normalize_identifier,
    resolve_tool_name,
    to_snake_case,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from agentdecompile_cli.registry import (
        Tool,
    )

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default limits and constants
# ---------------------------------------------------------------------------

DEFAULT_PAGE_LIMIT = 100
DEFAULT_LARGE_PAGE_LIMIT = 1000
DEFAULT_MAX_INSTRUCTIONS = 2000000
DEFAULT_SAMPLES_PER_CONSTANT = 5
DEFAULT_MAX_ENTRIES = 200
DEFAULT_TIMEOUT_SECONDS = 60

# Auto match-function propagation (env-driven). When the user renames/sets prototype/tags/comments
# on a function, we can optionally run match-function to other binaries; args must not be re-entered.
AUTO_MATCH_INVOCATION_KEY = "automatchinvocation"
_ENV_AUTO_MATCH_PROPAGATE = "AGENTDECOMPILE_AUTO_MATCH_PROPAGATE"
_ENV_AUTO_MATCH_TARGET_PATHS = "AGENTDECOMPILE_AUTO_MATCH_TARGET_PATHS"
# Map normalized tool name → set of modes that trigger auto-match (e.g. managefunction + rename)
_AUTO_MATCH_TRIGGER_MODES: dict[str, frozenset[str]] = {
    "managefunction": frozenset({"rename", "setprototype", "setreturntype", "callingconvention", "setcallingconvention"}),
    "managecomments": frozenset({"set", "post", "eol", "pre", "plate", "repeatable"}),
    "managefunctiontags": frozenset({"add", "remove", "set"}),
}

# ProcessPoolExecutor for auto match-function (child process, does not block main). Spawn context so child gets fresh interpreter (no JVM fork).
_AUTO_MATCH_EXECUTOR: ProcessPoolExecutor | None = None


def _get_auto_match_executor() -> ProcessPoolExecutor:
    """Create or return the ProcessPoolExecutor for auto-match (spawn, max_workers=cpu count)."""
    global _AUTO_MATCH_EXECUTOR
    if _AUTO_MATCH_EXECUTOR is None:
        ctx = multiprocessing.get_context("spawn")
        cpu_count = multiprocessing.cpu_count()
        _AUTO_MATCH_EXECUTOR = ProcessPoolExecutor(max_workers=cpu_count, mp_context=ctx)
    return _AUTO_MATCH_EXECUTOR


# ---------------------------------------------------------------------------
# Canonical normalize – ``re.sub(r'[^a-z]', '', s.lower())``.
# Imported from registry.py.  Everything else imports from HERE.
# ---------------------------------------------------------------------------
n = normalize_identifier  # short alias used throughout providers


# ---------------------------------------------------------------------------
# Tool recommendation helpers
# ---------------------------------------------------------------------------


def recommend_tool(tool_name: str, fallback: str | None = None) -> str:
    """Return an advertised tool name, optionally falling back to another tool."""
    if is_tool_advertised(tool_name):
        return tool_name
    if fallback and is_tool_advertised(fallback):
        return fallback
    return ""


def filter_recommendations(steps: list[str]) -> list[str]:
    """Remove recommendation lines that reference disabled tools in backticks."""
    filtered: list[str] = []
    for step in steps:
        tools = re.findall(r"`([a-zA-Z0-9_-]+)`", step)
        if all(is_tool_advertised(tool) for tool in tools):
            filtered.append(step)
    return filtered


# ---------------------------------------------------------------------------
# Parameter type inference for advertised schemas
# ---------------------------------------------------------------------------

# Normalized param-name fragments → JSON schema type.
# Used when a TOOL_PARAMS entry doesn't match any provider property.
_INT_FRAGMENTS = frozenset(
    {
        "batchsize",
        "bottomlayers",
        "callers",
        "condensethreshold",
        "count",
        "depth",
        "entries",
        "height",
        "index",
        "length",
        "limit",
        "linenumber",
        "max",
        "maxcallers",
        "maxcount",
        "maxdepth",
        "maxentries",
        "maxfunctions",
        "maxinstructions",
        "maxreferencers",
        "maxresults",
        "maxruntime",
        "maxvalue",
        "min",
        "minreferencecount",
        "minsimilarity",
        "minvalue",
        "offset",
        "propagatemaxcandidates",
        "propagatemaxinstructions",
        "referencecount",
        "results",
        "serverport",
        "size",
        "startindex",
        "toplayers",
        "topn",
        "value",
        "width",
    },
)
_BOOL_FRAGMENTS = frozenset(
    {
        "analyzeafterimport",
        "casesensitive",
        "clearexisting",
        "createifnotexists",
        "demangleall",
        "enableversioncontrol",
        "exclusive",
        "filterdefaultnames",
        "force",
        "groupbylibrary",
        "hastags",
        "include",
        "includebuiltin",
        "includecallcontext",
        "includecallees",
        "includecallers",
        "includecomments",
        "includedatarefs",
        "includeexternal",
        "includeincomingreferences",
        "includeparameters",
        "includerefcontext",
        "includereferencecontext",
        "includereferencingfunctions",
        "includerefs",
        "includesmallvalues",
        "includesubcategories",
        "includevariables",
        "keepcheckedout",
        "mirrorfs",
        "openallprograms",
        "overridemaxfunctionslimit",
        "packed",
        "propagate",
        "propagatecomments",
        "propagatenames",
        "propagatetags",
        "recursive",
        "removeall",
        "setasprimary",
        "stripallcontainerpath",
        "stripleadingpath",
        "untagged",
        "verbose",
    },
)

# Boolean prefix patterns (used for efficient startswith checking in _infer_param_schema)
# This constant consolidates the hardcoded tuple that was previously in _infer_param_schema(),
# enabling reuse and documentation of the boolean naming convention. Parameters starting with
# these prefixes are inferred to be booleans, unless they appear in _BOOL_PREFIX_EXCEPTIONS.
# Optimization: By defining at module level rather than function scope, we enable:
#   1. Documentation of the inference strategy
#   2. Reuse in other schema-related functions (if needed)
#   3. Single reference point for schema design decisions
_BOOL_PREFIXES = (
    "enable",
    "filter",
    "include",
    "mirror",
    "override",
    "propagate",
    "strip",
)

# Params that look like booleans by prefix but are actually strings/arrays.
_BOOL_PREFIX_EXCEPTIONS = frozenset(
    {
        "filterbytag",  # tag name string, not a boolean
    },
)
# Params that should be arrays, not strings.
_ARRAY_PARAMS = frozenset(
    {
        "functionaddresses",
        "identifiers",
        "propagateprogrampaths",
        "tags",
    },
)

_SELECTOR_PARAM_ALIASES = frozenset(
    {
        "action",
        "actiontype",
        "command",
        "intent",
        "method",
        "mode",
        "op",
        "operation",
        "task",
        "type",
        "verb",
    },
)


def _infer_param_schema(param_name: str) -> dict[str, Any]:
    """Infer JSON schema type from a parameter name.

    Uses common naming patterns to guess integer vs boolean vs string.
    This is the fallback when a parameter from TOOL_PARAMS doesn't match
    any property in the provider's input schema.
    """
    norm = n(param_name)
    if norm in _ARRAY_PARAMS:
        return {"type": "array", "items": {"type": "string"}}
    if norm in _INT_FRAGMENTS:
        return {"type": "integer"}
    if norm in _BOOL_FRAGMENTS:
        return {"type": "boolean"}
    if norm in _BOOL_PREFIX_EXCEPTIONS:
        return {"type": "string"}
    # Check prefixes for booleans
    for prefix in _BOOL_PREFIXES:
        if norm.startswith(prefix) and len(norm) > len(prefix) and norm not in _BOOL_PREFIX_EXCEPTIONS:
            return {"type": "boolean"}
    return {"type": "string"}


# ---------------------------------------------------------------------------
# Response helpers (canonical location)
# ---------------------------------------------------------------------------


def create_success_response(data: dict[str, Any]) -> list[types.TextContent]:
    """Create a standardized MCP success response."""
    return [types.TextContent(type="text", text=_json.dumps(data))]


class ActionableError(Exception):
    """Structured error that carries state context and explicit next steps for resolution.

    Use this instead of generic exceptions when you want to help users fix the problem.
    The MCP response layer automatically includes context and next_steps in the error
    response, along with auto-inferred guidance from error message patterns.

    **When to use ActionableError:**
    - No program loaded (user needs to call `import-binary` for local binaries, or `open-project` for project/shared contexts)
    - Authentication failed (user should verify credentials)
    - Invalid path (user should check if file exists)
    - Required parameter missing (user should include the param)
    - Ghidra operation timeout (user might retry with longer timeout)

    **Example:**
        ```python
        if not program:
            raise ActionableError(
                "No program loaded",
                context={"state": "no-active-program"},
                next_steps=[
                    "Call `import-binary` with `path` for a local binary, or `open-project` for a `.gpr` project/shared server session.",
                    "Then retry the current tool.",
                ],
            )
        ```

    **Response Format:**
    When caught by the MCP dispatcher, becomes:
        ```json
        {
            "success": false,
            "error": "No program loaded",
            "context": {"state": "no-active-program"},
            "nextSteps": ["Call `import-binary` for binaries or `open-project` for project/shared contexts...", "Then retry..."],
            "state": "no-active-program"  (context keys flattened into response)
        }
        ```

    Args:
        message: Error message shown to user
        context: Optional dict of state/contextinfo (e.g., {"state": "no-program"})
        next_steps: Optional list of suggested next actions
    """

    def __init__(
        self,
        message: str,
        *,
        context: dict[str, Any] | None = None,
        next_steps: list[str] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.context = context or {}
        self.next_steps = next_steps or []


def _merge_context(
    base: dict[str, Any] | None,
    extra: dict[str, Any] | None,
) -> dict[str, Any] | None:
    merged: dict[str, Any] = {}
    if isinstance(base, dict):
        merged.update(base)
    if isinstance(extra, dict):
        merged.update(extra)
    return merged or None


def _merge_steps(base: list[str] | None, extra: list[str] | None) -> list[str] | None:
    """Merge base and extra recommendation steps, deduplicated and trimmed; return None if empty."""
    seen: set[str] = set()
    merged: list[str] = []
    for step in base or []:
        normalized = str(step).strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        merged.append(normalized)
    for step in extra or []:
        normalized = str(step).strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        merged.append(normalized)
    return merged or None


def _default_error_guidance(msg: str) -> tuple[dict[str, Any] | None, list[str] | None]:
    """Map common error phrases to (context dict, recommended next steps). Used by create_error_response."""
    lowered = msg.lower()

    if "unknown tool" in lowered:
        return (
            {"state": "unknown-tool"},
            [
                "Call `list_tools` to discover the canonical tool name.",
                "Retry with the canonical tool name in snake_case.",
            ],
        )

    if "required parameter missing" in lowered:
        match = re.search(r"required parameter missing(?: or empty)?:\s*(.+)$", msg, flags=re.IGNORECASE)
        param_name = match.group(1).strip() if match else None
        context: dict[str, Any] = {"state": "missing-required-parameter"}
        if param_name:
            context["missingParameter"] = param_name
        return (
            context,
            [
                "Read the tool input schema and include all required parameters.",
                "Retry with the missing value populated.",
            ],
        )

    if "no program loaded" in lowered or "ghidra tools unavailable" in lowered:
        return (
            {"state": "no-active-program"},
            filter_recommendations(
                [
                    "Call `import-binary` with `path` for a local binary, or `open-project` with a `.gpr` path/shared server args (`serverHost`, `serverPort`, `serverUsername`, `serverPassword`).",
                    "Then call `get-current-program` to verify an active program is loaded.",
                ],
            ),
        )

    if "authentication failed" in lowered:
        return (
            {"state": "authentication-failed"},
            filter_recommendations(
                [
                    "Verify `serverUsername`/`serverPassword` and retry `open-project`.",
                    "If credentials are correct, verify the Ghidra server is running and reachable on `serverHost:serverPort`.",
                ],
            ),
        )

    if "not connected to repository server" in lowered or "shared-server" in lowered:
        manage_files_tool = recommend_tool(Tool.MANAGE_FILES.value, Tool.LIST_PROJECT_FILES.value)
        steps = [
            "Call `open-project` first with shared-server parameters to establish a repository session.",
        ]
        if manage_files_tool:
            steps.append(f"Then call `list-project-files` or `{manage_files_tool}` `mode=list` to verify repository visibility.")
        else:
            steps.append("Then call `list-project-files` to verify repository visibility.")
        return (
            {"state": "shared-session-unavailable"},
            filter_recommendations(steps),
        )

    if "path does not exist" in lowered or "path not found" in lowered or "invalid folder path" in lowered:
        manage_files_tool = recommend_tool(Tool.MANAGE_FILES.value)
        if manage_files_tool:
            steps = [
                f"Call `{manage_files_tool}` with `mode=list` on the parent folder to discover the correct path.",
                "Retry with an absolute path visible to the backend runtime.",
            ]
        else:
            steps = [
                "Verify the path exists in the backend filesystem.",
                "Retry with an absolute path visible to the backend runtime.",
            ]
        return (
            {"state": "path-not-found"},
            filter_recommendations(steps),
        )

    if "not a readable file" in lowered or "is not a directory" in lowered:
        manage_files_tool = recommend_tool(Tool.MANAGE_FILES.value)
        if manage_files_tool:
            steps = [
                f"Call `{manage_files_tool}` `mode=info` on the same path to verify file vs directory.",
                "Use `mode=read` for files and `mode=list` for directories.",
            ]
        else:
            steps = [
                "Verify whether the path is a file or directory.",
                "Retry with the correct path type.",
            ]
        return (
            {"state": "path-type-mismatch"},
            filter_recommendations(steps),
        )

    if "provided but could not be resolved/opened" in lowered:
        return (
            {"state": "program-resolution-failed"},
            filter_recommendations(
                [
                    "Call `list-project-files` to locate the exact program path in the active project/session.",
                    "If this is a local binary, call `import-binary` first. Otherwise, ensure `open-project` is already connected to the correct project/repository session, then retry analysis tools.",
                ],
            ),
        )

    return None, None


def create_error_response(
    error: str | Exception,
    *,
    context: dict[str, Any] | None = None,
    next_steps: list[str] | None = None,
) -> list[types.TextContent]:
    """Create a standardized MCP error response with optional actionable metadata."""
    if isinstance(error, ActionableError):
        msg = error.message
        context = _merge_context(error.context, context)
        next_steps = _merge_steps(error.next_steps, next_steps)
    else:
        msg = str(error) if isinstance(error, Exception) else str(error)

    inferred_context, inferred_steps = _default_error_guidance(msg)
    context = _merge_context(inferred_context, context)
    next_steps = _merge_steps(inferred_steps, next_steps)

    payload: dict[str, Any] = {"success": False, "error": msg}
    if context:
        payload["context"] = context
        for key, value in context.items():
            if key in payload:
                continue
            if isinstance(value, (str, int, float, bool, type(None))):
                payload[key] = value
    if next_steps:
        payload["nextSteps"] = next_steps
    return [types.TextContent(type="text", text=_json.dumps(payload))]


# ---------------------------------------------------------------------------
# Value coercion helpers
# ---------------------------------------------------------------------------

_TRUTHY = frozenset({"true", "1", "yes", "on", "enabled"})


def _coerce_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in _TRUTHY
    if isinstance(v, (int, float)):
        return bool(v)
    return bool(v)


def _coerce_int(v: Any, default: int = 0) -> int:
    if isinstance(v, int):
        return v
    try:
        return int(v)
    except (ValueError, TypeError):
        return default


def _coerce_list(v: Any) -> list:
    """Coerce to list.  Handles: list, tuple, comma-separated string, scalar."""
    if isinstance(v, list):
        return v
    if isinstance(v, tuple):
        return list(v)
    if isinstance(v, str) and "," in v:
        return [s.strip() for s in v.split(",") if s.strip()]
    return [v]


# ---------------------------------------------------------------------------
# Base ToolProvider
# ---------------------------------------------------------------------------


class ToolProvider:
    """Base class for MCP tool providers with centralized normalization.

    Subclasses populate **HANDLERS**: ``{normalized_tool_name: "method_name"}``.

    **HANDLERS Pattern:**
        ``HANDLERS`` is a dict mapping normalized (lowercase a-z) tool names to
        handler method names (as strings). The base class dispatch in ``call_tool()``
        automatically routes tool invocations to the appropriate method.

        Example::

            class MyToolProvider(ToolProvider):
                HANDLERS = {
                    'mytool': '_handle_my_tool',
                    'anotherone': '_handle_another',
                }

                async def _handle_my_tool(self, args: dict[str, Any]) -> list[TextContent]:
                    # args dict keys are already normalized (lowercase a-z)
                    mode = self._get_str(args, 'mode', 'action', default='list')
                    return create_success_response({...})

    **Normalization Contract:**
        1. All tool names and argument keys are normalized via ``n()`` (alias for
           ``registry.normalize_identifier()``): ``re.sub(r'[^a-z]', '', s.lower())``.
           This strips everything except lowercase letters, making matching case/punct-insensitive.
        2. Handlers NEVER receive raw keys; the base class normalizes ALL keys before dispatch.
        3. Handlers use the helper methods ``_get*()`` which handle alias lookup
           on already-normalized dicts.

    **call_tool() Flow:**
        1. Normalize tool name via ``resolve_tool_name()`` in registry.
        2. Find the handler method in HANDLERS dict.
        3. Normalize ALL argument keys (recursively for nested dicts).
        4. Dispatch to handler method.
        5. Wrap any exception as an error response with context and guidance.

    See ``dispatch_tool()`` and ``call_tool()`` for implementation details.
    """

    HANDLERS: ClassVar[dict[str, str]] = {}
    """Mapping from normalized tool name (a-z only) to handler method name.
    
    Example: {'mytool': '_handle', 'anothertool': '_handle'} means
    call self._handle when either 'mytool', 'my-tool', 'MY_TOOL', etc. is invoked.
    """

    def __init__(self, program_info: ProgramInfo | None = None) -> None:
        self.program_info: ProgramInfo | None = program_info
        self.ghidra_tools: Any | None = None
        self._manager: ToolProviderManager | None = None  # set by manager._register
        if program_info is not None:
            self._init_ghidra_tools()

    def _init_ghidra_tools(self) -> None:
        try:
            if self.program_info is None:
                raise ValueError("Program info is required to initialize Ghidra tools")
            from agentdecompile_cli.tools.wrappers import GhidraTools

            self.ghidra_tools = GhidraTools(self.program_info)
        except Exception:
            self.ghidra_tools = None

    def set_program_info(self, program_info: ProgramInfo) -> None:
        self.program_info = program_info
        self._init_ghidra_tools()

    def list_tools(self) -> list[types.Tool]:
        return []

    # ------------------------------------------------------------------
    # Dispatch – the ONLY normalization site
    # ------------------------------------------------------------------

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
    ) -> list[types.TextContent]:
        """Normalize name + args, dispatch to handler, catch errors."""
        norm_name: str = n(name)
        handler_method_name: str | None = self.HANDLERS.get(norm_name)
        if handler_method_name is None:
            resolved_name = resolve_tool_name(name) or name
            norm_name = n(resolved_name)
            handler_method_name = self.HANDLERS.get(norm_name)
            if handler_method_name is not None:
                logger.debug("tool name resolved: %s -> %s", name, resolved_name)
        if handler_method_name is None:
            logger.warning("unknown tool requested: %s", name)
            raise NotImplementedError(f"Unknown tool: {name}")

        canonical_tool = resolve_tool_name(name) or name
        logger.info("tool=%s provider=%s", canonical_tool, self.__class__.__name__)

        handler: Callable[[dict[str, Any]], Awaitable[list[types.TextContent]]] = getattr(self, handler_method_name)

        # Normalize ALL argument keys here – the single place normalization happens so handlers
        # always see lowercase a-z keys (e.g. programpath, function, mode).
        norm_args: dict[str, Any] = {n(k): v for k, v in (arguments or {}).items()}
        auto_prereq_invocation: bool = self._get_bool(norm_args, "autoprereqinvocation", default=False)

        # Apply tool-specific parameter aliases: if the client sent a synonym (e.g. "action"
        # instead of "mode"), copy the value to the canonical key so _get_str(args, "mode", "action")
        # finds it. alias_map comes from registry TOOL_PARAM_ALIASES per tool.
        alias_map: dict[str, set[str]] | None = TOOL_PARAM_ALIASES.get(norm_name)
        if alias_map:
            for key, value in list(norm_args.items()):
                targets: set[str] | None = alias_map.get(key)
                if not targets:
                    continue
                for target in targets:
                    if norm_args.get(target) is None:
                        norm_args[target] = value
            for alias, canonicals in alias_map.items():
                if norm_args.get(alias) is not None:
                    continue
                for canonical in canonicals:
                    canonical_value = norm_args.get(canonical)
                    if canonical_value is not None:
                        norm_args[alias] = canonical_value
                        break

        try:
            result = await handler(norm_args)
            logger.debug("tool=%s completed", canonical_tool)
            return result
        except Exception as e:
            logger.error("tool=%s error=%s message=%s", canonical_tool, e.__class__.__name__, e)
            extra_context: dict[str, Any] | None = None
            if isinstance(e, ActionableError) and not auto_prereq_invocation:
                try:
                    extra_context = await self._build_prerequisite_call_context(e, norm_args)
                except Exception as prereq_exc:
                    logger.debug("Failed to build prerequisite call context for %s: %s", name, prereq_exc)
            return create_error_response(
                e,
                context=_merge_context(
                    {
                        "tool": to_snake_case(resolve_tool_name(name) or name),
                        "canonicalTool": resolve_tool_name(name) or name,
                        "provider": self.__class__.__name__,
                        "handler": handler_method_name,
                        "errorTimestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    },
                    extra_context,
                ),
            )

    @staticmethod
    def _extract_path_hint_from_context(context: dict[str, Any] | None, args: dict[str, Any] | None) -> str | None:
        """Extract a directory path from error context or args (e.g. for suggesting list-project-files with a path)."""
        context_path = ""
        if isinstance(context, dict):
            value = context.get("path")
            if value is not None:
                context_path = str(value).strip()

        if not context_path and isinstance(args, dict):
            value = args.get("path")
            if value is not None:
                context_path = str(value).strip()

        if not context_path:
            return None

        try:
            candidate = Path(context_path)
            parent = candidate.parent
            if str(parent).strip() and str(parent) != ".":
                return str(parent)
        except Exception:
            pass

        return None

    def _build_prerequisite_call_plan(
        self,
        next_steps: list[str] | None,
        context: dict[str, Any] | None,
        args: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Turn 'Suggested Next Steps' text into a list of {tool, arguments, trigger} to run for error context.

        Parses phrases like 'Call `list-project-files`' or 'Call `get-current-program`' and optional path hints.
        """
        plan: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        path_hint = self._extract_path_hint_from_context(context, args)

        for step in next_steps or []:
            normalized_step = str(step).strip()
            if not normalized_step:
                continue

            lowered = normalized_step.lower()
            entries: list[tuple[str, dict[str, Any]]] = []
            # Match suggested-step phrases to concrete tool + args (for prerequisiteCall in error response)
            if "call `list-project-files`" in lowered:
                entries.append((Tool.LIST_PROJECT_FILES.value, {}))

            if "call `get-current-program`" in lowered:
                entries.append(("get-current-program", {}))

            if "call `manage-files`" in lowered and "mode=list" in lowered:
                manage_args: dict[str, Any] = {"mode": "list"}
                if path_hint:
                    manage_args["path"] = path_hint
                entries.append((Tool.MANAGE_FILES.value, manage_args))

            if "call `list_tools`" in lowered or "call `list-tools`" in lowered:
                entries.append(("list_tools", {}))

            for tool_name, tool_args in entries:
                dedupe_key = (tool_name, _json.dumps(tool_args, sort_keys=True))
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                plan.append(
                    {
                        "tool": tool_name,
                        "arguments": tool_args,
                        "trigger": normalized_step,
                    },
                )

        return plan

    async def _run_prerequisite_call(self, tool_name: str, tool_args: dict[str, Any]) -> dict[str, Any]:
        """Run a single prerequisite tool (e.g. list_tools or list-project-files) and return a result dict for error context."""
        if tool_name == "list_tools":
            tools = self._manager.list_tools() if self._manager is not None else []
            return {
                "tool": "list_tools",
                "arguments": {},
                "success": True,
                "output": {"count": len(tools), "tools": [t.name for t in tools]},
            }

        if self._manager is None:
            return {
                "tool": tool_name,
                "arguments": tool_args,
                "success": False,
                "output": {"error": "Tool provider manager unavailable"},
            }

        invocation_args = dict(tool_args)
        invocation_args["__auto_prereq_invocation"] = True  # skip building nested prerequisite context on this call
        response = await self._manager.call_tool(tool_name, invocation_args, program_info=self.program_info)

        output: Any
        success: bool
        if response and isinstance(response[0], types.TextContent):
            raw_text = str(response[0].text)
            try:
                parsed = _json.loads(raw_text)
            except Exception:
                parsed = {"raw": raw_text}
            output = parsed
            success = not (isinstance(parsed, dict) and parsed.get("success") is False)
        else:
            output = {"raw": str(response)}
            success = True

        return {
            "tool": tool_name,
            "arguments": tool_args,
            "success": success,
            "output": output,
        }

    async def _build_prerequisite_call_context(self, error: ActionableError, args: dict[str, Any]) -> dict[str, Any] | None:
        """Build error context with prerequisiteCalls: merge error's next_steps with inferred steps, run suggested tools, attach outputs."""
        inferred_context, inferred_steps = _default_error_guidance(error.message)
        combined_steps = _merge_steps(error.next_steps, inferred_steps)
        combined_context = _merge_context(error.context, inferred_context)

        plan = self._build_prerequisite_call_plan(combined_steps, combined_context, args)
        if not plan:
            return None

        results: list[dict[str, Any]] = []
        for entry in plan:
            tool_name = str(entry.get("tool", "")).strip()
            raw_args = entry.get("arguments")
            tool_args: dict[str, Any] = raw_args if isinstance(raw_args, dict) else {}
            trigger = str(entry.get("trigger", "")).strip()
            result = await self._run_prerequisite_call(tool_name, tool_args)
            result["trigger"] = trigger
            results.append(result)

        if not results:
            return None

        return {"prerequisiteCalls": results}

    # ------------------------------------------------------------------
    # Argument extraction helpers (on already-normalized dicts)
    # ------------------------------------------------------------------

    @staticmethod
    def _get(args: dict[str, Any], *keys: str, default: Any | None = None) -> Any:
        """First non-None value matching any *keys* (normalized before lookup)."""
        for k in keys:
            v = args.get(n(k))
            if v is not None:
                return v
        return default

    @staticmethod
    def _get_str(args: dict[str, Any], *keys: str, default: str = "") -> str:
        """First non-empty string value for any of the given keys (normalized)."""
        for k in keys:
            v = args.get(n(k))
            if v is not None and str(v).strip():
                return str(v)
        return default

    @staticmethod
    def _get_int(args: dict[str, Any], *keys: str, default: int | None = 0) -> int | None:
        """First value that coerces to int for any of the given keys (normalized). Returns default when no key present (default can be None)."""
        for k in keys:
            v = args.get(n(k))
            if v is not None:
                return _coerce_int(v, 0 if default is None else default)
        return default

    @staticmethod
    def _get_bool(args: dict[str, Any], *keys: str, default: bool | None = False) -> bool:
        """First value that coerces to bool for any of the given keys (normalized)."""
        for k in keys:
            v = args.get(n(k))
            if v is not None:
                return _coerce_bool(v)
        return False if default is None else default

    @staticmethod
    def _get_list(args: dict[str, Any], *keys: str) -> list[Any] | None:
        """First value that coerces to list for any of the given keys (normalized)."""
        for k in keys:
            v = args.get(n(k))
            if v is not None:
                return _coerce_list(v)
        return None

    @staticmethod
    def _require(args: dict[str, Any], *keys: str, name: str = "") -> Any:
        """Like ``_get`` but raises ``ValueError`` if nothing found."""
        for k in keys:
            v = args.get(n(k))
            if v is not None:
                return v
        label = name or " or ".join(keys)
        raise ValueError(f"Required parameter missing: `{label}`")

    @staticmethod
    def _require_str(args: dict[str, Any], *keys: str, name: str = "") -> str:
        for k in keys:
            v = args.get(n(k))
            if v is not None and str(v).strip():
                return str(v)
        label = name or " or ".join(keys)
        raise ValueError(f"Required parameter missing or empty: `{label}`")

    def _get_address_or_symbol(self, args: dict[str, Any], default: str | None = None) -> str:
        """Get address or symbol parameter with common aliases consolidated.

        **Consolidates 8-10 parameter aliases into a single lookup**, eliminating
        24 instances of verbose parameter extraction across 10+ providers.

        This method replaces the repeated pattern found in dataflow, vtable, bookmarks,
        callgraph, getfunction, decompiler, and others:
            addr = self._get_str(args, "addressorsymbol", "address", "addr",
                                  "symbol", "functionidentifier", "functionaddress", ...)

        **Consolidation Impact:**
        - Reduced code volume: ~4-6 lines per call site
        - Improved readability: single method call instead of 6+ aliases
        - Centralized alias management: changes propagate everywhere automatically
        - Applied to: dataflow, vtable, bookmarks, callgraph, getfunction, functions, decompiler, suggestions
        - Total elimination: 24+ instances of parameter enumeration

        Args:
        ----
            args: Normalized arguments dict
            default: Value to return if no address found

        Returns:
        -------
            The address string, symbol name, or function identifier

        Example:
        -------
            >>> addr = self._get_address_or_symbol(args)
            >>> # Automatically tries: addressorsymbol, address, addr, symbol, etc.
        """
        return self._get_str(
            args,
            "addressorsymbol",
            "address",
            "addr",
            "symbol",
            "function",
            "functionidentifier",
            "functionaddress",
            "targetaddress",
            default="" if default is None else default,
        )

    def _require_address_or_symbol(self, args: dict[str, Any]) -> str:
        """Like _get_address_or_symbol but raises ValueError if not found."""
        result = self._get_address_or_symbol(args)
        if not result:
            raise ValueError("Required parameter missing: `address` or `symbol`")
        return result

    def _get_pagination_params(self, args: dict[str, Any], default_limit: int | None = DEFAULT_PAGE_LIMIT) -> tuple[int, int]:
        """Extract pagination parameters (offset, limit) from args.

        Consolidates two repeated extraction calls:
            offset = self._get_int(args, "offset", "startindex", default=0)
            limit = self._get_int(args, "limit", "maxresults", "maxcount", default=...)

        This single method eliminates 2+ lines per pagination method across
        15+ providers that perform result slicing/pagination.

        Args:
        ----
            args: Normalized arguments dict
            default_limit: Default value for limit parameter

        Returns:
        -------
            Tuple of (offset, limit)

        Example:
        -------
            >>> offset, limit = self._get_pagination_params(args, default_limit=50)
            >>> results = all_results[offset : offset + limit]
        """
        offset = self._get_int(args, "offset", "startindex", default=0)
        limit = self._get_int(args, "limit", "maxresults", "maxcount", "max", default= DEFAULT_PAGE_LIMIT if default_limit is None else default_limit)
        return offset, limit

    def _dispatch_handler(self, *args, **kwargs) -> Any:
        """Unified handler dispatch with error handling.

        Supports two calling patterns:
        1. _dispatch_handler(dispatch_dict, key, param_name) -> callable
        2. _dispatch_handler(args, mode, dispatch_dict, **extra_kwargs) -> awaitable result

        **Pattern 1 (legacy):** Returns handler function for manual calling
        **Pattern 2 (new):** Calls handler directly and returns result

        Args:
            For pattern 1: dispatch, key, param_name
            For pattern 2: args_dict, mode_key, dispatch_dict, **handler_kwargs

        Returns:
            For pattern 1: handler function
            For pattern 2: result of await handler(args, **kwargs)

        Raises:
            ActionableError: If mode/key not found in dispatch
        """
        # Pattern 1: (dispatch_dict, key, param_name) → returns handler callable for caller to invoke
        if len(args) == 3 and isinstance(args[0], dict) and isinstance(args[1], str) and isinstance(args[2], str):
            dispatch: dict[str, Callable[[dict[str, Any]], Awaitable[list[types.TextContent]]]]
            key: str
            param_name: str
            dispatch, key, param_name = args
            handler: Callable[[dict[str, Any]], Awaitable[list[types.TextContent]]] | None = dispatch.get(key)
            if handler is None:
                available: list[str] = list(dispatch.keys())
                raise ActionableError(
                    f"Unsupported {param_name}: '{key}'",
                    context={"state": "unsupported-parameter-value", "parameter": param_name, "value": key, "available": available},
                    next_steps=[
                        f"Use one of the supported {param_name} values: {', '.join(available)}",
                        "Check the tool's inputSchema for valid enum values.",
                    ],
                )
            return handler
        # Pattern 2: (args_dict, mode_key, dispatch_dict, **kwargs) → invokes handler and returns result
        if len(args) == 3 and isinstance(args[2], dict):
            args_dict: dict[str, Any]
            mode_key: str
            dispatch_dict: dict[str, Callable[[dict[str, Any]], Awaitable[list[types.TextContent]]]]
            args_dict, mode_key, dispatch_dict = args
            mode_norm = n(mode_key)
            normalized_dispatch: dict[str, Callable[[dict[str, Any]], Awaitable[list[types.TextContent]]]] = {n(k): v for k, v in dispatch_dict.items()}
            handler_name = normalized_dispatch.get(mode_norm)
            if handler_name is None:
                available = list(normalized_dispatch.keys())
                raise ActionableError(
                    f"Unsupported mode: '{mode_key}'",
                    context={"state": "unsupported-parameter-value", "parameter": "mode", "value": mode_key, "available": available},
                    next_steps=[
                        f"Use one of the supported mode values: {', '.join(available)}",
                        "Check the tool's inputSchema for valid enum values.",
                    ],
                )
            handler = getattr(self, handler_name)
            return handler(args_dict, **kwargs)
        raise ValueError("Invalid _dispatch_handler call signature")

    # ------------------------------------------------------------------
    # Program guards
    # ------------------------------------------------------------------

    def _require_program(self) -> None:
        """Ensure a program is loaded for this request; raise ActionableError with next_steps if not.

        program_info is set by the manager from SessionContext (active or programPath) before
        dispatching to the handler; if still None here, the client must open a program first.
        """
        if self.program_info is None or getattr(self.program_info, "program", None) is None:
            raise ActionableError(
                "No program loaded",
                context={"state": "no-active-program"},
                next_steps=[
                    "Call `import-binary` with `path` for a local binary, or `open-project` for a `.gpr` project/shared server session.",
                    "Call `get-current-program` to confirm `loaded=true`.",
                ],
            )

    def _require_ghidra(self) -> None:
        """Ensure GhidraTools wrapper is available; used by providers that need script/analysis beyond raw program API."""
        if self.ghidra_tools is None:
            raise ActionableError(
                "No program loaded (Ghidra tools unavailable)",
                context={"state": "no-active-program"},
                next_steps=[
                    "Call `import-binary` with `path` for a local binary, or `open-project` for a `.gpr` project/shared server session.",
                    "Then retry the current analysis tool.",
                ],
            )

    # ------------------------------------------------------------------
    # Shared provider helpers
    # ------------------------------------------------------------------

    def _resolve_function(
        self,
        function_identifier: str,
        program: Any | None = None,
        include_externals: bool = True,
    ) -> Any | None:
        """Resolve a function by name, entrypoint string, or address/symbol.

        Tries in order: exact name match, exact entry point string, then AddressUtil
        (hex address or symbol name) and getFunctionContaining(addr).
        """
        if not function_identifier:
            return None

        target_program = program or getattr(self.program_info, "program", None)
        if target_program is None or not hasattr(target_program, "getFunctionManager"):
            return None

        fm = target_program.getFunctionManager()
        for func in fm.getFunctions(include_externals):
            if func.getName() == function_identifier or str(func.getEntryPoint()) == function_identifier:
                return func

        try:
            from agentdecompile_cli.mcp_utils.address_util import AddressUtil

            addr = AddressUtil.resolve_address_or_symbol(target_program, function_identifier)
            if addr is not None:
                return fm.getFunctionContaining(addr)
        except Exception:
            return None

        return None

    def _resolve_address(self, address_or_symbol: str, program: Any | None = None) -> Any:
        """Resolve an address/symbol string against the active program."""
        target_program = program or getattr(self.program_info, "program", None)
        if target_program is None:
            raise ValueError("No program loaded")

        from agentdecompile_cli.mcp_utils.address_util import AddressUtil

        return AddressUtil.resolve_address_or_symbol(target_program, address_or_symbol)

    def _get_function_manager(self, program: Any | None = None) -> Any:
        """Get function manager from program, with safe access and caching.

        Consolidates 20+ repeated patterns of:
            fm = program.getFunctionManager()

        Eliminates boilerplate and ensures consistent error handling.
        """
        target_program = program or getattr(self.program_info, "program", None)
        if target_program is None:
            raise ValueError("No program loaded")
        return target_program.getFunctionManager()

    def _get_listing(self, program: Any | None = None) -> Any:
        """Get program listing (instructions/data units) with safe access.

        Consolidates 15+ repeated patterns of:
            listing = program.getListing()
        """
        target_program = program or getattr(self.program_info, "program", None)
        if target_program is None:
            raise ValueError("No program loaded")
        return target_program.getListing()

    def _get_memory(self, program: Any | None = None) -> Any:
        """Get program memory interface with safe access.

        Consolidates repeated memory access patterns:
            memory = program.getMemory()
        """
        target_program = program or getattr(self.program_info, "program", None)
        if target_program is None:
            raise ValueError("No program loaded")
        return target_program.getMemory()

    def _get_symbol_table(self, program: Any | None = None) -> Any:
        """Get symbol table from program with safe access.

        Consolidates patterns like:
            st = program.getSymbolTable()
        """
        target_program = program or getattr(self.program_info, "program", None)
        if target_program is None:
            raise ValueError("No program loaded")
        return target_program.getSymbolTable()

    @staticmethod
    def _run_program_transaction(program: Any, label: str, operation: Callable[[], Any]) -> Any:
        """Run an operation inside a Ghidra transaction with consistent commit/rollback."""
        tx = program.startTransaction(label)
        try:
            result = operation()
            program.endTransaction(tx, True)
            return result
        except Exception:
            program.endTransaction(tx, False)
            raise

    @staticmethod
    def _build_decompile_fallback(
        program: Any,
        target_func: Any,
        reason: str | None = None,
        max_instructions: int = 300,
    ) -> str:
        """When DecompInterface is unavailable, return a comment block + disassembly up to max_instructions."""
        listing = program.getListing()
        body = target_func.getBody()
        lines: list[str] = []

        if body:
            instr_iter = listing.getInstructions(body, True)
            count = 0
            while instr_iter.hasNext() and count < max_instructions:
                instr = instr_iter.next()
                lines.append(f"{instr.getAddress()}: {instr}")
                count += 1

        reason_text = reason.strip() if reason else "native decompiler unavailable"
        signature = str(target_func.getSignature())
        fallback = [
            f"/* Fallback decompilation ({reason_text}) */",
            f"/* Function: {target_func.getName()} @ {target_func.getEntryPoint()} */",
            f"/* Signature: {signature} */",
            "",
            "/* Disassembly */",
        ]

        if lines:
            fallback.extend(lines)
        else:
            fallback.append("<no instructions available>")

        return "\n".join(fallback)

    def _paginate_results(
        self,
        all_results: list[Any],
        offset: int,
        limit: int,
    ) -> tuple[list[Any], bool]:
        """Slice results for pagination and compute hasMore flag.

        Consolidates the repeated pattern across multiple providers:
            paginated = results[offset : offset + limit]
            hasMore = offset + len(paginated) < len(results)

        This single helper eliminates ~6 lines of duplication per method that
        performs slicing + pagination response creation.

        Args:
        ----
            all_results: Complete list of results before pagination
            offset: Number of results to skip (0-based)
            limit: Maximum number of results to include

        Returns:
        -------
            (paginated_list, has_more_flag) tuple

        Example:
        -------
            >>> results, has_more = self._paginate_results(all_users, offset=10, limit=20)
            >>> response = {"users": results, "count": len(results), "hasMore": has_more}
        """
        paginated = all_results[offset : offset + limit]
        has_more = offset + len(paginated) < len(all_results)
        return paginated, has_more

    async def _handle_paginated_search(
        self,
        args: dict[str, Any],
        search_func: Callable[[dict[str, Any]], Awaitable[list[dict[str, Any]]]],
        mode: str = "search",
        **extra_response_fields: Any,
    ) -> list[types.TextContent]:
        """Handle a paginated search operation with common boilerplate.

        Consolidates the repeated pattern of:
            self._require_program()
            query = self._get_str(args, "query", ...)
            offset, limit = self._get_pagination_params(args)
            results = await search_func(args)
            paginated, has_more = self._paginate_results(results, offset, limit)
            return self._create_paginated_response(paginated, offset, limit, mode=mode, **extra)

        This helper eliminates 8-12 lines of duplication per search method
        across providers like symbols, strings, bookmarks, etc.

        Args:
        ----
            args: Normalized arguments dict
            search_func: Async function that takes args and returns list of results
            mode: Response mode string
            extra_response_fields: Additional fields for response

        Returns:
        -------
            Paginated MCP response
        """
        self._require_program()
        offset, limit = self._get_pagination_params(args)
        results = await search_func(args)
        paginated, _ = self._paginate_results(results, offset, limit)
        return self._create_paginated_response(paginated, offset, limit, total=len(results), mode=mode, **extra_response_fields)

    def _create_paginated_response(
        self,
        results: list[Any],
        offset: int,
        limit: int,
        total: int | None = None,
        mode: str | None = None,
        **extra_fields: Any,
    ) -> list[types.TextContent]:
        """Create a standardized paginated response with count, total, hasMore.

        Consolidates the repeated pattern across multiple providers:
            return create_success_response({
                "mode": mode,
                "results": results,
                "count": len(results),
                "total": total,
                "hasMore": offset + len(results) < total,
                "offset": offset,
                "limit": limit,
                **extra_fields
            })

        This helper eliminates ~6-8 lines of response construction per method
        that returns paginated results. Used in symbols, bookmarks, strings,
        and other providers.

        Args:
        ----
            results: The paginated results list
            offset: Pagination offset used
            limit: Pagination limit used
            total: Total number of items (if known), or None to calculate from results
            mode: Optional mode string for response
            extra_fields: Additional fields to include in response

        Returns:
        -------
            MCP TextContent list with standardized paginated response

        Example:
        -------
            >>> results, has_more = self._paginate_results(all_items, offset, limit)
            >>> return self._create_paginated_response(results, offset, limit, total=len(all_items), mode="search")
        """
        if total is None:
            total = len(results)  # Assume results is the full set if total not provided
        response = {
            "results": results,
            "count": len(results),
            "total": total,
            "hasMore": offset + len(results) < total,
            "offset": offset,
            "limit": limit,
            **extra_fields,
        }
        if mode:
            response["mode"] = mode
        return create_success_response(response)

    # ------------------------------------------------------------------
    # Lifecycle hooks
    # ------------------------------------------------------------------

    def program_opened(self, program_path: str) -> None:
        pass

    def program_closed(self, program_path: str) -> None:
        pass

    def cleanup(self) -> None:
        """Override to release provider-specific resources (e.g. caches, handles); default no-op."""


# ---------------------------------------------------------------------------
# ToolProviderManager – routes tool calls to the correct provider
# ---------------------------------------------------------------------------


class ToolProviderManager:
    """Routes MCP tool calls to the correct ToolProvider by normalized name."""

    def __init__(self) -> None:
        self.providers: list[ToolProvider] = []
        self._tool_map: dict[str, ToolProvider] = {}  # normalized tool name → provider; filled by _register()
        self.program_info: ProgramInfo | None = None
        self.ghidra_project: Any | None = None  # GhidraProject from PyGhidraContext
        self._on_program_info_changed: Callable[[ProgramInfo], None] | None = None

    def set_ghidra_project(self, project: Any) -> None:
        """Store the GhidraProject reference so providers can use it for checkout."""
        self.ghidra_project = project

    def _register(self, provider: ToolProvider) -> None:
        """Register a provider: store back-reference for prerequisite calls, then map each of its tool names to this provider."""
        provider._manager = self
        self.providers.append(provider)
        for tool in provider.list_tools():
            self._tool_map[n(tool.name)] = provider

    def register_all_providers(self) -> None:
        """Import and register every concrete provider; called at server startup so _tool_map has all HANDLERS."""
        from agentdecompile_cli.mcp_server.providers import (
            BookmarkToolProvider,
            CallGraphToolProvider,
            CommentToolProvider,
            ConstantSearchToolProvider,
            CrossReferencesToolProvider,
            DataFlowToolProvider,
            DataToolProvider,
            DataTypeToolProvider,
            DecompilerToolProvider,
            FunctionToolProvider,
            GetFunctionAioToolProvider,
            GetFunctionToolProvider,
            ImportExportToolProvider,
            MemoryToolProvider,
            ProjectToolProvider,
            ScriptToolProvider,
            SearchEverythingToolProvider,
            StringToolProvider,
            StructureToolProvider,
            SuggestionToolProvider,
            SymbolToolProvider,
            VtableToolProvider,
        )

        # Register each provider; one failure does not block others
        for cls in (
            BookmarkToolProvider,
            CallGraphToolProvider,
            CommentToolProvider,
            ConstantSearchToolProvider,
            CrossReferencesToolProvider,
            DataFlowToolProvider,
            DataToolProvider,
            DataTypeToolProvider,
            DecompilerToolProvider,
            GetFunctionAioToolProvider,
            FunctionToolProvider,
            GetFunctionToolProvider,
            ImportExportToolProvider,
            MemoryToolProvider,
            ProjectToolProvider,
            ScriptToolProvider,
            SearchEverythingToolProvider,
            StringToolProvider,
            StructureToolProvider,
            SuggestionToolProvider,
            SymbolToolProvider,
            VtableToolProvider,
        ):
            try:
                self._register(cls(self.program_info))
            except Exception as e:
                logger.warning(f"Failed to register {cls.__name__}: {e}")

    def set_program_info(
        self,
        program_info: ProgramInfo,
    ) -> None:
        logger.info("Setting program info: %s", program_info)
        self.program_info = program_info
        for p in self.providers:
            try:
                p.set_program_info(program_info)
            except Exception as e:
                logger.warning(f"Failed to set program info for {p.__class__.__name__}! {e.__class__.__name__}: {e}")
        if self._on_program_info_changed is not None:
            try:
                self._on_program_info_changed(program_info)
            except Exception as e:
                logger.warning("_on_program_info_changed callback failed: %s", e)

    def _get_project_provider(self) -> Any | None:
        """Return the provider that handles open-project and shared checkout (ProjectToolProvider)."""
        for provider in self.providers:
            if hasattr(provider, "_handle_open") and hasattr(provider, "_checkout_shared_program"):
                return provider
        return None

    async def _bootstrap_shared_session_from_env(
        self,
        session_id: str,
        requested_program_key: str,
    ) -> None:
        """Connect to shared server from request auth context (X-Ghidra-* headers) or env, then checkout the requested program in this session."""
        project_provider = self._get_project_provider()
        if project_provider is None:
            return

        host = ""
        port_str = "13100"
        username = ""
        password = ""
        repo = ""
        try:
            from agentdecompile_cli.mcp_server.auth import get_current_auth_context

            auth_ctx = get_current_auth_context()
            if auth_ctx is not None and (auth_ctx.server_host or auth_ctx.username):
                host = (auth_ctx.server_host or "").strip()
                port_str = str(auth_ctx.server_port) if auth_ctx.server_port else "13100"
                username = (auth_ctx.username or "").strip()
                password = (auth_ctx.password or "").strip()
                repo = (auth_ctx.repository or "").strip()
        except Exception:
            pass
        if not host:
            host = (
                os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_HOST", os.getenv("AGENT_DECOMPILE_SERVER_HOST", os.getenv("AGENTDECOMPILE_GHIDRA_SERVER_HOST", os.getenv("AGENTDECOMPILE_GHIDRA_HOST", os.getenv("AGENTDECOMPILE_SERVER_HOST", "")))))
            ).strip()
        if not host:
            return
        if not port_str or port_str == "0":
            port_str = (
                os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_PORT", os.getenv("AGENTDECOMPILE_GHIDRA_PORT", os.getenv("AGENTDECOMPILE_SERVER_PORT", "13100")))
            ).strip() or "13100"
        if not username:
            username = (
                os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME", os.getenv("AGENTDECOMPILE_GHIDRA_USERNAME", os.getenv("AGENT_DECOMPILE_SERVER_USERNAME", os.getenv("AGENTDECOMPILE_SERVER_USERNAME", ""))))
            ).strip()
        if not password:
            password = (
                os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD", os.getenv("AGENTDECOMPILE_GHIDRA_SERVER_PASSWORD", os.getenv("AGENTDECOMPILE_GHIDRA_PASSWORD", os.getenv("AGENTDECOMPILE_SERVER_PASSWORD", ""))))
            ).strip()
        if not repo:
            repo = (
                os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY", os.getenv("AGENTDECOMPILE_GHIDRA_SERVER_REPOSITORY", os.getenv("AGENTDECOMPILE_GHIDRA_REPOSITORY", "")))
            ).strip()

        open_args: dict[str, Any] = {
            "shared": True,
            "serverhost": host,
            "serverport": port_str,
            "serverusername": username,
            "serverpassword": password,
            "path": repo or requested_program_key,
        }

        try:
            await project_provider._handle_open_project(open_args)
        except Exception as e:
            logger.debug("Shared-session bootstrap (open-project) failed: %s", e)
            return

        session = SESSION_CONTEXTS.get_or_create(session_id)
        handle = session.project_handle if isinstance(session.project_handle, dict) else None
        if handle and n(str(handle.get("mode", ""))) == "sharedserver":
            repository_adapter = handle.get("repository_adapter")
            if repository_adapter is not None:
                try:
                    await project_provider._checkout_shared_program(repository_adapter, requested_program_key, session_id)
                except Exception as e:
                    logger.debug("Shared-session bootstrap (checkout program) failed for %s: %s", requested_program_key, e)

    def _resolve_project_data(self) -> Any | None:
        ghidra_project = self.ghidra_project
        if ghidra_project is None:
            return None
        try:
            return ghidra_project.getProject().getProjectData()
        except Exception:
            try:
                return ghidra_project.getProjectData()
            except Exception:
                return None

    def _find_domain_file_by_name(
        self,
        folder: Any,
        file_name: str,
        max_results: int = 5000,
    ) -> Any | None:
        stack: list[Any] = [folder]
        visited = 0
        while stack and visited < max_results:
            current = stack.pop()
            visited += 1
            try:
                for domain_file in current.getFiles() or []:
                    if str(domain_file.getName()) == file_name:
                        return domain_file
                for subfolder in current.getFolders() or []:
                    stack.append(subfolder)
            except Exception:
                continue
        return None

    def _activate_local_program_by_path(
        self,
        session_id: str,
        requested_program_key: str,
    ) -> ProgramInfo | None:
        project_data: Any = self._resolve_project_data()
        if project_data is None:
            return None

        normalized: str = str(requested_program_key).strip()
        if not normalized:
            return None

        candidate_paths: list[str] = [normalized]
        if not normalized.startswith("/"):
            candidate_paths.append(f"/{normalized}")

        domain_file: Any = None
        for candidate in candidate_paths:
            try:
                domain_file = project_data.getFile(candidate)
            except Exception:
                domain_file = None
            if domain_file is not None:
                break

        if domain_file is None:
            file_name = Path(normalized).name
            if file_name:
                try:
                    root = project_data.getRootFolder()
                    domain_file = self._find_domain_file_by_name(root, file_name)
                except Exception:
                    domain_file = None

        if domain_file is None:
            return None

        program: Any = None
        project_provider = self._get_project_provider()
        if project_provider is not None:
            try:
                program = project_provider._open_program_from_domain_file(domain_file)
            except Exception:
                program = None

        if program is None:
            try:
                from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingImports, reportMissingModuleSource]

                program = domain_file.getDomainObject(self, True, False, TaskMonitor.DUMMY)
            except Exception:
                program = None

        if program is None:
            return None

        try:
            from ghidra.app.decompiler import DecompInterface  # pyright: ignore[reportMissingImports, reportMissingModuleSource]

            decompiler = DecompInterface()
            decompiler.openProgram(program)
        except Exception:
            decompiler = None

        from agentdecompile_cli.launcher import ProgramInfo

        program_path = normalized
        try:
            if hasattr(domain_file, "getPathname"):
                program_path = str(domain_file.getPathname())
        except Exception:
            program_path = normalized

        program_info = ProgramInfo(
            name=program.getName() if hasattr(program, "getName") else Path(program_path).name,
            program=program,
            flat_api=None,
            decompiler=decompiler,
            metadata={},
            ghidra_analysis_complete=True,
            file_path=None,
            load_time=None,
        )

        SESSION_CONTEXTS.set_active_program_info(session_id, program_path, program_info)
        if program_path.strip().lower() != normalized.strip().lower():
            SESSION_CONTEXTS.set_active_program_info(session_id, normalized, program_info)
        self.set_program_info(program_info)
        return program_info

    async def _activate_requested_program(
        self,
        session_id: str,
        requested_program_key: str,
    ) -> ProgramInfo | None:
        """Resolve and activate a program by path: cache → shared checkout → bootstrap → local path."""
        existing = SESSION_CONTEXTS.get_program_info(session_id, requested_program_key)
        if existing is not None:
            _sid_hint = (session_id[:12] + "…") if session_id and len(session_id) > 12 else (session_id or "—")
            logger.debug("program already in session: session_id=%s program=%s", _sid_hint, requested_program_key)
            return existing

        _sid_hint = (session_id[:12] + "…") if session_id and len(session_id) > 12 else (session_id or "—")
        logger.debug("activating program: session_id=%s program=%s", _sid_hint, requested_program_key)
        session = SESSION_CONTEXTS.get_or_create(session_id)
        handle = session.project_handle if isinstance(session.project_handle, dict) else None
        project_provider = self._get_project_provider()

        if project_provider is not None and handle and n(str(handle.get("mode", ""))) == "sharedserver":
            repository_adapter = handle.get("repository_adapter")
            if repository_adapter is not None:
                try:
                    await project_provider._checkout_shared_program(repository_adapter, requested_program_key, session_id)
                except Exception as e:
                    logger.debug("Shared checkout attempt failed for %s: %s", requested_program_key, e)

        activated = SESSION_CONTEXTS.get_program_info(session_id, requested_program_key)
        if activated is not None:
            logger.debug("program activated via shared checkout: program=%s", requested_program_key)
            return activated

        if project_provider is not None:
            await self._bootstrap_shared_session_from_env(session_id, requested_program_key)
            activated = SESSION_CONTEXTS.get_program_info(session_id, requested_program_key)
            if activated is not None:
                logger.debug("program activated via bootstrap: program=%s", requested_program_key)
                return activated

        logger.debug("activating program via local path: program=%s", requested_program_key)
        return self._activate_local_program_by_path(session_id, requested_program_key)

    async def get_or_open_program(
        self,
        session_id: str,
        program_path: str,
    ) -> ProgramInfo | None:
        """Open a program by path if not already open; return its ProgramInfo without leaving it active.

        Used by match-function for cross-program matching: open each target program,
        read its functions, then restore the original active program.
        """
        existing = SESSION_CONTEXTS.get_program_info(session_id, program_path)
        if existing is not None:
            return existing
        # Remember current active program so we can restore it after opening the requested one
        saved_key = SESSION_CONTEXTS.get_active_program_key(session_id)
        saved_info = SESSION_CONTEXTS.get_active_program_info(session_id)
        activated = await self._activate_requested_program(session_id, program_path)
        if activated is None:
            return None
        if saved_key and saved_info:
            # Restore previous active program so this call didn't change the session's "current" program
            SESSION_CONTEXTS.set_active_program_info(session_id, saved_key, saved_info)
            self.set_program_info(saved_info)
        return activated

    def list_tools(self) -> list[types.Tool]:
        """Build the MCP tools/list response: merge all providers' tools, then return only ADVERTISED_TOOLS with normalized params and format option."""
        provider_tools: list[types.Tool] = []
        for p in self.providers:
            provider_tools.extend(p.list_tools())

        # One tool per normalized name (first provider wins if duplicate)
        by_norm: dict[str, types.Tool] = {}
        for tool in provider_tools:
            by_norm.setdefault(n(tool.name), tool)

        advertised_tools: list[types.Tool] = []
        for canonical_name in ADVERTISED_TOOLS:
            canonical_params: list[str] = ADVERTISED_TOOL_PARAMS.get(canonical_name, [])

            normalized_name: str = n(canonical_name)
            provider_tool: types.Tool | None = by_norm.get(normalized_name)

            schema: dict[str, Any] = getattr(provider_tool, "inputSchema", None) or {"type": "object", "properties": {}, "required": []}
            properties: dict[str, Any] = schema.get("properties", {}) if isinstance(schema, dict) else {}
            required: list[str] = schema.get("required", []) if isinstance(schema, dict) else []

            props_by_norm: dict[str, Any] = {}
            for key, value in properties.items():
                props_by_norm[n(key)] = value

            # Build properties from canonical param list; use provider schema when present, else infer from param name
            advertised_properties: dict[str, Any] = {}
            for param in canonical_params:
                snake_param = to_snake_case(param)
                normalized_param = n(param)
                provider_param_schema = props_by_norm.get(normalized_param)
                if provider_param_schema is None and normalized_param in _SELECTOR_PARAM_ALIASES:
                    for selector_alias in _SELECTOR_PARAM_ALIASES:
                        provider_param_schema = props_by_norm.get(selector_alias)
                        if provider_param_schema is not None:
                            break

                advertised_properties[snake_param] = provider_param_schema or _infer_param_schema(param)

            # Let client choose markdown (human-readable) vs json (machine-readable) for tool output
            advertised_properties["format"] = {
                "type": "string",
                "enum": ["markdown", "json"],
                "default": "markdown",
                "description": "Output format (default: markdown). Use --format json / -f json only when you strictly need machine-readable output; markdown is recommended.",
            }

            # Required list: if provider marks "mode" or any selector alias as required, treat mode as required in advertised schema
            required_norm: frozenset[str] = frozenset(n(str(item)) for item in required)
            advertised_required: list[str] = []
            for param in canonical_params:
                normalized_param = n(param)
                is_required = normalized_param in required_norm
                if not is_required and normalized_param == "mode":
                    is_required = any(selector_alias in required_norm for selector_alias in _SELECTOR_PARAM_ALIASES)
                if is_required:
                    advertised_required.append(to_snake_case(param))

            # Build schema from canonical params + provider schema; add format (markdown/json) for response formatting
            advertised_tools.append(
                types.Tool(
                    name=canonical_name,
                    description=(provider_tool.description if provider_tool is not None and getattr(provider_tool, "description", None) else canonical_name),
                    inputSchema={
                        "type": "object",
                        "properties": advertised_properties,
                        "required": advertised_required,
                    },
                ),
            )

        return advertised_tools

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        program_info: ProgramInfo | None = None,
    ) -> list[types.TextContent]:
        """Resolve tool name and program, find provider, set provider's program_info, then delegate to provider.call_tool.

        Flow:
          (1) Resolve tool name (alias → canonical).
          (2) Reject GUI-only tools in headless.
          (3) Record in session tool history.
          (4) Find provider (direct or via TOOL_ALIASES).
          (5) Resolve program: from args (programPath/binary/path), else session active, else manager default.
          (6) If a program was requested but not open, try _activate_requested_program (open-project/import).
          (7) Set provider's program_info and call provider.call_tool; optionally apply markdown formatting.
        """
        if program_info is not None and program_info is not self.program_info:
            self.set_program_info(program_info)

        session_id: str = get_current_mcp_session_id()
        resolved_name: str = resolve_tool_name(name) or name
        tool_enum: Tool | None = Tool.from_string(name)
        if tool_enum is not None and tool_enum.is_gui_only_disabled:
            return create_error_response(
                ActionableError(
                    f"Tool '{resolved_name}' is disabled (GUI-only). TODO: add capability-gated GUI enablement.",
                    context={"tool": tool_enum.snake_name, "state": "gui-only-disabled"},
                    next_steps=[
                        "Run this tool in GUI mode (Code Browser) instead of headless mode.",
                        "Use a headless-compatible alternative tool for automation workflows.",
                    ],
                ),
            )
        # Security: do not log full session id (log redacted hint only)
        _sid_hint = (session_id[:12] + "…") if session_id and len(session_id) > 12 else (session_id or "—")
        logger.info("mcp call_tool tool=%s session_id=%s", resolved_name, _sid_hint)
        SESSION_CONTEXTS.add_tool_history(session_id, n(resolved_name), arguments or {})

        norm_name: str = n(resolved_name)
        provider: ToolProvider | None = self._tool_map.get(norm_name)
        # Follow alias chain: if the resolved name maps to an alias target, look that up
        if provider is None:
            alias_target: str | None = TOOL_ALIASES.get(norm_name)
            if alias_target and alias_target.strip():
                alias_norm = n(alias_target)
                provider = self._tool_map.get(alias_norm)
                if provider is not None:
                    norm_name = alias_norm
                    resolved_name = alias_target
        if provider is None:
            logger.warning("no provider for tool: name=%s resolved=%s", name, resolved_name)
            tools: list[types.Tool] = self.list_tools()
            logger.debug("found %d tools", len(tools))
            return create_error_response(
                ActionableError(
                    f"Unknown tool: {name}",
                    context={
                        "tool": str(name),
                        "state": "unknown-tool",
                        "prerequisiteCalls": [
                            {
                                "tool": "list_tools",
                                "arguments": {},
                                "success": True,
                                "output": {"count": len(tools), "tools": [t.name for t in tools]},
                                "trigger": "Call `list_tools` to discover canonical tool names.",
                            },
                        ],
                    },
                    next_steps=[
                        "Call `list_tools` to discover canonical tool names.",
                        "Retry with the canonical snake_case tool name.",
                    ],
                ),
            )

        norm_args: dict[str, Any] = {n(k): v for k, v in (arguments or {}).items()}
        logger.debug("normalized args: %s", norm_args)

        # Program resolution order: args (programPath/binary/path) → session active → manager default
        requested_program_key: str | None = None
        for key in ("programpath", "binary", "binaryname", "path"):
            value = norm_args.get(key)
            if value is None:
                continue
            value_s = str(value).strip()
            if value_s:
                requested_program_key = value_s
                break

        requested_program_info = SESSION_CONTEXTS.get_program_info(session_id, requested_program_key) if requested_program_key else None

        # If client asked for a program by path but we don't have it open, try to open it (open-project/import)
        if requested_program_key and requested_program_info is None:
            requested_program_info = await self._activate_requested_program(session_id, requested_program_key)

        session_program_info: ProgramInfo | None = SESSION_CONTEXTS.get_active_program_info(session_id)
        effective_program_info: ProgramInfo | None = requested_program_info or session_program_info or self.program_info

        # Client asked for a program we couldn't open: attach list-project-files result so they can see available paths
        if requested_program_key and effective_program_info is None:
            prereq_calls: list[dict[str, Any]] = []
            try:
                response: list[types.TextContent] | None = await self.call_tool(Tool.LIST_PROJECT_FILES.value, {"__auto_prereq_invocation": True})
                output: dict[str, Any]
                success: bool = True
                if response and isinstance(response[0], types.TextContent):
                    raw_text: str = str(response[0].text)
                    try:
                        parsed: dict[str, Any] = _json.loads(raw_text)
                    except Exception:
                        parsed = {"raw": raw_text}
                    output = parsed
                    success = not (isinstance(parsed, dict) and parsed.get("success") is False)
                else:
                    output = {"raw": str(response)}

                prereq_calls.append(
                    {
                        "tool": Tool.LIST_PROJECT_FILES.value,
                        "arguments": {},
                        "success": success,
                        "output": output,
                        "trigger": "Call `list-project-files` to discover the exact program path available in this session.",
                    },
                )
            except Exception as prereq_exc:
                logger.debug("Failed auto prerequisite list-project-files call: %s", prereq_exc)

            return create_error_response(
                ActionableError(
                    f"Program path '{requested_program_key}' was provided but could not be resolved in this session. Sessions are fully isolated: this session has no project or program open for that path.",
                    context={
                        "state": "program-resolution-failed",
                        "requestedProgramPath": requested_program_key,
                        **({"prerequisiteCalls": prereq_calls} if prereq_calls else {}),
                    },
                    next_steps=[
                        "In this same session, open a project first: call `open-project` (shared server or local .gpr) or `import-binary` (local file), then retry this tool. CLI: use tool-seq to run open-project then this tool in one connection.",
                        "Call `list-project-files` after opening a project to see available program paths in this session.",
                    ],
                ),
            )

        if effective_program_info is not None and provider.program_info is not effective_program_info:
            try:
                provider.set_program_info(effective_program_info)
            except Exception as e:
                logger.warning(f"Failed to set session program info for {provider.__class__.__name__}: {e}")

        # Dispatch to the provider that owns this tool; provider receives original name + normalized args
        result = await provider.call_tool(name, arguments)

        # Auto match-function: when env AGENTDECOMPILE_AUTO_MATCH_PROPAGATE or header
        # X-AgentDecompile-Auto-Match-Propagate is set and this tool+mode is a trigger (e.g. managefunction+rename),
        # run match-function in background to propagate name/tags/comments to other open programs.
        # Skip when we're already inside that invocation.
        if not norm_args.get(AUTO_MATCH_INVOCATION_KEY):
            _run_auto_match = False
            _propagate_raw = get_current_request_auto_match_propagate()
            if _propagate_raw is None:
                _propagate_raw = os.environ.get(_ENV_AUTO_MATCH_PROPAGATE, "")
            env_propagate = (_propagate_raw or "").strip().lower() in ("1", "true", "yes")
            if env_propagate and norm_name in _AUTO_MATCH_TRIGGER_MODES:
                allowed_modes = _AUTO_MATCH_TRIGGER_MODES[norm_name]
                mode_val = norm_args.get("mode") or norm_args.get("action") or ""
                mode_str = (str(mode_val).strip().lower() if mode_val is not None else "") or ""
                mode_norm = n(mode_str) if mode_str else ""
                if mode_norm in allowed_modes:
                    _run_auto_match = True
            if _run_auto_match and result and isinstance(result[0], types.TextContent):
                try:
                    parsed = _json.loads(result[0].text)
                    tool_success = parsed.get("success", True) is not False and "error" not in (parsed.get("error") or "")
                except Exception:
                    tool_success = True
                if tool_success and effective_program_info is not None:
                    current_path = getattr(effective_program_info, "file_path", None) or getattr(effective_program_info, "path", None)
                    if current_path is not None:
                        current_path_str = str(current_path).strip()
                    else:
                        current_path_str = SESSION_CONTEXTS.get_active_program_key(session_id) or ""
                    func_id = None
                    for key in ("function", "functionidentifier", "addressorsymbol", "address"):
                        v = norm_args.get(n(key))
                        if v is not None and str(v).strip():
                            func_id = str(v).strip()
                            break
                    # Targets: header X-AgentDecompile-Auto-Match-Target-Paths or env AGENTDECOMPILE_AUTO_MATCH_TARGET_PATHS (comma list) or all other open programs in session
                    target_paths: list[str] = []
                    _target_paths_raw = get_current_request_auto_match_target_paths()
                    if _target_paths_raw is None:
                        _target_paths_raw = os.environ.get(_ENV_AUTO_MATCH_TARGET_PATHS, "")
                    env_paths = (_target_paths_raw or "").strip()
                    if env_paths:
                        target_paths = [p.strip() for p in env_paths.split(",") if p.strip()]
                    else:
                        session_ctx = SESSION_CONTEXTS.get_or_create(session_id)
                        for path_key in session_ctx.open_programs or {}:
                            if path_key != current_path_str:
                                target_paths.append(path_key)
                    if func_id and target_paths:
                        match_args: dict[str, Any] = {
                            "programPath": current_path_str,
                            "functionIdentifier": func_id,
                            "targetProgramPaths": target_paths,
                            "propagateNames": True,
                            "propagateTags": True,
                            "propagateComments": True,
                            "propagatePrototype": True,
                            "propagateBookmarks": True,
                            "format": "json",
                            "__auto_match_invocation": True,
                        }
                        try:
                            await self.call_tool(Tool.MATCH_FUNCTION.value, match_args, program_info=effective_program_info)
                        except Exception as auto_match_exc:
                            logger.warning("Auto match-function propagation failed (best-effort): %s", auto_match_exc)

        # Convert JSON response to rich markdown via response_formatter unless format=json or internal prereq
        if not norm_args.get("autoprereqinvocation") and norm_args.get("format", "markdown") != "json" and result and isinstance(result[0], types.TextContent):
            try:
                data = _json.loads(result[0].text)
                markdown = render_tool_response(norm_name, data)
                return [types.TextContent(type="text", text=markdown)]
            except Exception:
                pass  # Fall back to raw JSON on any formatting error

        return result

    def program_opened(self, program_info_or_path: ProgramInfo | os.PathLike | str) -> None:
        """Notify all providers that a program was opened; accept path string or ProgramInfo/PathLike."""
        if isinstance(program_info_or_path, str):
            for p in self.providers:
                p.program_opened(program_info_or_path)
        else:
            # ProgramInfo or PathLike case: convert and set
            pi: ProgramInfo | None = None
            if isinstance(program_info_or_path, ProgramInfo):
                pi = program_info_or_path
            elif isinstance(program_info_or_path, (os.PathLike, str)):
                from agentdecompile_cli.context import ProgramInfo as ContextProgramInfo

                _path = Path(str(program_info_or_path))
                pi = ContextProgramInfo(  # type: ignore[call-arg]
                    name=_path.name,
                    program=None,  # type: ignore[arg-type]
                    flat_api=None,
                    decompiler=None,  # type: ignore[arg-type]
                    metadata={},
                    ghidra_analysis_complete=False,
                    file_path=_path,
                )
            if pi is not None:
                self.set_program_info(pi)

    def program_closed(self, program_path: str) -> None:
        """Notify all providers that a program was closed so they can clear cached state."""
        for p in self.providers:
            p.program_closed(program_path)

    def cleanup(self) -> None:
        """Call cleanup() on all providers; exceptions are swallowed so one failure does not block others."""
        for p in self.providers:
            try:
                p.cleanup()
            except Exception:
                pass


# Backward compatibility aliases
UnifiedToolProviderManager = ToolProviderManager
UnifiedToolProvider = ToolProviderManager
