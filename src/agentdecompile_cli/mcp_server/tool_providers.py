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
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from mcp import types

from agentdecompile_cli.mcp_server.session_context import (
    SESSION_CONTEXTS,
    get_current_mcp_session_id,
)
from agentdecompile_cli.registry import (
    ADVERTISED_TOOL_PARAMS,
    ADVERTISED_TOOLS,
    DISABLED_GUI_ONLY_TOOLS,
    TOOL_PARAM_ALIASES,
    normalize_identifier,
    resolve_tool_name,
    to_snake_case,
)

if TYPE_CHECKING:
    from agentdecompile_cli.launcher import ProgramInfo

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

# ---------------------------------------------------------------------------
# Canonical normalize – ``re.sub(r'[^a-z]', '', s.lower())``.
# Imported from registry.py.  Everything else imports from HERE.
# ---------------------------------------------------------------------------
n = normalize_identifier  # short alias used throughout providers


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
    - No program loaded (user needs to call `open` first)
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
                    "Call `open` with `path` (local binary/.gpr) or shared server args.",
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
            "nextSteps": ["Call `open`...", "Then retry..."],
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
    seen: set[str] = set()
    merged: list[str] = []
    for step in (base or []):
        normalized = str(step).strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        merged.append(normalized)
    for step in (extra or []):
        normalized = str(step).strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        merged.append(normalized)
    return merged or None


def _default_error_guidance(msg: str) -> tuple[dict[str, Any] | None, list[str] | None]:
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
            [
                "Call `open` with `path` (local binary/.gpr) or shared server args (`serverHost`, `serverPort`, `serverUsername`, `serverPassword`).",
                "Then call `get-current-program` to verify an active program is loaded.",
            ],
        )

    if "authentication failed" in lowered:
        return (
            {"state": "authentication-failed"},
            [
                "Verify `serverUsername`/`serverPassword` and retry `open`.",
                "If credentials are correct, verify the Ghidra server is running and reachable on `serverHost:serverPort`.",
            ],
        )

    if "not connected to repository server" in lowered or "shared-server" in lowered:
        return (
            {"state": "shared-session-unavailable"},
            [
                "Call `open` first with shared-server parameters to establish a repository session.",
                "Then call `list-project-files` or `manage-files` `mode=list` to verify repository visibility.",
            ],
        )

    if "path does not exist" in lowered or "path not found" in lowered or "invalid folder path" in lowered:
        return (
            {"state": "path-not-found"},
            [
                "Call `manage-files` with `mode=list` on the parent folder to discover the correct path.",
                "Retry with an absolute path visible to the backend runtime.",
            ],
        )

    if "not a readable file" in lowered or "is not a directory" in lowered:
        return (
            {"state": "path-type-mismatch"},
            [
                "Call `manage-files` `mode=info` on the same path to verify file vs directory.",
                "Use `mode=read` for files and `mode=list` for directories.",
            ],
        )

    if "provided but could not be resolved/opened" in lowered:
        return (
            {"state": "program-resolution-failed"},
            [
                "Call `list-project-files` to locate the exact program path in the active project/session.",
                "Call `open` with that exact path (or with shared server args and repository) before retrying analysis tools.",
            ],
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

    HANDLERS: dict[str, str] = {}
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
        if handler_method_name is None:
            raise NotImplementedError(f"Unknown tool: {name}")

        handler: Callable[[dict[str, Any]], Awaitable[list[types.TextContent]]] = getattr(self, handler_method_name)

        # Normalize ALL argument keys – the ONE place normalization happens.
        norm_args: dict[str, Any] = {n(k): v for k, v in (arguments or {}).items()}

        # Tool-specific parameter synonym bridging from TOOLS_LIST.md.
        # Note: alias_map returns dict[str, set[str]] from TOOL_PARAM_ALIASES
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
            return await handler(norm_args)
        except Exception as e:
            logger.error(f"Tool {name} error: {e.__class__.__name__}: {e}")
            return create_error_response(
                e,
                context={
                    "tool": to_snake_case(resolve_tool_name(name) or name),
                    "provider": self.__class__.__name__,
                },
            )

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
        for k in keys:
            v = args.get(n(k))
            if v is not None and str(v).strip():
                return str(v)
        return default

    @staticmethod
    def _get_int(args: dict[str, Any], *keys: str, default: int = 0) -> int:
        for k in keys:
            v = args.get(n(k))
            if v is not None:
                return _coerce_int(v, default)
        return default

    @staticmethod
    def _get_bool(args: dict[str, Any], *keys: str, default: bool = False) -> bool:
        for k in keys:
            v = args.get(n(k))
            if v is not None:
                return _coerce_bool(v)
        return default

    @staticmethod
    def _get_list(args: dict[str, Any], *keys: str) -> list | None:
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
        raise ValueError(f"Required parameter missing: {label}")

    @staticmethod
    def _require_str(args: dict[str, Any], *keys: str, name: str = "") -> str:
        for k in keys:
            v = args.get(n(k))
            if v is not None and str(v).strip():
                return str(v)
        label = name or " or ".join(keys)
        raise ValueError(f"Required parameter missing or empty: {label}")

    def _get_address_or_symbol(self, args: dict[str, Any], default: str = "") -> str:
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
            "functionidentifier",
            "functionaddress",
            "targetaddress",
            default=default,
        )

    def _require_address_or_symbol(self, args: dict[str, Any]) -> str:
        """Like _get_address_or_symbol but raises ValueError if not found."""
        result = self._get_address_or_symbol(args)
        if not result:
            raise ValueError("Required parameter missing: address or symbol")
        return result

    def _get_pagination_params(self, args: dict[str, Any], default_limit: int = DEFAULT_PAGE_LIMIT) -> tuple[int, int]:
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
        limit = self._get_int(args, "limit", "maxresults", "maxcount", "max", default=default_limit)
        return offset, limit

    def _dispatch_handler(
        self,
        *args,
        **kwargs
    ) -> Any:
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
        if len(args) == 3 and isinstance(args[0], dict) and isinstance(args[1], str) and isinstance(args[2], str):
            # Pattern 1: _dispatch_handler(dispatch, key, param_name) -> callable
            dispatch, key, param_name = args
            handler = dispatch.get(key)
            if handler is None:
                available = list(dispatch.keys())
                raise ActionableError(
                    f"Unsupported {param_name}: '{key}'",
                    context={"state": "unsupported-parameter-value", "parameter": param_name, "value": key, "available": available},
                    next_steps=[
                        f"Use one of the supported {param_name} values: {', '.join(available)}",
                        "Check the tool's inputSchema for valid enum values.",
                    ],
                )
            return handler
        elif len(args) == 3 and isinstance(args[2], dict):
            # Pattern 2: _dispatch_handler(args, mode, dispatch_dict, **kwargs) -> result
            args_dict, mode_key, dispatch_dict = args
            mode_norm = n(mode_key)
            normalized_dispatch = {n(k): v for k, v in dispatch_dict.items()}
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
        else:
            raise ValueError("Invalid _dispatch_handler call signature")

    # ------------------------------------------------------------------
    # Program guards
    # ------------------------------------------------------------------

    def _require_program(self) -> None:
        if self.program_info is None or getattr(self.program_info, "program", None) is None:
            raise ActionableError(
                "No program loaded",
                context={"state": "no-active-program"},
                next_steps=[
                    "Call `open` with `path` (local binary/.gpr) or shared server args.",
                    "Call `get-current-program` to confirm `loaded=true`.",
                ],
            )

    def _require_ghidra(self) -> None:
        if self.ghidra_tools is None:
            raise ActionableError(
                "No program loaded (Ghidra tools unavailable)",
                context={"state": "no-active-program"},
                next_steps=[
                    "Call `open` with `path` (local binary/.gpr) or shared server args.",
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
        """Resolve a function by name, entrypoint string, or address/symbol."""
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
        return self._create_paginated_response(
            paginated, offset, limit, total=len(results), mode=mode, **extra_response_fields
        )

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
        pass


# ---------------------------------------------------------------------------
# ToolProviderManager – routes tool calls to the correct provider
# ---------------------------------------------------------------------------


class ToolProviderManager:
    """Routes MCP tool calls to the correct ToolProvider by normalized name."""

    def __init__(self) -> None:
        self.providers: list[ToolProvider] = []
        self._tool_map: dict[str, ToolProvider] = {}
        self.program_info: ProgramInfo | None = None
        self.ghidra_project: Any | None = None  # GhidraProject from PyGhidraContext

    def set_ghidra_project(self, project: Any) -> None:
        """Store the GhidraProject reference so providers can use it for checkout."""
        self.ghidra_project = project

    def _register(self, provider: ToolProvider) -> None:
        provider._manager = self  # back-reference for cross-provider updates
        self.providers.append(provider)
        for tool in provider.list_tools():
            self._tool_map[n(tool.name)] = provider

    def register_all_providers(self) -> None:
        """Import and register every concrete provider."""
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
            GetFunctionToolProvider,
            ImportExportToolProvider,
            MemoryToolProvider,
            ProjectToolProvider,
            ScriptToolProvider,
            StringToolProvider,
            StructureToolProvider,
            SuggestionToolProvider,
            SymbolToolProvider,
            VtableToolProvider,
        )

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
            FunctionToolProvider,
            GetFunctionToolProvider,
            ImportExportToolProvider,
            MemoryToolProvider,
            ProjectToolProvider,
            ScriptToolProvider,
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

    def _get_project_provider(self) -> Any | None:
        for provider in self.providers:
            if hasattr(provider, "_handle_open") and hasattr(provider, "_checkout_shared_program"):
                return provider
        return None

    async def _bootstrap_shared_session_from_env(self, session_id: str, requested_program_key: str) -> None:
        project_provider = self._get_project_provider()
        if project_provider is None:
            return

        host = os.getenv("AGENT_DECOMPILE_SERVER_HOST", "").strip()
        if not host:
            return

        open_args: dict[str, Any] = {
            "serverhost": host,
            "serverport": os.getenv("AGENT_DECOMPILE_SERVER_PORT", "13100").strip() or "13100",
            "serverusername": os.getenv("AGENT_DECOMPILE_SERVER_USERNAME", "").strip(),
            "serverpassword": os.getenv("AGENT_DECOMPILE_SERVER_PASSWORD", "").strip(),
            "path": requested_program_key,
        }

        try:
            await project_provider._handle_open(open_args)
        except Exception as e:
            logger.debug("Shared-session bootstrap failed for %s: %s", requested_program_key, e)

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

    def _find_domain_file_by_name(self, folder: Any, file_name: str, max_results: int = 5000) -> Any | None:
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

    def _activate_local_program_by_path(self, session_id: str, requested_program_key: str) -> ProgramInfo | None:
        project_data = self._resolve_project_data()
        if project_data is None:
            return None

        normalized = str(requested_program_key).strip()
        if not normalized:
            return None

        candidate_paths = [normalized]
        if not normalized.startswith("/"):
            candidate_paths.append(f"/{normalized}")

        domain_file = None
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

        program = None
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

    async def _activate_requested_program(self, session_id: str, requested_program_key: str) -> ProgramInfo | None:
        existing = SESSION_CONTEXTS.get_program_info(session_id, requested_program_key)
        if existing is not None:
            return existing

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
            return activated

        if project_provider is not None:
            await self._bootstrap_shared_session_from_env(session_id, requested_program_key)
            activated = SESSION_CONTEXTS.get_program_info(session_id, requested_program_key)
            if activated is not None:
                return activated

        return self._activate_local_program_by_path(session_id, requested_program_key)

    def list_tools(self) -> list[types.Tool]:
        provider_tools: list[types.Tool] = []
        for p in self.providers:
            provider_tools.extend(p.list_tools())

        by_norm: dict[str, types.Tool] = {}
        for tool in provider_tools:
            by_norm.setdefault(n(tool.name), tool)

        advertised_tools: list[types.Tool] = []
        for canonical_name in ADVERTISED_TOOLS:
            canonical_params = ADVERTISED_TOOL_PARAMS.get(canonical_name, [])

            normalized_name = n(canonical_name)
            provider_tool = by_norm.get(normalized_name)

            schema = getattr(provider_tool, "inputSchema", None) or {"type": "object", "properties": {}, "required": []}
            properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
            required = schema.get("required", []) if isinstance(schema, dict) else []

            props_by_norm: dict[str, Any] = {}
            for key, value in properties.items():
                props_by_norm[n(key)] = value

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

            required_norm: set[str] = {n(str(item)) for item in required}
            advertised_required: list[str] = []
            for param in canonical_params:
                normalized_param = n(param)
                is_required = normalized_param in required_norm
                if not is_required and normalized_param == "mode":
                    is_required = any(selector_alias in required_norm for selector_alias in _SELECTOR_PARAM_ALIASES)
                if is_required:
                    advertised_required.append(to_snake_case(param))

            advertised_tools.append(
                types.Tool(
                    name=to_snake_case(canonical_name),
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
        if program_info is not None and program_info is not self.program_info:
            self.set_program_info(program_info)

        resolved_name: str = resolve_tool_name(name) or name
        if resolved_name in DISABLED_GUI_ONLY_TOOLS:
            return create_error_response(
                ActionableError(
                    f"Tool '{resolved_name}' is disabled (GUI-only). TODO: add capability-gated GUI enablement.",
                    context={"tool": to_snake_case(resolved_name), "state": "gui-only-disabled"},
                    next_steps=[
                        "Run this tool in GUI mode (Code Browser) instead of headless mode.",
                        "Use a headless-compatible alternative tool for automation workflows.",
                    ],
                ),
            )
        session_id: str = get_current_mcp_session_id()
        SESSION_CONTEXTS.add_tool_history(session_id, n(resolved_name), arguments or {})

        norm_name = n(resolved_name)
        provider = self._tool_map.get(norm_name)
        if provider is None:
            return create_error_response(
                ActionableError(
                    f"Unknown tool: {name}",
                    context={"tool": str(name), "state": "unknown-tool"},
                    next_steps=[
                        "Call `list_tools` to discover canonical tool names.",
                        "Retry with the canonical snake_case tool name.",
                    ],
                ),
            )

        norm_args = {n(k): v for k, v in (arguments or {}).items()}

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

        if requested_program_key and requested_program_info is None:
            requested_program_info = await self._activate_requested_program(session_id, requested_program_key)

        session_program_info = SESSION_CONTEXTS.get_active_program_info(session_id)
        effective_program_info = requested_program_info or session_program_info or self.program_info

        if requested_program_key and effective_program_info is None:
            return create_error_response(
                ActionableError(
                    f"Program path '{requested_program_key}' was provided but could not be resolved/opened from the current project or shared repository session.",
                    context={
                        "state": "program-resolution-failed",
                        "requestedProgramPath": requested_program_key,
                    },
                    next_steps=[
                        "Call `list-project-files` to discover the exact program path available in this session.",
                        "Call `open` with that program path (or with shared-server credentials and repository) before retrying this tool.",
                    ],
                ),
            )

        if effective_program_info is not None and provider.program_info is not effective_program_info:
            try:
                provider.set_program_info(effective_program_info)
            except Exception as e:
                logger.warning(f"Failed to set session program info for {provider.__class__.__name__}: {e}")

        return await provider.call_tool(name, arguments)

    def program_opened(self, program_info_or_path: ProgramInfo | os.PathLike | str) -> None:
        if isinstance(program_info_or_path, str):
            # String case: notify providers of program path
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
        for p in self.providers:
            p.program_closed(program_path)

    def cleanup(self) -> None:
        for p in self.providers:
            try:
                p.cleanup()
            except Exception:
                pass


# Backward compatibility aliases
UnifiedToolProviderManager = ToolProviderManager
UnifiedToolProvider = ToolProviderManager
