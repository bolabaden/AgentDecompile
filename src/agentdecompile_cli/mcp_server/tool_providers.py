"""Base ToolProvider with centralized normalization, dispatch, and manager.

ALL normalization happens HERE, in ONE place.  The single canonical function
is ``n()`` (alias for ``registry.normalize_identifier``).  It strips everything
except lowercase ASCII letters: ``re.sub(r'[^a-z]', '', s.lower())``.

Flow:
  1. MCP Server → ToolProviderManager.call_tool(name, arguments)
  2. Manager normalizes ``name`` → looks up the owning ToolProvider
  3. Provider.call_tool() normalizes ALL argument keys, dispatches to handler.
  4. Handler uses ``self._get(args, ...)`` helpers on already-normalized dicts.
"""

from __future__ import annotations

import json as _json
import logging
import os

from pathlib import Path
from typing import TYPE_CHECKING, Any

from mcp import types

from agentdecompile_cli.mcp_server.session_context import (
    SESSION_CONTEXTS,
    get_current_mcp_session_id,
)
from agentdecompile_cli.registry import ADVERTISED_TOOL_PARAMS, ADVERTISED_TOOLS, DISABLED_GUI_ONLY_TOOLS, TOOL_PARAM_ALIASES, normalize_identifier, resolve_tool_name, to_snake_case

if TYPE_CHECKING:
    from agentdecompile_cli.launcher import ProgramInfo

logger = logging.getLogger(__name__)

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
        "mode",
        "action",
        "operation",
        "command",
        "op",
        "task",
        "intent",
        "verb",
        "actiontype",
        "method",
        "type",
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
    for prefix in ("include", "filter", "enable", "propagate", "strip", "mirror", "override"):
        if norm.startswith(prefix) and len(norm) > len(prefix) and norm not in _BOOL_PREFIX_EXCEPTIONS:
            return {"type": "boolean"}
    return {"type": "string"}


# ---------------------------------------------------------------------------
# Response helpers (canonical location)
# ---------------------------------------------------------------------------


def create_success_response(data: dict[str, Any]) -> list[types.TextContent]:
    """Create a standardized MCP success response."""
    return [types.TextContent(type="text", text=_json.dumps(data))]


def create_error_response(error: str | Exception) -> list[types.TextContent]:
    """Create a standardized MCP error response."""
    msg = str(error) if isinstance(error, Exception) else error
    return [types.TextContent(type="text", text=_json.dumps({"success": False, "error": msg}))]


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

    ``call_tool()`` normalizes the tool name and ALL argument keys in ONE
    place, dispatches to the handler, and wraps any exception as an error
    response.  Handlers read a dict whose keys are already lowercase a-z only.
    """

    HANDLERS: dict[str, str] = {}

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
        resolved_name = resolve_tool_name(name) or name
        norm_name = n(resolved_name)

        handler_method_name = self.HANDLERS.get(norm_name)
        if handler_method_name is None:
            raise NotImplementedError(f"Unknown tool: {name}")

        handler = getattr(self, handler_method_name)

        # Normalize ALL argument keys – the ONE place normalization happens.
        norm_args: dict[str, Any] = {n(k): v for k, v in (arguments or {}).items()}

        # Tool-specific parameter synonym bridging from TOOLS_LIST.md.
        alias_map = TOOL_PARAM_ALIASES.get(norm_name, {})
        if alias_map:
            for key, value in list(norm_args.items()):
                targets = alias_map.get(key)
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
            return create_error_response(e)

    # ------------------------------------------------------------------
    # Argument extraction helpers (on already-normalized dicts)
    # ------------------------------------------------------------------

    @staticmethod
    def _get(args: dict[str, Any], *keys: str, default: Any = None) -> Any:
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

    # ------------------------------------------------------------------
    # Program guards
    # ------------------------------------------------------------------

    def _require_program(self) -> None:
        if self.program_info is None or getattr(self.program_info, "program", None) is None:
            raise ValueError("No program loaded")

    def _require_ghidra(self) -> None:
        if self.ghidra_tools is None:
            raise ValueError("No program loaded (Ghidra tools unavailable)")

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

            required_norm = {n(str(item)) for item in required}
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

        resolved_name = resolve_tool_name(name) or name
        if resolved_name in DISABLED_GUI_ONLY_TOOLS:
            return create_error_response(
                f"Tool '{resolved_name}' is disabled (GUI-only). TODO: add capability-gated GUI enablement.",
            )
        session_id = get_current_mcp_session_id()
        SESSION_CONTEXTS.add_tool_history(session_id, n(resolved_name), arguments or {})

        norm_name = n(resolved_name)
        provider = self._tool_map.get(norm_name)
        if provider is None:
            return create_error_response(f"Unknown tool: {name}")

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
                f"Program path '{requested_program_key}' was provided but could not be resolved/opened from the current project or shared repository session.",
            )

        if effective_program_info is not None and provider.program_info is not effective_program_info:
            try:
                provider.set_program_info(effective_program_info)
            except Exception as e:
                logger.warning(f"Failed to set session program info for {provider.__class__.__name__}: {e}")

        return await provider.call_tool(resolved_name, arguments)

    def program_opened(self, program_info_or_path: ProgramInfo | os.PathLike | str) -> None:
        if isinstance(program_info_or_path, str):
            for p in self.providers:
                p.program_opened(program_info_or_path)
        else:
            if program_info_or_path is None:
                raise ValueError("`program_info_or_path` is required to initialize Ghidra tools")
            if isinstance(program_info_or_path, (os.PathLike, str)):
                from agentdecompile_cli.context import ProgramInfo

                _path = Path(str(program_info_or_path))
                program_info_or_path = ProgramInfo(  # type: ignore[call-arg]
                    name=_path.name,
                    program=None,  # type: ignore[arg-type]
                    flat_api=None,
                    decompiler=None,  # type: ignore[arg-type]
                    metadata={},
                    ghidra_analysis_complete=False,
                    file_path=_path,
                )
            self.set_program_info(program_info_or_path)

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
