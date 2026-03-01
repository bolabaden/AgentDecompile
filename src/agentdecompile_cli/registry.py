"""Unified tool registry - schema definitions, normalization, and ToolRegistry class.

Merged from tools_schema.py and tool_registry.py.
Single source of truth for all tool names, parameter schemas, normalization helpers,
and the ToolRegistry that parses and validates arguments.
"""

from __future__ import annotations

import json as _json
import logging
import os
import re

from pathlib import Path
from typing import Any

from mcp import types
from mcp.client.session import ClientSession

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MCP tool names (exact strings expected by Java server)
# ---------------------------------------------------------------------------
TOOLS = [
    "analyze-data-flow",
    "analyze-program",
    "analyze-vtables",
    "apply-data-type",
    "capture-agentdecompile-debug-info",
    "change-processor",
    "checkin-program",
    "create-label",
    "decompile-function",
    "sync-shared-project",
    "export",
    "delete-project-binary",
    "gen-callgraph",
    "get-call-graph",
    "get-current-address",
    "get-current-function",
    "get-current-program",
    "get-data",
    "get-functions",
    "get-references",
    "import-binary",
    "inspect-memory",
    "list-cross-references",
    "list-exports",
    "list-functions",
    "list-imports",
    "list-open-programs",
    "list-project-binaries",
    "list-project-binary-metadata",
    "list-project-files",
    "list-processors",
    "list-strings",
    "manage-bookmarks",
    "manage-comments",
    "manage-data-types",
    "manage-files",
    "manage-function-tags",
    "manage-function",
    "manage-strings",
    "manage-structures",
    "manage-symbols",
    "match-function",
    "execute-script",
    "open-all-programs-in-code-browser",
    "open-program-in-code-browser",
    "open",
    "read-bytes",
    "search-code",
    "search-constants",
    "search-strings",
    "search-symbols",
    "search-symbols-by-name",
    "suggest",
]

# ---------------------------------------------------------------------------
# Resource URIs (exact strings for read_resource)
# ---------------------------------------------------------------------------

RESOURCE_URI_PROGRAMS = "ghidra://programs"
RESOURCE_URI_STATIC_ANALYSIS = "ghidra://static-analysis-results"
RESOURCE_URI_DEBUG_INFO = "ghidra://agentdecompile-debug-info"

RESOURCE_URIS: list[str] = [
    RESOURCE_URI_PROGRAMS,
    RESOURCE_URI_STATIC_ANALYSIS,
    RESOURCE_URI_DEBUG_INFO,
]

# ---------------------------------------------------------------------------
# Parameter names (camelCase) per tool – for building payloads from CLI
# ---------------------------------------------------------------------------


def _params(*names: str) -> list[str]:
    return list(names)


MODE_PARAM_ALIASES: frozenset[str] = frozenset(
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
        "analysismode",
        "behaviormode",
        "kind",
        "strategy",
    },
)

NATURAL_LANGUAGE_INPUT_KEYS: frozenset[str] = frozenset(
    {
        "applescript",
        "naturallanguage",
        "instruction",
        "instructions",
        "commandtext",
        "script",
        "text",
        "input",
        "prompt",
        "query",
        "utterance",
    },
)


def _canonical_param_name(param: str) -> str:
    if normalize_identifier(param) in MODE_PARAM_ALIASES:
        return "mode"
    return param


# Required / common: programPath is optional in GUI, required in headless for program-scoped tools
TOOL_PARAMS: dict[str, list[str]] = {
    "analyze-data-flow": _params("programPath", "functionAddress", "startAddress", "variableName", "direction"),
    "analyze-program": _params( "programPath", "forceAnalysis", "verbose", "noSymbols", "gdts", "programOptions", "threaded", "maxWorkers", "waitForAnalysis" ),
    "analyze-vtables": _params("programPath", "mode", "vtableAddress", "functionAddress", "maxEntries", "maxResults"),
    "apply-data-type": _params("programPath", "addressOrSymbol", "dataTypeString", "archiveName"),
    "capture-agentdecompile-debug-info": _params("message"),
    "change-processor": _params("programPath", "processor", "languageId", "compilerSpecId", "endian"),
    "checkin-program": _params("programPath", "comment", "keepCheckedOut"),
    "create-label": _params("programPath", "addressOrSymbol", "labelName", "setAsPrimary"),
    "decompile-function": _params("functionIdentifier", "includeCallees", "includeCallers", "includeComments", "includeDisassembly", "includeIncomingReferences", "includeReferenceContext", "limit", "offset", "programPath", "signatureOnly", "timeout"),
    "delete-project-binary": _params("programPath", "confirm"),
    "execute-script": _params("code", "programPath", "timeout"),
    "export": _params("programPath", "outputPath", "format", "createHeader", "includeTypes", "includeGlobals", "includeComments", "tags"),
    "gen-callgraph": _params( "programPath", "functionIdentifier", "depth", "direction", "format", "displayType", "includeRefs", "maxDepth", "maxRunTime", "condenseThreshold", "topLayers", "bottomLayers" ),
    "get-call-graph": _params( "programPath", "functionIdentifier", "mode", "depth", "maxDepth", "direction", "startIndex", "maxCallers", "includeCallContext", "functionAddresses" ),
    "get-current-address": _params("programPath"),
    "get-current-function": _params("programPath"),
    "get-current-program": _params("programPath"),
    "get-data": _params("programPath", "addressOrSymbol", "view"),
    "get-functions": _params( "programPath", "identifier", "view", "offset", "limit", "includeCallers", "includeCallees", "includeComments", "includeIncomingReferences", "includeReferenceContext", "filterDefaultNames", "filterByTag", "untagged", "verbose" ),
    "get-references": _params( "programPath", "target", "mode", "direction", "offset", "limit", "libraryName", "startIndex", "maxReferencers", "includeRefContext", "includeDataRefs", "contextLines", "importName", "includeFlow" ),
    "import-binary": _params("path", "destinationFolder", "recursive", "maxDepth", "analyzeAfterImport", "stripLeadingPath", "stripAllContainerPath", "mirrorFs", "enableVersionControl"),
    "inspect-memory": _params("programPath", "mode", "address", "length", "offset", "limit"),
    "list-cross-references": _params("programPath", "address", "direction", "maxResults"),
    "list-exports": _params("programPath", "filter", "maxResults", "offset", "startIndex"),
    "list-functions": _params( "programPath", "mode", "query", "searchString", "minReferenceCount", "startIndex", "maxCount", "offset", "limit", "filterDefaultNames", "filterByTag", "untagged", "hasTags", "verbose", "identifiers" ),
    "list-imports": _params("programPath", "libraryFilter", "maxResults", "offset", "startIndex", "query", "groupByLibrary"),
    "list-open-programs": [],
    "list-processors": _params("filter"),
    "list-project-binaries": [],
    "list-project-binary-metadata": _params("programPath"),
    "list-project-files": [],
    "list-strings": _params("programPath", "filter", "maxResults", "offset"),
    "manage-bookmarks": _params( "programPath", "mode", "addressOrSymbol", "type", "category", "comment", "bookmarks", "searchText", "maxResults", "removeAll", "addressRange", "categories", "types" ),
    "manage-comments": _params( "programPath", "mode", "addressOrSymbol", "function", "lineNumber", "comment", "commentType", "comments", "start", "end", "commentTypes", "searchText", "pattern", "caseSensitive", "maxResults", "overrideMaxFunctionsLimit", "addressRange" ),
    "manage-data-types": _params( "programPath", "mode", "archiveName", "categoryPath", "includeSubcategories", "startIndex", "maxCount", "offset", "limit", "dataTypeString", "addressOrSymbol" ),
    "manage-files": _params( "mode", "path", "sourcePath", "filePath", "programPath", "newPath", "destinationPath", "newName", "content", "encoding", "createParents", "keep", "force", "exclusive", "dryRun", "maxResults", "destinationFolder", "recursive", "maxDepth", "analyzeAfterImport", "stripLeadingPath", "stripAllContainerPath", "mirrorFs", "enableVersionControl", "exportType", "format", "includeParameters", "includeVariables", "includeComments" ),
    "manage-function-tags": _params("programPath", "function", "mode", "tags"),
    "manage-function": _params( "programPath", "mode", "address", "functionIdentifier", "name", "functions", "oldName", "newName", "variableMappings", "prototype", "variableName", "newType", "datatypeMappings", "archiveName", "createIfNotExists", "propagate", "propagateProgramPaths", "propagateMaxCandidates", "propagateMaxInstructions" ),
    "manage-strings": _params( "programPath", "mode", "pattern", "searchString", "filter", "query", "startIndex", "maxCount", "offset", "limit", "includeReferencingFunctions" ),
    "manage-structures": _params( "programPath", "mode", "cDefinition", "headerContent", "structureName", "name", "size", "type", "category", "packed", "description", "fields", "addressOrSymbol", "clearExisting", "force", "nameFilter", "includeBuiltIn", "fieldName", "dataType", "offset", "comment", "bitfield", "newDataType", "newFieldName", "newComment", "newLength" ),
    "manage-symbols": _params( "programPath", "mode", "address", "labelName", "newName", "libraryFilter", "startIndex", "maxCount", "offset", "limit", "groupByLibrary", "includeExternal", "filterDefaultNames", "demangleAll" ),
    "match-function": _params( "programPath", "functionIdentifier", "targetProgramPaths", "maxInstructions", "minSimilarity", "propagateNames", "propagateTags", "propagateComments", "filterDefaultNames", "filterByTag", "maxFunctions", "batchSize" ),
    "open-all-programs-in-code-browser": _params("extensions", "folderPath"),
    "open-program-in-code-browser": _params("programPath"),
    "open": _params( "path", "extensions", "openAllPrograms", "destinationFolder", "analyzeAfterImport", "enableVersionControl", "serverUsername", "serverPassword", "serverHost", "serverPort" ),
    "read-bytes": _params("programPath", "address", "length"),
    "search-code": _params( "programPath", "pattern", "maxResults", "offset", "caseSensitive", "searchMode", "includeFullCode", "previewLength", "similarityThreshold", "overrideMaxFunctionsLimit" ),
    "search-constants": _params("programPath", "mode", "value", "minValue", "maxValue", "maxResults", "includeSmallValues", "topN"),
    "search-strings": _params("programPath", "pattern", "searchString", "maxResults"),
    "search-symbols-by-name": _params("programPath", "query", "maxResults", "offset"),
    "search-symbols": _params("programPath", "query", "offset", "limit", "includeExternal", "filterDefaultNames"),
    "suggest": _params("programPath", "suggestionType", "address", "function", "dataType", "variableAddress"),
    "sync-shared-project": _params( "mode", "path", "sourcePath", "newPath", "destinationPath", "destinationFolder", "recursive", "maxResults", "force", "dryRun" ),
}

# Populated from TOOLS_LIST.md when available.
# Key: normalized canonical tool name -> {normalized param alias -> {normalized canonical params}}
TOOL_PARAM_ALIASES: dict[str, dict[str, set[str]]] = {}

# Populated from TOOLS_LIST.md overload/synonyms when available.
# Key: normalized alias tool name -> canonical kebab-case tool name
TOOL_ALIASES: dict[str, str] = {}

# Alias tools accepted for compatibility but intentionally not advertised.
# TODO(gui-only): Keep GUI-only tools disabled in headless advertisement/call flow.
NON_ADVERTISED_TOOL_ALIASES: dict[str, str] = {
    # Canonical tools forwarded to parent tools
    "create-label": "manage-symbols",
    "download-shared-repository": "sync-shared-project",
    "sync-shared-repository": "sync-shared-project",
    "pull-shared-repository": "sync-shared-project",
    "push-shared-repository": "sync-shared-project",
    "download-shared-project": "sync-shared-project",
    "gen-callgraph": "get-call-graph",
    "list-cross-references": "get-references",
    "list-exports": "manage-symbols",
    "list-imports": "manage-symbols",
    "list-strings": "manage-strings",
    "search-strings": "manage-strings",
    "search-symbols": "manage-symbols",
    "search-symbols-by-name": "manage-symbols",
    # analyze-data-flow overloads
    "find-variable-accesses": "analyze-data-flow",
    "trace-data-flow-backward": "analyze-data-flow",
    "trace-data-flow-forward": "analyze-data-flow",
    # analyze-vtables overloads
    "analyze-vtable": "analyze-vtables",
    "find-vtable-callers": "analyze-vtables",
    "find-vtables-containing-function": "analyze-vtables",
    # capture-agentdecompile-debug-info overloads
    "capture-reva-debug-info": "capture-agentdecompile-debug-info",
    # decompile-function overloads/synonyms
    "get-decompilation": "decompile-function",
    # get-call-graph overloads
    "find-common-callers": "get-call-graph",
    "get-call-tree": "get-call-graph",
    "get-callers-decompiled": "get-call-graph",
    # get-functions overloads/synonyms
    "get-function-by-address": "get-functions",
    "find-function": "get-functions",
    "get-all-functions": "list-functions",
    # get-references overloads
    "find-cross-references": "get-references",
    "find-import-references": "get-references",
    "get-referencers-decompiled": "get-references",
    "resolve-thunk": "get-references",
    # import-binary overloads/legacy
    "import-file": "import-binary",
    # inspect-memory overloads
    "get-memory-blocks": "inspect-memory",
    "read-memory": "inspect-memory",
    "read-bytes": "inspect-memory",
    # list-functions overloads
    "get-function-count": "list-functions",
    "get-functions-by-similarity": "list-functions",
    "get-undefined-function-candidates": "list-functions",
    "list-methods": "list-functions",
    # manage-bookmarks overloads/legacy
    "set-bookmark": "manage-bookmarks",
    "get-bookmarks": "manage-bookmarks",
    "remove-bookmark": "manage-bookmarks",
    "search-bookmarks": "manage-bookmarks",
    "list-bookmark-categories": "manage-bookmarks",
    # manage-comments overloads/legacy
    "set-comment": "manage-comments",
    "get-comments": "manage-comments",
    "remove-comment": "manage-comments",
    "search-comments": "manage-comments",
    "set-decompilation-comment": "manage-comments",
    # manage-data-types overloads
    "get-data-type-archives": "manage-data-types",
    "get-data-type-by-string": "manage-data-types",
    "get-data-types": "manage-data-types",
    # manage-function overloads/legacy
    "rename-function": "manage-function",
    "rename-function-by-address": "manage-function",
    "set-function-prototype": "manage-function",
    "set-local-variable-type": "manage-function",
    "rename-variable": "manage-function",
    "change-variable-datatypes": "manage-function",
    "create-function": "manage-function",
    "rename-variables": "manage-function",
    # manage-function-tags overloads
    "function-tags": "manage-function-tags",
    # manage-strings overloads
    "get-strings": "manage-strings",
    "get-strings-by-similarity": "manage-strings",
    "get-strings-count": "manage-strings",
    "search-strings-regex": "manage-strings",
    # manage-structures overloads
    "add-structure-field": "manage-structures",
    "apply-structure": "manage-structures",
    "create-structure": "manage-structures",
    "delete-structure": "manage-structures",
    "get-structure-info": "manage-structures",
    "list-structures": "manage-structures",
    "modify-structure-field": "manage-structures",
    "modify-structure-from-c": "manage-structures",
    "parse-c-header": "manage-structures",
    "parse-c-structure": "manage-structures",
    "validate-c-structure": "manage-structures",
    # manage-symbols overloads/legacy
    "list-classes": "manage-symbols",
    "list-namespaces": "manage-symbols",
    "rename-data": "manage-symbols",
    "get-symbols": "manage-symbols",
    "get-symbols-count": "manage-symbols",
    # search-code overloads
    "search-decompilation": "search-code",
    # search-constants overloads
    "find-constant-uses": "search-constants",
    "find-constants-in-range": "search-constants",
    "list-common-constants": "search-constants",
    # search-symbols legacy
    "search-functions-by-name": "search-symbols",
}

# TODO: GUI Only tools/commands
# Disabled for MCP/CLI usage in this headless-focused surface.
# Re-enable when a GUI capability flag is introduced.
DISABLED_GUI_ONLY_TOOLS: frozenset[str] = frozenset(
    {
        "get-current-address",
        "get-current-function",
        "open-program-in-code-browser",
        "open-all-programs-in-code-browser",
    },
)


def to_camel_case_key(key: str) -> str:
    """Convert snake_case to camelCase for MCP payload keys."""
    parts = key.split("_")
    return parts[0].lower() + "".join(p.capitalize() for p in parts[1:])


def build_tool_payload(snake_kwargs: dict[str, Any]) -> dict[str, Any]:
    """Convert CLI kwargs (snake_case) to MCP payload (camelCase), dropping None."""
    out: dict[str, Any] = {}
    for k, v in snake_kwargs.items():
        if v is None:
            continue
        out[to_camel_case_key(k)] = v
    return out


def get_tool_params(tool_name: str) -> list[str]:
    """Return the list of parameter names (camelCase) for a tool, or empty if unknown."""
    return list(TOOL_PARAMS.get(tool_name, []))


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------


def normalize_identifier(s: str) -> str:
    """Normalize an identifier for case-insensitive, separator-insensitive matching.

    Lowercases, strips whitespace from both sides, and removes ALL non-alphabet
    characters (only a-z letters remain).  Used for fuzzy matching of tool names
    and argument/parameter names so that callers can supply any casing or
    separator style and still get a match.

    Examples::

        normalize_identifier("analyze-data-flow")  # -> "analyzedataflow"
        normalize_identifier("Analyze_Data_Flow")  # -> "analyzedataflow"
        normalize_identifier("programPath")         # -> "programpath"
        normalize_identifier("program_path")        # -> "programpath"
        normalize_identifier("PROGRAM PATH")        # -> "programpath"
    """
    return re.sub(r"[^a-z]", "", s.lower().strip())


def _find_repo_root_for_tools_list() -> Path | None:
    """Best-effort discovery of repository root containing TOOLS_LIST.md."""
    current = Path(__file__).resolve()
    for parent in [current.parent, *current.parents]:
        candidate = parent / "TOOLS_LIST.md"
        if candidate.exists():
            return parent
    return None


def _extract_tools_list_sync_data() -> tuple[dict[str, list[str]], dict[str, dict[str, set[str]]], dict[str, str]]:
    """Parse TOOLS_LIST.md and extract parameter names, param aliases, and tool aliases.

    Returns:
        (params_by_tool, param_aliases_by_tool_norm, tool_aliases_by_norm)
    """
    root = _find_repo_root_for_tools_list()
    if root is None:
        return {}, {}, {}

    tools_list: Path = root / "TOOLS_LIST.md"
    try:
        text = tools_list.read_text(encoding="utf-8")
    except Exception:
        return {}, {}, {}

    parts: list[str] = re.split(r"^### `([^`]+)`(?: \(forwards to `([^`]+)`\))?\n", text, flags=re.MULTILINE)
    if len(parts) < 3:
        return {}, {}, {}

    params_by_tool: dict[str, list[str]] = {}
    param_aliases_by_tool: dict[str, dict[str, set[str]]] = {}
    tool_aliases_by_norm: dict[str, str] = {}

    for i in range(1, len(parts), 3):
        tool_name: str = parts[i]
        forwarded_to: str | None = parts[i + 1]
        body: str = parts[i + 2]
        canonical_tool: str = forwarded_to or tool_name
        canonical_norm: str = normalize_identifier(canonical_tool)

        if forwarded_to and forwarded_to.strip():
            tool_aliases_by_norm[normalize_identifier(tool_name)] = canonical_tool

        params_match: re.Match[str] | None = re.search(
            r"\*\*Parameters\*\*:\n(.*?)(?:\n\*\*Overloads\*\*|\n\*\*Synonyms\*\*|\n\*\*Examples\*\*)",
            body,
            flags=re.DOTALL,
        )
        if params_match is not None:
            block: str = params_match.group(1)
            lines: list[str] = block.splitlines()
            extracted_params: list[str] = []
            alias_map: dict[str, set[str]] = param_aliases_by_tool.setdefault(canonical_norm, {})

            idx = 0
            while idx < len(lines):
                line: str = lines[idx]
                param_match: re.Match[str] | None = re.match(r"^- `([^`]+)` \(", line)
                if param_match is not None:
                    param_name: str = param_match.group(1)
                    extracted_params.append(param_name)
                    canonical_param_norm: str = normalize_identifier(param_name)
                    alias_map.setdefault(canonical_param_norm, set()).add(canonical_param_norm)

                    j = idx + 1
                    while j < len(lines):
                        next_line = lines[j]
                        if next_line.startswith("- `"):
                            break
                        if "Synonyms:" in next_line:
                            for alias in re.findall(r"`([^`]+)`", next_line):
                                alias_map.setdefault(normalize_identifier(alias), set()).add(canonical_param_norm)
                        j += 1
                    idx = j
                    continue
                idx += 1

            if extracted_params:
                existing = params_by_tool.setdefault(canonical_tool, [])
                for param in extracted_params:
                    if normalize_identifier(param) not in {normalize_identifier(x) for x in existing}:
                        existing.append(param)

        overload_match: re.Match[str] | None = re.search(
            r"\*\*Overloads\*\*:\n(.*?)(?:\n\*\*Synonyms\*\*|\n\*\*Examples\*\*)",
            body,
            flags=re.DOTALL,
        )
        if overload_match is not None:
            for alias, target in re.findall(r"- `([^`(]+)\([^`]*\)`.*?forwards to `([^`]+)`", overload_match.group(1)):
                tool_aliases_by_norm[normalize_identifier(alias)] = target

        synonyms_match: re.Match[str] | None = re.search(
            r"\*\*Synonyms\*\*:\s*(.*?)(?:\n\*\*Examples\*\*|\n\*\*API References\*\*|\Z)",
            body,
            flags=re.DOTALL,
        )
        if synonyms_match is not None:
            for alias in re.findall(r"`([^`]+)`", synonyms_match.group(1)):
                tool_aliases_by_norm[normalize_identifier(alias)] = canonical_tool

    return params_by_tool, param_aliases_by_tool, tool_aliases_by_norm


def _merge_tools_list_params(base: dict[str, list[str]], extra: dict[str, list[str]]) -> dict[str, list[str]]:
    """Merge TOOLS_LIST parameter names into TOOL_PARAMS without losing existing names."""
    merged = {k: list(v) for k, v in base.items()}
    for tool, params in extra.items():
        if tool not in merged:
            continue
        existing: list[str] = [_canonical_param_name(param) for param in merged[tool]]
        existing_norm: set[str] = {normalize_identifier(x) for x in existing}
        for param in params:
            canonical_param = _canonical_param_name(param)
            param_norm: str = normalize_identifier(canonical_param)
            if param_norm not in existing_norm:
                existing.append(canonical_param)
                existing_norm.add(param_norm)
        merged[tool] = existing
    return merged


_tools_list_params, _tools_list_param_aliases, _tools_list_tool_aliases = _extract_tools_list_sync_data()
TOOL_PARAMS = _merge_tools_list_params(TOOL_PARAMS, _tools_list_params)
TOOL_PARAM_ALIASES.update(_tools_list_param_aliases)
TOOL_ALIASES.update(_tools_list_tool_aliases)
TOOL_ALIASES.update({normalize_identifier(alias): target for alias, target in NON_ADVERTISED_TOOL_ALIASES.items()})

# Minimal advertised surface (MCP + CLI) by default.
# All tools remain accepted via normalize/resolve/dispatch regardless of advertisement.
DEFAULT_ADVERTISED_TOOLS: tuple[str, ...] = (
    "analyze-data-flow",
    "analyze-program",
    "analyze-vtables",
    "change-processor",
    "checkin-program",
    "decompile-function",
    "execute-script",
    "get-call-graph",
    "get-functions",
    "get-references",
    "inspect-memory",
    "list-functions",
    "list-project-files",
    "manage-bookmarks",
    "manage-comments",
    "manage-data-types",
    "manage-files",
    "manage-function-tags",
    "manage-function",
    "manage-strings",
    "manage-structures",
    "manage-symbols",
    "match-function",
    "open",
    "search-constants",
)

_LEGACY_TOOLS_ENV_VARS: tuple[str, ...] = (
    "AGENTDECOMPILE_SHOW_LEGACY_TOOLS",
    "AGENTDECOMPILE_ENABLE_LEGACY_TOOLS",
)


def _is_truthy_env(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _legacy_tools_advertised() -> bool:
    return any(_is_truthy_env(os.getenv(var_name)) for var_name in _LEGACY_TOOLS_ENV_VARS)


def _build_advertised_tools() -> list[str]:
    canonical_visible = [tool for tool in TOOLS if tool not in DISABLED_GUI_ONLY_TOOLS]
    default_set = {normalize_identifier(tool) for tool in DEFAULT_ADVERTISED_TOOLS}

    if _legacy_tools_advertised():
        return canonical_visible

    return [tool for tool in canonical_visible if normalize_identifier(tool) in default_set]


ADVERTISED_TOOLS: list[str] = _build_advertised_tools()

_ADVERTISED_SELECTOR_ALIASES: tuple[str, ...] = ("action", "operation")


def _build_advertised_tool_params() -> dict[str, list[str]]:
    advertised: dict[str, list[str]] = {}
    advertised_set = set(ADVERTISED_TOOLS)
    for tool, params in TOOL_PARAMS.items():
        if tool not in advertised_set:
            continue
        expanded: list[str] = list(params)
        normalized_expanded = {normalize_identifier(param) for param in expanded}
        if "mode" in normalized_expanded:
            for alias in _ADVERTISED_SELECTOR_ALIASES:
                alias_norm = normalize_identifier(alias)
                if alias_norm not in normalized_expanded:
                    expanded.append(alias)
                    normalized_expanded.add(alias_norm)
        advertised[tool] = expanded
    return advertised


ADVERTISED_TOOL_PARAMS: dict[str, list[str]] = _build_advertised_tool_params()


_TOOL_PREFIXES = (
    "agentdecompile",
    "api",
    "cmd",
    "do",
    "execute",
    "ghidra",
    "mcp",
    "run",
    "tool",
)
_TOOL_SUFFIXES = (
    "action",
    "command",
    "op",
    "task",
    "tool",
)


def resolve_tool_name(tool_name: str) -> str | None:
    """Resolve arbitrary tool aliases/noisy variants to canonical kebab-case tool names."""
    norm = normalize_identifier(tool_name)
    if not norm:
        return None

    by_norm: dict[str, str] = {normalize_identifier(tool): tool for tool in TOOLS}
    direct: str | None = by_norm.get(norm)
    if direct is not None:
        return direct

    aliased: str | None = TOOL_ALIASES.get(norm)
    if aliased is not None:
        return aliased

    stripped: str = norm
    changed: bool = True
    while changed and stripped:
        changed = False
        for prefix in _TOOL_PREFIXES:
            if stripped.startswith(prefix) and len(stripped) > len(prefix):
                stripped = stripped[len(prefix) :]
                changed = True
                break
    changed: bool = True
    while changed and stripped:
        changed = False
        for suffix in _TOOL_SUFFIXES:
            if stripped.endswith(suffix) and len(stripped) > len(suffix):
                stripped = stripped[: -len(suffix)]
                changed = True
                break

    if stripped:
        direct = by_norm.get(stripped)
        if direct is not None:
            return direct
        aliased: str | None = TOOL_ALIASES.get(stripped)
        if aliased is not None:
            return aliased

    return None


def to_snake_case(s: str) -> str:
    """Convert any identifier format to snake_case for advertising.

    Handles:
    - kebab-case:   ``"analyze-data-flow"``  →  ``"analyze_data_flow"``
    - camelCase:    ``"programPath"``         →  ``"program_path"``
    - PascalCase:   ``"ProgramPath"``         →  ``"program_path"``
    - snake_case:   returned unchanged
    """
    # Replace hyphens and spaces with underscores
    s = s.replace("-", "_").replace(" ", "_")
    # Insert underscore before uppercase letters (camelCase / PascalCase)
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    return s.lower()


# ---------------------------------------------------------------------------
# ToolRegistry
# ---------------------------------------------------------------------------


class ToolRegistry:
    """Unified tool registry and argument parsing system."""

    def __init__(self):
        self._tool_params: dict[str, list[str]] = TOOL_PARAMS.copy()
        self._tools: list[str] = ADVERTISED_TOOLS.copy()
        self._tool_aliases: dict[str, str] = TOOL_ALIASES.copy()
        # Pre-computed normalized (alpha-only, lowercase) lookups so that
        # callers using alpha-only keys (e.g. "getdata") resolve correctly
        # alongside the kebab-case storage keys (e.g. "get-data").
        self._params_by_norm: dict[str, list[str]] = {normalize_identifier(k): v for k, v in TOOL_PARAMS.items()}
        self._display_name_by_norm: dict[str, str] = {normalize_identifier(k): k for k in TOOL_PARAMS}
        self._tool_by_norm: dict[str, str] = {normalize_identifier(tool): tool for tool in self._tools}

    def get_tools(self) -> list[str]:
        """Get all available tool names."""
        return list(self._tools)

    def get_tool_params(self, tool_name: str) -> list[str]:
        """Get parameter names for a tool.

        Accepts any tool name format (kebab-case, snake_case, alpha-only, etc.).
        Performs an exact match first, then a normalized (alpha-only, lowercase)
        fallback so callers using the internal alpha-only form still resolve.
        """
        resolved_tool: str = self.resolve_tool_name(tool_name) or tool_name

        # Fast path: exact match on the storage key (kebab-case)
        result: list[str] | None = self._tool_params.get(resolved_tool)
        if result:
            return result
        # Normalized fallback: alpha-only form resolves to kebab-case key params
        return self._params_by_norm.get(normalize_identifier(resolved_tool), [])

    def get_display_name(self, normalized_name: str) -> str:
        """Return the kebab-case display name for an alpha-only (normalized) tool name.

        Used when we need to send the canonical kebab-case name to an external
        backend (e.g. Java MCP server) after resolving internally with alpha-only form.

        Returns the input unchanged if no mapping is found.
        """
        return self._display_name_by_norm.get(
            normalize_identifier(normalized_name),
            normalized_name,
        )

    def is_valid_tool(self, tool_name: str) -> bool:
        """Check if a tool name is valid (with fuzzy matching)."""
        return self.resolve_tool_name(tool_name) is not None

    def resolve_tool_name(self, tool_name: str) -> str | None:
        """Resolve any supported alias/noisy variation to canonical kebab-case name."""
        resolved: str | None = resolve_tool_name(tool_name)
        if resolved is not None:
            return resolved

        # Local fallback using internal tables (defensive; should be redundant).
        norm: str = self.canonicalize_tool_name(tool_name)
        if not norm:
            return None
        direct: str | None = self._tool_by_norm.get(norm)
        if direct is not None:
            return direct
        return self._tool_aliases.get(norm)

    def canonicalize_tool_name(self, tool_name: str) -> str:
        """Canonicalize a tool name for matching by removing all non-alphabet chars.

        Lowercases, strips surrounding whitespace, and removes every character
        that is not an ASCII letter so that separators, digits, and case
        differences are all ignored.  Only the alphabetic characters matter.

        Examples::

            canonicalize_tool_name("analyze-vtables")   # -> "analyzevtables"
            canonicalize_tool_name("analyze_vtables")   # -> "analyzevtables"
            canonicalize_tool_name("Analyze Vtables")   # -> "analyzevtables"

        Args:
        ----
            tool_name: The tool name to canonicalize

        Returns:
        -------
            The canonicalized tool name (only a-z letters, lowercase)
        """
        if not tool_name or not tool_name.strip():
            return ""
        return normalize_identifier(tool_name)

    def match_tool_name(
        self,
        tool_name: str,
        canonical_name: str,
    ) -> bool:
        """Check if a tool name matches a canonical name, handling variations.

        Args:
        ----
            tool_name: The tool name to check
            canonical_name: The canonical tool name to match against

        Returns:
        -------
            True if the tool names match (after canonicalization), False otherwise
        """
        resolved_tool: str | None = self.resolve_tool_name(tool_name)
        resolved_canonical: str | None = self.resolve_tool_name(canonical_name)
        if resolved_canonical is None:
            resolved_canonical = canonical_name
        if resolved_tool is None:
            return False
        return self.canonicalize_tool_name(resolved_tool) == self.canonicalize_tool_name(resolved_canonical)

    def parse_arguments(
        self,
        arguments: dict[str, Any],
        tool_name: str,
    ) -> dict[str, Any]:
        """Parse and validate arguments for a tool using dynamic fuzzy matching.

        This single function replaces all the hardcoded get_*_arg functions.

        Args:
        ----
            arguments: Raw arguments dictionary
            tool_name: Name of the tool to parse arguments for

        Returns:
        -------
            Parsed and validated arguments dictionary
        """
        resolved_tool = self.resolve_tool_name(tool_name)
        if resolved_tool is None:
            raise ValueError(f"Unknown tool: {tool_name}")

        actual_tool_key: str = resolved_tool

        augmented_arguments: dict[str, Any] = self._expand_natural_language_arguments(arguments, actual_tool_key)

        expected_params: list[str] = self._tool_params.get(actual_tool_key, [])
        param_aliases: dict[str, set[str]] = TOOL_PARAM_ALIASES.get(normalize_identifier(actual_tool_key), {})

        parsed_args: dict[str, Any] = {}

        # For each expected parameter, try various naming variations
        for param in expected_params:
            value = self._extract_argument_value(augmented_arguments, param)
            if value is not None:
                parsed_args[param] = value

        # Alias-driven pass: map tool-specific synonym names (from TOOLS_LIST)
        # to canonical parameter keys when not already set.
        if param_aliases:
            expected_by_norm = {normalize_identifier(param): param for param in expected_params}
            for arg_key, arg_val in augmented_arguments.items():
                alias_norm = normalize_identifier(arg_key)
                target_norms = param_aliases.get(alias_norm)
                if not target_norms:
                    continue
                for target_norm in target_norms:
                    canonical_param = expected_by_norm.get(target_norm)
                    if canonical_param is not None and parsed_args.get(canonical_param) is None:
                        parsed_args[canonical_param] = arg_val

        # Pass through arguments not recognized by this tool's param set.
        # Parameters are interchangeable between aliased/forwarded tools
        # (e.g. search-symbols-by-name's "query" must survive resolution to
        # manage-symbols).  The server-side normalization handles the rest.
        parsed_norms: set[str] = {normalize_identifier(k) for k in parsed_args}
        for key, value in augmented_arguments.items():
            if normalize_identifier(key) not in parsed_norms:
                parsed_args[key] = value

        return parsed_args

    def _expand_natural_language_arguments(
        self,
        arguments: dict[str, Any],
        tool_name: str,
    ) -> dict[str, Any]:
        """Expand AppleScript/natural-language payloads into structured arguments.

        Accepts free-form content passed under keys like "appleScript",
        "naturalLanguage", "instruction", etc. Explicit structured arguments
        always win; extracted values only fill missing keys.
        """
        expanded: dict[str, Any] = dict(arguments)

        expected_params = self.get_tool_params(tool_name)
        if not expected_params:
            return expanded

        alias_map: dict[str, str] = self._build_natural_language_alias_map(tool_name, expected_params)

        for key, value in arguments.items():
            key_norm = normalize_identifier(key)
            if key_norm not in NATURAL_LANGUAGE_INPUT_KEYS:
                continue
            if not isinstance(value, str) or not value.strip():
                continue

            # Avoid over-eager NL parsing for opaque scalar values passed via
            # generic keys like "text" (e.g., alias-value tests).  Treat as
            # natural language only when the payload looks sentence/kv-like.
            compact_value = value.strip()
            looks_nl = (
                (" " in compact_value)
                or any(token in compact_value for token in ("=", ":", ",", ";"))
                or (" with " in compact_value.lower())
                or (" and " in compact_value.lower())
            )
            if not looks_nl:
                continue

            extracted = self._extract_natural_language_pairs(value, alias_map)
            for canonical_param, parsed_value in extracted.items():
                # Preserve explicit caller-provided arguments over inferred values.
                if canonical_param not in expanded:
                    expanded[canonical_param] = parsed_value

        return expanded

    def _build_natural_language_alias_map(
        self,
        tool_name: str,
        expected_params: list[str],
    ) -> dict[str, str]:
        """Build normalized alias->canonical-param map for NL extraction."""
        map_out: dict[str, str] = {}
        tool_norm = normalize_identifier(tool_name)
        tool_aliases = TOOL_PARAM_ALIASES.get(tool_norm, {})
        expected_by_norm = {normalize_identifier(param): param for param in expected_params}

        for canonical_param in expected_params:
            canonical_norm = normalize_identifier(canonical_param)
            map_out[canonical_norm] = canonical_param
            for variation in self._generate_param_variations(canonical_param):
                map_out[normalize_identifier(variation)] = canonical_param

        for alias_norm, target_norms in tool_aliases.items():
            for target_norm in target_norms:
                canonical_param = expected_by_norm.get(target_norm)
                if canonical_param is not None:
                    map_out[alias_norm] = canonical_param

        return map_out

    def _extract_natural_language_pairs(
        self,
        text: str,
        alias_map: dict[str, str],
    ) -> dict[str, Any]:
        """Extract key/value pairs from free-form AppleScript/NL text.

        Supported forms include:
        - "programPath=/tmp/a.bin"
        - "program path: '/tmp/a.bin'"
        - "target is main"
        - "with include ref context true and max results 5"
        """
        extracted: dict[str, Any] = {}

        value_pattern = r'"[^\"]*"|\'[^\']*\'|\[[^\]]*\]|\{[^\}]*\}|0x[0-9a-fA-F]+|true|false|-?\d+(?:\.\d+)?|/[^,;\n ]+|[^,;\n ]+'

        kv_pattern = re.compile(
            rf"(?P<key>[A-Za-z][A-Za-z0-9_\-\s]{{1,80}}?)\s*(?:=|:|\bis\b|\bto\b|\bas\b)\s*(?P<value>{value_pattern})(?=\s+\band\b\s+[A-Za-z]|\s+\bwith\b\s+[A-Za-z]|[,;\n]|$)",
            flags=re.IGNORECASE,
        )

        for match in kv_pattern.finditer(text):
            key_raw = match.group("key").strip()
            value_raw = match.group("value").strip()
            canonical_param = alias_map.get(normalize_identifier(key_raw))
            if canonical_param is None:
                continue
            extracted[canonical_param] = self._coerce_natural_language_value(value_raw)

        # Alias-driven phrase extraction handles natural forms like
        # "with program path /tmp/a.bin and max results 10".
        phrases_by_param: dict[str, set[str]] = {}
        for alias_norm, canonical_param in alias_map.items():
            phrase = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", canonical_param)
            phrase = phrase.replace("_", " ").replace("-", " ").strip().lower()
            phrases_by_param.setdefault(canonical_param, set()).add(phrase)
            if alias_norm:
                alias_phrase = " ".join(re.findall(r"[a-z]+", alias_norm))
                if alias_phrase:
                    phrases_by_param[canonical_param].add(alias_phrase)

        for canonical_param, phrases in phrases_by_param.items():
            for phrase in sorted(phrases, key=len, reverse=True):
                if not phrase:
                    continue
                phrase_re = re.escape(phrase).replace("\\ ", r"\s+")
                pattern = re.compile(
                    rf"(?:\bwith\b|\band\b|^|[,;\n])\s*(?:{phrase_re})\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>{value_pattern})(?=\s+\band\b\s+[A-Za-z]|\s+\bwith\b\s+[A-Za-z]|[,;\n]|$)",
                    flags=re.IGNORECASE,
                )
                for match in pattern.finditer(text):
                    value_raw = match.group("value").strip()
                    extracted[canonical_param] = self._coerce_natural_language_value(value_raw)

        # Cleanup common NL artifacts for paths (e.g. "path '/tmp/a.bin'").
        if "programPath" in extracted and isinstance(extracted["programPath"], str):
            cleaned = re.sub(
                r"^(?:program\s+path|program|path|_?path)\s*(?:is\b|[:=])?\s*",
                "",
                extracted["programPath"],
                flags=re.IGNORECASE,
            ).strip()
            cleaned = re.split(r"\s+to\s+", cleaned, maxsplit=1, flags=re.IGNORECASE)[0].strip()
            if (cleaned.startswith('"') and not cleaned.endswith('"')) or (cleaned.startswith("'") and not cleaned.endswith("'")):
                quoted_path_match = re.search(r'"[^"]+"|\'[^\']+\'', text)
                if quoted_path_match:
                    cleaned = quoted_path_match.group(0)
            extracted["programPath"] = self._coerce_natural_language_value(cleaned)

        # Common phrase fallback extraction to improve NL robustness.
        def _capture(name: str, pattern: str, *, flags: int = re.IGNORECASE, transform=None) -> None:
            m = re.search(pattern, text, flags=flags)
            if not m:
                return
            value_raw = m.group("value") if "value" in m.groupdict() else m.group(1)
            value: Any = self._coerce_natural_language_value(value_raw.strip())
            if transform is not None:
                value = transform(value)
            if name not in extracted or extracted.get(name) in (None, "", f"{name}"):
                extracted[name] = value

        # Path/program patterns
        _capture(
            "programPath",
            r"\bprogram\s+path\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>\"[^\"]+\"|'[^']+'|/[^,;\n ]+)",
        )
        _capture(
            "programPath",
            r"\bprogram\s+(?P<value>\"[^\"]+\"|'[^']+'|/[^,;\n ]+)",
        )

        # Address/target/function
        _capture("addressOrSymbol", r"\baddress\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>0x[0-9a-fA-F]+)")
        _capture("addressOrSymbol", r"\bat\s+(?P<value>0x[0-9a-fA-F]+)")
        _capture("target", r"\btarget\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>\"[^\"]+\"|'[^']+'|[^,;\n\s]+)")
        _capture("function", r"\bfunction\s+(?P<value>[A-Za-z_][A-Za-z0-9_]*)")

        # String/search patterns
        _capture("pattern", r"\bpattern\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>\"[^\"]+\"|'[^']+'|[^,;\n\s]+)")
        _capture("query", r"\bquery\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>\"[^\"]+\"|'[^']+'|[^,;\n\s]+)")
        _capture("comment", r"\bcomment\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>\"[^\"]+\"|'[^']+')")
        _capture("mode", r"\bmode\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>[A-Za-z_][A-Za-z0-9_]*)")

        # Boolean flags
        _capture("includeRefContext", r"\binclude\s+ref\s+context\s+(?P<value>true|false)")
        _capture("includeDataRefs", r"\binclude\s+data\s+refs\s+(?P<value>true|false)")
        _capture("skipAnalysis", r"\bskip\s+analysis\s+(?P<value>true|false)")

        # Numeric options
        _capture("limit", r"\blimit\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>-?\d+)")
        _capture("maxResults", r"\bmax\s+results\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>-?\d+)")
        _capture("maxCount", r"\bmax\s+count\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>-?\d+)")
        _capture("startIndex", r"\bstart\s+index\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>-?\d+)")
        _capture("minLength", r"\bmin\s+length\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>-?\d+)")
        _capture("maxDepth", r"\bmax\s+depth\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>-?\d+)")
        _capture("length", r"\blength\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>-?\d+)")

        # Cleanup common artifacts again after fallback.
        if "programPath" in extracted and isinstance(extracted["programPath"], str):
            cleaned = re.sub(
                r"^(?:program\s+path|program|path|_?path)\s*(?:is\b|[:=])?\s*",
                "",
                extracted["programPath"],
                flags=re.IGNORECASE,
            ).strip()
            cleaned = re.split(r"\s+to\s+", cleaned, maxsplit=1, flags=re.IGNORECASE)[0].strip()
            extracted["programPath"] = self._coerce_natural_language_value(cleaned)

        if "addressOrSymbol" in extracted and "address" not in extracted and "startAddress" not in extracted:
            extracted["address"] = extracted["addressOrSymbol"]

        return extracted

    def _coerce_natural_language_value(self, raw_value: str) -> Any:
        """Coerce natural-language scalar text to bool/int/float/json/string."""
        value = raw_value.strip()
        if not value:
            return value

        if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
            return value[1:-1]

        lowered = value.lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False

        if re.fullmatch(r"-?\d+", value):
            try:
                return int(value)
            except Exception:
                return value

        if re.fullmatch(r"-?\d+\.\d+", value):
            try:
                return float(value)
            except Exception:
                return value

        if (value.startswith("[") and value.endswith("]")) or (value.startswith("{") and value.endswith("}")):
            try:
                return _json.loads(value)
            except Exception:
                return value

        return value

    def _extract_argument_value(
        self,
        arguments: dict[str, Any],
        param_name: str,
    ) -> Any:
        """Extract an argument value using fuzzy matching for parameter names.

        Handles variations like:
        - programPath, program_path, program-path
        - addressOrSymbol, address_or_symbol, addressOrSymbol
        - maxResults, max_results, maxResults

        Args:
        ----
            arguments: Arguments dictionary
            param_name: Canonical parameter name

        Returns:
        -------
            The argument value or None if not found
        """
        # Try exact match first
        if param_name in arguments:
            return arguments[param_name]

        # Try variations of the parameter name
        variations: list[str] = self._generate_param_variations(param_name)

        for variation in variations:
            if variation in arguments:
                return arguments[variation]

        # Selector fallback: canonical "mode" accepts action/operation/etc.
        normalized_param = normalize_identifier(param_name)
        if _canonical_param_name(param_name) == "mode":
            for key, value in arguments.items():
                if normalize_identifier(key) in MODE_PARAM_ALIASES:
                    return value

        # Normalized fallback: strip all non-alpha chars and compare.
        # This means any casing or separator style will match as long as the
        # alphabetic characters are the same.
        for key in arguments:
            if normalize_identifier(key) == normalized_param:
                return arguments[key]

        return None

    def _generate_param_variations(
        self,
        param_name: str,
    ) -> list[str]:
        """Generate parameter name variations.

        Examples:
          - programPath -> [programPath, program_path, program-path]
          - addressOrSymbol -> [addressOrSymbol, address_or_symbol, addressOrSymbol]
          - maxResults -> [maxResults, max_results, maxResults]

        Args:
        ----
            param_name: Canonical parameter name

        Returns:
        -------
            List of parameter name variations
        """
        variations: list[str] = [param_name]

        # Convert camelCase to snake_case
        snake_case: str = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", param_name).lower()
        if snake_case != param_name.lower():
            variations.append(snake_case)

        # Convert camelCase to kebab-case
        kebab_case: str = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", param_name).lower()
        if kebab_case != param_name.lower():
            variations.append(kebab_case)

        # Handle special cases
        if param_name == "addressOrSymbol":
            variations.extend(["address_or_symbol", "addressOrSymbol", "address"])
        elif param_name == "programPath":
            variations.extend(["program_path", "program-path", "program", "filepath", "path"])
        elif param_name == "maxResults":
            variations.extend(["max_results", "max-results", "limit", "maxResults", "limits"])

        return variations

    def validate_required_arguments(
        self,
        arguments: dict[str, Any],
        tool_name: str,
    ) -> None:
        """Validate that required arguments are present for a tool.

        Args:
        ----
            arguments: Parsed arguments
            tool_name: Tool name

        Raises:
        -------
            ValueError: If required arguments are missing
        """
        resolved_tool = self.resolve_tool_name(tool_name) or tool_name
        canonical_name: str = self.canonicalize_tool_name(resolved_tool)
        expected_params: list[str] = self.get_tool_params(canonical_name)  # noqa: F841

        # Define which parameters are required for each tool
        # Keys are alpha-only (normalize_identifier form) so the lookup against
        # canonical_name (which is already alpha-only from canonicalize_tool_name)
        # always succeeds.
        required_params: dict[str, list[str]] = {
            "analyzedataflow": ["programPath"],
            "analyzeprogram": ["programPath"],
            "analyzevtables": ["programPath", "mode"],
            "applydatatype": ["programPath", "addressOrSymbol", "dataTypeString"],
            "createlabel": ["programPath", "addressOrSymbol", "labelName"],
            "decompile": ["programPath"],
            "getcallgraph": ["programPath"],
            "getdata": ["programPath", "addressOrSymbol"],
            "getreferences": ["programPath", "target"],
            "inspectmemory": ["programPath", "mode"],
            "managebookmarks": ["programPath", "mode"],
            "managecomments": ["programPath", "mode"],
            "managestructures": ["programPath", "mode"],
            "open": ["path"],
            "searchconstants": ["programPath", "mode"],
        }

        required: list[str] = required_params.get(canonical_name, [])
        for param in required:
            if param not in arguments or arguments[param] is None:
                raise ValueError(f"Required parameter '{param}' is missing for tool '{tool_name}'")

    def create_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        validate: bool = True,
    ) -> dict[str, Any]:
        """Create a standardized tool call payload.

        Args:
        ----
            tool_name: Name of the tool
            arguments: Tool arguments
            validate: Whether to validate arguments

        Returns:
        -------
            Tool call payload dictionary
        """
        if validate:
            resolved_tool = self.resolve_tool_name(tool_name) or tool_name
            parsed_args: dict[str, Any] = self.parse_arguments(arguments, resolved_tool)
            self.validate_required_arguments(parsed_args, resolved_tool)
        else:
            parsed_args = arguments

        return {
            "name": self.resolve_tool_name(tool_name) or tool_name,
            "arguments": parsed_args,
        }

    def parse_natural_language_tool_call(
        self,
        text: str,
    ) -> tuple[str | None, dict[str, Any]]:
        """Parse a complete free-form tool call sentence into tool name and arguments.

        Accepts full natural language sentences like:
        - "list all functions in program /path/to/binary"
        - "manage symbols with program path '/tmp/a.bin' and mode list"
        - "search strings in program /tmp/test with pattern http and max results 10"

        The tool name is extracted from the beginning of the text (using fuzzy
        matching via normalization), and the remaining text is parsed as
        natural language arguments.

        Args:
        ----
            text: Free-form natural language tool call sentence

        Returns:
        -------
            Tuple of (resolved_tool_name, arguments_dict), or (None, {}) if no tool matched
        """
        if not text or not text.strip():
            return None, {}

        # Normalize the input text for comparison
        text = text.strip()

        # Try to match known tool names from the beginning
        # Sort by length descending to match longer names first (e.g., "search-symbols-by-name" before "search-symbols")
        sorted_tools = sorted(TOOLS, key=len, reverse=True)

        matched_tool: str | None = None
        remaining_text: str = text

        for tool_name in sorted_tools:
            # Create variations of the tool name to match
            variations = [
                tool_name,  # Original (kebab-case)
                tool_name.replace("-", " "),  # Space-separated
                tool_name.replace("-", "_"),  # Snake case
                tool_name.replace("-", ""),  # No separators
            ]

            for variation in variations:
                # Check if text starts with this variation (case-insensitive)
                if text.lower().startswith(variation.lower()):
                    matched_tool = tool_name
                    remaining_text = text[len(variation) :].strip()
                    break

                # Also try with normalized (alpha-only) matching for extra flexibility
                tool_norm = normalize_identifier(variation)
                # Find how many characters at the start of text match the normalized tool name
                text_prefix_norm = normalize_identifier(text[: len(variation)])
                if text_prefix_norm == tool_norm:
                    matched_tool = tool_name
                    remaining_text = text[len(variation) :].strip()
                    break

            if matched_tool:
                break

        if not matched_tool:
            return None, {}

        # Preprocess common English phrases before parsing
        # Convert natural language patterns to explicit key-value forms
        remaining_text = self._preprocess_nl_phrases(remaining_text)

        # Parse the remaining text as natural language arguments
        # Use our existing NL extraction logic
        expected_params = self.get_tool_params(matched_tool)
        if not expected_params:
            return matched_tool, {}

        alias_map = self._build_natural_language_alias_map(matched_tool, expected_params)
        arguments = self._extract_natural_language_pairs(remaining_text, alias_map)

        return matched_tool, arguments

    def _preprocess_nl_phrases(self, text: str) -> str:
        """Preprocess common English phrases into explicit key-value forms.

        Converts patterns like:
        - "in program /path" → "with program path /path"
        - "from program /path" → "with program path /path"
        - "at address 0x1000" → "with address 0x1000"
        - "for function main" → "with function main"
        """
        if not text or not text.strip():
            return text

        # Define common phrase patterns and their replacements
        # These are applied in order, so more specific patterns should come first
        replacements = [
            # "in program X" → "with program path X"
            (r"\b(in|from|on)\s+program\s+", r"with program path ", re.IGNORECASE),
            # "at address X" → "with address X"
            (r"\bat\s+address\s+", r"with address ", re.IGNORECASE),
            # "to address X" → "with address X"
            (r"\bto\s+address\s+", r"with address ", re.IGNORECASE),
            # "for function X" → "with function X"
            (r"\bfor\s+function\s+", r"with function ", re.IGNORECASE),
            # "of function X" → "with function X"
            (r"\bof\s+function\s+", r"with function ", re.IGNORECASE),
            # "at offset X" → "with offset X"
            (r"\bat\s+offset\s+", r"with offset ", re.IGNORECASE),
            # "in binary X" → "with program path X"
            (r"\b(in|from)\s+binary\s+", r"with program path ", re.IGNORECASE),
            # "to project X" → "with project name X"
            (r"\bto\s+project\s+", r"with project name ", re.IGNORECASE),
            # "in project X" → "with project name X"
            (r"\bin\s+project\s+", r"with project name ", re.IGNORECASE),
            # "from X to Y" for import/export → keep the structure but add explicit markers
            # (handled by existing patterns)
        ]

        processed_text = text
        for pattern, replacement, flags in replacements:
            processed_text = re.sub(pattern, replacement, processed_text, flags=flags)

        return processed_text

    def execute_tool_cli(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        client: ClientSession | None = None,
    ) -> Any:
        """Execute a tool via CLI client.

        Args:
        ----
            tool_name: Tool name
            arguments: Tool arguments
            client: MCP client instance

        Returns:
        -------
            Tool execution result
        """
        if client is None:
            raise ValueError("MCP client is required")

        tool_call: dict[str, Any] = self.create_tool_call(tool_name, arguments)

        # Use the client's tool execution method
        result: Any = client.call_tool(tool_call["name"], tool_call["arguments"])
        return result

    def format_tool_response(
        self,
        response: list[types.TextContent] | None = None,
        output_format: str = "text",
    ) -> str:
        """Format tool response for CLI output.

        Args:
        ----
            response: MCP tool response
            output_format: Output format (json, text, table)

        Returns:
        -------
            Formatted response string
        """
        if not response:
            return ""

        # Extract JSON content from response
        json_content: str = ""
        for content in response:
            if content.type == "text":
                json_content = content.text
                break

        if not json_content or not json_content.strip():
            return "No response content"

        try:
            data: Any = _json.loads(json_content)

            if output_format.lower().strip() == "json":
                return _json.dumps(data, indent=2)
            if output_format.lower().strip() == "text":
                if isinstance(data, dict):
                    return "\n".join(f"{k}: {v}" for k, v in data.items())
                if isinstance(data, list):
                    return "\n".join(f"- {item}" for item in data)
                return str(data)
            if output_format.lower().strip() == "table":
                if isinstance(data, list) and data and isinstance(data[0], dict):
                    headers = list(data[0].keys())
                    lines = [" | ".join(headers), "-" * (len(headers) * 10)]
                    for item in data:
                        row = [str(item.get(h, "")) for h in headers]
                        lines.append(" | ".join(row))
                    return "\n".join(lines)
                return str(data)
            return str(data)

        except _json.JSONDecodeError:
            return json_content


# Global tool registry instance
tool_registry = ToolRegistry()
