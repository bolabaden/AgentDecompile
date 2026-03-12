"""Unified tool registry - schema definitions, normalization, and ToolRegistry class.

Merged from tools_schema.py and tool_registry.py. Single source of truth for:
  - Tool names: ToolName enum (canonical kebab-case); TOOLS list for advertisement.
  - Parameter schemas: TOOL_PARAMS, TOOL_PARAM_ALIASES (e.g. mode/action/operation).
  - Normalization: normalize_identifier() strips non-alpha and lowercases so that
    "program-path", "programPath", and "program_path" all match the same param.
  - Resolution: resolve_tool_name() / resolve_tool_name_enum() map input to ToolName.
  - Resource URIs: RESOURCE_URIS, RESOURCE_URI_DEBUG_INFO, etc. for read_resource.

Tool execution flow: CLI or MCP client sends tool name + args → registry normalizes
tool name and param keys → ToolProviderManager dispatches to provider HANDLERS →
handlers use _get_* / _require_* with normalized keys. Do not add provider-local
normalization; keep it all here.
"""

from __future__ import annotations

import json as _json
import logging
import os
import re

from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any

from mcp import types
from mcp.client.session import ClientSession

logger = logging.getLogger(__name__)

_NON_ALPHA_PATTERN = re.compile(r"[^a-z]")

# ---------------------------------------------------------------------------
# Precompiled regex patterns (used in NL extraction and value coercion)
# ---------------------------------------------------------------------------
# These are compiled once at module load, not in hot loops/functions

_CAMEL_TO_SNAKE_PATTERN = re.compile(r"([a-z0-9])([A-Z])")
_CAMEL_TO_KEBAB_PATTERN = re.compile(r"([a-z0-9])([A-Z])")

# Natural language value patterns
_QUOTED_STR_PATTERN = re.compile(r'"[^\\"]*"|\'[^\']*\'')
_HEX_PATTERN = re.compile(r"0x[0-9a-fA-F]+")
_INT_PATTERN = re.compile(r"-?\d+$")
_FLOAT_PATTERN = re.compile(r"-?\d+\.\d+$")
_JSON_PATTERN = re.compile(r"^[\[\{].*[\]\}]$", re.DOTALL)

# NL value extraction patterns (used in _extract_natural_language_pairs)
_NL_VALUE_PATTERN = r'"[^\"]*"|\'[^\']*\'|\[[^\]]*\]|\{[^\}]*\}|0x[0-9a-fA-F]+|true|false|-?\d+(?:\.\d+)?|/[^,;\n ]+|[^,;\n ]+'
_NL_KV_PATTERN = re.compile(
    rf"(?P<key>[A-Za-z][A-Za-z0-9_\-\s]{{1,80}}?)\s*(?:=|:|\bis\b|\bto\b|\bas\b)\s*(?P<value>{_NL_VALUE_PATTERN})(?=\s+\band\b\s+[A-Za-z]|\s+\bwith\b\s+[A-Za-z]|[,;\n]|$)",
    flags=re.IGNORECASE,
)
_NL_PHRASE_VALUE_PATTERN_TEMPLATE = (
    rf"(?:\bwith\b|\band\b|^|[,;\n])\s*(?:__PHRASE_RE__)\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*"
    rf"(?P<value>{_NL_VALUE_PATTERN})(?=\s+\band\b\s+[A-Za-z]|\s+\bwith\b\s+[A-Za-z]|[,;\n]|$)"
)

# Program path cleanup patterns
_PROGRAM_PATH_CLEANUP_PATTERN = re.compile(
    r"^(?:program\s+path|program|path|_?path)\s*(?:is\b|[:=])?\s*",
    flags=re.IGNORECASE,
)
_PROGRAM_PATH_SCOPE_PATTERN = re.compile(r"\s+to\s+", flags=re.IGNORECASE)
_QUOTED_PATH_PATTERN = re.compile(r'"[^"]+"|\'[^\']+\'')


@lru_cache(maxsize=512)
def _compile_nl_phrase_pattern(phrase: str) -> re.Pattern[str]:
    """Return cached regex used to capture values for a normalized NL phrase."""
    phrase_re = re.escape(phrase).replace("\\ ", r"\s+")
    pattern_text = _NL_PHRASE_VALUE_PATTERN_TEMPLATE.replace("__PHRASE_RE__", phrase_re)
    return re.compile(
        pattern_text,
        flags=re.IGNORECASE,
    )


# NL phrase preprocessing patterns (used in _preprocess_nl_phrases)
_NL_PHRASE_PATTERNS = [
    (r"\b(in|from|on)\s+program\s+", r"with program path ", re.IGNORECASE),
    (r"\bat\s+address\s+", r"with address ", re.IGNORECASE),
    (r"\bto\s+address\s+", r"with address ", re.IGNORECASE),
    (r"\bfor\s+function\s+", r"with function ", re.IGNORECASE),
    (r"\bof\s+function\s+", r"with function ", re.IGNORECASE),
    (r"\bat\s+offset\s+", r"with offset ", re.IGNORECASE),
    (r"\b(in|from)\s+binary\s+", r"with program path ", re.IGNORECASE),
    (r"\bto\s+project\s+", r"with project name ", re.IGNORECASE),
    (r"\bin\s+project\s+", r"with project name ", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# MCP tool names (canonical wire names) – enum is single source of truth
# ---------------------------------------------------------------------------


class ToolName(str, Enum):
    """Canonical MCP tool names. Use .value for wire/CLI (kebab-case string)."""

    ANALYZE_DATA_FLOW = "analyze-data-flow"
    ANALYZE_PROGRAM = "analyze-program"
    ANALYZE_VTABLES = "analyze-vtables"
    APPLY_DATA_TYPE = "apply-data-type"
    CHANGE_PROCESSOR = "change-processor"
    CHECKIN_PROGRAM = "checkin-program"
    CHECKOUT_PROGRAM = "checkout-program"
    CHECKOUT_STATUS = "checkout-status"
    CREATE_LABEL = "create-label"
    DECOMPILE_FUNCTION = "decompile-function"
    DELETE_PROJECT_BINARY = "delete-project-binary"
    SYNC_PROJECT = "sync-project"
    EXPORT = "export"
    GEN_CALLGRAPH = "gen-callgraph"
    GET_CALL_GRAPH = "get-call-graph"
    REMOVE_PROGRAM_BINARY = "remove-program-binary"
    GET_CURRENT_ADDRESS = "get-current-address"
    GET_CURRENT_FUNCTION = "get-current-function"
    GET_CURRENT_PROGRAM = "get-current-program"
    GET_DATA = "get-data"
    GET_FUNCTION = "get-function"
    GET_FUNCTIONS = "get-functions"
    GET_REFERENCES = "get-references"
    IMPORT_BINARY = "import-binary"
    INSPECT_MEMORY = "inspect-memory"
    LIST_CROSS_REFERENCES = "list-cross-references"
    LIST_EXPORTS = "list-exports"
    LIST_FUNCTIONS = "list-functions"
    LIST_IMPORTS = "list-imports"
    LIST_PROJECT_FILES = "list-project-files"
    LIST_PROCESSORS = "list-processors"
    LIST_STRINGS = "list-strings"
    MANAGE_BOOKMARKS = "manage-bookmarks"
    MANAGE_COMMENTS = "manage-comments"
    MANAGE_DATA_TYPES = "manage-data-types"
    MANAGE_FILES = "manage-files"
    MANAGE_FUNCTION_TAGS = "manage-function-tags"
    MANAGE_FUNCTION = "manage-function"
    MANAGE_STRINGS = "manage-strings"
    MANAGE_STRUCTURES = "manage-structures"
    MANAGE_SYMBOLS = "manage-symbols"
    MATCH_FUNCTION = "match-function"
    EXECUTE_SCRIPT = "execute-script"
    OPEN_ALL_PROGRAMS_IN_CODE_BROWSER = "open-all-programs-in-code-browser"
    OPEN_PROGRAM_IN_CODE_BROWSER = "open-program-in-code-browser"
    OPEN_PROJECT = "open-project"
    READ_BYTES = "read-bytes"
    SEARCH_CODE = "search-code"
    SEARCH_CONSTANTS = "search-constants"
    SEARCH_EVERYTHING = "search-everything"
    SEARCH_STRINGS = "search-strings"
    SEARCH_SYMBOLS = "search-symbols"
    SVR_ADMIN = "svr-admin"
    SUGGEST = "suggest"


TOOLS: list[str] = [t.value for t in ToolName]


# ---------------------------------------------------------------------------
# Resource URIs (exact strings for read_resource)
# ---------------------------------------------------------------------------


class ResourceUri(str, Enum):
    """Canonical resource URIs for read_resource."""

    DEBUG_INFO = "agentdecompile://debug-info"


RESOURCE_URI_DEBUG_INFO = ResourceUri.DEBUG_INFO.value
RESOURCE_URI_PROGRAMS = "ghidra://programs"
RESOURCE_URI_STATIC_ANALYSIS = "ghidra://static-analysis-results"

RESOURCE_URIS: list[str] = [u.value for u in ResourceUri]

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
# Built as str keys for _merge_tools_list_params; then converted to dict[ToolName, list[str]] below.
_TOOL_PARAMS_STR: dict[str, list[str]] = {
    "analyze-data-flow": _params("programPath", "functionAddress", "startAddress", "variableName", "direction"),
    "analyze-program": _params("programPath", "analyzers", "force"),
    "analyze-vtables": _params("programPath", "mode", "vtableAddress", "functionAddress", "maxEntries", "maxResults"),
    "apply-data-type": _params("programPath", "addressOrSymbol", "dataTypeString", "archiveName"),
    "change-processor": _params("programPath", "processor", "languageId", "compilerSpecId", "endian"),
    "checkin-program": _params("programPath", "comment", "keepCheckedOut"),
    "checkout-program": _params("programPath", "exclusive"),
    "checkout-status": _params("programPath"),
    "create-label": _params("programPath", "addressOrSymbol", "labelName", "setAsPrimary"),
    "decompile-function": _params("functionIdentifier", "includeCallees", "includeCallers", "includeComments", "includeDisassembly", "includeIncomingReferences", "includeReferenceContext", "limit", "offset", "programPath", "signatureOnly", "timeout"),
    "delete-project-binary": _params("programPath", "confirm"),
    "get-function": _params("programPath", "function", "addressOrSymbol", "functionIdentifier", "timeout", "maxInstructions", "maxRefs"),
    "remove-program-binary": _params("programPath", "confirm"),
    "execute-script": _params("code", "programPath", "timeout"),
    "export": _params("programPath", "outputPath", "format", "createHeader", "includeTypes", "includeGlobals", "includeComments", "tags"),
    "gen-callgraph": _params("programPath", "functionIdentifier", "depth", "direction", "format", "displayType", "includeRefs", "maxDepth", "maxRunTime", "condenseThreshold", "topLayers", "bottomLayers"),
    "get-call-graph": _params("programPath", "functionIdentifier", "mode", "depth", "maxDepth", "direction", "startIndex", "maxCallers", "includeCallContext", "functionAddresses"),
    "get-current-address": _params("programPath"),
    "get-current-function": _params("programPath"),
    "get-current-program": _params("programPath"),
    "get-data": _params("programPath", "addressOrSymbol"),
    "get-functions": _params("programPath", "identifier", "view", "offset", "limit", "includeCallers", "includeCallees", "includeComments", "includeIncomingReferences", "includeReferenceContext", "filterDefaultNames", "filterByTag", "untagged", "verbose"),
    "get-references": _params("programPath", "target", "mode", "direction", "offset", "limit", "libraryName", "startIndex", "maxReferencers", "includeRefContext", "includeDataRefs", "contextLines", "importName", "includeFlow"),
    "import-binary": _params("path", "destinationFolder", "recursive", "maxDepth", "analyzeAfterImport", "stripLeadingPath", "stripAllContainerPath", "mirrorFs", "enableVersionControl"),
    "inspect-memory": _params("programPath", "mode", "address", "length", "offset", "limit"),
    "list-cross-references": _params("programPath", "address", "direction", "maxResults"),
    "list-exports": _params("programPath", "filter", "maxResults", "offset", "startIndex"),
    "list-functions": _params("programPath", "mode", "query", "searchString", "minReferenceCount", "startIndex", "maxCount", "offset", "limit", "filterDefaultNames", "filterByTag", "untagged", "hasTags", "verbose", "identifiers"),
    "list-imports": _params("programPath", "libraryFilter", "maxResults", "offset", "startIndex", "query", "groupByLibrary"),
    "list-processors": _params("filter"),
    "list-project-files": [],
    "list-strings": _params("programPath", "filter", "maxResults", "offset"),
    "manage-bookmarks": _params("programPath", "mode", "addressOrSymbol", "type", "category", "comment", "bookmarks", "searchText", "maxResults", "removeAll", "addressRange", "categories", "types"),
    "manage-comments": _params("programPath", "mode", "addressOrSymbol", "function", "lineNumber", "comment", "commentType", "comments", "start", "end", "commentTypes", "searchText", "pattern", "caseSensitive", "maxResults", "overrideMaxFunctionsLimit", "addressRange"),
    "manage-data-types": _params("programPath", "mode", "archiveName", "categoryPath", "includeSubcategories", "startIndex", "maxCount", "offset", "limit", "dataTypeString", "addressOrSymbol"),
    "manage-files": _params(
        "mode",
        "path",
        "sourcePath",
        "filePath",
        "programPath",
        "newPath",
        "destinationPath",
        "newName",
        "content",
        "encoding",
        "createParents",
        "keep",
        "force",
        "exclusive",
        "dryRun",
        "maxResults",
        "destinationFolder",
        "recursive",
        "maxDepth",
        "analyzeAfterImport",
        "stripLeadingPath",
        "stripAllContainerPath",
        "mirrorFs",
        "enableVersionControl",
        "exportType",
        "format",
        "includeParameters",
        "includeVariables",
        "includeComments",
        "processor",
        "languageId",
        "compilerSpecId",
        "endian",
    ),
    "manage-function-tags": _params("programPath", "function", "mode", "tags"),
    "manage-function": _params(
        "programPath", "mode", "address", "functionIdentifier", "name", "functions", "oldName", "newName", "variableMappings", "prototype", "variableName", "newType", "datatypeMappings", "archiveName", "createIfNotExists", "propagate", "propagateProgramPaths", "propagateMaxCandidates", "propagateMaxInstructions"
    ),
    "manage-strings": _params("programPath", "mode", "pattern", "searchString", "filter", "query", "startIndex", "maxCount", "offset", "limit", "includeReferencingFunctions"),
    "manage-structures": _params(
        "programPath",
        "mode",
        "cDefinition",
        "headerContent",
        "structureName",
        "name",
        "size",
        "type",
        "category",
        "packed",
        "description",
        "fields",
        "addressOrSymbol",
        "clearExisting",
        "force",
        "nameFilter",
        "includeBuiltIn",
        "fieldName",
        "dataType",
        "offset",
        "comment",
        "bitfield",
        "newDataType",
        "newFieldName",
        "newComment",
        "newLength",
    ),
    "manage-symbols": _params("programPath", "mode", "address", "labelName", "newName", "libraryFilter", "startIndex", "maxCount", "offset", "limit", "groupByLibrary", "includeExternal", "filterDefaultNames", "demangleAll"),
    "match-function": _params("programPath", "functionIdentifier", "targetProgramPaths", "maxInstructions", "minSimilarity", "propagateNames", "propagateTags", "propagateComments", "filterDefaultNames", "filterByTag", "maxFunctions", "batchSize"),
    "open-all-programs-in-code-browser": _params("extensions", "folderPath"),
    "open-program-in-code-browser": _params("programPath"),
    "open-project": _params("path", "shared", "extensions", "openAllPrograms", "destinationFolder", "analyzeAfterImport", "enableVersionControl", "serverUsername", "serverPassword", "serverHost", "serverPort", "repositoryName"),
    "read-bytes": _params("programPath", "address", "length"),
    "search-code": _params("programPath", "pattern", "maxResults", "offset", "caseSensitive", "searchMode", "includeFullCode", "previewLength", "similarityThreshold", "overrideMaxFunctionsLimit"),
    "search-constants": _params("programPath", "mode", "value", "minValue", "maxValue", "maxResults", "includeSmallValues", "topN"),
    "search-everything": _params("programPath", "programName", "binaryName", "query", "queries", "mode", "scopes", "caseSensitive", "similarityThreshold", "offset", "limit", "perScopeLimit", "maxFunctionsScan", "maxInstructionsScan", "decompileTimeout", "groupByFunction"),
    "search-strings": _params("programPath", "pattern", "searchString", "maxResults"),
    "search-symbols": _params("programPath", "query", "offset", "limit", "includeExternal", "filterDefaultNames"),
    "svr-admin": _params("args", "command", "timeoutSeconds"),
    "suggest": _params("programPath", "suggestionType", "address", "function", "dataType", "variableAddress"),
    "sync-project": _params("mode", "path", "sourcePath", "newPath", "destinationPath", "destinationFolder", "recursive", "maxResults", "force", "dryRun"),
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
    "open": "open-project",
    "switch-project": "open-project",  # folded into open-project
    "download-shared-repository": "sync-project",
    "sync-shared-repository": "sync-project",
    "sync-shared-project": "sync-project",
    "pull-shared-repository": "sync-project",
    "push-shared-repository": "sync-project",
    "download-shared-project": "sync-project",
    "delete-project-binary": "remove-program-binary",
    "gen-callgraph": "get-call-graph",
    "list-cross-references": "get-references",
    "list-strings": "manage-strings",
    "search-strings": "manage-strings",
    # analyze-data-flow overloads
    "find-variable-accesses": "analyze-data-flow",
    "trace-data-flow-backward": "analyze-data-flow",
    "trace-data-flow-forward": "analyze-data-flow",
    # analyze-vtables overloads
    "analyze-vtable": "analyze-vtables",
    "find-vtable-callers": "analyze-vtables",
    "find-vtables-containing-function": "analyze-vtables",
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
    # search-everything overloads
    "global-search": "search-everything",
    "search-anything": "search-everything",
    "unified-search": "search-everything",
}

# GUI-only tools disabled for headless MCP/CLI usage.
# These tools require a graphical interface and are not available in server/headless mode.
# They remain defined for completeness but are filtered out of advertised tool lists.
DISABLED_GUI_ONLY_TOOLS: frozenset[ToolName] = frozenset(
    {
        ToolName.GET_CURRENT_ADDRESS,
        ToolName.GET_CURRENT_FUNCTION,
        ToolName.OPEN_PROGRAM_IN_CODE_BROWSER,
        ToolName.OPEN_ALL_PROGRAMS_IN_CODE_BROWSER,
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


def resolve_tool_name_enum(tool_name: str) -> ToolName | None:
    """Resolve arbitrary tool name/alias to canonical ToolName enum, or None if unknown."""
    resolved = resolve_tool_name(tool_name)
    if resolved is None:
        return None
    try:
        return ToolName(resolved)
    except ValueError:
        return None


def get_tool_params(tool_name: ToolName | str) -> list[str]:
    """Return the list of parameter names (camelCase) for a tool, or empty if unknown."""
    if isinstance(tool_name, ToolName):
        return list(TOOL_PARAMS.get(tool_name, []))
    resolved = resolve_tool_name_enum(tool_name)
    if resolved is None:
        return []
    return list(TOOL_PARAMS.get(resolved, []))


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
    return _NON_ALPHA_PATTERN.sub("", s.lower().strip())


def _find_repo_root_for_tools_list() -> Path | None:
    """Best-effort discovery of repository root containing TOOLS_LIST.md.

    Walks up the directory tree from the current file location to find a directory
    containing TOOLS_LIST.md. This allows the registry to dynamically load tool
    specifications and aliases from documentation.

    Returns:
        Path to the repository root directory, or None if TOOLS_LIST.md not found
    """
    current = Path(__file__).resolve()
    for parent in [current.parent, *current.parents]:
        candidate = parent / "TOOLS_LIST.md"
        if candidate.exists():
            return parent
    return None


def _extract_tools_list_sync_data() -> tuple[dict[str, list[str]], dict[str, dict[str, set[str]]], dict[str, str]]:
    """Parse TOOLS_LIST.md and extract parameter names, param aliases, and tool aliases.

    Reads the TOOLS_LIST.md file and extracts:
    - Tool parameter definitions
    - Parameter aliases/synonyms
    - Tool aliases (forwarding relationships)

    This enables dynamic synchronization between documentation and code,
    ensuring tool specifications stay in sync with the implementation.

    Returns:
        Tuple of (params_by_tool, param_aliases_by_tool_norm, tool_aliases_by_norm):
        - params_by_tool: dict[tool_name, list[param_names]]
        - param_aliases_by_tool_norm: dict[normalized_tool_name, dict[normalized_alias, set[normalized_canonicals]]]
        - tool_aliases_by_norm: dict[normalized_alias_tool, canonical_tool_name]
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
                existing_norm: set[str] = {normalize_identifier(x) for x in existing}
                for param in extracted_params:
                    param_norm = normalize_identifier(param)
                    if param_norm not in existing_norm:
                        existing.append(param)
                        existing_norm.add(param_norm)

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
    """Merge TOOLS_LIST parameter names into TOOL_PARAMS without losing existing names.

    Combines parameter definitions from code (TOOL_PARAMS) with those extracted from
    TOOLS_LIST.md documentation. Preserves existing parameters while adding any
    new ones found in the documentation, ensuring comprehensive parameter coverage.

    Args:
        base: Base parameter definitions from code (TOOL_PARAMS)
        extra: Additional parameters extracted from TOOLS_LIST.md

    Returns:
        Merged parameter dictionary with all parameters from both sources
    """
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
_merged_params_str: dict[str, list[str]] = _merge_tools_list_params(_TOOL_PARAMS_STR, _tools_list_params)
TOOL_PARAMS: dict[ToolName, list[str]] = {ToolName(k): v for k, v in _merged_params_str.items()}
TOOL_PARAM_ALIASES.update(_tools_list_param_aliases)
TOOL_ALIASES.update(_tools_list_tool_aliases)
TOOL_ALIASES.update({normalize_identifier(alias): target for alias, target in NON_ADVERTISED_TOOL_ALIASES.items()})


def _add_builtin_param_aliases() -> None:
    def _add(tool: str, alias: str, canonical_param: str, *, replace: bool = False) -> None:
        tool_norm = normalize_identifier(tool)
        alias_norm = normalize_identifier(alias)
        canonical_norm = normalize_identifier(canonical_param)
        if not tool_norm or not alias_norm or not canonical_norm:
            return
        per_tool = TOOL_PARAM_ALIASES.setdefault(tool_norm, {})
        if replace:
            per_tool[alias_norm] = {canonical_norm}
            return
        per_tool.setdefault(alias_norm, set()).add(canonical_norm)

    # Correct import-binary aliases even if TOOLS_LIST-derived aliases were polluted.
    for alias_name, canonical_param in (
        ("filePath", "path"),
        ("binaryPath", "path"),
        ("binary_path", "path"),
        ("destFolder", "destinationFolder"),
        ("recurse", "recursive"),
        ("autoAnalyze", "analyzeAfterImport"),
        ("stripPath", "stripLeadingPath"),
        ("stripContainer", "stripAllContainerPath"),
        ("mirror", "mirrorFs"),
        ("versioning", "enableVersionControl"),
        ("depth", "maxDepth"),
    ):
        _add(ToolName.IMPORT_BINARY.value, alias_name, canonical_param, replace=True)

    # Open/shared-server argument harmonization.
    for tool_name in (ToolName.OPEN_PROJECT.value,):
        _add(tool_name, "isShared", "shared")
        _add(tool_name, "sharedMode", "shared")
        _add(tool_name, "shared_mode", "shared")
        _add(tool_name, "ghidraServerHost", "serverHost")
        _add(tool_name, "ghidra_server_host", "serverHost")
        _add(tool_name, "ghidraServerPort", "serverPort")
        _add(tool_name, "ghidra_server_port", "serverPort")
        _add(tool_name, "ghidraServerUsername", "serverUsername")
        _add(tool_name, "ghidra_server_username", "serverUsername")
        _add(tool_name, "ghidraServerPassword", "serverPassword")
        _add(tool_name, "ghidra_server_password", "serverPassword")
        _add(tool_name, "ghidraServerRepository", "path")
        _add(tool_name, "ghidra_server_repository", "path")
        _add(tool_name, "serverRepository", "path")
        _add(tool_name, "server_repository", "path")
        _add(tool_name, "repositoryName", "path")
        _add(tool_name, "repository_name", "path")


_add_builtin_param_aliases()

# Default advertised surface (MCP + CLI) is blacklist-driven.
# All tools remain accepted via normalize/resolve/dispatch regardless of advertisement.
# New tools are auto-advertised unless added to this hidden set.
_DEFAULT_HIDDEN_TOOLS: frozenset[ToolName] = frozenset(
    {
        ToolName.DELETE_PROJECT_BINARY,
        ToolName.GEN_CALLGRAPH,
        ToolName.GET_FUNCTIONS,
        ToolName.MANAGE_BOOKMARKS,
        ToolName.MANAGE_COMMENTS,
        ToolName.MANAGE_DATA_TYPES,
        ToolName.MANAGE_FILES,
        ToolName.MANAGE_FUNCTION,
        ToolName.MANAGE_STRINGS,
        ToolName.MANAGE_STRUCTURES,
        ToolName.MANAGE_SYMBOLS,
        ToolName.SUGGEST,
    },
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


def _get_disabled_tools() -> set[str]:
    """Parse AGENTDECOMPILE_DISABLE_TOOLS env var and return normalized tool names to disable."""
    disable_env = os.getenv("AGENT_DECOMPILE_DISABLE_TOOLS", os.getenv("AGENTDECOMPILE_DISABLE_TOOLS", "")).strip()
    if not disable_env:
        return set()
    disabled = set()
    for tool in disable_env.split(","):
        tool = tool.strip()
        if tool:
            disabled.add(normalize_identifier(tool))
    return disabled


def _get_explicit_enabled_tools() -> set[str] | None:
    """Parse AGENTDECOMPILE_ENABLE_TOOLS env var.

    Returns a set of normalized tool names that should be forcibly enabled,
    taking priority over default/hidden filtering and DISABLE_TOOLS.
    Returns None when the var is unset or empty.
    """
    raw = os.environ.get("AGENTDECOMPILE_ENABLE_TOOLS") or os.environ.get("AGENT_DECOMPILE_ENABLE_TOOLS") or ""
    enable_env = raw.strip()
    if not enable_env:
        return None
    enabled: set[str] = set()
    for tool in enable_env.split(","):
        tool = tool.strip()
        if tool:
            enabled.add(normalize_identifier(tool))
    return enabled if enabled else None


def _build_advertised_tools() -> list[str]:
    """Build the list of tool names to advertise in MCP tools/list (and CLI).

    Priority: AGENTDECOMPILE_ENABLE_TOOLS (if set) → exact list to expose.
    Otherwise: start from all canonical tools, remove disabled, then either hide
    _DEFAULT_HIDDEN_TOOLS or include them if legacy env vars are set.
    """
    canonical_visible = [t.value for t in ToolName if t not in DISABLED_GUI_ONLY_TOOLS]
    hidden_set = {normalize_identifier(t.value) for t in _DEFAULT_HIDDEN_TOOLS}
    disabled_set = _get_disabled_tools()
    explicit_set = _get_explicit_enabled_tools()

    if explicit_set is not None:
        # AGENTDECOMPILE_ENABLE_TOOLS takes absolute priority – expose exactly these tools.
        return [tool for tool in canonical_visible if normalize_identifier(tool) in explicit_set]

    include_hidden = _legacy_tools_advertised()

    result: list[str] = []
    for tool in canonical_visible:
        norm = normalize_identifier(tool)
        if norm in disabled_set:
            continue
        if norm not in hidden_set or include_hidden:
            result.append(tool)
    return result


ADVERTISED_TOOLS: list[str] = _build_advertised_tools()

_ADVERTISED_SELECTOR_ALIASES: tuple[str, ...] = ()


def is_tool_advertised(tool_name: str) -> bool:
    """Check if a tool is currently advertised based on env var configuration."""
    normalized = normalize_identifier(tool_name)
    return any(normalize_identifier(t) == normalized for t in ADVERTISED_TOOLS)


def get_advertised_tools() -> list[str]:
    """Get the list of currently advertised tools."""
    return list(ADVERTISED_TOOLS)


def _build_advertised_tool_params() -> dict[str, list[str]]:
    advertised: dict[str, list[str]] = {}
    advertised_set = set(ADVERTISED_TOOLS)
    for tool, params in TOOL_PARAMS.items():
        if tool.value not in advertised_set:
            continue
        expanded: list[str] = list(params)
        advertised[tool.value] = expanded
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

_TOOLS_BY_NORMALIZED: dict[str, str] = {normalize_identifier(tool): tool for tool in TOOLS}


def _build_tool_match_candidates() -> list[tuple[str, str, str]]:
    """Build sorted tool-name variants used by natural language parsing.

    Returns tuples of ``(canonical_tool_name, raw_variant, normalized_variant)``
    ordered by descending variant length so more specific names win first.
    """
    candidates: list[tuple[str, str, str]] = []
    for tool_name in TOOLS:
        seen: set[str] = set()
        variations = (
            tool_name,
            tool_name.replace("-", " "),
            tool_name.replace("-", "_"),
            tool_name.replace("-", ""),
        )
        for variation in variations:
            if variation in seen:
                continue
            seen.add(variation)
            candidates.append((tool_name, variation, normalize_identifier(variation)))
    candidates.sort(key=lambda item: len(item[1]), reverse=True)
    return candidates


_TOOL_MATCH_CANDIDATES = _build_tool_match_candidates()
_TOOL_SUFFIXES = (
    "action",
    "command",
    "op",
    "task",
    "tool",
)


def resolve_tool_name(tool_name: str) -> str | None:
    """Resolve arbitrary tool aliases/noisy variants to canonical kebab-case tool names.

    Handles fuzzy matching by normalizing tool names (removing non-alphabetic characters,
    case-insensitive comparison) and checking against known tools and aliases. Also
    strips common prefixes/suffixes like "agentdecompile", "tool", "action", etc.

    Examples::
        resolve_tool_name("analyze-data-flow")     # -> "analyze-data-flow"
        resolve_tool_name("analyze_data_flow")     # -> "analyze-data-flow"
        resolve_tool_name("Analyze Data Flow")     # -> "analyze-data-flow"
        resolve_tool_name("tool-analyze-data-flow") # -> "analyze-data-flow"
        resolve_tool_name("search-symbols-by-name") # -> "manage-symbols" (alias)

    Args:
        tool_name: The tool name to resolve (any format/casing/separators)

    Returns:
        The canonical kebab-case tool name, or None if no match found
    """
    norm = normalize_identifier(tool_name)
    if not norm:
        return None

    direct: str | None = _TOOLS_BY_NORMALIZED.get(norm)
    if direct is not None:
        return direct

    aliased: str | None = TOOL_ALIASES.get(norm)
    if aliased is not None:
        return aliased

    # Strip common prefixes/suffixes (e.g. "agentdecompile", "tool") so noisy names still resolve
    stripped: str = norm
    changed: bool = True
    while changed and stripped:
        changed = False
        for prefix in _TOOL_PREFIXES:
            if stripped.startswith(prefix) and len(stripped) > len(prefix):
                stripped = stripped[len(prefix) :]
                changed = True
                break
    changed = True
    while changed and stripped:
        changed = False
        for suffix in _TOOL_SUFFIXES:
            if stripped.endswith(suffix) and len(stripped) > len(suffix):
                stripped = stripped[: -len(suffix)]
                changed = True
                break

    if stripped:
        direct = _TOOLS_BY_NORMALIZED.get(stripped)
        if direct is not None:
            return direct
        aliased = TOOL_ALIASES.get(stripped)
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
        self._tool_params: dict[str, list[str]] = {t.value: list(p) for t, p in TOOL_PARAMS.items()}
        self._tools: list[str] = list(ADVERTISED_TOOLS)
        self._tool_aliases: dict[str, str] = TOOL_ALIASES.copy()
        # Pre-computed normalized (alpha-only, lowercase) lookups so that
        # callers using alpha-only keys (e.g. "getdata") resolve correctly
        # alongside the kebab-case storage keys (e.g. "get-data").
        self._params_by_norm: dict[str, list[str]] = {
            normalize_identifier(t.value): p for t, p in TOOL_PARAMS.items()
        }
        self._display_name_by_norm: dict[str, str] = {
            normalize_identifier(t.value): t.value for t in TOOL_PARAMS
        }
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
        normalized_argument_keys: dict[str, str] = {key: normalize_identifier(key) for key in augmented_arguments}
        normalized_arguments: dict[str, Any] = {}
        for key, value in augmented_arguments.items():
            normalized_arguments.setdefault(normalized_argument_keys[key], value)

        parsed_args: dict[str, Any] = {}

        # For each expected parameter, try various naming variations
        for param in expected_params:
            value = self._extract_argument_value(
                augmented_arguments,
                param,
                normalized_arguments=normalized_arguments,
            )
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
            if normalized_argument_keys[key] not in parsed_norms:
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
            looks_nl = (" " in compact_value) or any(token in compact_value for token in ("=", ":", ",", ";")) or (" with " in compact_value.lower()) or (" and " in compact_value.lower())
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

        # Use precompiled pattern for KV extraction to avoid repeated compilation
        for match in _NL_KV_PATTERN.finditer(text):
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
                phrases_by_param[canonical_param].add(alias_norm)

        for canonical_param, phrases in phrases_by_param.items():
            for phrase in sorted(phrases, key=len, reverse=True):
                if not phrase:
                    continue
                pattern = _compile_nl_phrase_pattern(phrase)
                for match in pattern.finditer(text):
                    value_raw = match.group("value").strip()
                    extracted[canonical_param] = self._coerce_natural_language_value(value_raw)

        # Cleanup common NL artifacts for paths (e.g. "path '/tmp/a.bin'").
        if "programPath" in extracted and isinstance(extracted["programPath"], str):
            extracted["programPath"] = self._normalize_extracted_program_path(
                extracted["programPath"],
                text,
                recover_unbalanced_quotes=True,
            )

        # Common phrase fallback extraction to improve NL robustness.
        self._extract_common_nl_patterns(text, extracted)

        # Cleanup common artifacts again after fallback.
        if "programPath" in extracted and isinstance(extracted["programPath"], str):
            extracted["programPath"] = self._normalize_extracted_program_path(
                extracted["programPath"],
                text,
            )

        if "addressOrSymbol" in extracted and "address" not in extracted and "startAddress" not in extracted:
            extracted["address"] = extracted["addressOrSymbol"]

        return extracted

    def _capture_nl_pattern(self, text: str, extracted: dict[str, Any], param_name: str, pattern: str, flags: int = re.IGNORECASE) -> None:
        """Capture a natural language pattern and extract the value if not already present."""
        m = re.search(pattern, text, flags=flags)
        if not m:
            return
        value_raw = m.group("value") if "value" in m.groupdict() else m.group(1)
        value: Any = self._coerce_natural_language_value(value_raw.strip())
        if param_name not in extracted or extracted.get(param_name) in (None, "", f"{param_name}"):
            extracted[param_name] = value

    def _extract_common_nl_patterns(self, text: str, extracted: dict[str, Any]) -> None:
        """Extract common natural language patterns using predefined capture rules."""
        capture_patterns = [
            # Path/program patterns
            ("programPath", r"\bprogram\s+path\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>\"[^\"]+\"|'[^']+'|/[^,;\n ]+)"),
            ("programPath", r"\bprogram\s+(?P<value>\"[^\"]+\"|'[^']+'|/[^,;\n ]+)"),
            # Address/target/function patterns
            ("addressOrSymbol", r"\baddress\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>0x[0-9a-fA-F]+)"),
            ("addressOrSymbol", r"\bat\s+(?P<value>0x[0-9a-fA-F]+)"),
            ("target", r"\btarget\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>\"[^\"]+\"|'[^']+'|[^,;\n\s]+)"),
            ("function", r"\bfunction\s+(?P<value>[A-Za-z_][A-Za-z0-9_]*)"),
            # String/search patterns
            ("pattern", r"\bpattern\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>\"[^\"]+\"|'[^']+'|[^,;\n\s]+)"),
            ("query", r"\bquery\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>\"[^\"]+\"|'[^']+'|[^,;\n\s]+)"),
            ("comment", r"\bcomment\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>\"[^\"]+\"|'[^']+')"),
            ("mode", r"\bmode\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>[A-Za-z_][A-Za-z0-9_]*)"),
            # Boolean flags
            ("includeRefContext", r"\binclude\s+ref\s+context\s+(?P<value>true|false)"),
            ("includeDataRefs", r"\binclude\s+data\s+refs\s+(?P<value>true|false)"),
            ("skipAnalysis", r"\bskip\s+analysis\s+(?P<value>true|false)"),
            # Numeric options
            ("limit", r"\blimit\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>-?\d+)"),
            ("maxResults", r"\bmax\s+results\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>-?\d+)"),
            ("maxCount", r"\bmax\s+count\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>-?\d+)"),
            ("startIndex", r"\bstart\s+index\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>-?\d+)"),
            ("minLength", r"\bmin\s+length\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>-?\d+)"),
            ("maxDepth", r"\bmax\s+depth\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>-?\d+)"),
            ("length", r"\blength\s*(?:=|:|\bis\b|\bto\b|\bas\b)?\s*(?P<value>-?\d+)"),
        ]

        for param_name, pattern in capture_patterns:
            self._capture_nl_pattern(text, extracted, param_name, pattern)

    def _normalize_extracted_program_path(
        self,
        raw_value: str,
        full_text: str,
        recover_unbalanced_quotes: bool = False,
    ) -> Any:
        """Normalize natural-language extracted ``programPath`` values."""
        # Use precompiled pattern for cleanup step
        cleaned = _PROGRAM_PATH_CLEANUP_PATTERN.sub("", raw_value).strip()
        # Use precompiled pattern to split on "to" keyword
        cleaned = _PROGRAM_PATH_SCOPE_PATTERN.split(cleaned, maxsplit=1)[0].strip()

        if recover_unbalanced_quotes and ((cleaned.startswith('"') and not cleaned.endswith('"')) or (cleaned.startswith("'") and not cleaned.endswith("'"))):
            # Use precompiled quoted path pattern
            quoted_path_match = _QUOTED_PATH_PATTERN.search(full_text)
            if quoted_path_match:
                cleaned = quoted_path_match.group(0)

        return self._coerce_natural_language_value(cleaned)

    def _coerce_natural_language_value(self, raw_value: str) -> Any:
        """Coerce natural-language scalar text to appropriate Python types.

        Attempts to parse string values extracted from natural language into
        their most appropriate Python types: booleans, integers, floats, JSON objects,
        or strings. Handles quoted strings, boolean literals, numeric values,
        and JSON structures.

        Examples:
            "true" -> True
            "42" -> 42
            "3.14" -> 3.14
            '"hello"' -> "hello"
            '{"key": "value"}' -> {"key": "value"}

        Args:
            raw_value: Raw string value from natural language extraction

        Returns:
            Coerced value in appropriate Python type, or original string if coercion fails
        """
        value = raw_value.strip()
        if not value:
            return value

        # Check for quoted strings using precompiled pattern
        if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
            return value[1:-1]

        lowered = value.lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False

        # Use precompiled patterns for numeric coercion (more efficient than fullmatch)
        if _INT_PATTERN.match(value):
            try:
                return int(value)
            except Exception:
                return value

        if _FLOAT_PATTERN.match(value):
            try:
                return float(value)
            except Exception:
                return value

        # Check JSON structures using precompiled pattern
        if _JSON_PATTERN.match(value):
            try:
                return _json.loads(value)
            except Exception:
                return value

        return value

    def _extract_argument_value(
        self,
        arguments: dict[str, Any],
        param_name: str,
        normalized_arguments: dict[str, Any] | None = None,
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
        variations = self._generate_param_variations(param_name)

        for variation in variations:
            if variation in arguments:
                return arguments[variation]

        # Selector fallback: canonical "mode" accepts action/operation/etc.
        normalized_param = normalize_identifier(param_name)
        if _canonical_param_name(param_name) == "mode":
            lookup = normalized_arguments or {normalize_identifier(k): v for k, v in arguments.items()}
            for alias in MODE_PARAM_ALIASES:
                if alias in lookup:
                    return lookup[alias]

        # Normalized fallback: strip all non-alpha chars and compare.
        # This means any casing or separator style will match as long as the
        # alphabetic characters are the same.
        if normalized_arguments is not None:
            return normalized_arguments.get(normalized_param)
        for key, value in arguments.items():
            if normalize_identifier(key) == normalized_param:
                return value

        return None

    @staticmethod
    @lru_cache(maxsize=512)
    def _generate_param_variations(
        param_name: str,
    ) -> tuple[str, ...]:
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

        # Convert camelCase to snake_case using precompiled pattern
        snake_case: str = _CAMEL_TO_SNAKE_PATTERN.sub(r"\1_\2", param_name).lower()
        if snake_case != param_name.lower():
            variations.append(snake_case)

        # Convert camelCase to kebab-case using precompiled pattern
        kebab_case: str = _CAMEL_TO_KEBAB_PATTERN.sub(r"\1-\2", param_name).lower()
        if kebab_case != param_name.lower():
            variations.append(kebab_case)

        # Handle special cases with explicit aliases
        if param_name == "addressOrSymbol":
            variations.extend(["address_or_symbol", "addressOrSymbol", "address"])
        elif param_name == "programPath":
            variations.extend(["program_path", "program-path", "program", "filepath", "path"])
        elif param_name == "maxResults":
            variations.extend(["max_results", "max-results", "limit", "maxResults", "limits"])

        return tuple(dict.fromkeys(variations))

    def validate_required_arguments(
        self,
        arguments: dict[str, Any],
        tool_name: str,
    ) -> None:
        """Validate that required arguments are present for a tool.

        Checks that all mandatory parameters for a given tool are provided in the
        arguments dictionary. Required parameters vary by tool - for example,
        most program-scoped tools require a programPath, while some operations
        require additional parameters like mode or addressOrSymbol.

        Args:
            arguments: Parsed arguments dictionary to validate
            tool_name: Name of the tool to validate arguments for

        Raises:
            ValueError: If any required arguments are missing, with details about
                       which parameters are required for the tool
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

        matched_tool: str | None = None
        remaining_text: str = text

        for tool_name, variation, variation_norm in _TOOL_MATCH_CANDIDATES:
            if text.lower().startswith(variation.lower()):
                matched_tool = tool_name
                remaining_text = text[len(variation) :].strip()
                break

            text_prefix_norm = normalize_identifier(text[: len(variation)])
            if text_prefix_norm == variation_norm:
                matched_tool = tool_name
                remaining_text = text[len(variation) :].strip()
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

        # Apply precompiled patterns to avoid repeated compilation
        processed_text = text
        for pattern, replacement, flags in _NL_PHRASE_PATTERNS:
            processed_text = re.sub(pattern, replacement, processed_text, flags=flags)

        return processed_text

    def execute_tool_cli(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        client: ClientSession | None = None,
    ) -> Any:
        """Execute a tool via CLI client.

        Creates a standardized tool call payload and executes it using the provided
        MCP client session. Handles argument parsing, validation, and tool resolution
        before dispatching to the backend.

        Args:
            tool_name: Name of the tool to execute
            arguments: Raw tool arguments (will be parsed and validated)
            client: MCP client session for tool execution

        Returns:
            Tool execution result from the MCP server

        Raises:
            ValueError: If client is not provided or tool execution fails
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

        Converts MCP tool response content into various human-readable formats
        for CLI display. Supports JSON, plain text, and table formats depending
        on the data structure and user preference.

        Args:
            response: MCP tool response containing text content with JSON data
            output_format: Desired output format - "json", "text", or "table"

        Returns:
            Formatted response string suitable for CLI display
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
