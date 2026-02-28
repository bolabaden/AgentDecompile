"""Canonical MCP tool and resource names for AgentDecompile.

Content is mirrored in registry.py, which is the primary source of truth.
This module is retained for compatibility with existing imports.
Prefer importing from agentdecompile_cli.registry.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# MCP tool names (canonical wire names)
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


# Required / common: programPath is optional in GUI, required in headless for program-scoped tools
TOOL_PARAMS: dict[str, list[str]] = {
    "get-data": _params("programPath", "addressOrSymbol"),
    "apply-data-type": _params("programPath", "addressOrSymbol", "dataTypeString", "archiveName"),
    "create-label": _params("programPath", "addressOrSymbol", "labelName", "setAsPrimary"),
    "manage-strings": _params(
        "programPath",
        "mode",
        "pattern",
        "searchString",
        "filter",
        "startIndex",
        "maxCount",
        "offset",
        "limit",
        "maxResults",
        "includeReferencingFunctions",
    ),
    "get-references": _params(
        "programPath",
        "target",
        "mode",
        "direction",
        "offset",
        "limit",
        "maxResults",
        "libraryName",
        "startIndex",
        "maxReferencers",
        "includeRefContext",
        "includeDataRefs",
    ),
    "get-functions": _params(
        "programPath",
        "identifier",
        "view",
        "offset",
        "limit",
        "includeCallers",
        "includeCallees",
        "includeComments",
        "includeIncomingReferences",
        "includeReferenceContext",
    ),
    "manage-symbols": _params(
        "programPath",
        "mode",
        "address",
        "labelName",
        "newName",
        "libraryFilter",
        "maxResults",
        "startIndex",
        "offset",
        "limit",
        "groupByLibrary",
        "includeExternal",
        "maxCount",
        "filterDefaultNames",
        "demangleAll",
    ),
    "manage-data-types": _params(
        "programPath",
        "action",
        "archiveName",
        "categoryPath",
        "includeSubcategories",
        "startIndex",
        "maxCount",
        "dataTypeString",
        "addressOrSymbol",
    ),
    "manage-structures": _params(
        "programPath",
        "action",
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
    ),
    "manage-comments": _params(
        "programPath",
        "action",
        "addressOrSymbol",
        "function",
        "lineNumber",
        "comment",
        "commentType",
        "comments",
        "start",
        "end",
        "commentTypes",
        "searchText",
        "pattern",
        "caseSensitive",
        "maxResults",
        "overrideMaxFunctionsLimit",
    ),
    "manage-bookmarks": _params("programPath", "action", "addressOrSymbol", "type", "category", "comment", "bookmarks", "searchText", "maxResults", "removeAll"),
    "inspect-memory": _params("programPath", "mode", "address", "length", "offset", "limit"),
    "get-call-graph": _params(
        "programPath",
        "functionIdentifier",
        "mode",
        "depth",
        "direction",
        "maxDepth",
        "startIndex",
        "maxCallers",
        "includeCallContext",
        "functionAddresses",
    ),
    "search-constants": _params("programPath", "mode", "value", "minValue", "maxValue", "maxResults", "includeSmallValues", "topN"),
    "analyze-vtables": _params("programPath", "mode", "vtableAddress", "functionAddress", "maxEntries", "maxResults"),
    "analyze-data-flow": _params("programPath", "functionAddress", "startAddress", "variableName", "direction"),
    "suggest": _params("programPath", "suggestionType", "address", "function", "dataType", "variableAddress"),
    "list-functions": _params(
        "programPath",
        "mode",
        "query",
        "searchString",
        "minReferenceCount",
        "startIndex",
        "maxCount",
        "offset",
        "limit",
        "filterDefaultNames",
        "filterByTag",
        "untagged",
        "hasTags",
        "verbose",
        "identifiers",
    ),
    "manage-function": _params(
        "programPath",
        "action",
        "address",
        "functionIdentifier",
        "name",
        "functions",
        "oldName",
        "newName",
        "variableMappings",
        "prototype",
        "variableName",
        "newType",
        "datatypeMappings",
        "archiveName",
        "createIfNotExists",
        "propagate",
        "propagateProgramPaths",
        "propagateMaxCandidates",
        "propagateMaxInstructions",
    ),
    "manage-function-tags": _params("programPath", "function", "mode", "tags"),
    "match-function": _params(
        "programPath",
        "functionIdentifier",
        "targetProgramPaths",
        "maxInstructions",
        "minSimilarity",
        "propagateNames",
        "propagateTags",
        "propagateComments",
        "filterDefaultNames",
        "filterByTag",
        "maxFunctions",
        "batchSize",
    ),
    "get-current-program": _params("programPath"),
    "get-current-address": _params("programPath"),
    "get-current-function": _params("programPath"),
    "list-project-files": [],
    "list-open-programs": [],
    "checkin-program": _params("programPath", "message", "keepCheckedOut"),
    "analyze-program": _params("programPath"),
    "change-processor": _params("programPath", "languageId", "compilerSpecId"),
    "manage-files": _params(
        "operation",
        "path",
        "destinationFolder",
        "recursive",
        "maxDepth",
        "analyzeAfterImport",
        "stripLeadingPath",
        "stripAllContainerPath",
        "mirrorFs",
        "enableVersionControl",
        "programPath",
        "exclusive",
        "exportType",
        "format",
        "includeParameters",
        "includeVariables",
        "includeComments",
    ),
    "open": _params(
        "path",
        "extensions",
        "openAllPrograms",
        "destinationFolder",
        "analyzeAfterImport",
        "enableVersionControl",
        "serverUsername",
        "serverPassword",
        "serverHost",
        "serverPort",
        "forceIgnoreLock",
    ),
    "open-program-in-code-browser": _params("programPath"),
    "open-all-programs-in-code-browser": _params("extensions", "folderPath"),
    "capture-agentdecompile-debug-info": _params("message"),
    "search-code": _params("binaryName", "query", "limit"),
    "list-cross-references": _params("binaryName", "nameOrAddress"),
    "gen-callgraph": _params(
        "binaryName",
        "functionNameOrAddress",
        "direction",
        "displayType",
        "includeRefs",
        "maxDepth",
        "maxRunTime",
        "condenseThreshold",
        "topLayers",
        "bottomLayers",
    ),
    "decompile-function": _params("binaryName", "name"),
    "import-binary": _params("binaryPath"),
    "list-exports": _params("binaryName", "query", "offset", "limit"),
    "list-imports": _params("binaryName", "query", "offset", "limit"),
    "list-project-binaries": [],
    "list-project-binary-metadata": _params("binaryName"),
    "delete-project-binary": _params("binaryName"),
    "read-bytes": _params("binaryName", "address", "size"),
    "search-strings": _params("binaryName", "query", "limit"),
    "search-symbols-by-name": _params("binaryName", "query", "offset", "limit"),
    "list-strings": _params("binaryName", "query", "limit"),
    "search-symbols": _params("binaryName", "query", "offset", "limit"),
}


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
