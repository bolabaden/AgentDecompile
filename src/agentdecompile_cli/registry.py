"""Unified tool registry - schema definitions, normalization, and ToolRegistry class.

Merged from tools_schema.py and tool_registry.py.
Single source of truth for all tool names, parameter schemas, normalization helpers,
and the ToolRegistry that parses and validates arguments.
"""

from __future__ import annotations

import json as _json
import logging
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
        "query",
        "offset",
        "limit",
        "includeReferencingFunctions",
    ),
    "get-references": _params(
        "programPath",
        "target",
        "mode",
        "direction",
        "offset",
        "limit",
        "libraryName",
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
        "action",
        "address",
        "labelName",
        "newName",
        "libraryFilter",
        "offset",
        "limit",
        "groupByLibrary",
        "includeExternal",
        "filterDefaultNames",
        "demangleAll",
    ),
    "manage-data-types": _params(
        "programPath",
        "action",
        "archiveName",
        "categoryPath",
        "includeSubcategories",
        "offset",
        "limit",
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
        "query",
        "caseSensitive",
        "limit",
        "overrideMaxFunctionsLimit",
    ),
    "manage-bookmarks": _params("programPath", "action", "addressOrSymbol", "type", "category", "comment", "bookmarks", "query", "limit", "removeAll"),
    "inspect-memory": _params("programPath", "mode", "address", "length", "offset", "limit"),
    "get-call-graph": _params(
        "programPath",
        "functionIdentifier",
        "mode",
        "maxDepth",
        "direction",
        "maxCallers",
        "includeCallContext",
        "functionAddresses",
    ),
    "search-constants": _params("programPath", "mode", "value", "minValue", "maxValue", "limit", "includeSmallValues", "topN"),
    "analyze-vtables": _params("programPath", "mode", "vtableAddress", "functionAddress", "maxEntries", "limit"),
    "analyze-data-flow": _params("programPath", "functionAddress", "startAddress", "variableName", "direction"),
    "suggest": _params("programPath", "suggestionType", "address", "function", "dataType", "variableAddress"),
    "list-functions": _params(
        "programPath",
        "mode",
        "query",
        "minReferenceCount",
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
        "limit",
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

# Populated from TOOLS_LIST.md when available.
# Key: normalized canonical tool name -> {normalized param alias -> {normalized canonical params}}
TOOL_PARAM_ALIASES: dict[str, dict[str, set[str]]] = {}

# Populated from TOOLS_LIST.md overload/synonyms when available.
# Key: normalized alias tool name -> canonical kebab-case tool name
TOOL_ALIASES: dict[str, str] = {}


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

    tools_list = root / "TOOLS_LIST.md"
    try:
        text = tools_list.read_text(encoding="utf-8")
    except Exception:
        return {}, {}, {}

    parts = re.split(r"^### `([^`]+)`(?: \(forwards to `([^`]+)`\))?\n", text, flags=re.M)
    if len(parts) < 3:
        return {}, {}, {}

    params_by_tool: dict[str, list[str]] = {}
    param_aliases_by_tool: dict[str, dict[str, set[str]]] = {}
    tool_aliases_by_norm: dict[str, str] = {}

    for i in range(1, len(parts), 3):
        tool_name = parts[i]
        forwarded_to = parts[i + 1]
        body = parts[i + 2]
        canonical_tool = forwarded_to or tool_name
        canonical_norm = normalize_identifier(canonical_tool)

        if forwarded_to:
            tool_aliases_by_norm[normalize_identifier(tool_name)] = canonical_tool

        params_match = re.search(
            r"\*\*Parameters\*\*:\n(.*?)(?:\n\*\*Overloads\*\*|\n\*\*Synonyms\*\*|\n\*\*Examples\*\*)",
            body,
            flags=re.S,
        )
        if params_match:
            block = params_match.group(1)
            lines = block.splitlines()
            extracted_params: list[str] = []
            alias_map = param_aliases_by_tool.setdefault(canonical_norm, {})

            idx = 0
            while idx < len(lines):
                line = lines[idx]
                param_match = re.match(r"^- `([^`]+)` \(", line)
                if param_match:
                    param_name = param_match.group(1)
                    extracted_params.append(param_name)
                    canonical_param_norm = normalize_identifier(param_name)
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

        overload_match = re.search(
            r"\*\*Overloads\*\*:\n(.*?)(?:\n\*\*Synonyms\*\*|\n\*\*Examples\*\*)",
            body,
            flags=re.S,
        )
        if overload_match:
            for alias, target in re.findall(r"- `([^`(]+)\([^`]*\)`.*?forwards to `([^`]+)`", overload_match.group(1)):
                tool_aliases_by_norm[normalize_identifier(alias)] = target

        synonyms_match = re.search(
            r"\*\*Synonyms\*\*:\s*(.*?)(?:\n\*\*Examples\*\*|\n\*\*API References\*\*|\Z)",
            body,
            flags=re.S,
        )
        if synonyms_match:
            for alias in re.findall(r"`([^`]+)`", synonyms_match.group(1)):
                tool_aliases_by_norm[normalize_identifier(alias)] = canonical_tool

    return params_by_tool, param_aliases_by_tool, tool_aliases_by_norm


def _merge_tools_list_params(base: dict[str, list[str]], extra: dict[str, list[str]]) -> dict[str, list[str]]:
    """Merge TOOLS_LIST parameter names into TOOL_PARAMS without losing existing names."""
    merged = {k: list(v) for k, v in base.items()}
    for tool, params in extra.items():
        if tool not in merged:
            continue
        existing = merged[tool]
        existing_norm = {normalize_identifier(x) for x in existing}
        for param in params:
            param_norm = normalize_identifier(param)
            if param_norm not in existing_norm:
                existing.append(param)
                existing_norm.add(param_norm)
    return merged


_tools_list_params, _tools_list_param_aliases, _tools_list_tool_aliases = _extract_tools_list_sync_data()
TOOL_PARAMS = _merge_tools_list_params(TOOL_PARAMS, _tools_list_params)
TOOL_PARAM_ALIASES.update(_tools_list_param_aliases)
TOOL_ALIASES.update(_tools_list_tool_aliases)


_TOOL_PREFIXES = (
    "agentdecompile",
    "ghidra",
    "execute",
    "tool",
    "cmd",
    "run",
    "do",
    "api",
    "mcp",
)
_TOOL_SUFFIXES = ("command", "action", "task", "tool", "op")


def resolve_tool_name(tool_name: str) -> str | None:
    """Resolve arbitrary tool aliases/noisy variants to canonical kebab-case tool names."""
    norm = normalize_identifier(tool_name)
    if not norm:
        return None

    by_norm = {normalize_identifier(tool): tool for tool in TOOLS}
    direct = by_norm.get(norm)
    if direct is not None:
        return direct

    aliased = TOOL_ALIASES.get(norm)
    if aliased is not None:
        return aliased

    stripped = norm
    changed = True
    while changed and stripped:
        changed = False
        for prefix in _TOOL_PREFIXES:
            if stripped.startswith(prefix) and len(stripped) > len(prefix):
                stripped = stripped[len(prefix):]
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
        direct = by_norm.get(stripped)
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
        self._tool_params: dict[str, list[str]] = TOOL_PARAMS.copy()
        self._tools: list[str] = TOOLS.copy()
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
        resolved_tool = self.resolve_tool_name(tool_name) or tool_name

        # Fast path: exact match on the storage key (kebab-case)
        result = self._tool_params.get(resolved_tool)
        if result is not None:
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
        resolved = resolve_tool_name(tool_name)
        if resolved is not None:
            return resolved

        # Local fallback using internal tables (defensive; should be redundant).
        norm = self.canonicalize_tool_name(tool_name)
        if not norm:
            return None
        direct = self._tool_by_norm.get(norm)
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
        resolved_tool = self.resolve_tool_name(tool_name)
        resolved_canonical = self.resolve_tool_name(canonical_name) or canonical_name
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

        expected_params: list[str] = self._tool_params.get(actual_tool_key, [])
        param_aliases: dict[str, set[str]] = TOOL_PARAM_ALIASES.get(normalize_identifier(actual_tool_key), {})

        parsed_args: dict[str, Any] = {}

        # For each expected parameter, try various naming variations
        for param in expected_params:
            value = self._extract_argument_value(arguments, param)
            if value is not None:
                parsed_args[param] = value

        # Alias-driven pass: map tool-specific synonym names (from TOOLS_LIST)
        # to canonical parameter keys when not already set.
        if param_aliases:
            expected_by_norm = {normalize_identifier(param): param for param in expected_params}
            for arg_key, arg_val in arguments.items():
                alias_norm = normalize_identifier(arg_key)
                target_norms = param_aliases.get(alias_norm)
                if not target_norms:
                    continue
                for target_norm in target_norms:
                    canonical_param = expected_by_norm.get(target_norm)
                    if canonical_param is not None and parsed_args.get(canonical_param) is None:
                        parsed_args[canonical_param] = arg_val

        return parsed_args

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

        # Normalized fallback: strip all non-alpha chars and compare.
        # This means any casing or separator style will match as long as the
        # alphabetic characters are the same.
        normalized_param = normalize_identifier(param_name)
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
            "managebookmarks": ["programPath", "action"],
            "managecomments": ["programPath", "action"],
            "managestructures": ["programPath", "action"],
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
