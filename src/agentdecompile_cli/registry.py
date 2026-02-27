"""Unified tool registry - schema definitions, normalization, and ToolRegistry class.

Merged from tools_schema.py and tool_registry.py.
Single source of truth for all tool names, parameter schemas, normalization helpers,
and the ToolRegistry that parses and validates arguments.
"""

from __future__ import annotations

import json as _json
import logging
import re

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
        "action",
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
        # Pre-computed normalized (alpha-only, lowercase) lookups so that
        # callers using alpha-only keys (e.g. "getdata") resolve correctly
        # alongside the kebab-case storage keys (e.g. "get-data").
        self._params_by_norm: dict[str, list[str]] = {normalize_identifier(k): v for k, v in TOOL_PARAMS.items()}
        self._display_name_by_norm: dict[str, str] = {normalize_identifier(k): k for k in TOOL_PARAMS}

    def get_tools(self) -> list[str]:
        """Get all available tool names."""
        return list(self._tools)

    def get_tool_params(self, tool_name: str) -> list[str]:
        """Get parameter names for a tool.

        Accepts any tool name format (kebab-case, snake_case, alpha-only, etc.).
        Performs an exact match first, then a normalized (alpha-only, lowercase)
        fallback so callers using the internal alpha-only form still resolve.
        """
        # Fast path: exact match on the storage key (kebab-case)
        result = self._tool_params.get(tool_name)
        if result is not None:
            return result
        # Normalized fallback: alpha-only form resolves to kebab-case key params
        return self._params_by_norm.get(normalize_identifier(tool_name), [])

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
        canonical_input: str = self.canonicalize_tool_name(tool_name)
        for tool_key in self._tool_params.keys():
            if self.canonicalize_tool_name(tool_key) == canonical_input:
                return True
        return False

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
        parsed_tool_name: str = self.canonicalize_tool_name(tool_name)
        parsed_canonical_name: str = self.canonicalize_tool_name(canonical_name)
        return parsed_tool_name == parsed_canonical_name

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
        if not self.is_valid_tool(tool_name):
            raise ValueError(f"Unknown tool: {tool_name}")

        # Find the actual tool key that matches this canonicalized name
        canonical_input: str = self.canonicalize_tool_name(tool_name)
        actual_tool_key: str | None = None
        for tool_key in self._tool_params.keys():
            if self.canonicalize_tool_name(tool_key) == canonical_input:
                actual_tool_key = tool_key
                break

        if actual_tool_key is None:
            raise ValueError(f"Could not find tool key for: {tool_name}")

        expected_params: list[str] = self._tool_params[actual_tool_key]

        parsed_args: dict[str, Any] = {}

        # For each expected parameter, try various naming variations
        for param in expected_params:
            value = self._extract_argument_value(arguments, param)
            if value is not None:
                parsed_args[param] = value

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
            variations.extend(["program_path", "program-path", "program"])
        elif param_name == "maxResults":
            variations.extend(["max_results", "max-results", "limit", "maxResults"])

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
        canonical_name: str = self.canonicalize_tool_name(tool_name)
        expected_params: list[str] = self.get_tool_params(canonical_name)  # noqa: F841

        # Define which parameters are required for each tool
        # Keys are alpha-only (normalize_identifier form) so the lookup against
        # canonical_name (which is already alpha-only from canonicalize_tool_name)
        # always succeeds.
        required_params: dict[str, list[str]] = {
            "getdata": ["programPath", "addressOrSymbol"],
            "applydatatype": ["programPath", "addressOrSymbol", "dataTypeString"],
            "createlabel": ["programPath", "addressOrSymbol", "labelName"],
            "getreferences": ["programPath", "target"],
            "managestructures": ["programPath", "action"],
            "managecomments": ["programPath", "action"],
            "managebookmarks": ["programPath", "action"],
            "inspectmemory": ["programPath", "mode"],
            "getcallgraph": ["programPath"],
            "searchconstants": ["programPath", "mode"],
            "analyzevtables": ["programPath", "mode"],
            "analyzedataflow": ["programPath"],
            "decompile": ["programPath"],
            "analyzeprogram": ["programPath"],
            "open": ["path"],
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
            parsed_args: dict[str, Any] = self.parse_arguments(arguments, tool_name)
            self.validate_required_arguments(parsed_args, tool_name)
        else:
            parsed_args = arguments

        return {
            "name": tool_name,
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
