"""Executor, shared utilities, and response helpers for AgentDecompile.

Merged from:
  - dynamic_tool_executor.py  (DynamicToolExecutor, dynamic_executor singleton)
  - utils.py                  (shared CLI utilities, arg helpers, type coercions)
  - utils_original.py         (real implementations of connectivity helpers)
  - responses.py              (inline; create_success_response / create_error_response)

All tool execution flows through DynamicToolExecutor.execute_tool().
All connectivity helpers (get_client, normalize_backend_url, etc.) live here.
"""

from __future__ import annotations

import asyncio
import json as _json
import logging
import os
import re
import sys

from typing import Any
from urllib.parse import urlparse, urlunparse

from mcp import types

from agentdecompile_cli.registry import (
    ToolRegistry,
    normalize_identifier,
    resolve_tool_name,
    tool_registry,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Response helpers (formerly responses.py – that file never existed on disk)
# ---------------------------------------------------------------------------


def create_success_response(data: dict[str, Any]) -> list[types.TextContent]:
    """Create a standardized MCP success response."""
    return [types.TextContent(type="text", text=_json.dumps(data))]


def create_error_response(error: str | Exception) -> list[types.TextContent]:
    """Create a standardized MCP error response."""
    error_msg = str(error) if isinstance(error, Exception) else error
    return [types.TextContent(type="text", text=_json.dumps({"success": False, "error": error_msg}))]


# ---------------------------------------------------------------------------
# Connectivity / URL utilities  (real implementations from utils_original.py)
# ---------------------------------------------------------------------------


def get_server_start_message() -> str:
    """Return the standardized server start message."""
    return (
        "Please start the server first.\n\n"
        "Connect to an existing AgentDecompile MCP server:\n\n"
        "  mcp-agentdecompile --server-url http://host:port\n"
        "  mcp-agentdecompile --host 127.0.0.1 --port 8080\n"
        "  AGENT_DECOMPILE_MCP_SERVER_URL=http://host:port mcp-agentdecompile\n"
        "  AGENT_DECOMPILE_SERVER_HOST=host AGENT_DECOMPILE_SERVER_PORT=8080 mcp-agentdecompile\n\n"
        "Or run Ghidra with AgentDecompile enabled and use the URL from File > Edit Tool Options > AgentDecompile."
    )


def build_backend_url(host: str, port: int, use_tls: bool = False) -> str:
    """Build MCP backend URL from host and port (for connect mode)."""
    scheme = "https" if use_tls else "http"
    return f"{scheme}://{host}:{port}"


def normalize_backend_url(value: str) -> str:
    """Normalize a backend URL or host[:port] into a full MCP message endpoint URL."""
    raw = value.strip()
    if not raw:
        raise ValueError("Backend URL cannot be empty")
    if "://" not in raw:
        raw = f"http://{raw}"
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(
            f"Unsupported URL scheme '{parsed.scheme}'. Use http:// or https://.",
        )
    if not parsed.netloc:
        raise ValueError("Backend URL must include a host")
    path = (parsed.path or "").rstrip("/")
    if not path or path == "":
        path = "/mcp/message"
    elif not path.endswith("/mcp/message"):
        path = f"{path}/mcp/message"
    return urlunparse(parsed._replace(path=path))


def resolve_backend_url(
    server_url: str | None,
    host: str | None,
    port: int | None,
    env_url_keys: tuple[str, ...] = (
        "AGENT_DECOMPILE_MCP_SERVER_URL",
        "AGENT_DECOMPILE_SERVER_URL",
    ),
    env_host_key: str = "AGENT_DECOMPILE_SERVER_HOST",
    env_port_key: str = "AGENT_DECOMPILE_SERVER_PORT",
    default_host: str = "127.0.0.1",
    default_port: int = 8080,
) -> str | None:
    """Resolve backend URL for connect mode.

    Priority: explicit server_url > env URL > host+port (cli or env).
    Returns None if no connect-mode option is set.
    """
    if server_url and server_url.strip():
        return server_url.strip()
    for key in env_url_keys:
        val = os.getenv(key)
        if val and val.strip():
            return val.strip()
    h = host or os.getenv(env_host_key)
    p = port
    if p is None:
        try:
            p = int(os.getenv(env_port_key, "") or default_port)
        except ValueError:
            p = default_port
    if h is not None and h.strip():
        return build_backend_url(h.strip(), p)
    if os.getenv(env_port_key) is not None:
        return build_backend_url(default_host, p)
    return None


def format_output(data: Any, fmt: str, verbose: bool = False) -> str:
    """Format data for human-readable output.

    fmt: 'shell' (default) | 'json' | 'markdown' | 'xml' | legacy aliases ('text', 'table')
    """
    normalized = (fmt or "shell").strip().lower()

    if normalized == "json":
        return _json.dumps(data, indent=2)

    if normalized in {"shell", "text"}:
        if isinstance(data, dict):
            return "\n".join(f"{k}: {v}" for k, v in data.items())
        if isinstance(data, list):
            return "\n".join(f"- {item}" for item in data)
        return str(data)

    if normalized == "markdown":
        if isinstance(data, dict):
            return "\n".join(f"- **{k}**: {v}" for k, v in data.items())
        if isinstance(data, list):
            if data and isinstance(data[0], dict):
                headers = list(data[0].keys())
                header_row = "| " + " | ".join(headers) + " |"
                sep_row = "| " + " | ".join(["---"] * len(headers)) + " |"
                body_rows = ["| " + " | ".join(str(item.get(h, "")) for h in headers) + " |" for item in data]
                return "\n".join([header_row, sep_row, *body_rows])
            return "\n".join(f"- {item}" for item in data)
        return str(data)

    if normalized == "xml":
        def _xml_escape(value: Any) -> str:
            return (
                str(value)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&apos;")
            )

        def _to_xml(value: Any, tag: str = "item") -> str:
            if isinstance(value, dict):
                inner = "".join(_to_xml(v, k) for k, v in value.items())
                return f"<{tag}>{inner}</{tag}>"
            if isinstance(value, list):
                inner = "".join(_to_xml(item, "item") for item in value)
                return f"<{tag}>{inner}</{tag}>"
            return f"<{tag}>{_xml_escape(value)}</{tag}>"

        return _to_xml(data, "result")

    if normalized == "table":
        if isinstance(data, list) and data and isinstance(data[0], dict):
            headers = list(data[0].keys())
            lines = [" | ".join(headers), "-" * (len(headers) * 10)]
            for item in data:
                row = [str(item.get(h, "")) for h in headers]
                lines.append(" | ".join(row))
            return "\n".join(lines)
        return str(data)

    return str(data)


def handle_noisy_mcp_errors(error_msg: str) -> bool:
    """Check if error_msg contains noisy MCP/async cleanup patterns and handle them.

    Returns True if the error was handled (was noisy), False otherwise.
    """
    noisy_patterns = [
        "async_generator",
        "GeneratorExit",
        "aclose()",
        "unhandled errors in a TaskGroup",
        "Attempted to exit cancel scope",
        "asynchronous generator is already running",
        "Exception Group",
        "CancelledError: Cancelled by cancel scope",
        "anyio.WouldBlock",
    ]
    if not any(pattern in error_msg for pattern in noisy_patterns):
        return False
    if "ServerNotRunningError" in error_msg or "Cannot connect" in error_msg:
        for line in error_msg.split("\n"):
            line = line.strip()
            if "Cannot connect" in line or "AgentDecompile" in line:
                sys.stderr.write(f"Error: {line}\n")
                return True
    if any(p in error_msg.lower() for p in ["connection", "connect", "refused", "failed"]):
        show_connection_error()
        return True
    sys.stderr.write(
        "Error: An error occurred. Please ensure the AgentDecompile backend is running.\n",
    )
    return True


def show_connection_error() -> None:
    """Display a standardized connection error message to stderr."""
    sys.stderr.write(
        f"Error: Cannot connect to AgentDecompile backend.\n\n{get_server_start_message()}\n",
    )


def run_async(coro: Any) -> Any:
    """Run an async coroutine."""
    return asyncio.run(coro)


def handle_command_error(error: BaseException) -> None:
    """Handle CLI errors and display user-friendly messages to stderr."""
    error_msg = str(error)
    if (
        isinstance(error, (ConnectionRefusedError, ConnectionError, OSError))
        or "ConnectError" in error_msg
        or "connection refused" in error_msg.lower()
        or "all connection attempts failed" in error_msg.lower()
    ):
        show_connection_error()
        return
    if isinstance(error, asyncio.exceptions.CancelledError):
        show_connection_error()
        return
    if handle_noisy_mcp_errors(error_msg):
        return
    if type(error).__name__ == "ServerNotRunningError":
        sys.stderr.write(f"Error: {error}\n")
        return
    if type(error).__name__ == "ClientError":
        sys.stderr.write(f"Error: {error}\n")
        return
    sys.stderr.write(f"Error: {error_msg}\n")


def get_client(
    host: str = "127.0.0.1",
    port: int = 8080,
    url: str | None = None,
    api_key: str | None = None,
) -> Any:
    """Create and return an AgentDecompileMcpClient instance (not connected)."""
    from agentdecompile_cli.bridge import AgentDecompileMcpClient

    return AgentDecompileMcpClient(
        host=host,
        port=port,
        url=url,
    )


# ---------------------------------------------------------------------------
# Backward-compat tool name helpers (delegate to registry)
# ---------------------------------------------------------------------------


def canonicalize_tool_name(tool_name: str) -> str:
    """Canonicalize tool name using dynamic executor."""
    return dynamic_executor._resolve_tool_name(tool_name) or ""


def match_tool_name(tool_name: str, canonical_name: str) -> bool:
    """Check tool name match using dynamic executor."""
    return dynamic_executor._registry.match_tool_name(tool_name, canonical_name)


# ---------------------------------------------------------------------------
# Argument getter helpers (delegate to DynamicToolExecutor)
# ---------------------------------------------------------------------------


def execute_tool_dynamically(
    tool_name: str,
    arguments: dict[str, Any],
    context: dict[str, Any] | None = None,
) -> Any:
    """Execute any tool dynamically using the unified executor."""
    return dynamic_executor.execute_tool(tool_name, arguments, context)


# ---------------------------------------------------------------------------
# Safe type conversions
# ---------------------------------------------------------------------------


def safe_int_conversion(value: Any, default: int = 0) -> int:
    """Safely convert value to int."""
    try:
        return int(value) if value is not None else default
    except (ValueError, TypeError):
        return default


def safe_bool_conversion(value: Any, default: bool = False) -> bool:
    """Safely convert value to bool."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ("true", "1", "yes", "on", "enabled")
    return bool(value) if value is not None else default


def safe_str_conversion(value: Any, default: str = "") -> str:
    """Safely convert value to str."""
    return str(value) if value is not None else default


# ---------------------------------------------------------------------------
# HTTP utilities
# ---------------------------------------------------------------------------


def extract_json_from_response(response_text: str) -> dict[str, Any] | None:
    """Extract JSON from HTTP response text."""
    try:
        return _json.loads(response_text)
    except _json.JSONDecodeError:
        return None


def build_http_url(base_url: str, endpoint: str) -> str:
    """Build HTTP URL from base and endpoint."""
    if not base_url.endswith("/"):
        base_url += "/"
    endpoint = endpoint.removeprefix("/")
    return base_url + endpoint


def parse_http_response(response: Any) -> dict[str, Any] | None:
    """Parse HTTP response into dictionary."""
    if hasattr(response, "json"):
        try:
            return response.json()
        except Exception:
            pass

    if hasattr(response, "text"):
        return extract_json_from_response(response.text)

    if isinstance(response, str):
        return extract_json_from_response(response)

    return None


# ---------------------------------------------------------------------------
# Async utilities
# ---------------------------------------------------------------------------


async def run_async_in_thread(func: Any, *args: Any, **kwargs: Any) -> Any:
    """Run async function in thread."""
    loop = asyncio.new_event_loop()
    try:
        return await loop.run_in_executor(None, func, *args, **kwargs)
    finally:
        loop.close()


def run_sync_in_async(func: Any, *args: Any, **kwargs: Any) -> Any:
    """Run sync function in async context."""
    return asyncio.get_event_loop().run_in_executor(None, func, *args, **kwargs)


# ---------------------------------------------------------------------------
# Multi-key argument helpers (mirror Java ToolProvider convenience methods)
# ---------------------------------------------------------------------------


def get_argument_variations(arguments: dict[str, Any], *keys: str) -> Any:
    """Return the first non-None value from *arguments* matching any of *keys*.

    Tries exact key match first, then falls back to normalized
    (alphabet-only, lowercase) matching so callers can pass camelCase,
    snake_case, kebab-case, or any other casing and still get a match.

    Example::

        path = get_argument_variations(args, "program_path")
        # Matches "program_path", "programPath", "program-path", etc.
    """
    # Fast path: exact match
    for key in keys:
        val = arguments.get(key)
        if val is not None:
            return val
    # Slow path: normalized (alphabet-only, lowercase) match
    normalized_keys = {normalize_identifier(k) for k in keys}
    for arg_key, arg_val in arguments.items():
        if arg_val is not None and normalize_identifier(arg_key) in normalized_keys:
            return arg_val
    return None


def get_optional_bool(
    arguments: dict[str, Any],
    *key_defaults: tuple[str, bool],
) -> bool:
    """Return the first non-None bool value from *arguments*.

    Each element of *key_defaults* is a ``(key_name, default_value)`` pair.
    Falls back to the default from the first pair if nothing is found.
    Performs exact match first, then normalized (alphabet-only, lowercase)
    fallback so any casing or separator style is accepted.

    Example::

        include_externals = get_optional_bool(args, ("include_externals", False))
        # Matches "include_externals", "includeExternals", "include-externals", etc.
    """
    fallback: bool = key_defaults[0][1] if key_defaults else False

    def _to_bool(raw: Any) -> bool:
        if isinstance(raw, bool):
            return raw
        if isinstance(raw, str):
            return raw.strip().lower() in ("true", "1", "yes", "on")
        return bool(raw)

    # Fast path: exact match
    for key, _ in key_defaults:
        raw = arguments.get(key)
        if raw is not None:
            return _to_bool(raw)
    # Slow path: normalized match
    normalized_keys = {normalize_identifier(k) for k, _ in key_defaults}
    for arg_key, raw in arguments.items():
        if raw is not None and normalize_identifier(arg_key) in normalized_keys:
            return _to_bool(raw)
    return fallback


def get_optional_int(
    arguments: dict[str, Any],
    *key_defaults: tuple[str, int],
) -> int:
    """Return the first non-None int value from *arguments*.

    Tries exact key match first, then normalized (alphabet-only, lowercase)
    fallback so any casing or separator style is accepted.

    Example::

        limit = get_optional_int(args, ("max_results", 100))
        # Matches "max_results", "maxResults", "max-results", etc.

    Args:
    ----
        arguments: The raw arguments dictionary to search.
        *key_defaults: A variable number of (key, default) pairs to check in order.

    Returns:
        The first int value found for any of the keys, or the default from the first pair if none found.
    """
    fallback: int = key_defaults[0][1] if key_defaults else 0
    # Fast path: exact match
    for key, _ in key_defaults:
        raw = arguments.get(key)
        if raw is not None:
            try:
                return int(raw)
            except (TypeError, ValueError):
                pass
    # Slow path: normalized match
    normalized_keys = {normalize_identifier(k) for k, _ in key_defaults}
    for arg_key, raw in arguments.items():
        if raw is not None and normalize_identifier(arg_key) in normalized_keys:
            try:
                return int(raw)
            except (TypeError, ValueError):
                pass
    return fallback


def get_optional_str(
    arguments: dict[str, Any],
    *key_defaults: tuple[str, str],
) -> str:
    """Return the first non-empty string value from *arguments*.

    Tries exact key match first, then normalized (alphabet-only, lowercase)
    fallback so any casing or separator style is accepted.

    Example::

        mode = get_optional_str(args, ("output_mode", "list"))
        # Matches "output_mode", "outputMode", "output-mode", etc.

    Args:
    ----

    Returns:
    -------
        The first non-empty string value found for any of the keys, or the default from the first pair if none found.
    """
    fallback: str = key_defaults[0][1] if key_defaults else ""
    # Fast path: exact match
    for key, _ in key_defaults:
        raw = arguments.get(key)
        if raw is not None and str(raw).strip():
            return str(raw)
    # Slow path: normalized match
    normalized_keys = {normalize_identifier(k) for k, _ in key_defaults}
    for arg_key, raw in arguments.items():
        if raw is not None and str(raw).strip() and normalize_identifier(arg_key) in normalized_keys:
            return str(raw)
    return fallback


def validate_required_argument(value: Any, name: str) -> None:
    """Raise ``ValueError`` if *value* is ``None`` or an empty string.

    Example::

        validate_required_argument(program_path, "programPath")

    Args:
    ----
        value: The value to validate.
        name: The name of the argument (used in error message).

    Raises:
    ------
        ValueError: If the value is None or an empty string.
    """
    if value is None or (isinstance(value, str) and not value.strip()):
        raise ValueError(f"'{name}' is required")


# ---------------------------------------------------------------------------
# DynamicToolExecutor
# ---------------------------------------------------------------------------


class DynamicToolExecutor:
    """Executes any tool dynamically based on the tool registry.

    This class provides a single interface for all tool execution, eliminating
    the need for tool-specific parsing and validation code.

    Attributes:
    ----------
        _registry: The tool registry containing tool schemas and execution logic.
    """

    def __init__(self):
        self._registry: ToolRegistry = tool_registry

    def execute_tool(
        self,
        tool_name: str,
        raw_arguments: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> list[types.TextContent]:
        """Execute any tool dynamically.

        Args:
        ----
            tool_name: Tool name (any variation accepted)
            raw_arguments: Raw arguments dict (any case variations accepted)
            context: Execution context (program_info, ghidra_tools, etc.)

        Returns:
        -------
            Tool execution result as list of TextContent
        """
        try:
            # Step 1: Resolve tool name dynamically
            canonical_name: str | None = self._resolve_tool_name(tool_name)
            if not canonical_name or not canonical_name.strip():
                raise ValueError(f"Unknown tool: {tool_name}")

            # Step 2: Parse arguments dynamically
            parsed_args = self._parse_arguments_dynamically(canonical_name, raw_arguments)

            # Step 3: Validate arguments dynamically
            self._validate_arguments_dynamically(canonical_name, parsed_args)

            # Step 4: Execute tool dynamically
            result = self._execute_tool_dynamically(canonical_name, parsed_args, context)

            return result

        except Exception as e:
            logger.error(f"Tool execution failed: {tool_name} - {e}")
            return self._create_error_response(e)

    def _resolve_tool_name(self, tool_name: str) -> str | None:
        """Resolve tool name to the canonical registry display name.

        Accepts any variation (kebab-case, snake_case, camelCase, etc.) and
        returns the canonical tool name as stored in the registry (kebab-case).
        Only alphabetic characters matter for matching.

        Args:
        ----
            tool_name: The input tool name to resolve.

        Returns:
        -------
            Canonical registry tool name (kebab-case), or None if no match found.
        """
        return resolve_tool_name(tool_name)

    def _parse_arguments_dynamically(
        self,
        canonical_tool_name: str,
        raw_arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """Parse arguments dynamically based on tool schema.

        Accepts any argument name variations and maps them to canonical parameter names.
        For each expected parameter, tries all variations (camelCase, snake_case, kebab-case)

        Args:
        ----
            canonical_tool_name: The canonical tool name to look up the schema.
            raw_arguments: The raw arguments dictionary to parse.

        Returns:
        -------
            A dictionary of parsed arguments with canonical parameter names.
        """
        # Resolve noisy tool name variants (e.g. GET-DATA, get_data) to the
        # actual registry key so param lookup always succeeds.
        resolved = self._resolve_tool_name(canonical_tool_name)
        if resolved is not None:
            canonical_tool_name = resolved

        parsed_args: dict[str, Any] = {}
        expected_params: list[str] = self._registry.get_tool_params(canonical_tool_name)

        for param_name in expected_params:
            # Try all possible variations of the parameter name
            param_variations = self._generate_param_variations(param_name)

            found = False
            for variation in param_variations:
                if variation in raw_arguments:
                    value = raw_arguments[variation]
                    parsed_value = self._coerce_value_dynamically(param_name, value)
                    parsed_args[param_name] = parsed_value
                    found = True
                    break

            if not found:
                # Normalized fallback: strip all non-alpha chars from both sides
                # and compare.  Accepts any casing or separator style as long
                # as the alphabetic characters match.
                normalized_param = normalize_identifier(param_name)
                for key, value in raw_arguments.items():
                    if normalize_identifier(key) == normalized_param:
                        parsed_value = self._coerce_value_dynamically(param_name, value)
                        parsed_args[param_name] = parsed_value
                        break

        return parsed_args

    def _generate_param_variations(
        self,
        param_name: str,
    ) -> list[str]:
        """Generate all possible variations of a parameter name.

        Supports: camelCase, snake_case, kebab-case

        Args:
        ----
            param_name: The canonical parameter name to generate variations for.

        Returns:
        -------
            A list of possible parameter name variations to check against input arguments.
        """
        variations: list[str] = [param_name]

        # Convert camelCase to snake_case
        snake_case = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", param_name).lower()
        if snake_case != param_name.lower():
            variations.append(snake_case)

        # Convert camelCase to kebab-case
        kebab_case = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", param_name).lower()
        if kebab_case != param_name.lower():
            variations.append(kebab_case)

        # Handle special cases from the schemas
        if param_name == "addressOrSymbol":
            variations.extend(["address", "symbol", "addr"])
        elif param_name == "programPath":
            variations.extend(["path", "program", "binary", "file", "filepath"])
        elif param_name == "maxResults":
            variations.extend(["limit", "count", "max"])
        elif param_name == "startIndex":
            variations.extend(["offset", "start"])
        elif param_name == "includeSignature":
            variations.extend(["signature", "include_sig"])
        elif param_name == "simplifyExpressions":
            variations.extend(["simplify", "simple"])

        return variations

    def _coerce_value_dynamically(
        self,
        param_name: str,
        value: Any,
    ) -> Any:
        """Coerce value to appropriate type based on parameter name patterns."""
        if value is None:
            return None

        # List/array parameters (checked first, based on known array parameters from docs)
        array_params: set[str] = {
            "address",
            "labelname",
            "newname",
            "identifiers",
            "functionidentifier",
            "functions",
            "prototype",
            "propagateprogrampaths",
            "tags",
            "targetprogrampaths",
            "fields",
            "comments",
            "bookmarks",
            "commenttypes",
            "addresses",
            "names",
            "symbols",
        }
        if param_name.lower() in array_params:
            if isinstance(value, list):
                return value
            # Return non-list values unchanged; callers handle wrapping if needed
            return value

        # Boolean parameters
        if (
            any(
                keyword in param_name.lower()
                for keyword in (
                    "analyze",
                    "disable",
                    "enable",
                    "exclude",
                    "filter",
                    "include",
                    "remove",
                    "resolve",
                    "set",
                )
            )
            or "sensitive" in param_name.lower()
        ):
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                lower = value.lower()
                if lower in ("true", "1", "yes", "on", "enabled"):
                    return True
                if lower in ("false", "0", "no", "off", "disabled"):
                    return False
                return value  # Not a bool-looking string; return unchanged
            if isinstance(value, int):
                return value != 0
            return bool(value)

        # Integer parameters
        if any(
            keyword in param_name.lower()
            for keyword in (
                "count",
                "depth",
                "index",
                "length",
                "limit",
                "max",
                "min",
                "offset",
                "size",
                "timeout",
            )
        ):
            if isinstance(value, int):
                return value
            if isinstance(value, str):
                try:
                    return int(value)
                except ValueError:
                    return value  # Not an int-looking string; return unchanged
            return int(value) if value else 0

        # String parameters (most common - checked last)
        if any(
            keyword in param_name.lower()
            for keyword in [
                "address",
                "format",
                "mode",
                "name",
                "path",
                "string",
                "symbol",
                "text",
                "type",
            ]
        ):
            return str(value)

        # Default to string
        return str(value)

    def _validate_arguments_dynamically(
        self,
        canonical_tool_name: str,
        parsed_args: dict[str, Any],
    ) -> None:
        """Validate arguments dynamically based on tool requirements."""
        normalized_tool_name = normalize_identifier(canonical_tool_name)

        required_params: dict[str, list[str]] = {
            "analyzedataflow": ["programpath"],
            "analyzeprogram": ["programpath"],
            "analyzevtables": ["programpath", "mode"],
            "applydatatype": ["programpath", "addressorsymbol", "datatypestring"],
            "createlabel": ["programpath", "addressorsymbol", "labelname"],
            "decompile": ["programpath"],
            "getcallgraph": ["programpath"],
            "getdata": ["programpath", "addressorsymbol"],
            "getreferences": ["programpath", "target"],
            "inspectmemory": ["programpath", "mode"],
            "managebookmarks": ["programpath", "action"],
            "managecomments": ["programpath", "action"],
            "managestructures": ["programpath", "action"],
            "searchconstants": ["programpath", "mode"],
            # pyghidra-mcp tools
            "decompilefunction": ["binaryname", "name"],
            "deleteprojectbinary": ["binaryname"],
            "gencallgraph": ["binaryname", "functionnameoraddress"],
            "importbinary": ["binarypath"],
            "listcrossreferences": ["binaryname", "nameoraddress"],
            "listexports": ["binaryname"],
            "listimports": ["binaryname"],
            "listprojectbinarymetadata": ["binaryname"],
            "readbytes": ["binaryname", "address"],
            "searchcode": ["binaryname", "query"],
            "searchstrings": ["binaryname", "query"],
            "searchsymbolsbyname": ["binaryname", "query"],
        }

        required: list[str] = required_params.get(normalized_tool_name, [])
        normalized_present: set[str] = {normalize_identifier(param_name) for param_name, value in parsed_args.items() if value is not None}

        for param in required:
            if normalize_identifier(param) in normalized_present:
                continue
            raise ValueError(f"Required parameter '{param}' is missing for tool '{canonical_tool_name}'")

        # Additional validations based on parameter patterns
        for param_name, value in parsed_args.items():
            if "path" in param_name.lower() and value is not None:
                if not isinstance(value, str) or not value.strip():
                    raise ValueError(f"Parameter '{param_name}' must be a non-empty string")
            elif "address" in param_name.lower() and value is not None:
                if not isinstance(value, str) or not value.strip():
                    raise ValueError(f"Parameter '{param_name}' must be a valid address string")

    def _execute_tool_dynamically(
        self,
        canonical_tool_name: str,
        parsed_args: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> list[types.TextContent]:
        """Execute tool dynamically based on tool type and available context."""
        context = {} if context is None else context

        if "ghidra_tools" in context:
            return self._execute_with_ghidra_tools(canonical_tool_name, parsed_args, context)
        if "program_info" in context:
            return self._execute_with_program_info(canonical_tool_name, parsed_args, context)
        return self._execute_placeholder(canonical_tool_name, parsed_args)

    def _execute_with_ghidra_tools(
        self,
        tool_name: str,
        args: dict[str, Any],
        context: dict[str, Any],
    ) -> list[types.TextContent]:
        """Execute tool using GhidraTools instance."""
        parsed_tool_name = self._resolve_tool_name(tool_name)
        if not parsed_tool_name:
            raise ValueError(f"Unknown tool: {tool_name}")

        parsed_args = self._parse_arguments_dynamically(parsed_tool_name, args)
        self._validate_arguments_dynamically(parsed_tool_name, parsed_args)

        from agentdecompile_cli.tools.wrappers import GhidraTools

        ghidra_tools: GhidraTools = context.get("ghidra_tools", GhidraTools())  # type: ignore

        try:
            normalized_tool_name = normalize_identifier(tool_name)

            if normalized_tool_name == "decompile":
                from agentdecompile_cli.tools.decompile_tool import DecompileTool

                decompile_tool = DecompileTool(context.get("program_info"), ghidra_tools.decompiler)
                result = decompile_tool.decompile_function_for_mcp(
                    function_name_or_address=args.get("function") or args.get("addressOrSymbol", ""),
                    timeout=args.get("timeout", 30),
                    include_signature=args.get("includeSignature", True),
                )
                return self._create_success_response(
                    {
                        "name": result.name,
                        "code": result.code,
                        "signature": result.signature,
                    },
                )
            if normalized_tool_name == "getcallgraph":
                from agentdecompile_cli.tools.callgraph_tool import CallGraphTool

                callgraph_tool = CallGraphTool(context.get("program_info"))
                result = callgraph_tool.generate_for_mcp(
                    function_name_or_address=args.get("function") or args.get("addressOrSymbol", ""),
                    direction=args.get("direction", "calling"),
                    display_type=args.get("displayType", "flow"),
                    include_refs=args.get("includeRefs", True),
                    max_depth=args.get("maxDepth"),
                    max_run_time=args.get("maxRunTime", 60),
                    condense_threshold=args.get("condenseThreshold", 50),
                    top_layers=args.get("topLayers", 5),
                    bottom_layers=args.get("bottomLayers", 5),
                )
                return self._create_success_response(
                    {
                        "functionName": result.function_name,
                        "direction": result.direction.value,
                        "displayType": result.display_type.value,
                        "graph": result.graph,
                        "mermaidUrl": result.mermaid_url,
                    },
                )
            # pyghidra-mcp tools (alpha-only internal names)
            _PYGHIDRA_MCP_TOOLS: frozenset[str] = frozenset(
                {
                    "decompilefunction",
                    "deleteprojectbinary",
                    "gencallgraph",
                    "importbinary",
                    "listcrossreferences",
                    "listexports",
                    "listimports",
                    "listprojectbinaries",
                    "listprojectbinarymetadata",
                    "readbytes",
                    "searchcode",
                    "searchstrings",
                    "searchsymbolsbyname",
                },
            )
            if normalized_tool_name in _PYGHIDRA_MCP_TOOLS:
                # Tools from pyghidra-mcp - placeholder implementations
                return self._create_success_response(
                    {
                        "tool": tool_name,
                        "status": "pyghidra_mcp_tool_placeholder",
                        "args": args,
                        "message": f"Tool '{tool_name}' from pyghidra-mcp needs integration",
                    },
                )
            # Generic tool execution for tools not yet fully implemented
            return self._create_success_response(
                {
                    "tool": tool_name,
                    "status": "executed_with_ghidra_tools",
                    "args": args,
                },
            )
        except Exception as e:
            return self._create_error_response(e)

    def _execute_with_program_info(
        self,
        tool_name: str,
        args: dict[str, Any],
        context: dict[str, Any],
    ) -> list[types.TextContent]:
        """Execute tool using only program info."""
        return self._create_success_response(
            {
                "tool": tool_name,
                "status": "executed_with_program_info",
                "args": args,
            },
        )

    def _execute_placeholder(
        self,
        tool_name: str,
        args: dict[str, Any],
    ) -> list[types.TextContent]:
        """Execute placeholder for unimplemented tools."""
        return self._create_success_response(
            {
                "tool": tool_name,
                "status": "placeholder_execution",
                "args": args,
                "message": f"Tool '{tool_name}' is not yet fully implemented",
            },
        )

    def _create_success_response(self, data: dict[str, Any]) -> list[types.TextContent]:
        """Create standardized success response."""
        return create_success_response(data)

    def _create_error_response(self, error: str | Exception) -> list[types.TextContent]:
        """Create standardized error response."""
        return create_error_response(error)


# Global dynamic executor instance
dynamic_executor = DynamicToolExecutor()
