"""Backward-compatible utility exports.

The authoritative implementations for shared response, normalization, argument,
connectivity, and conversion helpers live in ``agentdecompile_cli.executor`` and
``agentdecompile_cli.registry``. This module keeps legacy imports working
without duplicating logic.
"""

from __future__ import annotations

from typing import Any

from agentdecompile_cli.executor import (
    build_http_url,
    canonicalize_tool_name,
    create_error_response,
    create_success_response,
    extract_json_from_response,
    format_output,
    get_argument_variations,
    get_client,
    get_optional_bool,
    get_optional_int,
    get_optional_str,
    get_server_start_message,
    handle_command_error,
    handle_noisy_mcp_errors,
    normalize_backend_url,
    parse_http_response,
    run_async,
    run_async_in_thread,
    run_sync_in_async,
    safe_bool_conversion,
    safe_int_conversion,
    safe_str_conversion,
    show_connection_error,
    validate_required_argument,
)
from agentdecompile_cli.registry import normalize_identifier, to_snake_case

__all__ = [
    "create_error_response",
    "create_success_response",
    "normalize_identifier",
    "to_snake_case",
    "canonicalize_tool_name",
    "match_tool_name",
    "normalize_string_arg",
    "validate_required_program_path",
    "validate_required_address_or_symbol",
    "get_server_start_message",
    "normalize_backend_url",
    "get_client",
    "run_async",
    "show_connection_error",
    "handle_command_error",
    "handle_noisy_mcp_errors",
    "safe_int_conversion",
    "safe_bool_conversion",
    "safe_str_conversion",
    "extract_json_from_response",
    "build_http_url",
    "parse_http_response",
    "run_async_in_thread",
    "run_sync_in_async",
    "format_output",
    "get_argument_variations",
    "get_optional_bool",
    "get_optional_int",
    "get_optional_str",
    "validate_required_argument",
]


def match_tool_name(tool_name: str, canonical_name: str) -> bool:
    return normalize_identifier(tool_name) == normalize_identifier(canonical_name)


def normalize_string_arg(value: Any, default: str = "") -> str:
    return str(value).lower().strip() if value is not None else default.lower().strip()


def validate_required_program_path(program_path: str | None) -> str:
    if not program_path or not program_path.strip():
        raise ValueError("programPath is required")
    return program_path


def validate_required_address_or_symbol(address_or_symbol: str | None, context: str = "") -> str:
    if not address_or_symbol or not address_or_symbol.strip():
        msg = f"address or addressOrSymbol is required: {context}" if context else "address or addressOrSymbol is required"
        raise ValueError(msg)
    return address_or_symbol
