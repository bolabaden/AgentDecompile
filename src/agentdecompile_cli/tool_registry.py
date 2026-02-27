"""Backward-compatibility shim for the legacy tool_registry module.

The authoritative implementation now lives in ``agentdecompile_cli.registry``.
This module re-exports the same public API so existing imports continue to work
without maintaining duplicate logic.
"""

from __future__ import annotations

from agentdecompile_cli.registry import (
    TOOL_PARAMS,
    TOOLS,
    ToolRegistry,
    build_tool_payload,
    get_tool_params,
    normalize_identifier,
    tool_registry,
    to_camel_case_key,
    to_snake_case,
)

__all__ = [
    "TOOLS",
    "TOOL_PARAMS",
    "normalize_identifier",
    "to_snake_case",
    "to_camel_case_key",
    "build_tool_payload",
    "get_tool_params",
    "ToolRegistry",
    "tool_registry",
]
