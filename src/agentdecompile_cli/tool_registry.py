"""Backward-compatibility shim for the legacy tool_registry module.

The authoritative implementation now lives in ``agentdecompile_cli.registry``.
This module re-exports the same public API so existing imports continue to work
without maintaining duplicate logic.
"""

from __future__ import annotations

from agentdecompile_cli.registry import (
    TOOLS,
    TOOL_PARAMS,
    ToolRegistry,
    build_tool_payload,
    get_tool_params,
    normalize_identifier,
    to_camel_case_key,
    to_snake_case,
    tool_registry,
)

__all__ = [
    "TOOLS",
    "TOOL_PARAMS",
    "ToolRegistry",
    "build_tool_payload",
    "get_tool_params",
    "normalize_identifier",
    "to_camel_case_key",
    "to_snake_case",
    "tool_registry",
]
