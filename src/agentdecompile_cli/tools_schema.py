"""Canonical MCP tool and resource names for AgentDecompile.

Content is mirrored in registry.py, which is the primary source of truth.
This module is retained for compatibility with existing imports.
Prefer importing from agentdecompile_cli.registry.
"""

from __future__ import annotations

from agentdecompile_cli.registry import (
    RESOURCE_URIS,
    RESOURCE_URI_DEBUG_INFO,
    RESOURCE_URI_PROGRAMS,
    RESOURCE_URI_STATIC_ANALYSIS,
    TOOLS,
    TOOL_PARAMS as _TOOL_PARAMS_ENUM,
    ResourceUri,
    Tool,
    build_tool_payload,
    get_tool_params,
    to_camel_case_key,
)

# Re-export enums and TOOLS from registry (single source of truth).
__all__ = [
    "RESOURCE_URIS",
    "RESOURCE_URI_DEBUG_INFO",
    "RESOURCE_URI_PROGRAMS",
    "RESOURCE_URI_STATIC_ANALYSIS",
    "TOOLS",
    "TOOL_PARAMS",
    "ResourceUri",
    "Tool",
    "build_tool_payload",
    "get_tool_params",
    "to_camel_case_key",
]

# Backward-compat: str-keyed view of TOOL_PARAMS for code that does TOOL_PARAMS.get("open").
# Registry holds dict[Tool, list[str]]; we expose dict[str, list[str]] here.
TOOL_PARAMS: dict[str, list[str]] = {t.value: list(p) for t, p in _TOOL_PARAMS_ENUM.items()}
