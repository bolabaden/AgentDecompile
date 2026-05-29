"""Shared tool-reference and capabilities payload builders for MCP surfaces."""

from __future__ import annotations

import logging
from typing import Any

from agentdecompile_cli.registry import (
    RESOURCE_URI_CAPABILITIES,
    TOOLS,
    TOOL_ALIASES,
    get_active_tool_surface_profile,
    get_advertised_tools_for_list,
    get_effective_max_analysis_tier,
    get_tool_metadata,
    get_tool_params,
    get_tool_profiles,
)

logger = logging.getLogger(__name__)

_TIER_ROUTING: list[dict[str, Any]] = [
    {
        "tier": 0,
        "ghidra": False,
        "summary": "Static file / OS tools — file, strings, headers, yara/capa before open-project",
        "examples": ["run-file-triage", "file", "strings", "yara", "capa", "binwalk"],
    },
    {
        "tier": 1,
        "ghidra": "batch_cli",
        "summary": "Batch ghidrecomp export when offline bulk is faster than live MCP",
        "examples": ["run-batch-decompile", "ghidrecomp decompile", "ghidrecomp export"],
    },
    {
        "tier": 2,
        "ghidra": "mcp_read_only",
        "summary": "Ghidra MCP read-only — list/search/xrefs after analysis gate",
        "examples": ["list-functions", "get-references", "checkout-status"],
    },
    {
        "tier": 3,
        "ghidra": "mcp_deep_mutate",
        "summary": "Decompile, dataflow, and mutating manage-* tools",
        "examples": ["decompile-function", "manage-comments", "match-function"],
    },
]


def build_tool_alias_index() -> dict[str, list[str]]:
    """Build canonical tool name → sorted alias names."""
    logger.debug("diag.enter %s", "mcp_utils/tool_reference.py:build_tool_alias_index")
    alias_index: dict[str, list[str]] = {canonical: [] for canonical in TOOLS}
    for alias_name, canonical_name in TOOL_ALIASES.items():
        if canonical_name not in alias_index:
            alias_index[canonical_name] = []
        if alias_name != canonical_name:
            alias_index[canonical_name].append(alias_name)
    for canonical_name, aliases in alias_index.items():
        alias_index[canonical_name] = sorted(set(aliases))
    return alias_index


def build_tool_reference_payload() -> dict[str, Any]:
    """Build the /tool-reference OpenAPI payload (canonical tools + transport metadata)."""
    logger.debug("diag.enter %s", "mcp_utils/tool_reference.py:build_tool_reference_payload")
    alias_index = build_tool_alias_index()
    listed_tools = set(get_advertised_tools_for_list())
    max_tier = get_effective_max_analysis_tier()
    canonical_tools: list[dict[str, Any]] = []
    for canonical_name in sorted(TOOLS):
        params = [str(param) for param in get_tool_params(canonical_name)]
        metadata = get_tool_metadata(canonical_name)
        canonical_tools.append(
            {
                "name": canonical_name,
                "advertised": canonical_name in listed_tools,
                "parameters": params,
                "aliases": alias_index.get(canonical_name, []),
                "profiles": get_tool_profiles(canonical_name),
                "metadata": {
                    "context_rich": bool(metadata.context_rich) if metadata is not None else False,
                    "single_purpose": bool(metadata.single_purpose) if metadata is not None else False,
                    "writes_state": bool(metadata.writes_state) if metadata is not None else False,
                    "legacy": bool(metadata.legacy) if metadata is not None else False,
                    "analysis_tier": int(metadata.analysis_tier) if metadata is not None else 3,
                    "replacement": list(metadata.replacement) if metadata is not None else [],
                },
            },
        )

    profile_counts = {
        "curated": sum("curated" in item["profiles"] for item in canonical_tools),
        "full": sum("full" in item["profiles"] for item in canonical_tools),
        "legacy": sum("legacy" in item["profiles"] for item in canonical_tools),
    }

    return {
        "summary": {
            "canonical_tool_count": len(TOOLS),
            "advertised_tool_count": len(listed_tools),
            "alias_count": sum(len(item["aliases"]) for item in canonical_tools),
            "active_tool_surface_profile": get_active_tool_surface_profile(),
            "profile_counts": profile_counts,
            **({"max_analysis_tier": max_tier} if max_tier is not None else {}),
        },
        "transport": {
            "canonical_endpoint": "/mcp",
            "compatibility_endpoint": "/mcp/message",
            "notes": [
                "Use /mcp as the canonical MCP streamable-HTTP route.",
                "Use /mcp/message only for compatibility with clients that hardcode that path.",
                "Standalone CLI calls are session-isolated; use tool-seq to keep state in one session.",
            ],
        },
        "shared_server_headers": {
            "authorization": "Basic <base64(username:password)>",
            "x-ghidra-server-host": "Shared Ghidra server host",
            "x-ghidra-server-port": "Shared Ghidra server port (usually 13100)",
            "x-ghidra-repository": "Shared repository name",
            "x-agent-server-username": "Optional username alias header",
            "x-agent-server-password": "Optional password alias header",
            "x-agent-server-repository": "Optional repository alias header",
        },
        "shared_server_http_mapping": {
            "request_url": {
                "env": "AGENT_DECOMPILE_MCP_SERVER_URL",
                "usage": "Request URL itself, typically http://host:port/mcp",
            },
            "env_to_headers": {
                "AGENT_DECOMPILE_GHIDRA_SERVER_HOST": ["X-Ghidra-Server-Host"],
                "AGENT_DECOMPILE_GHIDRA_SERVER_PORT": ["X-Ghidra-Server-Port"],
                "AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY": ["X-Ghidra-Repository", "X-Agent-Server-Repository"],
                "AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME": ["Authorization", "X-Agent-Server-Username"],
                "AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD": ["Authorization", "X-Agent-Server-Password"],
            },
            "transport_headers": {
                "content-type": "application/json",
                "accept": "application/json, text/event-stream",
                "mcp-session-id": "Send on follow-up requests after the server returns it",
            },
            "precedence": {
                "credentials": ["Authorization", "X-Agent-Server-Username/X-Agent-Server-Password"],
                "repository": ["X-Ghidra-Repository", "X-Agent-Server-Repository"],
            },
        },
        "environment_variables": {
            "shared_server": [
                "AGENT_DECOMPILE_GHIDRA_SERVER_HOST",
                "AGENT_DECOMPILE_GHIDRA_SERVER_PORT",
                "AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME",
                "AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD",
                "AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY",
            ],
            "local_project": [
                "AGENT_DECOMPILE_PROJECT_PATH",
                "AGENT_DECOMPILE_PROJECT_NAME",
            ],
            "tool_advertisement": [
                "AGENTDECOMPILE_TOOL_SURFACE",
                "AGENT_DECOMPILE_TOOL_SURFACE",
                "AGENTDECOMPILE_ENABLE_TOOLS",
                "AGENTDECOMPILE_DISABLE_TOOLS",
                "AGENTDECOMPILE_ENABLE_LEGACY_TOOLS",
                "AGENTDECOMPILE_SHOW_LEGACY_TOOLS",
                "AGENTDECOMPILE_MAX_ANALYSIS_TIER",
                "AGENT_DECOMPILE_MAX_ANALYSIS_TIER",
            ],
        },
        "request_headers": {
            "max_analysis_tier": "X-AgentDecompile-Max-Analysis-Tier (values 2 or 3; per-request override of env)",
        },
        "canonical_tools": canonical_tools,
    }


def build_capabilities_payload() -> dict[str, Any]:
    """Build agentdecompile://capabilities JSON (tier routing + tool inventory)."""
    logger.debug("diag.enter %s", "mcp_utils/tool_reference.py:build_capabilities_payload")
    tool_ref = build_tool_reference_payload()
    listed_tools = get_advertised_tools_for_list()
    listed_set = set(listed_tools)
    tier_counts = {0: 0, 1: 0, 2: 0, 3: 0}
    tools = tool_ref.pop("canonical_tools")
    for item in tools:
        if item.get("name") not in listed_set:
            continue
        tier = int(item.get("metadata", {}).get("analysis_tier", 3))
        if tier in tier_counts:
            tier_counts[tier] += 1

    return {
        "resourceUri": RESOURCE_URI_CAPABILITIES,
        "tiers": _TIER_ROUTING,
        "tier_tool_counts": {
            "mcp_tier_0_static": tier_counts.get(0, 0),
            "mcp_tier_1_batch": tier_counts.get(1, 0),
            "mcp_tier_2_read_only": tier_counts[2],
            "mcp_tier_3_deep_mutate": tier_counts[3],
            "note": "Tier 0–1 MCP tools include run-file-triage and run-batch-decompile; see tiers[] for routing.",
        },
        "discovery": {
            "skill": ".cursor/skills/tiered-re-analysis/SKILL.md",
            "knowledge_base": "docs/solutions/architecture-patterns/tiered-re-analysis-knowledgebase.md",
            "slash_command": ".cursor/commands/capabilities.md",
            "debug_resource": "agentdecompile://debug-info",
        },
        "summary": tool_ref["summary"],
        "transport": tool_ref["transport"],
        "environment_variables": tool_ref["environment_variables"],
        "tools": [item for item in tools if item.get("name") in listed_set],
    }
