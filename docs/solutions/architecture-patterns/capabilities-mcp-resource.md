---
title: Capabilities MCP resource — compound learning
date: 2026-05-24
category: architecture-patterns
module: agentdecompile_cli.mcp_server.resources.capabilities
problem_type: architecture_pattern
component: tooling
symptoms:
  - Agents needed tools/list or slash /capabilities before knowing tier routing
  - No MCP-native discovery surface for analysis_tier metadata
  - tool-reference payload duplicated in server.py
root_cause: missing_capabilities_resource
resolution_type: code_and_docs
severity: medium
tags:
  - mcp-resources
  - capability-discovery
  - analysis_tier
  - agent-native
---

# Capabilities MCP resource

## Problem

Agent-native audit flagged **Capability Discovery** at ~71%: agents had `/capabilities` slash command and OpenAPI `/tool-reference`, but no **`resources/read`** URI for session bootstrap. Tiered RE routing lived in docs/skills only — not machine-readable at MCP initialize time.

## Solution (PR #64, master `cd4b069`)

### MCP resource

- **URI:** `agentdecompile://capabilities`
- **Provider:** `CapabilitiesResource` in `mcp_server/resources/capabilities.py`
- **Payload:** Tier 0–3 routing table, `summary` (tool surface profile), `tools[]` with `metadata.analysis_tier`

No Ghidra program required — safe at session start.

### Shared builder

Extracted `build_tool_reference_payload()` and `build_capabilities_payload()` to `mcp_utils/tool_reference.py`; `server.py` imports the shared builder (dedupes OpenAPI tool-reference).

### Registry

`ResourceUri.CAPABILITIES` → `RESOURCE_URI_CAPABILITIES` in `RESOURCE_URIS`.

## Prevention

- New discovery surfaces: prefer MCP resource + slash command + INDEX link
- Tool metadata changes: capabilities payload picks up `analysis_tier` from registry automatically
- After extracting helpers from `server.py`, run `ruff check` — CI gates on unused imports

## Related

- KB: [tiered-re-analysis-knowledgebase.md](./tiered-re-analysis-knowledgebase.md)
- Slash: `.cursor/commands/capabilities.md`
- Tests: `tests/test_capabilities_resource.py`
- PR: https://github.com/bolabaden/AgentDecompile/pull/64
