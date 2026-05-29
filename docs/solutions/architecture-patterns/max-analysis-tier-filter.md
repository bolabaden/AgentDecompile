---
title: Max analysis tier filter — compound learning
date: 2026-05-24
category: architecture-patterns
module: agentdecompile_cli.registry
problem_type: architecture_pattern
component: tooling
symptoms:
  - Agents saw full Tier 3 mutate/decompile tools in tools/list before completing Tier 2 triage
  - No env or header to constrain MCP tool surface by analysis_tier at runtime
  - Capabilities resource listed all advertised tools regardless of escalation policy
root_cause: missing_runtime_tier_filter
resolution_type: code_and_docs
severity: medium
tags:
  - analysis_tier
  - tools-list
  - tiered-re
  - agent-native
  - mcp
---

# Max analysis tier filter

## Problem

Tiered RE routing (PR #62) added `analysis_tier` metadata on tools, and PR #64 exposed it via `agentdecompile://capabilities`. Agents still received the **full** `tools/list` surface unless operators used curated profiles or explicit enable/disable lists — there was no way to say “Tier 2 read-only only until I escalate.”

## Solution (PR #66, master `4b8110d`)

### Runtime filter (list only)

- **Env:** `AGENTDECOMPILE_MAX_ANALYSIS_TIER` / `AGENT_DECOMPILE_MAX_ANALYSIS_TIER` — values `2` or `3`; unset = no filter
- **Header:** `X-AgentDecompile-Max-Analysis-Tier` — per-request override (valid header wins over env)
- **Helper:** `get_advertised_tools_for_list()` filters `ADVERTISED_TOOLS` by `get_tool_analysis_tier()`
- **Site:** `ToolProviderManager.list_tools()` iterates the filtered list

### tools/call unchanged

Tier-3 tools remain callable when hidden from list (same parity as curated surface / auto-checkin hiding `checkin-program`).

### Capabilities + proxy

- `build_capabilities_payload()` filters `tools[]` and adds `summary.max_analysis_tier` when active
- Proxy allowlists and forwards `x-agentdecompile-max-analysis-tier`

## Prevention

- New list-only filters: apply at `get_advertised_tools_for_list()` — not at import-time `ADVERTISED_TOOLS`
- Per-request overrides: follow `CURRENT_REQUEST_*` context var pattern in `session_context.py` + `server.py` middleware
- Tests: isolate env with `monkeypatch.delenv` in capabilities tests when asserting full tier mix

## Related

- KB: [tiered-re-analysis-knowledgebase.md](./tiered-re-analysis-knowledgebase.md)
- Capabilities: [capabilities-mcp-resource.md](./capabilities-mcp-resource.md)
- Tests: `tests/test_max_analysis_tier_filter.py`, `tests/test_proxy_forwarded_headers.py`
- PR: https://github.com/bolabaden/AgentDecompile/pull/66
