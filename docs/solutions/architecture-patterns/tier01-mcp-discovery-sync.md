---
title: Tier 0–1 MCP tools and discovery sync — compound learning
date: 2026-05-30
category: architecture-patterns
module: agentdecompile_cli
problem_type: architecture_pattern
component: tooling
symptoms:
  - Agents defaulted to shell triage or ghidrecomp CLI before Ghidra
  - Discovery docs advertised 60/56 tools after six run-* MCP tools landed
  - Capabilities resource lacked explicit tier 0–1 verification tests
root_cause: tier0_tier1_mcp_gap
resolution_type: code_and_docs
severity: medium
tags:
  - tiered-analysis
  - run-file-triage
  - run-batch-decompile
  - capability-discovery
  - agent-native
---

# Tier 0–1 MCP tools and discovery sync

## Problem

Tiered RE routing (PR #62) defined Tier 0–1 conceptually, but agents still lacked first-class MCP tools for cold-binary triage and batch export. After implementing six `run-*` tools (PRs #80–#85), human-facing discovery surfaces drifted (60/56 counts) and described Tier 1 as CLI-only.

## Solution arc

```mermaid
flowchart LR
  T0[run-file-triage] --> T0b[run-external-re-scan]
  T0b --> T1[run-batch-* x4]
  T1 --> D[Discovery sync PR #86]
  D --> V[Capabilities verify tests]
```

| Tier | MCP tools | PR |
|------|-----------|-----|
| 0 | `run-file-triage`, `run-external-re-scan` | #84, #82 |
| 0 embed | `externalScanTools` on triage | #85 |
| 1 | `run-batch-decompile`, `run-batch-export-gzf`, `run-batch-bsim-signatures`, `run-batch-sast-scan`, **`run-decomp-match`** | #80–#83, #113 |

**Discovery sync (PR #86):** Updated `.cursorrules`, `/capabilities`, `/help`, RE Planner, artifact protocol, KB, README/USAGE to **67 canonical / 63 advertised** (after `run-decomp-match`, PR #113) and document tier 0–1 `run-*` tools.

**Capabilities verification:** `tests/test_capabilities_resource.py` asserts each `run-*` appears in `agentdecompile://capabilities` with correct `analysis_tier` and dynamic summary counts.

## Agent routing (after arc)

1. Cold binary → **`run-file-triage`** (optional **`externalScanTools`**) before `open-project`.
2. Bulk offline → **`run-batch-*`** before long-lived MCP session.
3. Session bootstrap → `resources/read` **`agentdecompile://capabilities`** for tier routing + tool inventory.

## Prevention

- When adding `Tool` enum entries, update dynamic parity tests — not hardcoded counts in prose.
- Extend `test_capabilities_payload_includes_tier01_run_tools` when new tier 0–1 tools ship.
- Keep `_TIER_ROUTING` in `tool_reference.py` aligned with KB tier tables.

## Related

- KB: [tiered-re-analysis-knowledgebase.md](./tiered-re-analysis-knowledgebase.md)
- Capabilities: [capabilities-mcp-resource.md](./capabilities-mcp-resource.md)
- Skill: `.cursor/skills/tiered-re-analysis/SKILL.md`
- PR #86: https://github.com/bolabaden/AgentDecompile/pull/86
