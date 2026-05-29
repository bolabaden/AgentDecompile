---
title: Tiered RE analysis routing — compound learning
date: 2026-05-29
category: architecture-patterns
module: agentdecompile_cli.registry
problem_type: architecture_pattern
component: tooling
symptoms:
  - Agents defaulted to open-project and decompile for every RE question
  - No machine-readable signal for Ghidra MCP tool cost tier
  - Multi-agent RE pipeline lacked pre-Ghidra triage guidance
root_cause: missing_tiered_routing_guidance
resolution_type: code_and_docs
severity: medium
tags:
  - tiered-analysis
  - analysis_tier
  - multi-agent-re
  - ghidra-when-necessary
---

# Tiered RE analysis routing

## Problem

Agents treated Ghidra MCP as the only RE surface: cold binaries went straight to `open-project` and `decompile-function`, wasting JVM startup and analysis time on tasks answerable with shell tools or read-only MCP list/search primitives.

## Solution (PR #62, master `7471598`)

### Tier 0–3 routing

| Tier | Ghidra? | Agent action |
|------|---------|--------------|
| 0 | No | `file`, `strings`, headers, yara/capa before `open-project` |
| 1 | Batch CLI | `ghidrecomp` export when offline bulk is faster |
| 2 | MCP read-only | `list-*`, `search-*`, xrefs after analysis gate |
| 3 | MCP deep/mutate | decompile, `manage-*`, `match-function` |

Full matrix: [tiered-re-analysis-knowledgebase.md](./tiered-re-analysis-knowledgebase.md). Skill: `.cursor/skills/tiered-re-analysis/SKILL.md`.

### Code: `analysis_tier` metadata

- `ToolMetadata.analysis_tier` — **2** (read-only/session) or **3** (deep/mutate)
- `get_tool_analysis_tier()` in `registry.py`; exposed in OpenAPI tool-reference payload
- Tests: `tests/test_tool_analysis_tier.py`

### Agents aligned

- RE Planner Phase 0 shell triage before Ghidra
- Worker/Critic prefer Tier 2 before Tier 3
- Artifact protocol tier table in `.github/instructions/re-artifact-protocol.instructions.md`

## Prevention

- New MCP tools: assign tier in `_TIER3_GHIDRA_TOOLS` or default Tier 2; extend `test_tool_analysis_tier.py` if non-obvious
- New agent skills: link tiered-re-analysis skill before Ghidra tool lists
- Discovery: `/help` and `/capabilities` document Tier 0 first

## Related

- KB: [tiered-re-analysis-knowledgebase.md](./tiered-re-analysis-knowledgebase.md)
- PR: https://github.com/bolabaden/AgentDecompile/pull/62 (merged squash `7471598`, 2026-05-29)
- Plans: `docs/plans/2026-05-24-tiered-re-knowledgebase-c2bc.md`, `docs/plans/2026-05-29-lfg-pr62-analysis-tier-c2bc.md`
