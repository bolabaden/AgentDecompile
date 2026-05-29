---
title: LFG — Tiered RE arc closeout + master verify
type: chore
status: completed
date: 2026-05-30
branch: impl/tiered-re-arc-closeout-c2bc
pr: https://github.com/bolabaden/AgentDecompile/pull/90
merge_sha: a5a9e22
---

# LFG — Tiered RE arc closeout + master verify

## Summary

Tier 0–1 MCP tools, discovery sync (PR #86), and capabilities verification (PR #88) complete the tiered RE arc. This plan refreshes stale compound docs, closes residual trackers, adds a capabilities tier-routing regression test, and verifies `pytest -m unit` on master.

```mermaid
flowchart TD
  A[Stale tier docs + residual trackers] --> B[Refresh tiered-re-analysis-routing]
  B --> C[Close tiered-re knowledgebase residual]
  C --> D[Add capabilities tiers[] routing test]
  D --> E[Note rename-variable gap in audit tracker]
  E --> F[pytest -m unit green]
```

---

## Problem Frame

`tiered-re-analysis-routing.md` still describes Tier 0–1 as shell/CLI-only. `impl-tiered-re-knowledgebase-c2bc.md` lists Tier 0 wrappers as future work. No test asserts capabilities `tiers[]` examples include MCP `run-*` tools.

---

## Requirements

| ID | Requirement | Status |
|----|-------------|--------|
| R1 | Update `docs/solutions/architecture-patterns/tiered-re-analysis-routing.md` with Tier 0–1 MCP tools and link to `tier01-mcp-discovery-sync.md` | Done |
| R2 | Mark `docs/residual-review-findings/impl-tiered-re-knowledgebase-c2bc.md` future items Done | Done |
| R3 | Unit test: `build_capabilities_payload()["tiers"]` tier 0/1 examples include `run-file-triage` and `run-batch-decompile` | Done |
| R4 | `uv run pytest -m unit -q --timeout=120` passes on branch | Done |
| R5 | Note next agent-native gap (`rename-variable` handler) in audit residual tracker | Done |

---

## Scope Boundaries

- No new MCP tools or rename-variable implementation (separate slice).
- No browser/GUI testing.

---

## Implementation Units

- U1. **Refresh tiered-re-analysis-routing compound doc** — R1
- U2. **Close tiered-re residual tracker** — R2
- U3. **Capabilities tier routing test** — R3, test file `tests/test_capabilities_resource.py`
- U4. **Audit residual next-gap note** — R5, `docs/residual-review-findings/impl-agent-native-audit-c2bc.md`
- U5. **Master verify** — R4

---

## Sources

- PRs #62, #64, #66, #80–#88
- `docs/solutions/architecture-patterns/tier01-mcp-discovery-sync.md`

## Verification

```bash
uv run pytest tests/test_capabilities_resource.py -m unit -q
uv run pytest -m unit -q --timeout=120
```
