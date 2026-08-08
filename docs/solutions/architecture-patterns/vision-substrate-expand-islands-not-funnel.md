---
title: "VISION substrate: expand islands on MCP, do not grow the reconstruct funnel"
date: 2026-08-08
category: architecture-patterns
module: agentdecompile_cli.mcp_server.providers.context_substrate
problem_type: architecture_pattern
component: tooling
severity: high
applies_when:
  - "Aligning product work to VISION.md binary-as-context motif"
  - "Adding MCP tools that surface dismantling, acquisition, or provenance context"
  - "Tempted to grow reconstruct / sourcegen / CRITICAL_PATH as the primary product surface"
tags:
  - vision
  - substrate
  - mcp
  - export-context
  - acquisition-query
  - claim-boundary
---

# VISION substrate: expand islands on MCP, do not grow the reconstruct funnel

## Context

VISION reframes AgentDecompile around **binary-as-context**: seamless dismantlers, provenance against hallucination, agent-directed composition, partial usefulness, and claim honesty. The recovery tree is large (~85k LOC; `sourcegen` + `source_parity_synthesize` dominate). Research concluded that "expand-in-place into reconstruct" fails — megamodule accretion and funnel-as-product fight the charter. Thin islands already exist (`context_export`, acquisition bundles, claim reports, rewrite packs) but were buried behind CLI/pipeline paths, not first-class Ghidra MCP tools.

## Guidance

1. **Treat matching recovery as a recipe track**, not product identity. `agentdecompile-reconstruct` and CRITICAL_PATH remain operator one-shots; do not default every agent task through them.
2. **Elevate VISION islands onto the curated MCP surface** as Tier-0 (or appropriately tiered) primitives with explicit `claimBoundary` text — advisory layout/evidence ≠ verified/objdiff.
3. **New context tools go in a dedicated provider** (`ContextSubstrateToolProvider`), not `RecoveryToolProvider` (reconstruct / status / claim-report only).
4. **Refuse funnel growth as substrate work**: do not expand `sourcegen` / `source_parity_synthesize` / frontdoor defaults to "make context better."
5. **Ship docs in the same beat** as registry changes: advertised tool counts (`len(Tool)`, GUI-hidden set) and `TOOLS_LIST.md` entries for new tools.

First slice (PR #171): `export-context` and `acquisition-query` on the default advertised surface (72 canonical / 68 advertised).

## Why This Matters

Agents that only see reconstruct will keep treating leftover `target/` receipts as fresh work and will skip provenance-rich trees. Substrate tools make dismantling and acquisition addressable without inventing a greenfield package or deepening the funnel — preserving claim tiers while changing product gravity toward compose-don't-funnel.

## When to Apply

- Choosing where to put a new MCP tool related to trees, bundles, claims, or context packs
- Prioritizing follow-ups (NSIS strength, PE `.rsrc` forests, acquisition bridging) vs recovery-perf megamodule work
- Writing STRATEGY / plan units under VISION

## Examples

**Before:** Context export lived as recovery CLI/pipeline only; MCP recovery provider stayed reconstruct-centric; README still said 70/66 tools after new tools landed.

**After:**

```text
tools/call export-context
  inputPath=... outDir=... binaryAnalysis=light maxFiles=250
→ navigable tree + claimBoundary (advisory)

tools/call acquisition-query
  action=inspect
→ address-keyed advisory evidence + claimBoundary
```

Provider: `src/agentdecompile_cli/mcp_server/providers/context_substrate.py`. Plan: `docs/plans/2026-08-08-001-feat-vision-substrate-mcp-context-plan.md`.

## Related

- [VISION.md](../../../VISION.md)
- [STRATEGY.md](../../../STRATEGY.md)
- [docs/solutions/architecture-patterns/agent-native-mcp-patterns.md](agent-native-mcp-patterns.md)
- [docs/solutions/architecture-patterns/capabilities-mcp-resource.md](capabilities-mcp-resource.md)
- PR https://github.com/bodecloud/AgentDecompile/pull/171
