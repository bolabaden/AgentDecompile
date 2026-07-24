---
name: tiered-re-analysis
description: Route reverse-engineering work through Tier 0–3 tools — use Ghidra MCP only when lighter techniques cannot answer the question or when mutating the program DB. Use for RE planning, triage, multi-agent workflows, and performance-sensitive analysis.
---

# Tiered reverse engineering analysis

Use this skill **before** calling Ghidra MCP tools. Full knowledge base: [docs/solutions/architecture-patterns/tiered-re-analysis-knowledgebase.md](../../docs/solutions/architecture-patterns/tiered-re-analysis-knowledgebase.md).

## When to activate

- Starting analysis on a new binary
- Choosing between shell tools vs `open-project`
- RE Planner / Worker / Critic / Aggregator workflows
- User asks for faster or lighter analysis
- Prompts: `re-scout-*` before `re-diver-*`

## Tier summary

| Tier | Ghidra? | Use for |
|------|---------|---------|
| **0** | No | `run-file-triage`, `run-external-re-scan`, `file`, `strings`, `yara`/`capa`, `binwalk` |
| **1** | Batch / external decomp | `run-batch-*`, **`run-decomp-match`** (m2c, objdiff bytecode verify, permuter) |
| **2** | MCP read-only | After `open-project` + analysis complete: `list-*`, `search-*`, `get-references`, `get-call-graph` |
| **3** | MCP deep/mutate | `decompile-function`, `analyze-data-flow`, `manage-*`, `match-function`, `execute-script` (last resort) |

## Mandatory routing rules

1. **Cold binary:** Run Tier 0 triage before `open-project` unless the binary is already in the session/project.
2. **Check `projectContext.analysisComplete`** before Tier 2–3 program-scoped MCP calls.
3. **Prefer list/search primitives** over decompile when the question is discovery (addresses, names, xrefs).
4. **Workers produce JSON artifacts** per [re-artifact-protocol](../../../.github/instructions/re-artifact-protocol.instructions.md); Critic verifies with independent tool calls.
5. **Apply mutations only after Aggregator consensus** (confidence ≥ 0.7) unless the user explicitly requests immediate rename/comment.

## Triage checklist (Tier 0)

Run when the binary path is known and Ghidra is not yet open.

**Prefer MCP (structured JSON for `analysis/triage.json`):**

1. **`run-file-triage`** with `binaryPath` — returns `file`, `sha256`, `strings`, optional tool probes.
2. Optional **`externalScanTools`**: `["capa", "yara", "binwalk"]` embeds `run-external-re-scan` results under `externalScans`.
3. Or **`run-external-re-scan`** with `tool: "all"` when only external RE scans are needed.

Map MCP response fields into triage artifact:

| MCP field | `triage.json` |
|-----------|---------------|
| `sha256` | `hash` |
| `file` | `format`, `architecture` hints |
| `strings` | `notable_strings` |
| `externalScans` | `capability_hints` |
| `suggestedTierEscalation` | `priority_queue` seed |

**Shell fallback** when MCP unavailable:

```bash
file "$BINARY"
sha256sum "$BINARY"
strings -a "$BINARY" | rg -i 'error|http|password|debug|\.dll' | head -50
```

Record results in `analysis/triage.json` (hash, format, notable strings, suggested Tier escalation).

## Escalation triggers

Escalate to **Tier 2+** when you need:

- Cross-references or call graph edges
- Ghidra-analyzed function boundaries
- Shared Ghidra Server checkout / version control
- Mutations (rename, types, comments)

Stay at **Tier 0–1** when:

- Identifying file type, entropy, embedded files
- Hunting keywords before committing to JVM startup
- Batch-exporting decomp for ripgrep/semgrep offline
- **Verifying decomp with objdiff** (bytecode match %) — use `run-decomp-match`, not `match-function`
- Running **m2c** on `.s` assembly or **permuter** on near-matching C

Use **Ghidra MCP (Tier 2–3)** for shared/versioned projects when you need checkout, struct export to headers, or check-in — not for every objdiff iteration.

## Multi-agent handoff

| Agent | Tier focus |
|-------|------------|
| RE Planner | 0 → 2 triage; never decompile |
| RE Worker | 2 → 3 for assigned functions |
| RE Critic | 2 → 3 verify claims |
| RE Aggregator | 3 apply + gap reassignment |

## References

- Agents: `.github/agents/re-*.agent.md`
- Commands: `/help`, `/capabilities`
- MCP prompts: `re-scout-broad-sweep`, `re-convergence-orchestrator`
