---
description: "Reverse engineering artifact protocol: shared schema, workspace layout, confidence scoring, and convergence rules for the multi-agent RE pipeline (RE Planner, RE Worker, RE Critic, RE Aggregator)."
applyTo: "**"
---

# RE Artifact Protocol

## Workspace Layout

All agents in the RE pipeline share a structured workspace under `/analysis/` (relative to the working directory). This is the single source of ground truth.

```
/analysis/
  triage.json                    # Binary triage from Planner
  status.json                    # Current analysis status from Aggregator
  /functions/
    0x401000.json                # Merged artifact per function (by address)
    0x401200.json
  /worker_raw/
    0x401000_worker_1.json       # Raw Worker output (kept for audit)
    0x401000_worker_2.json
  /reviews/
    0x401000_review.json         # Critic review records
  /types/
    structs.json                 # Recovered struct definitions
    enums.json                   # Recovered enum definitions
    globals.json                 # Global variable catalog
  /hypotheses/
    <id>.json                    # Cross-function hypotheses
  /logs/
    runs.jsonl                   # Append-only log of agent runs
```

## Artifact Immutability

- Worker raw outputs are NEVER modified after creation. New analysis produces a new file.
- Merged artifacts (`/functions/`) are updated ONLY by the Aggregator.
- Critic reviews are NEVER modified. New reviews produce new files.
- The `runs.jsonl` log is append-only.

## Confidence Scale

| Score | Level | Meaning |
|-------|-------|---------|
| 0.9–1.0 | Certain | String/API evidence, trivial wrapper, well-known pattern |
| 0.7–0.8 | High | Strong circumstantial, Critic-confirmed, caller-consistent |
| 0.5–0.6 | Medium | Plausible, some gaps remain, partial evidence |
| 0.3–0.4 | Low | Educated guess, significant unknowns |
| 0.0–0.2 | Speculative | Minimal evidence, structural inference only |

## Convergence Rules

A function is **converged** when:
1. Confidence ≥ 0.6
2. Critic has reviewed and not disputed core hypothesis
3. No `blocking` gaps remain
4. Types are consistent with all callers and callees

The analysis is **complete** when:
1. All high/medium priority functions are converged
2. No cross-function type inconsistencies exist
3. Call graph is fully consistent
4. Remaining gaps are marked `UNKNOWN` with justification

## MCP Tool Mapping

These are the AgentDecompile MCP tools available for each analysis phase:

### Discovery / Read-Only
- `list-functions` — enumerate functions (pagination: offset/limit)
- `list-imports` / `list-exports` — external symbols
- `list-strings` — embedded strings
- `get-function` — metadata for one function
- `get-functions` — batch metadata/decompile/disassemble
- `get-references` / `list-cross-references` — xref analysis
- `get-call-graph` — call relationships
- `search-everything` — multi-scope keyword search
- `search-strings` / `search-symbols` / `search-constants` — targeted search
- `get-data` — data at address
- `inspect-memory` — raw memory inspection
- `analyze-data-flow` — data flow analysis
- `analyze-vtables` — C++ vtable recovery

### Mutation (apply findings)
- `manage-function` — rename, set prototype/return type/calling convention
- `manage-comments` — set/get/search comments at addresses
- `manage-symbols` / `create-label` — rename symbols, create labels
- `manage-bookmarks` — bookmark addresses with categories
- `manage-function-tags` — tag functions (crypto, network, etc.)
- `manage-structures` — create/edit recovered struct types
- `apply-data-type` — apply type to address
- `match-function` — cross-binary function matching
- `execute-script` — arbitrary PyGhidra script (last resort)

### Naming Conventions (from project standards)
- Local variables / parameters: `camelCase`
- Struct fields: `snake_case`
- Types / classes: `PascalCase`
- Enum constants: `SCREAMING_SNAKE_CASE`

## Anti-Hallucination Rules

1. If you cannot find evidence in the binary for a claim, mark it `UNKNOWN`.
2. If the decompiler output looks suspicious, cross-check with disassembly.
3. If a type is inferred from a single call site, confidence ≤ 0.5.
4. If a hypothesis has no supporting constants, strings, or API calls, confidence ≤ 0.4.
5. Never invent function names based on address proximity alone.
6. Never assume two functions are related just because they are adjacent in memory.
