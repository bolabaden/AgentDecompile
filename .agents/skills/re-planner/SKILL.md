---
name: re-planner
description: "Use this skill when the user wants a plan for a binary, triage of an executable, or the multi-agent RE pipeline. Do not decompile here; dispatch workers."
license: AGPL-3.0-or-later
metadata:
  author: AgentDecompile
  version: "1.0"
  role: planner
  argument-hint: "Binary path or program name"
---

# RE Planner

Single coordinator. Triage, decompose, assign, validate, aggregate. Never analyze function internals — dispatch **re-worker**.

**REQUIRED SUB-SKILL:** `tiered-re-analysis`

## Rules

1. Every action writes a structured artifact (see `.github/instructions/re-artifact-protocol.instructions.md`).
2. Track progress on a todo list.
3. Create the artifact workspace before delegating.

## Phase 0 — Tiered routing

Cold binary: Tier 0 `run-file-triage` / `run-external-re-scan` (or `file`/`strings` if MCP is down). Optional Tier 1 `run-batch-*`, `bsim-ingest`, `run-decomp-match`. Open Ghidra only for xrefs, analyzed bounds, shared checkout, or mutations.

Warm session (`projectContext.analysisComplete`): skip Tier 0; use Tier 2 list/search.

## Phase 1 — Ghidra map (Tier 2)

`get-current-program` → `list-functions` (paginate) → `list-imports` / `list-exports` → `list-strings` → `get-call-graph` → `search-everything`.

Write `analysis/triage.json` with binary, architecture, counts, entry points, suspicious clusters, and a priority queue.

## Phase 2–5

- High priority: entries, exports, high-xref, string-hit functions. Medium: their callees. Low: leaves.
- Each work unit → **re-worker** with address + focus. High-priority functions: 2–3 independent workers.
- Then **re-critic** on those artifacts. Issues → re-assign worker with critic notes.
- Batch → **re-aggregator**. Gaps → new work units.

Done when high/medium functions have hypothesis + evidence + confidence ≥ 0.6, no contradictions, consistent call-graph types, and gaps are empty or `UNKNOWN` with justification.

## User summary

Functions analyzed, confidence split, remaining gaps, naming recommendations.
