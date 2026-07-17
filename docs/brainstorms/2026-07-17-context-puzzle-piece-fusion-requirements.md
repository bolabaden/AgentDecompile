---
title: "requirements: Intuitive context puzzle-piece fusion"
type: requirements
status: active
date: 2026-07-17
origin: STRATEGY.md + docs/plans/2026-07-13-feat-unified-source-parity-recovery.md (Context IA)
---

# requirements: Intuitive context puzzle-piece fusion

## Problem Frame

Operators and agents already have messy puzzle pieces for a binary: ugly decompiler dumps, unstructured notes, structured JSON/JSONL, Ghidra `.gzf` / project snapshots. AgentDecompile can sniff and pack many of these (`acquire_context`, `discovery.sniff_path`, `context_pack`), but the **hand-off still feels like a pipeline** (`--context` flags only, weak visibility into placed vs unplaced, dumps not obviously seeding cleanup). Users need to **point at pieces** and have them integrate procedurally by address/provenance—not by LLM guesswork.

## Research Brief (repo + external)

### Tier 1 (Actionable Now)

- [REPO] Frozen UX already specifies: `reconstruct <target> [context…]`, auto-sniff, register by target fingerprint, later runs reuse registry without re-passing paths (`docs/plans/2026-07-13-feat-unified-source-parity-recovery.md` Context IA).
- [REPO] Implementation today: repeatable `--context` only — **positional context args are missing** (`frontdoor.py`).
- [REPO] Sniffer already classifies binary / ghidra-project / `.gzf` / facts-jsonl / source-dump / notes / json / directories (`discovery.py`).
- [REPO] Context pack extracts function facts from C dumps via header+brace parse and address regexes; notes become context-items; **rows without `entryOffset`/`address` are `unplaced`** and must stay evidence-only (`context_pack.py`).
- [REPO] Bundle builder records **address conflicts** when multiple names disagree (`acquisition_bundle.py`); claim boundary always advisory until objdiff.
- [REPO] Curated MCP already accepts `contextPaths` on `reconstruct` — no separate acquire peer tool by design (`mcp_server/providers/recovery.py`).
- [REPO] Ghidra mutations already use a **conflict/overwrite protocol** (`resolve-modification-conflict`) — bulk silent rename from context would fight that model.
- [SYNTH] Implication: ship **CLI positional parity + placement visibility + advisory seeding from dumps**; keep Ghidra label apply as explicit follow-up (agent uses `manage-function` with conflicts), not silent auto-apply.

### Tier 2 (Directional)

- [REPO] Mid-run re-acquire merges snapshots without mutating `verified/` (`acquire.py`).
- [OFFICIAL/adjacent] Community Ghidra tools focus on recompilable decomp cleanup or semantic search over decomp — not multi-artifact puzzle fusion; AgentDecompile’s fingerprint registry is the differentiator.
- [SYNTH] Implication: treat “cleanup of ugly dump” as **advisory seed → vacuum/objdiff**, not “overwrite Ghidra names from dump.”

### Tier 3 (Frontier)

- Embedding search over decomp (e.g. pyghidra-mcp Chroma) for fuzzy placement when address missing — defer; violates “no guesswork” for v1.

### Caveats

- [OPEN] Live Ghidra project dirs still require explicit unlocked `--project-snapshot` (safe-by-design); do not parse `.rep` internals.
- [OPEN] External web research was rate-limited; conclusions rely primarily on repo + frozen UX.

### Repo Implications

- Prefer: positional context; status fields for placed/unplaced/conflicts; materialize dump functions into `advisory/`; document one mental model.
- Defer: auto-apply renames into open Ghidra; embedding-based address inference; new peer `acquire` product verb.
- Avoid: inventing addresses for unplaced notes; counting context as objdiff proof; expanding curated MCP with vacuum/acquire peers.

## Actors

- A1. Human RE operator dumping folders of notes + partial C next to a PE/ELF.
- A2. Agent using MCP `reconstruct` with `contextPaths`.
- A3. Downstream reconstruct stages (sourcegen/synthesis/vacuum) consuming fused function-facts.

## Key Flows

- F1. First-run puzzle dump: `reconstruct game.exe ./ugly-decomp/ notes.md archive.gzf` → sniff → pack → registry → recovery uses fused facts; receipt shows placed/unplaced/conflicts.
- F2. Mid-run add piece: same target + new `--context` / positional piece with `--resume` → new snapshot merge; `verified/` untouched.
- F3. Ugly dump cleanup: source-dump functions with addresses land in acquisition facts **and** `advisory/` seeds; promotion only via objdiff.

## Requirements

- R1. CLI accepts context puzzle pieces as **positional paths after the target** and as repeatable `--context` (union, deduped).
- R2. Every piece is auto-sniffed; unsupported formats are listed as skipped with reason — never silently invented.
- R3. Placement is **procedural and address-keyed** (`entryOffset`/`address`); missing address ⇒ `unplaced` evidence only (no guessed VA).
- R4. Address conflicts retain all witnesses and a conflict record; do not auto-pick a winner.
- R5. Parsed source-dump functions with addresses materialize under `advisory/` (or equivalent advisory seed tree) with `context-hint` / advisory claim boundaries for cleanup workflows.
- R6. Acquisition/status surfaces `placed`, `unplaced`, `conflicts`, `skipped` counts so operators see integration health without digging JSONL.
- R7. MCP continues to pass pieces via `reconstruct.contextPaths` (no new curated peer acquire tool in v1).
- R8. Claim honesty: context never increments proof-ladder numerator; remains `context-hint` / advisory until objdiff.

## Success Criteria

- Operator can run one command with mixed paths and get a non-empty acquisition receipt with placement stats.
- A minimal C dump containing `FUN_00401000` / address prelude yields a fact **and** an advisory seed file.
- Unit tests cover positional parse, unplaced retention, and conflict non-resolution.
- Docs show the three-path mental model (CLI positional, `--context`, MCP `contextPaths`).

## Scope Boundaries

### In scope

- Positional CLI context; placement visibility; advisory seeding from dumps; docs.

### Deferred for later

- Auto-apply labels/comments into open Ghidra programs from the bundle.
- Embedding / fuzzy match for unplaced notes.
- Rich structured-note schemas beyond current regex/JSON parsers.

### Outside this product's identity

- Claiming context integration equals semantic recovery.
- Peer product verbs (`acquire` as primary docs surface).

## Key Decisions

- D1. Honor frozen Context IA: reconstruct-primary, positional pieces, fingerprint registry.
- D2. No address guesswork — unplaced stays unplaced.
- D3. Ghidra apply stays agent/conflict-protocol driven; fusion layer feeds reconstruct, not silent DB mutation.
- D4. Ugly dumps → advisory seeds + facts, not verified/.

## Outstanding Questions

None blocking for v1 slice. Auto-apply-to-Ghidra remains explicitly deferred.
