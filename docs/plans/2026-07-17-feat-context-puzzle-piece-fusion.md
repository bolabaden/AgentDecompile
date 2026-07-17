---
title: "feat: Context puzzle-piece fusion UX"
type: feat
status: completed
date: 2026-07-17
origin: docs/brainstorms/2026-07-17-context-puzzle-piece-fusion-requirements.md
---

# feat: Context puzzle-piece fusion UX

## Summary

Make context ingestion feel like dropping puzzle pieces on `reconstruct`: positional CLI paths, honest address-keyed placement stats, and advisory seeds from ugly source dumps—without guessing addresses or expanding curated MCP peers.

## Problem Frame

Acquisition/sniff/pack already exist, but operators still need `--context` flags, cannot see placed vs unplaced at a glance, and ugly decomp dumps do not obviously become cleanup seeds. Requirements pin reconstruct-primary fusion with no VA guesswork (see origin).

---

## Requirements

- R1. Positional context paths after target (union with `--context`).
- R2. Skipped/unrecognized pieces reported with reasons.
- R3–R4. Address-keyed place or unplaced; conflicts retained.
- R5. Source-dump → advisory seed files when address present.
- R6. Status/acquire receipt expose placement counts.
- R7–R8. MCP via `contextPaths` only; no proof-ladder inflation.

---

## Key Technical Decisions

- KTD1. **Parser change only for nargs** — `input` stays required; `context_positional` via `nargs='*'`; merge with `--context`.
- KTD2. **Advisory materialization** lives in acquire/context-pack post-pass writing `advisory/context-seeds/` under work_dir when acquire runs from reconstruct (not inside registry global store).
- KTD3. **Reuse existing conflict model** — do not invent a second conflict schema.
- KTD4. **Status reads acquire.json / context-pack manifest** for placement summary.

---

## Implementation Units

### U1. Positional context CLI parsing

**Goal:** `reconstruct bin.exe a.c notes.md dir/` works.

**Files:**
- Modify: `src/agentdecompile_recovery/frontdoor.py`
- Test: `tests/test_acquisition.py`

**Approach:** Add positional `context` nargs; merge+dedupe with `--context` before `acquire_context` / `RecoveryConfig`.

**Test scenarios:**
- Happy: positional + flag union
- Edge: zero context still works
- Error: missing target still fails as today

### U2. Placement summary + advisory seeds

**Goal:** After acquire, write placement stats and seed advisory files from placed source-dump facts.

**Files:**
- Modify: `src/agentdecompile_recovery/acquire.py` and/or `context_pack.py`
- Modify: `src/agentdecompile_recovery/recovery_status.py`
- Test: `tests/test_acquisition.py`, `tests/test_recovery_mcp.py`

**Approach:** From context-pack manifest + bundle conflicts, emit `acquisition/placement.json`; copy decompiled bodies to `advisory/context-seeds/<name>_<hex>.c` with sidecar claimBoundary.

**Test scenarios:**
- Happy: dump with address → seed file + placed count ≥ 1
- Edge: note without address → unplaced++, no seed
- Edge: two facts same address different names → conflictCount ≥ 1, both retained
- Integration: status exposes `contextFusion` summary

### U3. Operator docs (short)

**Goal:** Document the puzzle-piece mental model.

**Files:**
- Create or modify: `docs/CONTEXT_FUSION.md` (or shortest existing reconstruct doc section)
- Modify: reconstruct `--help` epilog one-liner

**Test expectation:** none -- docs

---

## Scope Boundaries

- No auto Ghidra rename apply
- No embedding placement
- No new curated MCP acquire tool

---

## Risks

| Risk | Mitigation |
|------|------------|
| Positional args confuse with subcommands | Only on reconstruct front door; self-check stays separate |
| Advisory seed spam | Only placed source-dump facts; cap by max_files already |
| Operators think seeds are verified | Sidecar + claimBoundary + R8 |
