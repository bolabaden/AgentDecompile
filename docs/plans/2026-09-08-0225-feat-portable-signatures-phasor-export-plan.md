---
title: Portable Signatures and Phasor Export - Plan
type: feat
date: 2026-09-08
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
product_contract_source: ce-plan-bootstrap
execution: code
---

# Portable Signatures and Phasor Export - Plan

**Target repos:** AgentDecompile (export + matcher docs), KotorPhasor (resolve by signature).

**Product Contract preservation:** authored here. Recovery ladder plan stays `docs/plans/2026-09-08-0156-feat-recovery-pipeline-ladder-plan.md`.

## Goal Capsule

- **Objective:** One `logical_id` per function across a corpus, found without treating a per-binary VA as identity. Export a Phasor-shaped hook pack. KotorPhasor resolves sites from unique `expected_bytes` when the recorded address is missing or stale.
- **Authority:** `STRATEGY.md` Approach + Portable identity track, then this plan.
- **Stop when:** `corpus.export-hookpack` writes a pack from the identity store, and KotorPhasor can bind a required site from `expected_bytes` alone.
- **Do not:** Implement DRM/unpack. Rewrite 2026-08-30 living-plan deltas. Hardcode KotOR names into AgentDecompile defaults. Re-analyze programs that already have analysis.
- **Execution profile:** Code. Smoke export on a temp SQLite store. Phasor change is resolve-before-install.

## Product Contract

### Summary

The matcher already refuses raw bytes and absolute addresses. The hook host still keys on per-build VAs and only uses `expected_bytes` to verify before patch. Flip that: recorded VA is a hint; unique byte window (then content/BSim/`logical_id`) is the identity. AgentDecompile emits the pack so the next corpus does not repeat the address hunt.

### Requirements

- R1. STRATEGY and CONCEPTS name the signal order: debug/STABS → content channels → BSim → unique byte window last.
- R2. A `logical_id` is the cross-build identity. A VA is an instance.
- R3. Prefer one signature family that hits every registered build; if it cannot, record coverage and keep the family that hits the most.
- R4. `corpus.export-hookpack` writes `agentdecompile.hookpack/v1` JSON from the identity store.
- R5. KotorPhasor `AddressTable` resolves a site from unique `expected_bytes` when the hint VA is missing or the bytes there do not match.
- R6. KotOR-specific names stay in data packs (`data/addresses/`, `data/routines/`), not in the resolver.
- R7. Skip-if-done and never-decompile-twice stay in force.

### Key Decisions

- Byte-window search is last-resort, not the matcher. (session-settled: user-directed — chosen over making copy-nearby-bytes the primary finder: `match_engine` already has a stronger stack.) Governs R1, R2.
- Recorded VA is a cache/hint. (session-settled: user-directed — chosen over per-binary address tables as identity.) Governs R5.
- New plan, not a rewrite of the 2026-08-30 living plan. Governs sequencing only.

### Key Flows

- F1. Export: operator runs `corpus.export-hookpack --db STORE --out PACK.json`. Pack lists logical sites, preferred signature, per-build instances.
- F2. Resolve: Phasor loads a build table, scans unique `expected_bytes` when the hint fails, then installs.

### Acceptance Examples

- AE1. Covers R1. STRATEGY Approach names debug/content/BSim before byte-window.
- AE2. Covers R4. Empty identity store still writes valid `format: agentdecompile.hookpack/v1` with `sites: {}`.
- AE3. Covers R5. Site with `addr: 0` and unique `expected_bytes` becomes `resolved` after `resolve_from_signatures`.

## Implementation Units

### U1. Docs (this pass)

- **Goal:** STRATEGY, CONCEPTS, this plan, corpus README mention portable identity.
- **Requirements:** R1, R2, R7.
- **Files:** `STRATEGY.md`, `CONCEPTS.md`, `docs/corpus/README.md`, `docs/plans/README.md`
- **Dependencies:** none

### U2. `corpus.export-hookpack`

- **Goal:** Cataloged verb writes the pack from `logical_function` + `identity` + `func`.
- **Requirements:** R3, R4.
- **Files:** `src/agentdecompile_recovery/corpus/export_hookpack.py`, `src/agentdecompile_recovery/corpus/cli.py`, `tests/test_corpus_export_hookpack.py`
- **Approach:** Prefer `logical_function.best_signature` when every member shares it. Else the most common `func.signature`. Instances keep slug + addr as cache. Do not invent bytes. Adjacent seams (`export-atlas-db`, `external-bridge`, `work-queue`) stay; this verb is the Phasor-shaped one. BSim vectors are eval-only today and do not write `identity`.
- **Test scenarios:** empty store → empty sites; one logical with two binaries → two instances; missing signature → `signature.kind=none`.

### U3. Phasor resolve-from-signatures

- **Goal:** Unique `expected_bytes` bind a site without a working hint VA.
- **Requirements:** R5, R6.
- **Files:** `src/api/memory.hpp`, `src/api/memory.cpp`, `src/hooks/registry.hpp`, `src/hooks/registry.cpp`, `src/runtime/runtime.cpp`
- **Approach:** `find_unique` on bound executable regions. Convert runtime hit back to image VA (`hit - (runtime_base - image_base)`) so `HookSet::install` still applies delta once. If the window is not unique, keep a hint that still matches. Do not scan ciphertext (regions already post-decipher).
- **Do not:** document or implement stub/DRM removal.

### U4. Shared pack load (follow-up if U2+U3 land)

- **Goal:** Phasor can load `agentdecompile.hookpack/v1` plus an optional per-build overlay.
- **Dependencies:** U2, U3
- **Deferred** if U2+U3 already let an operator drop `expected_bytes` into the existing address JSON.

## Sequencing

U1 and U2 in AgentDecompile (no file overlap with U3). U3 in KotorPhasor in parallel. U4 after both.

## Definition of Done

- AE1–AE3 hold.
- Export verb listed by `agentdecompile-corpus -h`.
- Phasor `resolve` logs when a site bound from scan rather than hint.
- No commit unless asked.
