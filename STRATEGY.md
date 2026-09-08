---
name: AgentDecompile
last_updated: 2026-09-08
charter: VISION.md
active_living_plan: docs/plans/2026-09-08-0156-feat-recovery-pipeline-ladder-plan.md
---

# AgentDecompile Strategy

Charter lives in [VISION.md](VISION.md). Operators start at [README.md](README.md). This file is the investment bet under that charter, not a second north star.

## Target problem

A Ghidra project holds dozens of builds of the same codebase. Each build has its own addresses, but the functions, labels, and types are the same logical objects. Without cross-build identity and a propagation path, every recovery pass repeats work and metadata edits on one binary never reach the others. The crux is telling honest source from a wrapper that only compiles because it still contains the original bytes.

## Our approach

Link the builds, recover on the easiest one, and propagate. Bind every function to a `logical_id` from evidence that survives a rebase, not from a virtual address. Prefer one signature family that hits every registered build: debug/STABS names and compilation unit, then strings/constants/imports and decompiled shape, then BSim, then a unique byte window only when those fail. Copying a nearby instruction blob from one exe into another is the last-resort signal, not the matcher. Do not re-run Ghidra analysis on a program that already has it. Solve compiler, ABI, and global layout once before per-function spend. Scaffold with a linking assembly floor, bulk-replace with compiling Ghidra C, place that C on siblings, spend agent compute only on leftovers, then audit bytes last. Export the identity as a Phasor-shaped hook pack. One catalog on 8080.

## Who it's for

**Primary:** An operator, or an agent acting as one, finishing byte-accurate, assembly-free source for every program in a multi-build Ghidra corpus, with labels and structures kept in sync across builds.

**Secondary:** Someone who only needs citeable facts or a navigable tree and stops before the recovery bar.

## Key metrics

- **Verified readable C:** distinct logical functions with objdiff 0 (coverage or isolated audit receipts). Can regress on audit. Not the same as `real_c`.
- **Compiling Ghidra C share:** functions whose decompiled C is assembly-free and compiles (`ghidra-bulk` tally, `real_c=1`). Leading indicator, not proof.
- **Cross-placed compiling C:** compiling functions placed on sibling builds via `logical_id` (`cross-place` receipts).
- **Identity coverage:** inventoried functions bound to a logical function (`identity` table). Must stay high before propagation claims.
- **Portable resolve:** share of those `logical_id`s that resolve on every registered build from one signature family, not a per-build VA. Can regress when a rebuild changes the window.
- **Loop completion:** catalog jobs from `/dashboard` end with named files on disk, not hang or silence.

## Tracks

### One operator surface (8080)

Workbench + kotorxid corpus pages + Atlas + report + `/api/v1/actions` on the MCP HTTP server. Deprecate leftover dashboard ports when in-tree server runs with corpus env.

_Why it serves the approach:_ Agents and humans must share one catalog and one progress view or they will diverge on what "done" means.

### Corpus recovery pipeline

Extract facts → `logical_id` → global calibration → scaffolding (assembly floor) → readable C (`ghidra-bulk`) → propagation (`cross-place`) → targeted AI on leftovers → parity (objdiff) last. Skip a step when its receipt or Ghidra state already exists. Parallelize analysis, evidence extract, bulk C, and matching. Serialize `logical_id` writes, mutations to one Ghidra project, and isolated compiler/objdiff environments.

_Why it serves the approach:_ Recover once on the easy build and share the win. Do not reverse twenty versions independently.

### Ghidra shared state

One store, BSim, prompt evidence from this tree's venv CLI, session-stable `ensure-program`. Label/type edits flow through identity, not per-address copies. Ghidra Server is RMI over SSL, not HTTP.

_Why it serves the approach:_ Cross-match metadata only works if Ghidra state and recovery receipts share the same program binding.

### Portable identity / hook-pack export

`corpus.export-hookpack` writes a Phasor-shaped pack: logical site names, the preferred signature family, and per-build addrs only as a cache. KotorPhasor (or a clone for another corpus) resolves by unique `expected_bytes` when the recorded VA is missing or stale. Game names stay in data packs, not the resolver.

_Why it serves the approach:_ The matcher already refuses raw addresses. A hook host that still keys on `0x005D45D0` per exe repeats the hunt the corpus just finished.

## Priority ladder (do not reorder)

1. **Identity:** extract facts, then bind `logical_id` (debug names, compilation unit, strings/constants/imports and decompiled shape, BSim, then unique byte window). Do not re-analyze a program that already has Ghidra analysis unless the previous analysis is incomplete or corrupted.
2. **Global calibration:** compiler versions, flags, ABIs, and global struct layouts before per-function recovery.
3. **Scaffolding:** donor workspace: one file per function, exact inline asm if no C, must link.
4. **Readable C:** `ghidra-bulk` replaces asm when C compiles; keep asm on failure.
5. **Propagation:** only after compile succeeds; sibling `.c` via `logical_id`.
6. **Targeted AI:** leftovers only, leaves before callers; not before tiers 4–5 for functions Ghidra C already compiles.
7. **Parity:** objdiff 0 per function when claiming verified; isolated toolchain; separate from "compiles."

## Marketing

**Key message:** Identity first, and identity is not an address. Skip work that is already done. Calibrate once. Recover on the easy build. Propagate. Export the hook pack. Byte-exactness is a last audit, not a compile receipt.
