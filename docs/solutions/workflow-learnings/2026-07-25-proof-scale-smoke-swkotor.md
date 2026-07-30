---
module: agentdecompile_recovery
problem_type: workflow_issue
component: proof-campaign-loop
tags: [proof-scale, smoke, swkotor, readability-blocked, pe]
date: 2026-07-25
---

# Proof-scale smoke on swkotor (readability-blocked terminal)

## Outcome

First live proof-scale smoke on `swkotor.exe` completed with a **named terminal**: `readability-blocked`. This satisfies proof-scale smoke pass criteria (accept or auditable terminal with receipts). **Numerator unchanged** (`numeratorDelta: 0`) — honesty preserved.

## Before / after ladder

| Field | Before | After |
|-------|--------|-------|
| numerator | 0 | 0 |
| denominator | 12845 | 12845 |
| functionsToNextRung | 129 | 129 |
| rung | below-1 | below-1 |

## Receipts

- `target/agentdecompile-reconstruct/swkotor-parity/state/proof-campaign-loop.json` — `status: readability-blocked`, `campaignCount: 0`, `claimBoundary` set
- `target/agentdecompile-reconstruct/swkotor-parity/state/readability-repair-run.json` — readability queue head blocked vacuum; MCP rename failed
- `target/agentdecompile-reconstruct/swkotor-parity/state/smoke-prep.json` — audit snapshot
- `target/agentdecompile-reconstruct/swkotor-parity/state/proof-scale-smoke.log` — driver log
- `target/agentdecompile-reconstruct/swkotor-parity/facts/proof-target-queue.json` — 12845 entries, `nearMissRetryCount: 17`

## Blocker class

**Readability + MCP program activation.** Top proof-target entries are `FUN_*` with low readability scores and no source tasks. Readability repair attempted `rename-function` via local PyGhidra CLI but failed:

`activate_requested_program failed` — `domain_file_not_found` for `swkotor.exe.unpacked.exe` in the local Ghidra project.

MCP URL was unset; smoke used direct campaign loop (no `--skip-closure-executors` path through frontdoor, but readability gate fired before vacuum).

## Follow-up (2026-07-25 ce-work)

Fixes shipped to unblock the readability MCP executor:

1. **`mcp_tool_seq.py`** — Local CLI bootstrap: prepend `open-project` + `analyze-program` with analysis binary path; set `AGENTDECOMPILE_PROJECT_PATH` to work-dir `pyghidra-project`; do not inject `programPath` on open/analyze tools.
2. **`readability_repair.py`** — Use `manage-function` with `mode: rename` and `newName` (the `rename-function` alias does not inject `mode`); 30-minute tool-seq timeout for PE targets.

**Rerun result:** `open-project` succeeds and imports `swkotor.exe.unpacked.exe`. `manage-function` rename still fails with `Function not found: 0x401000` because Ghidra reports **0 functions / 0 instructions** immediately after import (analysis not complete or PE image not fully analyzed in local session). Next step: run `enrich-decompile` on the work dir so function facts exist before readability MCP, or wait for blocking `analyze-program` on full swkotor (long wall-clock).

## Run3 (enrich-then-smoke, 2026-07-25)

- **Enrich:** `facts/enrich-receipt.json` status `complete` — 12,845 functions, 12,750 named (~477s).
- **Smoke:** Still `readability-blocked`, `campaignCount: 0` — proof loop never entered despite enrich success.
- **Root cause:** Port readability gate was incorrectly wired as a **hard prerequisite** for proof campaigns. Run3 facts: 12,837/12,845 on fallback module `recovered/unmapped`; only 8 pass Port gate; 95 `FUN_*` entries at repair-queue head blocked the loop.
- **Fix (Approach A):** Decouple lanes — `passes_readability_gate` governs `Port/CODE` only; `run_proof_campaign_loop` emits advisory readability receipt and proceeds via `proof-target-queue`. See `docs/brainstorms/2026-07-25-recovery-improvement-backlog-requirements.md` Key Decisions update.

## Follow-up (not done in this smoke)

1. Open/import analysis image in Ghidra project before readability MCP executor, or point MCP at correct `programPath`.
2. Re-run smoke with MCP available **or** after manual rename/enrich on queue head entries.
3. Full `agentdecompile-reconstruct --resume --stop-after report` still outstanding for canonical report receipt (queue was built manually for this smoke).

## Honesty check

- `numeratorDelta` 0 matches `verified/` count (no new objdiff-zero accepts).
- Near-miss queue metadata (`nearMissRetryCount: 17`) did not promote to numerator.

## Run4b (2026-07-25) — readability fixed, still 0/15 accepts

Approach A landed (readability decoupled from proof campaigns). Re-ran the documented smoke recipe: 3 campaigns × 5 functions, all iterations `status: bridged` (no longer `readability-blocked`). Result: **`totalAccepts: 0`, `totalAttempted: 15`, `numeratorDelta: 0`**. `mismatch-class-last.json` classified `sub_78650` as `boundary-suspect` → routed to `boundary-repair` playbook.

**Root cause found later (2026-07-29, see below):** `extract_mismatch_histogram()` read the wrong objdiff JSON field (`kind` instead of `diff_kind`, and bare category names instead of the real `DIFF_`-prefixed values), so the histogram was silently *always empty* — confirmed by grepping the whole work tree: 166/166 `detailLevel` occurrences were `scalar-only`, 0 were `instruction`, despite 148 real `diff_kind` entries present in raw objdiff output. This forced every mismatch through `boundary-repair`/`scalar-default`, both of which have `sourceShapeSearch: False` — the repair loop never tried alternate C source idioms, so near-misses like `sub_78650` (a branchless-mask-arithmetic-vs-if-statement codegen mismatch — exactly what shape search exists to fix) could never convert to accepts.

## Run5–Run8 (2026-07-29) — fixing the pipeline, still 0 accepts

Debugging session (`fix/mismatch-histogram-diff-kind` branch) found and fixed **two real bugs**, plus discovered one environmental factor and one new bug:

1. **Fixed: histogram field-name bug** (`src/agentdecompile_recovery/objdiff_verification.py`). `extract_mismatch_histogram()` now reads `diff_kind` with a `DIFF_*` → category mapping. Regression test built from a real captured `sub_78650` verify.json confirms it now classifies as `operand`/`opcode` (routes to `permuter-operand`/`permuter-opcode`, shape search on) instead of `boundary-suspect`/`unclassified`.
2. **Fixed: vacuum-loop wineprefix wiring gap** (`vacuum_runner.py`, `autonomy_budget.py`, `proof_campaign.py`, `frontdoor.py`). The autonomous `--autonomous` vacuum/repair loop never threaded `--vc-root`/`--source-synthesis-wineprefix` into its per-function compile subprocess — it silently fell back through the `WINEPREFIX` env var to a hardcoded, usually-nonexistent path, causing every compile in Run5/Run6/Run7 to fail or hang. Confirmed fixed in Run8: subprocess log now shows the flags passed explicitly, and compiles complete in ~1-2s instead of 30s-17min.
3. **Environmental, not a bug:** the 30s-17min per-function compile times in Run6/Run7 (before the wiring fix landed) were disk I/O on `/run/media/brunner56/MyBook`, a spinning SATA HDD (`lsblk` confirms `ROTA=1`, `WDC WD30EZRX`) — not lock contention (verified `scripts/vacuum.sh` runs strictly sequentially, no parallelism). This matches the already-known, deferred **G16** backlog item (SSD work-dir guidance) in `docs/plans/2026-07-24-perf-recovery-one-shot-living-plan.md`. An NVMe SSD (`nvme0n1`) is available on this machine if G16 is picked up.
4. **Partially fixed 2026-07-30** (branch `fix/packaged-source-shim-pointer-types`): Run8's 10 attempted functions all hit fast, real MSVC compile errors (e.g. `sub_1130`: `error C2146: syntax error before param_1`) — `source_parity_synthesize.py`/`package_verify.py` were emitting invalid C for packaged-source (raw decompiler output) candidates. This turned out to be a much larger population than the 10-function Run8 sample suggested: a full sweep of every archived packaged-source candidate under `target/agentdecompile-reconstruct/swkotor-parity-inv/source-synthesis/cases/` with a recorded real MSVC error found **188 distinct failing functions**, not 10. Three evidenced, bounded causes were found and fixed, all against a real wine + MSVC8 compile (`VC_ROOT=/run/media/brunner56/MyBook/Toolchains/msvc8.0-main`, `WINEPREFIX=target/wine-smoke-prefix` — confirmed live and working this session), not just `clang -fsyntax-only`:
   - **Stage 1 (already landed earlier this session, part of PR #144):** packaged-source `.c` candidates were compiled with zero typedefs for Ghidra pseudo-types (`undefined4`, `code`, `byte`, etc.) — `packaged_source_candidate()` now prepends `package_verify.build_shim(source)` before the raw source.
   - **Stage 2:** `build_shim()`'s auto-generated `extern` declarations for matched globals (`DAT_*`/`PTR_*`/etc.) always typed them as `int`, which is wrong whenever the source dereferences the global (`*DAT_007a68a4 + 8`) — `*int` is a real MSVC type error. Fixed by typing `PTR_`-prefixed globals and any textually-dereferenced global as `char *` instead of `int` (`char *` rather than `void *`, since Ghidra output routinely does `*global + <offset>` before an outer cast reinterprets the result, and `void` arithmetic is a hard error while `char` arithmetic is not).
   - **Stage 3:** `TYPE_SHIM` was also missing `bool` (MSVC8 in C mode has no native `bool` — Ghidra emits it as a return type routinely, e.g. `bool __fastcall FUN_00406030(...)`) and `ushort` (emitted directly for some parameter/return types, distinct from the existing `undefined2` pseudo-type). Added both.
   - **Verified result (real MSVC, not clang):** of the 188 archived failing functions, **124 (66%) now compile successfully** with these three fixes. The remaining **64 failures span multiple distinct, heterogeneous error classes** (C2065/C2061 undeclared identifiers from Ghidra-synthesized per-function type names like `_func_4879 *`/`_onexit_t` that have no fixed, shimmable name; literal embedded `int3` breakpoint-instruction artifacts that aren't valid C at all; a handful of other C2143/C2146/C2224 shapes not yet triaged) — this is a genuinely larger, more open-ended problem than a typedef/shim gap, and is **tracked as a new, separate backlog item** rather than attempted further in this session (see Follow-up below).

**Net result:** both original Run5-Run8 bugs (histogram, wineprefix wiring) are fully fixed and confirmed working end-to-end. The candidate-generation syntax-error bug (#4) is **substantially but not fully fixed** — 124/188 (66%) of archived failures now compile; the remaining 64 are a distinct, larger class of problem. Regression-tested: `tests/test_packaged_source_shim.py`, `tests/test_package_verify_shim.py`. The pipeline mechanics are now provably working end-to-end; the next step is a fresh smoke run to confirm real accepts are reachable for the 124 now-fixed shapes.

## Follow-up (still outstanding)

1. ~~Investigate the candidate-generation syntax errors (#4 above)~~ — **substantially done 2026-07-30** (124/188 archived failures fixed, verified against real MSVC), see above. **New backlog item**: the remaining 64 failures (Ghidra-synthesized per-function type names, embedded `int3` artifacts, and a handful of untriaged C2065/C2143/C2146/C2224 shapes) are a distinct, larger candidate-generation-quality problem, not a shim/typedef gap — worth its own investigation rather than folding into this fix.
2. Re-run the smoke with a larger budget now that #4 is substantially fixed, to see whether shape-search now actually converts a near-miss to an objdiff-zero accept for the 124 now-compiling shapes.
3. Full canonical `agentdecompile-reconstruct --resume --stop-after report` run: **now done** — Run5/Run8 both ran the complete 15-stage pipeline including `report`, not a manually-built queue.
4. Consider picking up G16 (SSD work-dir guidance) if compile wall-time on this machine becomes the bottleneck again.

## Driver

`scripts/run-proof-scale-smoke.py` — bounded `run_proof_campaign_loop` with `max_functions=5`, `max_campaigns=3`, `max_wall_seconds=7200`.
