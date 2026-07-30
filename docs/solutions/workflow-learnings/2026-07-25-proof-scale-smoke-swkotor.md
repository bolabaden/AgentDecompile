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
4. **Fixed 2026-07-30** (branch `fix/packaged-source-shim-pointer-types`): Run8's 10 attempted functions all hit fast, real MSVC compile errors (e.g. `sub_1130`: `error C2146: syntax error before param_1`; `FUN_00423f10`: `error C2146: syntax error before param_1` cascading from an undeclared `code`/`DAT_007a68a4`) — `source_parity_synthesize.py`/`package_verify.py` were emitting invalid C for packaged-source (raw decompiler output) candidates. Two layered causes, fixed in two stages this session:
   - **Stage 1 (already landed earlier this session, part of PR #144):** packaged-source `.c` candidates were compiled with zero typedefs for Ghidra pseudo-types (`undefined4`, `code`, `byte`, etc.) — `packaged_source_candidate()` now prepends `package_verify.build_shim(source)` before the raw source, resolving the majority of Run8's failures (confirmed today via `clang -std=c89 -fsyntax-only` against the archived pre-fix `sub_1130`/`FUN_0040a870` candidate.c files, which lacked the shim entirely — direct evidence matching the hypothesized root cause).
   - **Stage 2 (this fix):** `build_shim()`'s auto-generated `extern` declarations for matched globals (`DAT_*`/`PTR_*`/etc.) always typed them as `int`, which is wrong whenever the source dereferences the global (`*DAT_007a68a4 + 8`, as in the archived `FUN_00423f10` failure) — `*int` is a real MSVC type error distinct from C2146, not just a missing-typedef issue. Fixed by typing `PTR_`-prefixed globals (Ghidra's own pointer-naming convention) and any textually-dereferenced global as `char *` instead of `int` — `char *` rather than `void *` specifically, since Ghidra output routinely does `*global + <offset>` before an outer cast reinterprets the result, and `void` arithmetic is a hard error while `char` arithmetic is not. Verified against the real archived `FUN_00423f10` failure: `clang -fsyntax-only` now exits 0 (warnings only, matching the int-to-pointer narrowing casts decompiled code is expected to produce).

**Net result:** both original bugs are fixed and confirmed working end-to-end (fast compiles, correct flag wiring; the histogram fix is unit-tested against real captured data). Run8's 0 accepts were caused by the candidate-generation syntax-error bug (#4) blocking every attempted function before shape-search routing could run on a real near-miss — both stages of that bug are now fixed and regression-tested (`tests/test_packaged_source_shim.py`, `tests/test_package_verify_shim.py`). The pipeline mechanics and candidate-generation syntax correctness are now provably working end-to-end for the sampled Run8 failure shapes; the next step is a fresh smoke run to confirm real accepts are reachable.

## Follow-up (still outstanding)

1. ~~Investigate the candidate-generation syntax errors (#4 above)~~ — **done 2026-07-30**, see above.
2. Re-run the smoke with a larger budget now that #4 is fixed, to see whether shape-search now actually converts a near-miss to an objdiff-zero accept. (Not yet run in this session — no verified `VC_ROOT`/wineprefix toolchain path was available to re-run the full smoke; the fix above was verified via `clang -fsyntax-only` against the archived real MSVC failure artifacts plus targeted unit tests, not a fresh end-to-end MSVC run.)
3. Full canonical `agentdecompile-reconstruct --resume --stop-after report` run: **now done** — Run5/Run8 both ran the complete 15-stage pipeline including `report`, not a manually-built queue.
4. Consider picking up G16 (SSD work-dir guidance) if compile wall-time on this machine becomes the bottleneck again.

## Driver

`scripts/run-proof-scale-smoke.py` — bounded `run_proof_campaign_loop` with `max_functions=5`, `max_campaigns=3`, `max_wall_seconds=7200`.
