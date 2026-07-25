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

## Driver

`scripts/run-proof-scale-smoke.py` — bounded `run_proof_campaign_loop` with `max_functions=5`, `max_campaigns=3`, `max_wall_seconds=7200`.
