---
title: feat: Proof-Scale Live Validation (T0+T1)
type: feat
status: completed
date: 2026-07-25
origin: docs/brainstorms/2026-07-25-recovery-improvement-backlog-requirements.md
---

# Proof-Scale Live Validation (T0+T1)

## Summary

This plan executes the highest-leverage track from the recovery improvement backlog: **T0 (proof-scale perf + MCP hygiene)** to unblock **T1 (live proof-scale validation on swkotor)**. The work fixes three blocking hot paths in the autonomous agent loop — O(n²) proof-target queue rebuild, MCP tool-seq per-step parsing, and Ghidra session reuse — then runs the documented multi-campaign smoke to produce the first receipt-backed evidence that the loop promotes functions on a real PE target.

---

## Problem Frame

AgentDecompile's recovery pipeline has all the pieces (enrich, synthesis, match, proof campaign loop, mismatch routing) but has never validated end-to-end on a live target. Run3 showed enrich succeeded (12,845 functions, 12,750 named) but the proof campaign never started due to readability-gate coupling (since decoupled). The first real smoke (Run4b) requires T0 fixes to complete within minutes instead of hanging on queue rebuild.

---

## Requirements

- R1. Proof-target queue rebuild completes in <10s on swkotor work dir (~12,845 candidates)
- R2. MCP tool-seq receipts reflect per-step success/failure accurately (no silent hangs)
- R3. Ghidra project reuse avoids fresh import on each enrich cycle (session persistence)
- R4. `--autonomous --autonomous-max-functions 5 --autonomous-max-campaigns 3` reaches `campaignCount > 0` with a named terminal (`near-miss`, `budget-stop`, `empty-queue`, or `accept`)
- R5. `proof-ladder.json` numerator increases OR `proof-campaign-loop.json` records honest per-iteration receipts

**Origin actors:** A1 (reverse engineer running reconstruct), A2 (agent author wiring MCP)
**Origin flows:** F1 (enrich → proof campaign → verified/), F2 (mismatch routing → repair → re-prove)
**Origin acceptance examples:** AE1 (covers R1, R4): Run4b completes in <10min with campaign receipts; AE2 (covers R5): Ladder numerator Δ ≥ 1 OR named terminal with `claimBoundary` set

---

## Scope Boundaries

- In scope: T0 perf/hygiene fixes + T1 swkotor smoke execution
- Deferred for later: T2 (mismatch playbook execution), T3 (PDB provenance), T4 (readable default path), T5 (monotonic checkpoints), T6 (pattern memory), T7 (tiered ladder), T8 (dual-agent)
- Outside product identity: Promoting non-zero diff to `verified/`, second product brands, claiming whole-binary parity

---

## Context & Research

### Relevant Code and Patterns

- `src/agentdecompile_recovery/proof_campaign.py` — `run_proof_campaign_loop`, `build_proof_target_queue` (O(n²) scan)
- `src/agentdecompile_recovery/mcp_tool_seq.py` — `run_mcp_tool_seq`, step parsing, receipt emission
- `src/agentdecompile_recovery/ghidra_context.py` — `GhidraContextManager`, session reuse vs fresh import
- `src/agentdecompile_recovery/frontdoor.py` — `reconstruct` command, `--autonomous` flags wiring
- `src/agentdecompile_recovery/autonomy_budget.py` — `AutonomyPolicy`, attempt budget, promotion gates
- `src/agentdecompile_recovery/stage_timings.py` — `StageTimings`, wall-time capture
- `tests/test_proof_campaign.py` — campaign loop unit tests
- `tests/test_vacuum_runner.py` — vacuum runner tests (related autonomous flow)

### Institutional Learnings

- `docs/solutions/architecture-patterns/tiered-re-analysis-knowledgebase.md` — Tier 3 mutations only after Tier 2 read-only; proof campaign is Tier 3
- `docs/solutions/architecture-patterns/agent-native-mcp-patterns.md` — MCP tool-seq patterns, session persistence, UI hints
- `docs/CRITICAL_PATH.md` — Reconstruct pipeline stages, receipts, `--autonomous` usage
- `docs/plans/2026-07-24-perf-recovery-one-shot-living-plan.md` — U1-U5 completed, G14-G16 backlog

### External References

- objdiff/permuter compile-diff loop patterns (decomp-goal-harness, meteor-decomp)
- Ghidra headless project session management

---

## Key Technical Decisions

- **Queue rebuild optimization**: Replace per-candidate `tasks.jsonl` scan with single-pass index build (hash map from entry → task exists). File: `proof_campaign.py` `build_proof_target_queue`.
- **MCP tool-seq parsing**: Emit structured step receipts (`state/mcp-tool-seq-last.json`) after each step, not only at end. Parse `--continue-on-error` semantics correctly.
- **Ghidra session reuse**: `GhidraContextManager` should hold `Project`/`Program` handle across enrich→proof cycles when `--resume` and same work dir. Avoid `import-binary` repeat.
- **Smoke parameters**: Use existing `target/agentdecompile-reconstruct/swkotor-parity` work dir; `--workers 4`; `--vc-root` and `--source-synthesis-wineprefix` for MSVC/Wine.

---

## Open Questions

### Resolved During Planning

- **Which work dir for smoke?** Resolved: reuse `target/agentdecompile-reconstruct/swkotor-parity` (has enrich receipt, proof-target queue, proof-ladder)
- **PE toolchain availability?** Resolved: `--vc-root` and `--source-synthesis-wineprefix` required; assume present in CI/contributor env

### Deferred to Implementation

- Exact queue index structure (dict vs sqlite) — decide during U1 implementation
- Whether `GhidraContextManager` needs explicit `close()`/`__exit__` hardening — test during U2

---

## Implementation Units

### U1. Fix O(n²) Proof-Target Queue Rebuild

**Goal:** Reduce proof-target queue build from ~3min to <10s on 12,845 candidates by replacing per-candidate full `tasks.jsonl` scan with single-pass index.

**Requirements:** R1

**Dependencies:** None

**Files:**
- Modify: `src/agentdecompile_recovery/proof_campaign.py` (`build_proof_target_queue`, `entry_has_source_task`)
- Test: `tests/test_proof_campaign.py` (add queue build performance test)

**Approach:**
- Load `tasks.jsonl` once into a `set[tuple(entry, compiler_profile)]` or `dict[entry, list[task]]` index
- `entry_has_source_task` becomes O(1) lookup instead of O(m) file scan per candidate
- Preserve existing `ProofTargetQueueEntry` schema and `proof-target-queue.json` output

**Execution note:** Add a micro-benchmark in test using the actual swkotor `tasks.jsonl` fixture (or generated equivalent) to verify <10s on CI hardware.

**Patterns to follow:**
- `src/agentdecompile_recovery/match_cache.py` — digest-keyed lookup patterns
- `src/agentdecompile_recovery/inventory.py` — JSONL streaming with index build

**Test scenarios:**
- Happy path: Queue builds in <10s with 12k+ candidates, all `hasSourceTask` flags correct
- Edge case: Empty `tasks.jsonl` → all candidates `hasSourceTask=false`
- Edge case: Malformed JSONL lines skipped with warning, index build continues
- Integration: `run_proof_campaign_loop` completes first campaign without queue-build timeout

**Verification:**
- `proof-target-queue.json` produced with correct `nearMissRetryCount` and `hasSourceTask`
- Stage timing `build_proof_target_queue` < 10s in `stage-timings.json`

---

### U2. Fix MCP Tool-Seq Per-Step Receipts and Parsing

**Goal:** Ensure `tool-seq` emits per-step structured receipts (`state/mcp-tool-seq-last.json`) and correctly handles `--continue-on-error` so campaign loop sees step success/failure immediately.

**Requirements:** R2

**Dependencies:** None

**Files:**
- Modify: `src/agentdecompile_recovery/mcp_tool_seq.py` (`run_mcp_tool_seq`, `_parse_step_outcome`, `_parse_tool_seq_shell_stdout`)
- Modify: `src/agentdecompile_recovery/frontdoor.py` (autonomous loop calls `run_mcp_tool_seq`)
- Test: `tests/test_mcp_tool_seq.py` (add step-receipt emission tests)

**Approach:**
- After each tool call in sequence, write `state/mcp-tool-seq-last.json` with `{stepIndex, toolName, success, error?, durationMs}`
- Fix `_parse_step_outcome` to detect `## Error` markdown blocks and `## Modification conflict` in text parts even when `isError: false`
- Ensure `--continue-on-error` continues sequence but records failure per step; campaign loop reads per-step receipts

**Execution note:** Test with a crafted tool-seq that mixes success/failure/conflict steps.

**Patterns to follow:**
- `src/agentdecompile_recovery/stage_timings.py` — per-stage timing emission
- `src/agentdecompile_recovery/campaign_checkpoint.py` — JSONL append-only receipt pattern

**Test scenarios:**
- Happy path: 5-step sequence all succeed → 5 receipts, final success
- Error path: Step 2 fails with `## Error` → receipt shows failure, sequence continues (with `--continue-on-error`), final exit non-zero
- Conflict path: Step 3 returns modification conflict → receipt shows conflict, resolution step succeeds
- Integration: Autonomous loop reads per-step receipts to decide campaign continuation

**Verification:**
- `state/mcp-tool-seq-last.json` exists after each step with correct schema
- Campaign loop (`run_proof_campaign_loop`) observes step failures in real time

---

### U3. Enable Ghidra Project Reuse Across Enrich→Proof Cycles

**Goal:** Avoid fresh `import-binary` on each enrich cycle when `--resume` and same work dir; reuse existing Ghidra project handle across `enrich-decompile` → `proof-campaign` → `near-miss-repair` stages.

**Requirements:** R3

**Dependencies:** U1, U2 (campaign loop must run to exercise reuse)

**Files:**
- Modify: `src/agentdecompile_recovery/ghidra_context.py` (`GhidraContextManager`, `__enter__`, `__exit__`, `get_program`)
- Modify: `src/agentdecompile_recovery/reconstruct_enrich.py` (`run_enrich_decompile` to accept existing context)
- Modify: `src/agentdecompile_recovery/frontdoor.py` (wire context manager through autonomous stages)
- Test: `tests/test_ghidra_context.py` (add session reuse test)

**Approach:**
- `GhidraContextManager` holds `Project`/`Program` reference keyed by work dir + binary hash
- On `__enter__`, check for existing open project matching `analysisBinarySha256`; reuse if analysis complete
- `reconstruct_enrich.py` accepts optional `ghidra_context` parameter; frontdoor creates once, passes through
- Ensure `domain_file.save()` / `checkin-program` called on context exit (or auto-checkin env)

**Execution note:** Test with two sequential enrich calls — second should skip import, reuse program.

**Patterns to follow:**
- `src/agentdecompile_cli/context.py` — `ProgramInfo`, `PyGhidraContext`, session management
- `src/agentdecompile_cli/launcher.py` — `AgentDecompileLauncher`, project open/import logic

**Test scenarios:**
- Happy path: Two `run_enrich_decompile` calls with same work dir → second reuses program, no re-import
- Edge case: Different binary hash → fresh import
- Edge case: Analysis incomplete on first call → second call waits for analysis gate
- Integration: Full autonomous loop (enrich → proof → repair) uses single Ghidra session

**Verification:**
- `stage-timings.json` shows single `enrich-decompile` wall time (no duplicate)
- Logs show "Reusing existing Ghidra program" on second enrich-stage call

---

### U4. Execute Swkotor Proof-Scale Smoke (Run4b)

**Goal:** Run the documented multi-campaign autonomous smoke on the prepared swkotor work dir and capture receipts proving the loop works.

**Requirements:** R4, R5

**Dependencies:** U1, U2, U3

**Files:**
- Create: `scripts/run_swkotor_smoke.py` (orchestration script for CI/local)
- Modify: `src/agentdecompile_recovery/frontdoor.py` (ensure `--autonomous` flags wired end-to-end)
- Test: N/A (this is the validation run itself)

**Approach:**
- Target: `target/agentdecompile-reconstruct/swkotor-parity` (has enrich receipt, proof-target queue, proof-ladder)
- Command: `uv run agentdecompile-reconstruct <swkotor.exe> --work-dir <dir> --resume --autonomous --autonomous-max-functions 5 --autonomous-max-campaigns 3 --workers 4 --vc-root <vc> --source-synthesis-wineprefix <prefix>`
- Capture: Terminal output, `state/proof-campaign-loop.json`, `proof-ladder.json`, `facts/proof-target-queue.json`, `stage-timings.json`
- Success criteria: `campaignCount > 0` AND (`totalAccepts > 0` OR terminal ∈ {`near-miss`, `budget-stop`, `empty-queue`, `readability-blocked`} with `claimBoundary` set)

**Execution note:** Run manually first to validate; then add as CI job (opt-in, requires PE toolchain).

**Patterns to follow:**
- `scripts/decomp-cli.sh` — frontdoor invocation patterns
- `docs/CRITICAL_PATH.md` — Proof-scale smoke section

**Test scenarios (validation run):**
- Campaign 1: At least 1 function attempted, receipt recorded
- Campaign 2: Near-miss repair attempted if Campaign 1 produced near-misses
- Campaign 3: Budget stop or empty queue terminal
- Ladder numerator: Δ ≥ 1 OR honest terminal with per-iteration history in `proof-campaign-history.jsonl`

**Verification:**
- `proof-campaign-loop.json` exists with `status` ≠ `readability-blocked` (gate decoupled)
- `proof-ladder.json` `numerator` ≥ 1 OR `proof-campaign-loop.json` has `claimBoundary` + `proof-campaign-history.jsonl` rows
- `stage-timings.json` shows `proof-campaign-loop` wall time < 10min

---

## System-Wide Impact

- **Interaction graph:** Autonomous loop (frontdoor) → enrich (ghidra_context) → proof_campaign (queue) → near_miss_repair → synthesize → dump. U1-U3 touch all three internal seams.
- **Error propagation:** Tool-seq step failures now visible per-step; campaign loop can halt early on repeated failures instead of silent continuation.
- **State lifecycle risks:** Ghidra context reuse must clean up on exception; `GhidraContextManager.__exit__` must save/checkin even on error.
- **API surface parity:** No CLI/API changes — internal wiring only. `--autonomous` flags unchanged.
- **Integration coverage:** U4 is the integration test — unit tests for U1-U3 cover components; U4 proves end-to-end.
- **Unchanged invariants:** `verified/` still requires objdiff zero; `Port/CODE` still advisory; match cache keys unchanged.

---

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| PE toolchain (MSVC/Wine) unavailable in CI | Mark U4 as manual/opt-in; U1-U3 unit-testable without PE toolchain |
| Ghidra session reuse leaks handles on error | `try/finally` in `GhidraContextManager.__exit__`; add explicit `close()` test |
| Queue index memory on 100k+ functions | Dict of ~13k entries is ~few MB; acceptable. Monitor; add LRU if needed later |
| Tool-seq parsing misses edge-case error formats | Test against real tool outputs (capture from Run3/Run4 logs); extend patterns incrementally |
| Smoke flakiness (Wine/MSVC non-determinism) | `--autonomous-max-campaigns 3` bounds run; accept `budget-stop` as valid terminal |

---

## Documentation / Operational Notes

- Update `docs/CRITICAL_PATH.md` Proof-scale smoke section with Run4b command and expected receipts
- Add `stage-timings.json` fields to `docs/CRITICAL_PATH.md` Wall times table
- Document `GhidraContextManager` reuse pattern in `docs/solutions/architecture-patterns/` if novel

---

## Sources & References

- **Origin document:** [docs/brainstorms/2026-07-25-recovery-improvement-backlog-requirements.md](docs/brainstorms/2026-07-25-recovery-improvement-backlog-requirements.md)
- Related code: `src/agentdecompile_recovery/proof_campaign.py`, `src/agentdecompile_recovery/mcp_tool_seq.py`, `src/agentdecompile_recovery/ghidra_context.py`, `src/agentdecompile_recovery/frontdoor.py`
- Related plans: `docs/plans/2026-07-24-perf-recovery-one-shot-living-plan.md` (U1-U5 done, G14-G16 backlog)
- External: decomp-goal-harness campaign loop, objdiff/permuter compile-diff patterns