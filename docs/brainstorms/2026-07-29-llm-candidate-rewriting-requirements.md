# LLM-based candidate rewriting (challenger lane, mechanism 3)

## Overview

Third and final challenger-lane mechanism for the proof-scale recovery loop. Mechanisms 1 (compiler-flag/pragma exploration) and 2 (mechanical idiom permutation) are shipped on `master`. This covers the remaining gap: functions with no matching byte-pattern template and no narrow idiom rule, which today get zero shape-search variants regardless of `source_shape_search`.

## Problem Frame

`generate()` in `source_parity_synthesize.py` runs ~30 narrow byte-pattern generators plus (as of today) one rule-agnostic idiom-permutation fallback for the specific "byte-field-guard-return-self" shape. Any packaged-source candidate outside those patterns — i.e. most real functions with actual control flow — still has exactly one candidate: the raw decompiler output, recompiled under different flags. When that one candidate's near-miss diff isn't a flag-sensitive or idiom-permutable difference, the function is permanently stuck with no further lever.

Evidence: today's swkotor.exe smoke runs (Run9–Run12) showed 12–15 functions per campaign with real, classified near-miss evidence (operand/opcode/insert-delete) and no way to convert most of them. Mechanism 2 proved the concept works for one narrow shape — verified byte-identical against real captured target data for `sub_78650`. It cannot generalize to arbitrary control flow without either a large mechanical-rule catalog (high ongoing maintenance cost) or a general rewriter.

## Key Decisions

- **Fully autonomous, in the loop.** LLM calls happen inside `--autonomous` campaigns, not as a separate manual-trigger command. Chosen over an offline/manual-only v1 to prove the mechanism at the scale where it matters (bounded autonomous recovery), accepting real per-run API cost from the start.
- **Provider: Claude API (Anthropic).** Matches existing session/tooling; no new auth/billing surface to stand up.
- **Budget: extend the existing `AutonomyBudget` dataclass** (`src/agentdecompile_recovery/autonomy_budget.py`) with a new `max_llm_calls_per_function` field, following the same bounded/typed/receipts-not-claims pattern as `max_attempts_per_function`. Do not invent a parallel budget mechanism.
- **One candidate per call, fail-closed.** Each LLM call requests a single best-effort rewrite (not multiple candidates per call) to keep cost predictable. API error, timeout, or budget exhaustion produces a typed terminal (e.g. `llm-unavailable`) on that function and the campaign moves on — never blocks or stalls the loop.
- **Context fed to the model**: the packaged-source candidate (raw decompiler output), the target byte slice/disassembly, and the current objdiff mismatch data (histogram + `diff_kind` breakdown, already computed by this session's classification fixes) — not a bare "write C for these bytes" prompt. Giving the model the specific diff (what's wrong with the current candidate) rather than just the target is expected to converge faster than blind generation.

## Requirements

- R1. `max_llm_calls_per_function` added to `AutonomyBudget`, defaulting to 0 (opt-in; existing campaigns are unaffected unless explicitly enabled).
- R2. LLM rewrite only triggers for functions that are (a) classified as a real near-miss (operand/opcode/insert-delete, not unclassified/boundary-suspect) and (b) have exhausted mechanisms 1 and 2 without a match.
- R3. Every LLM call and its outcome is recorded as a receipt (prompt reference, response status, resulting candidate if any) — advisory metadata only, never a claim; the objdiff gate remains the sole proof mechanism, unchanged from every other candidate source.
- R4. Fail-closed on any API error, timeout, or budget exhaustion: typed terminal, no retry storm, no blocking the campaign loop.
- R5. The LLM-generated candidate goes through the identical compile+objdiff verification path as every other candidate — no special-cased acceptance criteria.

## Scope Boundaries

### Deferred for later

- Multiple candidates per LLM call (2–3 rewrite attempts in one call) — deferred in favor of predictable one-call-one-candidate cost.
- Pluggable/multi-provider abstraction — Claude API only for v1; do not build a provider interface speculatively.
- Prompt-tuning/iteration loops (e.g. feeding a failed rewrite's new diff back for a second LLM attempt) — v1 is one call, one candidate, verify, move on.

### Outside this mechanism's identity

- Claiming LLM-generated source as verified without the objdiff gate.
- Unbounded autonomous LLM spend — every campaign run must respect `max_llm_calls_per_function`.

## Dependencies / Assumptions

- Assumes Claude API credentials/access are available in the environment the autonomous loop runs in (not yet verified — flag as an implementation-time unknown for `/ce-plan`).
- Assumes the existing objdiff mismatch data (histogram, `diff_kind`) is available at the point in the pipeline where the LLM call would fire — confirmed available today via `mismatch_classify.py`'s `enrich_attempt_record`.

## Outstanding Questions

- Exact prompt structure/format for feeding decompiler output + target bytes + diff data to the model — implementation detail for `/ce-plan`.
- Where in `source_plugin_runner.py` / `plugin_pipeline.py` the LLM-call step should be inserted relative to the existing shape-search sequence (before or after mechanism 2's permutations exhaust) — implementation detail for `/ce-plan`.
- Cost estimate per campaign at realistic near-miss volumes — worth a rough calculation during planning before implementation.

## Sources / Research

- `src/agentdecompile_recovery/autonomy_budget.py` — existing budget pattern, extension point, and the "unbounded API or wall-clock spend" concern this design addresses directly.
- `src/agentdecompile_recovery/source_parity_synthesize.py` — `generate()`, `semantic_equivalent_variants()`, `byte_field_guard_return_self_variants()` (mechanism 2, shipped today).
- `docs/solutions/workflow-learnings/2026-07-25-proof-scale-smoke-swkotor.md` — Run9–Run12 near-miss evidence motivating this mechanism.
- STRATEGY.md — proof ladder honesty gate; this mechanism does not weaken it.
