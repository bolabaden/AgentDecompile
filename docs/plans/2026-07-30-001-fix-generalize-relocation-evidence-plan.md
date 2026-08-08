---
title: "fix: Generalize target-side relocation evidence across mechanical rule generators"
date: 2026-07-30
origin: docs/brainstorms/2026-07-30-relocation-evidence-generalization-requirements.md
---

# fix: Generalize target-side relocation evidence across mechanical rule generators

## Summary

Investigated extending the `absoluteAddressRelocations` fix shipped in PR #149 (`inc_abs_global`) to twelve other mechanical rule generators in `src/agentdecompile_recovery/source_parity_synthesize.py`. Real-toolchain A/B testing overturned the premise: none of the twelve need the fix, and adding it made two confirmed cases measurably worse. Shipped a shared helper (for any future rule that legitimately needs it), reverted the incorrect wiring, and added a regression test guarding the real anti-pattern this investigation found.

## Problem Frame

`render_target_coff_for_candidate()` reconstructs the objdiff target object with a matching symbol relocation for absolute-address (`DIR32`) references, via `absolute_address_relocations()`, which reads `candidate.evidence["absoluteAddressRelocations"]`. This only helps when the candidate's own compiled object *also* references the address through a compiler-emitted relocation — a named `extern` symbol, as in a packaged-source candidate's `DAT_00830540 = DAT_00830540 + 1;`, or a subagent-produced inline-asm rewrite referencing a named symbol.

`inc_abs_global` was fixed in PR #149 on that premise. A full read of every other rule generator embedding a raw absolute address found twelve more candidates for the same fix: ten single-address, two multi-address. Real-toolchain A/B testing (real MSVC8/wine compile + real objdiff, not just unit-level shape assertions) overturned that premise for all twelve: every one of them synthesizes a raw C **literal pointer cast** (`*(unsigned int *)0x...`), not a named-symbol reference — and MSVC compiles a literal cast as a bare immediate with no relocation on the candidate side at all. Reconstructing a *symbolic* target against a candidate that stays *literal* does not help; it was confirmed to introduce spurious `ARGUMENT_MISMATCH` entries that don't exist without the evidence (`global_and_global_bool`: 2 → 6 on the best profile; one of the ten single-address rules showed the same pattern). A/B testing `inc_abs_global`'s own already-shipped fix against its own literal-cast candidate found it neutral (identical mismatch counts with and without the evidence) — its value comes entirely from making the evidence *available* for a later, differently-constructed candidate (e.g. a subagent rewrite) to match against, not from helping its own candidate.

## Requirements

- R1. (Superseded — see Key Technical Decisions.) Originally: each of the ten single-address rule generators populates `absoluteAddressRelocations`. Real-toolchain testing found none of the ten need it; none were changed.
- R2. A shared helper (`single_absolute_address_relocation`) produces the `absoluteAddressRelocations` list for the single-address case, available for any rule that genuinely needs it (a candidate referencing the address through a named symbol, not a literal cast), using the same `_DAT_<addr>`-style symbol naming `inc_abs_global` established.
- R3. (Superseded — see Key Technical Decisions.) Originally: `rep_stos_global_clear` and `global_and_global_bool` populate `absoluteAddressRelocations`. Real-toolchain testing found neither needs it: `rep_stos_global_clear` already reaches `differences: 0` via literal `_emit` bytes; `global_and_global_bool`'s literal-cast candidate was measurably worse with the evidence added. Neither was changed.
- R4. A regression test guards the *actual* anti-pattern this investigation found: a rule generator populating `absoluteAddressRelocations` while its own generated source only references that address via a literal pointer cast (confirmed to make matching worse, not better).
- R5. (Superseded.) Originally called for real-toolchain verification of at least three fixed rules. Real-toolchain verification did run — on `float_multiply_global`, `global_and_global_bool`, and `inc_abs_global` itself — but as A/B comparisons proving the fix should *not* be applied, not as confirmation of a successful fix.

## Key Technical Decisions

- **The premise was wrong; real-toolchain A/B testing found this during implementation, not planning.** `absoluteAddressRelocations` only helps when the candidate's own compiled object contains a matching relocation. Every one of the twelve rule generators in scope synthesizes a literal pointer cast, which MSVC compiles as a bare immediate — no relocation exists on the candidate side for the evidence to usefully mirror. Confirmed by A/B testing three representative cases against the real MSVC8/wine toolchain and real objdiff:
  - `float_multiply_global`: unfixed best-profile histogram `{ARGUMENT_MISMATCH: 2, INSERTION: 14}`; with the evidence added, `{ARGUMENT_MISMATCH: 4, INSERTION: 14}` — worse.
  - `global_and_global_bool`: unfixed `{ARGUMENT_MISMATCH: 2, INSERTION: 4}`; with the evidence added, `{ARGUMENT_MISMATCH: 6, INSERTION: 4}` — worse.
  - `inc_abs_global` (PR #149's own shipped fix): identical histograms with and without the evidence on its own candidate — neutral. Its value is that the evidence field is now *available* on that `GeneratedCandidate` for a differently-constructed candidate for the same target (e.g. a subagent rewrite referencing a named `DAT_<addr>` symbol) to carry matching evidence of its own — demonstrated live in this session by combining a subagent's inline-asm rewrite (`inc dword ptr [DAT_00830540]`) with hand-attached relocation evidence, reaching `differences: 0`.
  - `rep_stos_global_clear`'s only returned candidate embeds every address as literal `_emit` bytes, not a pointer dereference at all — a different reason the evidence doesn't apply, verified to already reach `differences: 0` with no change.
- **U2's ten-rule wiring and U3's `global_and_global_bool` wiring were implemented, real-toolchain-tested, found to regress matching, and reverted** (see git history on this branch: commits wiring the fix, followed by a revert commit and a documentation commit explaining why). The shared helper (U1) was kept — it's correct and reusable for any future rule that legitimately references an address through a named symbol.
- **No changes to the objdiff verification harness itself.** `run_objdiff` and `render_target_coff_for_candidate` are correct as-is; this investigation was about which candidates should populate evidence for them, not about the harness.

## Scope Boundaries

- Does not touch `run_objdiff`, `parse_objdiff_report`, or `render_target_coff_for_candidate` — confirmed correct.
- Does not attempt the separate, already-documented "remaining 64" candidate-generation-quality backlog item (Ghidra-synthesized type names, embedded `int3` artifacts) — a distinct class of bug.
- Does not run a proof-campaign or vacuum loop against `swkotor.exe` to chase new verified accepts.

### Deferred to Follow-Up Work

- **The real generalization opportunity this investigation surfaced**: relocation evidence should be inherited or computed automatically wherever a subagent-rewrite or packaged-source candidate is constructed for a near-miss target that references an absolute address — not attached per mechanical rule generator. This session's subagent-rewrite proof required hand-attaching the evidence to the rewrite candidate; whether `pending_rewrite_variant()` (or wherever mechanism-3 candidates are actually constructed in the production path) does this automatically was not verified and is out of scope here.
- Any additional rule generators beyond the twelve investigated here that may embed absolute addresses in less obvious forms — the regression test (U4) is a static-source-text scan and may not catch every future variant.

## Implementation Units

### U1. Shared single-address relocation-evidence helper

**Goal:** Add a helper that produces the `absoluteAddressRelocations` list for the common single-address case, matching the shape `inc_abs_global` already emits.

**Requirements:** R2

**Dependencies:** None

**Files:**
- Modify: `src/agentdecompile_recovery/source_parity_synthesize.py` (add helper near `inc_abs_global`, e.g. adjacent to line 573)
- Test: `tests/test_relocation_evidence_helper.py`

**Approach:** A small function taking `(offset: int, addr: int)` (or `(offset, addr, symbol_prefix)` if a rule needs a non-`DAT_` symbol convention) and returning the single-entry `absoluteAddressRelocations` list, mirroring the literal `inc_abs_global` currently constructs inline. `inc_abs_global` itself is not required to switch to the helper (it already works and is out of scope for behavior change), but new callers use it.

**Patterns to follow:** `inc_abs_global` (`src/agentdecompile_recovery/source_parity_synthesize.py:573`) for the exact shape and the `_DAT_<addr>` symbol convention.

**Test scenarios:**
- Happy path: helper called with a representative offset/address returns a one-entry list with `type: "IMAGE_REL_I386_DIR32"`, correct `offset`, `symbol` formatted as `_DAT_<addr:08x>`, and `decodedAddress` formatted as `0x<addr:08x>`.
- Edge case: address value with leading zero bytes (e.g. `0x00830540`) formats consistently with the existing `inc_abs_global` convention.

**Verification:** Unit tests pass; output shape matches what `absolute_address_relocations()` (`:21725`) already reads without modification.

---

### U2. Investigate the ten single-address rules (superseded — reverted)

**Goal:** Originally: wire the U1 helper into each of the ten confirmed single-address rule generators. **Actual outcome:** implemented, real-toolchain-verified, found to regress matching for the tested representative (`float_multiply_global`), and reverted for all ten.

**Requirements:** R1 (superseded)

**Dependencies:** U1

**Files:**
- No net change to `src/agentdecompile_recovery/source_parity_synthesize.py` (wired, then reverted via `git revert`)
- `tests/test_rule_generator_relocation_evidence.py` was added, then removed by the revert

**Finding:** All ten rules synthesize a raw literal pointer cast (`*(type *)0x{addr:08x}`), which MSVC compiles as a bare immediate with no relocation. Adding target-side `absoluteAddressRelocations` against a literal candidate does not help. A/B tested for `float_multiply_global` against the real MSVC8/wine toolchain: unfixed best-profile histogram `{ARGUMENT_MISMATCH: 2, INSERTION: 14}` vs. fixed `{ARGUMENT_MISMATCH: 4, INSERTION: 14}` — worse, not better.

**Verification:** `git log` on this branch shows the wiring commit followed by a revert commit; the ten rules are unchanged from their pre-plan state.

---

### U3. Investigate the two multi-address rules (superseded — one reverted, one never applicable)

**Goal:** Originally: wire per-relocation evidence into `rep_stos_global_clear` and `global_and_global_bool`. **Actual outcome:** neither needed the fix.

**Requirements:** R3 (superseded)

**Dependencies:** None

**Files:**
- No net change to `src/agentdecompile_recovery/source_parity_synthesize.py`
- `tests/test_multi_address_rule_relocation_evidence.py` documents the finding for both rules

**Finding:**
- `rep_stos_global_clear`'s only returned candidate embeds every address as literal bytes via inline-asm `_emit` directives, not a pointer dereference — verified against the real toolchain to already reach `differences: 0` with no change.
- `global_and_global_bool` dereferences two addresses via literal casts, same as U2's rules. A/B tested: unfixed `{ARGUMENT_MISMATCH: 2, INSERTION: 4}` vs. fixed `{ARGUMENT_MISMATCH: 6, INSERTION: 4}` — worse. Wired, then reverted before commit.

**Verification:** `tests/test_multi_address_rule_relocation_evidence.py` asserts the current (correct, unchanged) shape for `global_and_global_bool` — no `absoluteAddressRelocations` in its evidence.

---

### U4. Regression test guarding the real anti-pattern (scope corrected)

**Goal:** Originally: guard against a rule generator embedding an address with no relocation evidence. **Corrected goal** (per the U2/U3 findings): guard against a rule generator pairing `absoluteAddressRelocations` with a literal pointer cast — the actual anti-pattern this investigation found and fixed.

**Requirements:** R4

**Dependencies:** U2, U3 (their findings are what U4 guards)

**Files:**
- Test: `tests/test_no_unrelocated_absolute_addresses.py`

**Approach:** An AST scan over `source_parity_synthesize.py` for rule-generator functions (matching the `(row, c_name, data)` parameter signature) whose body both sets `absoluteAddressRelocations` in evidence and contains a literal-cast pattern (`*(type *)0x{addr}`-shaped) referencing an address. `inc_abs_global` is exempted — its own literal-cast candidate is neutral (not harmful) per direct A/B testing, and the evidence field serves a different, later-constructed candidate rather than its own.

**Patterns to follow:** None directly — a new kind of test for this codebase.

**Test scenarios:**
- Happy path: the scan against the current, corrected state of `source_parity_synthesize.py` finds zero violations.
- Failure-path (regression guard): a synthetic in-test function shaped exactly like the mistake this test exists to prevent (literal cast + relocation evidence) is detected by the scan.

**Verification:** Both tests pass; the synthetic-violation test confirms the check has teeth, not that it passes vacuously.

## Dependencies / Assumptions

- Assumes the real MSVC8/wine toolchain used to verify PR #149 (`VC_ROOT=/run/media/brunner56/MyBook/Toolchains/msvc8.0-main`, `WINEPREFIX=target/wine-smoke-prefix`) remains available for the R5 sample verification.
- Assumes no other rule generators beyond these twelve reference absolute addresses in a form the manual read missed (see Deferred to Follow-Up Work).
