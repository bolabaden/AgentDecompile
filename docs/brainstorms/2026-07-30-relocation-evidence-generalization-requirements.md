---
date: 2026-07-30
topic: relocation-evidence-generalization
---

# Generalize target-side relocation evidence across mechanical rule generators

## Summary

Generalize the relocation-evidence fix shipped in PR #149 (`inc_abs_global`) to every other mechanical rule generator in `src/agentdecompile_recovery/source_parity_synthesize.py` with the same gap, via a shared helper plus a regression test that prevents the pattern from recurring in future rules.

## Problem Frame

`render_target_coff_for_candidate()` can reconstruct the objdiff target object with a matching symbol relocation for absolute-address (`DIR32`) references, via `absolute_address_relocations()`, which reads `candidate.evidence["absoluteAddressRelocations"]`. Without it, the target side falls back to a raw byte blob with the address baked in literally, and any candidate that correctly references the same global through a compiler-visible symbol can never byte-match — confirmed empirically (PR #149) against the real MSVC8/wine toolchain and real objdiff.

`inc_abs_global` had this gap and is now fixed. A scan for the same shape (a rule generator embedding a raw absolute address in generated C source without populating `absoluteAddressRelocations`) found roughly twenty more rule functions with the identical pattern. Some of these rules validate a single fixed-offset address the same way `inc_abs_global` did (e.g. `float_multiply_global`); others may reference multiple addresses or non-global values the initial heuristic scan can't distinguish without closer reading per function. Left unfixed, any function in a real recovery run whose target-matching rule falls into this class faces the same unclosable ceiling `inc_abs_global` did — a candidate can be semantically and structurally perfect and still never reach `objdiff differences: 0`.

## Requirements

- R1. Every mechanical rule generator that embeds an absolute global address in its generated C source populates `absoluteAddressRelocations` in its `GeneratedCandidate.evidence`, following the same `{offset, type: "IMAGE_REL_I386_DIR32", symbol, decodedAddress}` shape `absolute_address_relocations()` already reads.
- R2. A shared helper covers the common single-address case so each affected rule adopts the fix in one line rather than a hand-rolled dict, mirroring the naming convention already established (`_DAT_<addr>`-style symbols).
- R3. Rules with more than one absolute-address reference (following the `bink_buffer_set_direct_draw_forwarder` shape) are verified individually rather than assumed to fit the single-address helper.
- R4. A regression test scans rule generators for the anti-pattern (a literal hex address baked into generated C source with no matching relocation evidence) so a future new rule cannot reintroduce this gap silently.
- R5. Each fixed rule is verified against the real MSVC8/wine toolchain and real objdiff for at least one representative byte pattern, not just a unit-level assertion on the evidence shape (the same standard PR #149 held itself to).

## Scope Boundaries

- Does not change the objdiff verification harness itself (`run_objdiff`, `parse_objdiff_report`) — PR #149 established that harness is correct once given matching relocation evidence.
- Does not attempt to fix the separate, already-documented "remaining 64" candidate-generation-quality backlog item (Ghidra-synthesized type names, embedded `int3` artifacts) — that is a distinct class of bug.
- Does not run a full proof-campaign or vacuum loop against `swkotor.exe` to chase new verified accepts — that is a separate, later effort this fix unblocks but does not itself perform.

## Dependencies / Assumptions

- Assumes the exact set of affected rule generators is confirmed by reading each flagged function during planning/implementation, not taken as a fixed count from the initial heuristic scan.
- Assumes the real MSVC8/wine toolchain used to verify PR #149 (`VC_ROOT=/run/media/brunner56/MyBook/Toolchains/msvc8.0-main`, `WINEPREFIX=target/wine-smoke-prefix`) remains available for per-rule verification.

## Outstanding Questions

**Deferred to Planning**
- Whether the regression test (R4) should be a static scan over rule-generator source text, or a data-driven check that calls every rule generator with a representative byte pattern and inspects its returned `evidence` — the right mechanism depends on how uniformly testable the ~20 rules turn out to be once read individually.
