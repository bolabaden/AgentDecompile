"""U3 of docs/plans/2026-07-30-001-fix-generalize-relocation-evidence-plan.md:
findings on the two multi-address rule generators the plan targeted.

Real-toolchain verification (real MSVC8/wine compile + real objdiff, not just
unit-level evidence-shape assertions) overturned this plan's premise for both
rules -- see the plan's amended Key Technical Decisions for the full writeup.
Neither rule was changed; this file documents why, so the finding isn't lost
or rediscovered as an open gap.

**The corrected understanding:** `render_target_coff_for_candidate()`'s
relocation reconstruction only helps when the candidate's OWN compiled object
also references the address through a compiler-emitted relocation (e.g. a
named `extern` symbol, as in a packaged-source candidate's
`DAT_00830540 = DAT_00830540 + 1;`, or a subagent's inline-asm rewrite
referencing a named symbol). Every rule generator in this codebase that
synthesizes a raw C literal pointer cast (`*(unsigned int *)0x...`) compiles
that address as a bare immediate with NO relocation on the candidate side --
MSVC does not route a literal address cast through an extern symbol. Adding
`absoluteAddressRelocations` to reconstruct a *symbolic* target side against a
candidate that stays *literal* does not help; it was empirically confirmed to
introduce spurious `ARGUMENT_MISMATCH` entries that don't exist without the
evidence (verified for `global_and_global_bool` and, separately, for one of
the ten single-address rules this plan also reverted -- see git history on
this branch).

- `global_and_global_bool` dereferences two absolute addresses via literal
  casts. A/B tested against the real toolchain: WITHOUT relocation evidence,
  the best profile shows `ARGUMENT_MISMATCH: 2`; WITH the evidence this plan
  originally added, the same profile shows `ARGUMENT_MISMATCH: 6` -- strictly
  worse. The evidence was reverted; no fix was needed or applied.
- `rep_stos_global_clear` was a **false positive** from a different angle:
  its only returned candidate embeds every address as literal bytes via
  inline-asm `_emit` directives, not any pointer dereference at all. Verified
  directly against the real toolchain: it already reaches `differences: 0`
  with no evidence change.
"""

from __future__ import annotations

from agentdecompile_recovery.source_parity_synthesize import global_and_global_bool


def test_global_and_global_bool_uses_literal_address_casts_not_relocations() -> None:
    """Documents the current (correct, unchanged) shape: no
    absoluteAddressRelocations, because the candidate source uses literal
    pointer casts that a real MSVC compile bakes as bare immediates, not a
    relocation an objdiff target reconstruction could usefully mirror.
    """

    left = 0x00830560
    right = 0x00830564
    data = (
        b"\xa1"
        + left.to_bytes(4, "little")
        + b"\x8b\x0d"
        + right.to_bytes(4, "little")
        + b"\x23\xc8\x3b\xc8\x0f\x94\xc0\xc3"
    )
    candidates = global_and_global_bool({}, "FUN_test", data)
    assert len(candidates) == 1
    assert "absoluteAddressRelocations" not in candidates[0].evidence
    assert f"0x{left:08x}" in candidates[0].source
    assert f"0x{right:08x}" in candidates[0].source
