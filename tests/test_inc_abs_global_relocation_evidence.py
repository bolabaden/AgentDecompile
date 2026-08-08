"""Regression tests for inc_abs_global's target-side relocation evidence.

Bug: inc_abs_global() populated evidence={"absoluteAddress": ...} instead of
the absoluteAddressRelocations shape that render_target_coff_for_candidate()
actually reads. Without it, the target side of every objdiff comparison for
this rule is rendered as a raw byte blob with the address baked in literally,
while any correct compiled candidate necessarily references the global via a
real relocation -- an unclosable structural mismatch regardless of candidate
source quality (confirmed via a real MSVC8/objdiff run on FUN_004a23b0: an
instruction-for-instruction identical inline-asm rewrite still reported
DIFF_ARG_MISMATCH because the two sides were never rendered comparably).
"""

from __future__ import annotations

from agentdecompile_recovery.source_parity_synthesize import (
    inc_abs_global,
    render_target_coff_for_candidate,
)

TARGET_BYTES = bytes.fromhex("ff0540058300c3")  # inc dword ptr [0x00830540]; ret


def test_inc_abs_global_populates_absolute_address_relocations() -> None:
    candidates = inc_abs_global({}, "FUN_004a23b0", TARGET_BYTES)
    assert len(candidates) == 2

    for candidate in candidates:
        relocations = candidate.evidence.get("absoluteAddressRelocations")
        assert isinstance(relocations, list) and len(relocations) == 1
        relocation = relocations[0]
        assert relocation["offset"] == 2
        assert relocation["type"] == "IMAGE_REL_I386_DIR32"
        assert relocation["symbol"] == "_DAT_00830540"
        assert relocation["decodedAddress"] == "0x00830540"


def test_render_target_coff_reconstructs_relocation_for_inc_abs_global() -> None:
    candidates = inc_abs_global({}, "FUN_004a23b0", TARGET_BYTES)
    rendered = render_target_coff_for_candidate(candidates[0], TARGET_BYTES)

    # The address bytes (offset 2..6) must be emitted as a symbol relocation,
    # not as raw .byte literals -- otherwise the target side can never match
    # a candidate object that references the same global through a symbol.
    assert ".long _DAT_00830540" in rendered["asm"]
    assert rendered["relocations"]
    assert rendered["relocations"][0]["symbol"] == "_DAT_00830540"
    assert "reconstructed relocations" in rendered["origin"]
