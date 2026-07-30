"""Tests for the shared single-address relocation-evidence helper.

See src/agentdecompile_recovery/source_parity_synthesize.py's
single_absolute_address_relocation() and the inc_abs_global fix it
generalizes (PR #149) -- both exist to give render_target_coff_for_candidate()
a symbol relocation to reconstruct on the target side, instead of a raw byte
blob that a correctly-compiled candidate can never byte-match.
"""

from __future__ import annotations

from agentdecompile_recovery.source_parity_synthesize import single_absolute_address_relocation


def test_single_absolute_address_relocation_shape() -> None:
    relocations = single_absolute_address_relocation(offset=6, addr=0x00830540)

    assert relocations == [
        {
            "offset": 6,
            "type": "IMAGE_REL_I386_DIR32",
            "symbol": "_DAT_00830540",
            "decodedAddress": "0x00830540",
        }
    ]


def test_single_absolute_address_relocation_leading_zero_address() -> None:
    relocations = single_absolute_address_relocation(offset=0, addr=0x00001000)

    assert relocations[0]["symbol"] == "_DAT_00001000"
    assert relocations[0]["decodedAddress"] == "0x00001000"
