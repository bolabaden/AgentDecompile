r"""Regression test: packaged-source candidates for __stdcall functions must
compute the real `@N` stack-byte-decorated symbol name, not silently fall
back to plain cdecl naming.

Found while manually promoting a real swkotor.exe near-miss (sub_6c60) to
verified/: the candidate compiled to byte-identical machine code as the
target (`mov eax, 0x1; ret 0x10`, both 8 bytes) but objdiff still reported
`match_percent: 0.0` because the target-side synthetic symbol was named
`_sub_6c60` (infer_packaged_symbol's cdecl fallback) while the real compiled
object's stdcall-decorated symbol was `_sub_6c60@16` -- a symbol-name
mismatch masking an otherwise-exact code match. Root cause:
packaged_stack_bytes() only derives stack bytes from external row metadata
(automaticGenerator.stackBytes, a trailing `@N` in row["name"], or a
trailing `_N` in c_name) -- none of which apply to a plain decompiler-named
function like `sub_6c60` -- so it returns None and infer_packaged_symbol()
falls through to cdecl naming even though it already detected `stdcall` from
the source text itself.

A follow-up sweep of cached objdiff verify results (see session notes) found
a second, larger-impact instance of the same class: the `_(\d+)$` fallback
against c_name matches Ghidra's own auto-generated `sub_<hex>`/`FUN_<hex>`
names whenever the hex address happens to contain only decimal digits (no
a-f), misreading the function's own address as a bogus stack-byte count
(e.g. `sub_11240` -> 11240). This silently pre-empted the correct
source-derived parameter count for roughly a third of the swkotor.exe
near-miss stdcall population found in the same sweep.
"""

from __future__ import annotations

import pytest

from agentdecompile_recovery.source_parity_synthesize import (
    infer_packaged_symbol,
    packaged_stack_bytes,
)

pytestmark = pytest.mark.unit


def test_packaged_stack_bytes_counts_stdcall_params_from_source_when_no_metadata() -> None:
    row: dict = {"name": "sub_6c60"}
    source = (
        "undefined4 __stdcall sub_6c60(undefined4 param_1, undefined4 param_2, "
        "undefined4 param_3, undefined4 param_4)\n\n{\n  return 1;\n}\n"
    )

    assert packaged_stack_bytes(row, "sub_6c60", source=source) == 16


def test_packaged_stack_bytes_zero_for_void_params() -> None:
    row: dict = {"name": "sub_1a00"}
    source = "undefined4 __stdcall sub_1a00(void)\n\n{\n  return 1;\n}\n"

    assert packaged_stack_bytes(row, "sub_1a00", source=source) == 0


def test_packaged_stack_bytes_does_not_misread_all_decimal_address_as_suffix() -> None:
    # sub_11240's own address (0x11240) happens to be all decimal digits, so
    # the c_name "sub_11240" superficially looks like it ends in a "_<N>"
    # stack-byte annotation. Before this fix, packaged_stack_bytes() matched
    # that address digit run via `_(\d+)$` and returned 11240 (nonsense) for
    # ANY sub_XXXX name whose hex address contains no a-f digit, completely
    # bypassing the real 1-param count from source (4 bytes) and silently
    # producing a target-scale symbol suffix that could never match a real
    # compiled candidate. This affected roughly a third of the swkotor.exe
    # near-miss stdcall population discovered in this session's cache sweep.
    row: dict = {"name": "sub_11240"}
    source = "undefined4 __stdcall sub_11240(undefined4 *param_1)\n\n{\n  return 1;\n}\n"

    assert packaged_stack_bytes(row, "sub_11240", source=source) == 4


def test_packaged_stack_bytes_still_honors_deliberate_helper_suffix() -> None:
    # A manually-authored helper name like "helper_16" (not Ghidra's default
    # sub_/FUN_ auto-naming) legitimately uses a trailing "_N" to mean N
    # stack bytes -- the auto-decompiler-name guard must not suppress this.
    row: dict = {"name": "helper_16"}

    assert packaged_stack_bytes(row, "helper_16") == 16


def test_packaged_stack_bytes_prefers_explicit_metadata_over_source_parse() -> None:
    row = {"name": "sub_2000", "automaticGenerator": {"stackBytes": 8}}
    source = "undefined4 __stdcall sub_2000(undefined4 a, undefined4 b, undefined4 c)\n\n{\n  return 1;\n}\n"

    # Explicit metadata (8) wins over the source's 3-param count (12).
    assert packaged_stack_bytes(row, "sub_2000", source=source) == 8


def test_infer_packaged_symbol_produces_correct_stdcall_decoration_from_source_alone() -> None:
    row: dict = {"name": "sub_6c60"}
    c_name = "sub_6c60"
    source = (
        "undefined4 __stdcall sub_6c60(undefined4 param_1, undefined4 param_2, "
        "undefined4 param_3, undefined4 param_4)\n\n{\n  return 1;\n}\n"
    )

    assert infer_packaged_symbol(row, source, c_name, ".c") == "_sub_6c60@16"


def test_infer_packaged_symbol_still_falls_back_to_cdecl_when_params_unparseable() -> None:
    row: dict = {"name": "sub_9999"}
    c_name = "sub_9999"
    # No matching function definition in the source at all -- can't count params.
    source = "// no function body here\n"

    assert infer_packaged_symbol(row, source, c_name, ".c") == "_sub_9999"
