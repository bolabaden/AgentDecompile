"""Tests for the x86 half of asm_utils, against real captures.

Every fixture in `tests/fixtures/x86/` is a real capture, not a hand-written
snippet: the `.s` files are objdiff-cli disassembly taken from the
swkotor-parity work dir's `verify.json` alignedDiff rows, and the `.asm` file
is a `cl /FAs` listing from the vendored MSVC 13.10.3052 (VC7.1) toolkit
compiling `sub_d6660-msvc71-listing.c`. A parser that silently mis-parses is
worse than one with a stated boundary, so these assert on exact counts and
exact symbol sets rather than on substring presence.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.asm_utils import (
    count_body_lines_from_asm_function,
    extract_asm_function_body,
    extract_function_calls_from_assembly,
    is_x86_branch_mnemonic,
    is_x86_local_label,
    iter_x86_instructions,
    list_functions_from_asm_module,
    strip_commentaries,
    x86_label_name,
)

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "x86"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class TestMasmListing:
    """`cl /FAs` output: PROC/ENDP framing, DWORD PTR, OFFSET FLAT:, $L labels."""

    def test_splits_on_proc_endp(self):
        functions = list_functions_from_asm_module("x86", fixture("sub_d6660-msvc71-listing.asm"))
        assert [fn["name"] for fn in functions] == ["_sub_d6660"]

    def test_body_is_instructions_only(self):
        body = extract_asm_function_body("x86", fixture("sub_d6660-msvc71-listing.asm"))
        lines = body.split("\n")
        assert lines[0] == "push esi"
        assert lines[-1] == "ret 0"
        # None of the listing scaffolding survives.
        for banned in ("TITLE", "SEGMENT", "ENDS", "PUBLIC", "EXTRN", "INCLUDELIB",
                       "PROC", "ENDP", "ASSUME", "GROUP", "if @Version", "endif", "$L562:"):
            assert banned not in body, banned

    def test_body_line_count_matches_the_listing(self):
        # 24 instructions between PROC and ENDP in the real listing.
        assert count_body_lines_from_asm_function("x86", fixture("sub_d6660-msvc71-listing.asm")) == 24

    def test_extracts_call_target_and_offset_flat_symbol(self):
        calls = extract_function_calls_from_assembly("x86", fixture("sub_d6660-msvc71-listing.asm"))
        assert calls == ["_PTR_sub_d6660_007465a4", "__free"]

    def test_masm_frame_equates_are_not_call_edges(self):
        # `_in_ECX$[esp]` / `_param_1$[esp]` are stack slots the listing itself
        # declares with `_in_ECX$ = 8`. They are not references to other code.
        calls = extract_function_calls_from_assembly("x86", fixture("sub_d6660-msvc71-listing.asm"))
        assert not any(name.endswith("$") for name in calls)

    def test_local_labels_are_not_call_edges(self):
        calls = extract_function_calls_from_assembly("x86", fixture("sub_d6660-msvc71-listing.asm"))
        assert not any(name.startswith("$L") for name in calls)


class TestObjdiffDialect:
    """objdiff `instruction.formatted`: lowercase, `dword ptr`, `short 0x2a`."""

    def test_globl_and_label_open_a_function(self):
        functions = list_functions_from_asm_module("x86", fixture("sub_d6660-objdiff-target.s"))
        assert [fn["name"] for fn in functions] == ["_sub_d6660"]

    def test_target_side_has_no_symbolic_call_edges(self):
        # The target object is assembled from raw bytes and carries no
        # relocations, so `call 0x223d30` is an intra-object offset. The
        # documented boundary is that numeric targets are not callees.
        assert extract_function_calls_from_assembly("x86", fixture("sub_d6660-objdiff-target.s")) == []

    def test_candidate_side_recovers_the_same_symbols_as_the_masm_listing(self):
        calls = extract_function_calls_from_assembly("x86", fixture("sub_d6660-objdiff-candidate.s"))
        assert calls == ["_PTR_sub_d6660_007465a4", "__free"]

    def test_every_instruction_row_survives_parsing(self):
        for name in ("sub_d6660-objdiff-target.s", "sub_d6660-objdiff-candidate.s",
                     "x87-objdiff-candidate.s", "rep-string-ops-objdiff-candidate.s",
                     "mangled-names-objdiff-candidate.s", "jump-table-objdiff-candidate.s"):
            text = fixture(name)
            instruction_lines = [
                line.strip()
                for line in text.split("\n")
                if line.startswith("    ")
            ]
            parsed = list(iter_x86_instructions(text))
            assert len(parsed) == len(instruction_lines), name

    def test_hex_immediates_do_not_produce_phantom_symbols(self):
        # `0x4` must not yield a bogus `x4`; `[eax*0x4+$LN11]` must not yield `x4`.
        calls = extract_function_calls_from_assembly("x86", fixture("jump-table-objdiff-candidate.s"))
        assert not any(name.startswith("x") and name[1:].isdigit() for name in calls)


class TestMsvcDecoratedSymbols:
    def test_mangled_string_literal_survives_whole(self):
        calls = extract_function_calls_from_assembly("x86", fixture("mangled-names-objdiff-candidate.s"))
        assert "??_C@_08OEKJENGB@?$CFf?5?$CFf?5?$CFf?$AA@" in calls

    def test_stdcall_decorated_import_is_one_symbol(self):
        calls = extract_function_calls_from_assembly("x86", fixture("mangled-names-objdiff-candidate.s"))
        assert "__sscanf" in calls

    def test_at_is_not_a_comment_marker_for_x86(self):
        # The ARM path treats `@` as a comment start. Applying that rule to
        # x86 would truncate every MSVC-decorated symbol at its first `@`.
        line = "push ??_C@_08OEKJENGB@?$CFf?5?$CFf?5?$CFf?$AA@"
        assert strip_commentaries(line, "x86") == line
        assert strip_commentaries(line) == "push ??_C"

    def test_semicolon_still_ends_a_comment(self):
        assert strip_commentaries("push esi ; save", "x86") == "push esi"

    def test_quoted_semicolon_is_not_a_comment(self):
        line = "_TEXT SEGMENT PARA USE32 PUBLIC 'CO;DE'"
        assert strip_commentaries(line, "x86") == line


class TestPrefixesAndUndecodableBytes:
    def test_rep_prefix_does_not_hide_the_real_mnemonic(self):
        mnemonics = [mnemonic for _line, mnemonic in iter_x86_instructions(fixture("rep-string-ops-objdiff-candidate.s"))]
        assert "stosd" in mnemonics
        assert "rep" not in mnemonics

    def test_string_op_after_a_prefix_is_not_a_symbol(self):
        calls = extract_function_calls_from_assembly("x86", fixture("rep-string-ops-objdiff-candidate.s"))
        assert "stosd" not in calls
        assert "cmpsd" not in calls

    def test_bad_marker_parses_as_an_instruction(self):
        parsed = list(iter_x86_instructions("(bad)"))
        assert parsed == [("(bad)", "(bad)")]
        assert extract_function_calls_from_assembly("x86", "(bad)") == []


class TestX87:
    def test_st_operands_are_not_symbols(self):
        calls = extract_function_calls_from_assembly("x86", fixture("x87-objdiff-candidate.s"))
        assert "st" not in calls

    def test_float_pool_symbol_is_an_edge(self):
        asm = "fcomp st, qword ptr [__real@3ff0000000000000]"
        assert extract_function_calls_from_assembly("x86", asm) == ["__real@3ff0000000000000"]


class TestByteBlobs:
    def test_db_emission_has_no_instruction_body(self):
        # This repo's own MASM byte-emission candidates are `DB` blobs. They
        # carry no instruction structure, so they must not be indexed as if
        # they did.
        asm = "\n".join(
            [
                ".386",
                ".model flat",
                "PUBLIC _sub_1000",
                "_TEXT SEGMENT",
                "_sub_1000 PROC",
                "    DB 06ah, 0ffh, 068h, 0a6h",
                "_sub_1000 ENDP",
                "_TEXT ENDS",
                "END",
            ]
        )
        assert extract_asm_function_body("x86", asm) == ""
        assert count_body_lines_from_asm_function("x86", asm) == 0
        assert [fn["name"] for fn in list_functions_from_asm_module("x86", asm)] == ["_sub_1000"]


class TestHelpers:
    @pytest.mark.parametrize("mnemonic", ["je", "jne", "jmp", "jbe", "loop", "jecxz"])
    def test_branch_mnemonics(self, mnemonic):
        assert is_x86_branch_mnemonic(mnemonic)

    @pytest.mark.parametrize("mnemonic", ["call", "ret", "mov", "push", "leave"])
    def test_non_branch_mnemonics(self, mnemonic):
        assert not is_x86_branch_mnemonic(mnemonic)

    def test_label_name(self):
        assert x86_label_name("$L562:") == "$L562"
        assert x86_label_name("_sub_d6660:") == "_sub_d6660"
        assert x86_label_name("    push esi") is None

    def test_local_label_classification(self):
        assert is_x86_local_label("$L562")
        assert is_x86_local_label("$LN11")
        assert is_x86_local_label(".L2")
        assert not is_x86_local_label("_sub_d6660")


class TestPlatformDispatch:
    def test_x86_64_shares_the_x86_parser(self):
        asm = ".globl f\nf:\n    mov rax, [rbp-0x8]\n    call _helper\n    ret"
        assert extract_function_calls_from_assembly("x86_64", asm) == ["_helper"]
        assert count_body_lines_from_asm_function("x86_64", asm) == 3

    def test_unsupported_platform_still_raises(self):
        with pytest.raises(ValueError, match="Unsupported platform"):
            extract_function_calls_from_assembly("saturn", "nop")
