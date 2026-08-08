"""Tests for the x86 half of asm_metrics, against real captures.

Counts are pinned to the real fixtures in `tests/fixtures/x86/`, and the
MASM listing and the objdiff disassembly of the *same* function are asserted
to agree -- that agreement is what makes the two dialects interchangeable as
corpus input.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.asm_metrics import count_asm_metrics

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "x86"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class TestMasmListing:
    def test_counts_instructions_branches_and_local_labels(self):
        metrics = count_asm_metrics(fixture("sub_d6660-msvc71-listing.asm"), "x86")
        assert metrics.instruction_count == 24
        assert metrics.branch_count == 3  # three `je SHORT $L...`
        assert metrics.label_count == 3  # $L562, $L567, $L569

    def test_calls_are_instructions_but_not_branches(self):
        # Three `call __free` sites, none of which may count as a branch --
        # the same rule the ARM path applies to `bl`.
        metrics = count_asm_metrics(fixture("sub_d6660-msvc71-listing.asm"), "x86")
        assert metrics.branch_count == 3
        assert metrics.instruction_count > metrics.branch_count


class TestObjdiffDialect:
    def test_counts_match_the_instruction_rows(self):
        metrics = count_asm_metrics(fixture("sub_d6660-objdiff-target.s"), "x86")
        assert metrics.instruction_count == 25
        assert metrics.branch_count == 3

    def test_global_entry_label_is_not_counted(self):
        # `_sub_d6660:` names the function; only compiler-local labels are
        # branch targets, matching the ARM/MIPS `.L*` rule.
        metrics = count_asm_metrics(fixture("sub_d6660-objdiff-target.s"), "x86")
        assert metrics.label_count == 0

    def test_both_dialects_agree_on_branch_count_for_the_same_function(self):
        masm = count_asm_metrics(fixture("sub_d6660-msvc71-listing.asm"), "x86")
        objdiff = count_asm_metrics(fixture("sub_d6660-objdiff-candidate.s"), "x86")
        assert masm.instruction_count == objdiff.instruction_count == 24
        assert masm.branch_count == objdiff.branch_count == 3

    def test_jump_table_indirect_jmp_counts_as_a_branch(self):
        metrics = count_asm_metrics(fixture("jump-table-objdiff-candidate.s"), "x86")
        assert metrics.instruction_count == 33
        assert metrics.branch_count >= 2

    def test_prefixed_string_op_is_one_instruction(self):
        metrics = count_asm_metrics(fixture("rep-string-ops-objdiff-candidate.s"), "x86")
        assert metrics.instruction_count == 16

    def test_x87_body_has_no_branches(self):
        metrics = count_asm_metrics(fixture("x87-objdiff-candidate.s"), "x86")
        assert metrics.instruction_count == 12
        assert metrics.branch_count == 0


class TestDispatch:
    def test_byte_blob_scores_zero(self):
        asm = "_TEXT SEGMENT\n_f PROC\n    DB 06ah, 0ffh\n_f ENDP\n_TEXT ENDS\nEND"
        metrics = count_asm_metrics(asm, "x86")
        assert (metrics.instruction_count, metrics.branch_count, metrics.label_count) == (0, 0, 0)

    def test_x86_64_shares_the_counter(self):
        asm = "    mov rax, [rbp-0x8]\n    test rax, rax\n    je short 0x10\n    ret"
        metrics = count_asm_metrics(asm, "x86_64")
        assert metrics.instruction_count == 4
        assert metrics.branch_count == 1

    def test_unknown_platform_still_returns_zeroes(self):
        assert count_asm_metrics("push esi", "saturn").instruction_count == 0
