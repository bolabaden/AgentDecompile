"""Tests for asm_metrics.py, ported from the upstream reference asm-metrics spec."""

from __future__ import annotations

import pytest

from agentdecompile_recovery.asm_metrics import count_asm_metrics

pytestmark = pytest.mark.unit


class TestArmThumb:
    def test_counts_instructions_branches_labels_format_a(self):
        asm = "\n".join(
            [
                "sub_08001234: @ 0x08001234",
                "\tpush {r4, lr}",
                "\tmov r0, #1",
                "\tcmp r0, #0",
                "\tbeq .L0",
                "\tmov r1, #2",
                "\tbl sub_08005678",
                ".L0:",
                "\tpop {r4}",
                "\tpop {r0}",
                "\tbx r0",
            ]
        )

        metrics = count_asm_metrics(asm, "arm")
        assert metrics.instruction_count == 9
        assert metrics.branch_count == 1
        assert metrics.label_count == 1

    def test_counts_format_b_labels(self):
        asm = "\n".join(
            [
                "\tthumb_func_start sub_080AB000",
                "sub_080AB000: @ 0x080AB000",
                "\tpush {lr}",
                "\tmovs r0, #1",
                "\tbne _080AB010",
                "_080AB010:",
                "\tpop {r0}",
                "\tbx r0",
            ]
        )

        metrics = count_asm_metrics(asm, "arm")
        assert metrics.label_count == 1
        assert metrics.branch_count == 1
        assert metrics.instruction_count == 5

    def test_counts_format_b_labels_with_data_directives(self):
        asm = "\n".join(
            [
                "\tthumb_func_start sub_080AB000",
                "sub_080AB000: @ 0x080AB000",
                "\tpush {lr}",
                "\tldr r0, _080AB010",
                "\tbl some_func",
                "_080AB010: .4byte gStageData",
                "_080AB014: .4byte 0x00000001",
                "\tpop {r0}",
                "\tbx r0",
            ]
        )

        metrics = count_asm_metrics(asm, "arm")
        assert metrics.label_count == 2
        assert metrics.instruction_count == 5

    def test_does_not_count_bic_bics_as_branches(self):
        asm = "\n".join(["\tbic r0, r1", "\tbics r2, r3"])
        metrics = count_asm_metrics(asm, "arm")
        assert metrics.branch_count == 0
        assert metrics.instruction_count == 2

    def test_does_not_count_bx_as_a_branch(self):
        metrics = count_asm_metrics("\tbx lr", "arm")
        assert metrics.branch_count == 0
        assert metrics.instruction_count == 1

    def test_counts_bl_as_instruction_not_branch(self):
        metrics = count_asm_metrics("\tbl sub_08001234", "arm")
        assert metrics.branch_count == 0
        assert metrics.instruction_count == 1

    def test_does_not_count_directives_as_instructions(self):
        asm = "\n".join(["\t.align 2, 0", "\t.4byte 0x12345678", "\t.word 0xDEADBEEF", "\t.hword 0x1234", "\tmov r0, #1"])
        metrics = count_asm_metrics(asm, "arm")
        assert metrics.instruction_count == 1

    def test_handles_empty_asm_code(self):
        metrics = count_asm_metrics("", "arm")
        assert metrics.instruction_count == 0
        assert metrics.branch_count == 0
        assert metrics.label_count == 0

    def test_strips_at_comments_before_parsing(self):
        metrics = count_asm_metrics("\tmov r0, #1 @ load constant", "arm")
        assert metrics.instruction_count == 1

    def test_detects_thumb_encoding(self):
        asm = "\n".join(["\tthumb_func_start sub_080AB000", "sub_080AB000: @ 0x080AB000", "\tpush {lr}", "\tbx lr"])
        metrics = count_asm_metrics(asm, "arm")
        assert metrics.arm_encoding == "thumb"
        assert metrics.instruction_count == 2

    def test_detects_arm32_encoding(self):
        asm = "\n".join(["\tarm_func_start IntrMain", "IntrMain: @ 0x080000FC", "\tmov r3, #0x04000000", "\tbx lr"])
        metrics = count_asm_metrics(asm, "arm")
        assert metrics.arm_encoding == "arm32"
        assert metrics.instruction_count == 2

    def test_returns_none_arm_encoding_when_no_marker(self):
        asm = "\n".join(["push {lr}", "mov r0, #1", "pop {r0}", "bx r0"])
        metrics = count_asm_metrics(asm, "arm")
        assert metrics.arm_encoding is None


class TestMips:
    def test_counts_instructions_branches_labels(self):
        asm = "\n".join(
            [
                "glabel func_80001000",
                "/* 000000 80001000 27BDFFD0 */  addiu $sp, $sp, -0x30",
                "/* 000004 80001004 AFBF002C */  sw    $ra, 0x2c($sp)",
                "/* 000008 80001008 10400005 */  beq   $v0, $zero, .L80001020",
                "/* 00000C 8000100C 00000000 */   nop",
                "/* 000010 80001010 0C000500 */  jal   func_80001400",
                "/* 000014 80001014 00000000 */   nop",
                ".L80001020:",
                "/* 000018 80001018 8FBF002C */  lw    $ra, 0x2c($sp)",
                "/* 00001C 8000101C 03E00008 */  jr    $ra",
                "/* 000020 80001020 27BD0030 */   addiu $sp, $sp, 0x30",
            ]
        )

        metrics = count_asm_metrics(asm, "mips")
        assert metrics.instruction_count == 9
        assert metrics.branch_count == 1
        assert metrics.label_count == 1

    def test_handles_empty_asm_code(self):
        metrics = count_asm_metrics("", "mips")
        assert metrics.instruction_count == 0
        assert metrics.branch_count == 0
        assert metrics.label_count == 0

    def test_counts_jr_as_instruction(self):
        metrics = count_asm_metrics("/* 00001C 8000101C 03E00008 */  jr    $ra", "mips")
        assert metrics.instruction_count == 1
        assert metrics.branch_count == 0

    def test_does_not_set_arm_encoding_for_mips(self):
        metrics = count_asm_metrics("/* 000000 80001000 27BDFFD0 */  addiu $sp, $sp, -0x30", "mips")
        assert metrics.arm_encoding is None
