"""Tests for asm_embedding.py, ported from the upstream embedder's preprocessForEmbedding spec."""

from __future__ import annotations

import re

import pytest

from agentdecompile_recovery.asm_embedding import preprocess_for_embedding

pytestmark = pytest.mark.unit


def test_strips_arm_comments_and_markers_from_function_code():
    asm_code = "\n".join(
        [
            "\tthumb_func_start MyFunc",
            "MyFunc: @ 0x08001000",
            "\tpush {r4, lr} @ save regs",
            "\tmov r0, #1",
            "\tpop {r4}",
            "\tbx lr",
            "\tthumb_func_end MyFunc",
        ]
    )

    result = preprocess_for_embedding("arm", asm_code)
    assert "thumb_func_start" not in result
    assert "thumb_func_end" not in result
    assert "MyFunc:" not in result
    assert "@ save regs" not in result
    assert "push {r4, lr}" in result
    assert "mov r0, #1" in result


def test_strips_mips_comments_and_markers_from_function_code():
    asm_code = "\n".join(
        [
            "glabel func_80001000",
            "/* 000000 80001000 27BDFFD0 */  addiu $sp, $sp, -0x30 ; stack frame",
            "/* 000004 80001004 03E00008 */  jr    $ra",
            ".size func_80001000, . - func_80001000",
        ]
    )

    result = preprocess_for_embedding("mips", asm_code)
    assert "glabel" not in result
    assert ".size" not in result
    assert "; stack frame" not in result
    assert "addiu sp, sp, -0x30" in result


def test_returns_empty_string_for_empty_function():
    asm_code = "\tthumb_func_start Empty\nEmpty:\n\tthumb_func_end Empty"
    assert preprocess_for_embedding("arm", asm_code) == ""


def test_strips_objdiff_address_prefixes_and_reference_annotations():
    objdiff_asm = "\n".join(
        [
            "0:       ldr r1, [pc, #0x4] # REFERENCE_.L8",
            "2:       mov r0, #0x0",
            "4:       str r0, [r1, #0x4]",
            "6:       bx lr",
            "8:       .word gInputRecorder",
        ]
    )

    result = preprocess_for_embedding("arm", objdiff_asm)
    assert not re.search(r"^[0-9a-f]+:", result, re.MULTILINE)
    assert "# REFERENCE_" not in result
    assert "mov r0, #0x0" in result
    assert ".word gInputRecorder" in result


def test_strips_objdiff_line_number_annotations_before_instructions():
    objdiff_asm = "\n".join(["2c:  27add r2, #0x4", "2e:  13ldr r1, [r2, #0x0]"])

    result = preprocess_for_embedding("arm", objdiff_asm)
    assert "add r2, #0x4" in result
    assert "ldr r1, [r2, #0x0]" in result
    assert not re.search(r"^\d+[a-z]", result, re.MULTILINE)


def test_normalizes_thumb_s_suffix_instructions():
    raw_asm = "\n".join(
        [
            "\tthumb_func_start Fn",
            "Fn: @ 0x08001000",
            "\tadds r0, r1, r2",
            "\tmovs r0, #0xff",
            "\tlsls r0, r0, #0x10",
            "\tands r0, r1",
            "\torrs r3, r2",
            "\tnegs r0, r0",
            "\tthumb_func_end Fn",
        ]
    )

    result = preprocess_for_embedding("arm", raw_asm)
    assert "add r0, r1, r2" in result
    assert "mov r0, #0xff" in result
    assert "lsl r0, r0, #0x10" in result
    assert "and r0, r1" in result
    assert "orr r3, r2" in result
    assert "neg r0, r0" in result
    assert not re.search(r"\b(adds|movs|lsls|ands|orrs|negs)\b", result)


def test_normalizes_four_byte_to_word():
    raw_asm = "\n".join(
        [
            "\tthumb_func_start Fn",
            "Fn: @ 0x08001000",
            "\tldr r0, _08001010 @ =gData",
            "\tbx lr",
            "_08001010: .4byte gData",
            "\tthumb_func_end Fn",
        ]
    )

    result = preprocess_for_embedding("arm", raw_asm)
    assert ".word gData" in result
    assert ".4byte" not in result


def test_strips_mips_nonmatching_directive():
    asm_code = "\n".join(
        [
            "glabel func_8086F310_jp",
            "/* 000000 8086F310 27BDFFD0 */  addiu $sp, $sp, -0x30",
            "nonmatching func_8086F310_jp, 0x4C",
            "/* 000004 8086F314 03E00008 */  jr    $ra",
            ".size func_8086F310_jp, . - func_8086F310_jp",
        ]
    )

    result = preprocess_for_embedding("mips", asm_code)
    assert "nonmatching" not in result
    assert "addiu" in result
    assert "jr" in result


def test_strips_mips_register_dollar_prefix():
    asm_code = "\n".join(
        [
            "glabel func_80001000",
            "/* 000000 80001000 27BDFFD0 */  addiu $sp, $sp, -0x30",
            "/* 000004 80001004 AFBF001C */  sw    $ra, 0x1c($sp)",
            "/* 000008 80001008 AFA40030 */  sw    $a0, 0x30($sp)",
            "/* 00000C 8000100C 0320F809 */  jalr  $t9",
            "/* 000010 80001010 00000000 */  nop",
            "/* 000014 80001014 8FBF001C */  lw    $31, 0x1c($sp)",
            "/* 000018 80001018 44800000 */  mtc1  $zero, $fv0",
            "/* 00001C 8000101C 46006006 */  mov.s $ft3, $ft0",
            "/* 000020 80001020 44040000 */  mfc1  $a0, $f12",
            ".size func_80001000, . - func_80001000",
        ]
    )

    result = preprocess_for_embedding("mips", asm_code)
    assert "addiu sp, sp, -0x30" in result
    assert "sw ra, 0x1c(sp)" in result
    assert "sw a0, 0x30(sp)" in result
    assert "jalr t9" in result
    assert "lw 31, 0x1c(sp)" in result
    assert "mtc1 zero, fv0" in result
    assert "mov.s ft3, ft0" in result
    assert "mfc1 a0, f12" in result
    assert not re.search(r"\$[a-z]", result)
    assert not re.search(r"\$\d", result)


def test_normalizes_dot_l_hex_labels():
    objdiff_asm = "\n".join(
        ["0:       beq r0, r1, .L2c11", "4:       lui a1, %hi(data)", ".L2c11:", "8:       jr ra"]
    )
    raw_asm = "\n".join(
        [
            "glabel func_8086F310",
            "/* 000000 8086F310 */  beq $zero, $at, .L8086F350",
            "/* 000004 8086F314 */  lui $a1, (0x10108 >> 16)",
            ".L8086F350:",
            "/* 000040 8086F350 */  jr $ra",
            ".size func_8086F310, . - func_8086F310",
        ]
    )

    objdiff_result = preprocess_for_embedding("mips", objdiff_asm)
    raw_result = preprocess_for_embedding("mips", raw_asm)

    assert ".Lx" in objdiff_result
    assert ".L2c11" not in objdiff_result
    assert ".Lx" in raw_result
    assert ".L8086F350" not in raw_result


def test_normalizes_mips_relocation_syntax():
    objdiff_asm = "\n".join(
        ["0:       lui a1, %hi(common_data+0x105a4)", "4:       addiu a1, a1, %lo(common_data+0x105a4)"]
    )
    raw_asm = "\n".join(
        [
            "glabel func_80001000",
            "/* 000000 80001000 */  lui $at, (0x10108 >> 16)",
            "/* 000004 80001004 */  addiu $v0, $v0, (0x106DC & 0xFFFF)",
            ".size func_80001000, . - func_80001000",
        ]
    )

    objdiff_result = preprocess_for_embedding("mips", objdiff_asm)
    raw_result = preprocess_for_embedding("mips", raw_asm)

    assert "%hi(x)" in objdiff_result
    assert "%lo(x)" in objdiff_result
    assert "common_data" not in objdiff_result

    assert "%hi(x)" in raw_result
    assert "%lo(x)" in raw_result
    assert "0x10108" not in raw_result
    assert "0x106DC" not in raw_result


def test_normalizes_constant_pool_references_to_unified_format():
    raw_asm = "\n".join(
        [
            "\tthumb_func_start Fn",
            "Fn: @ 0x08001000",
            "\tldr r0, _08001010 @ =gData",
            "\tldr r1, _08001014 @ =gFlags",
            "\tbx lr",
            "_08001010: .4byte gData",
            "_08001014: .4byte gFlags",
            "\tthumb_func_end Fn",
        ]
    )
    raw_result = preprocess_for_embedding("arm", raw_asm)

    objdiff_asm = "\n".join(
        [
            "0:       ldr r0, [pc, #0x8] # REFERENCE_.L10",
            "2:       ldr r1, [pc, #0x8] # REFERENCE_.L14",
            "4:       bx lr",
            "8:       .word gData",
            "c:       .word gFlags",
        ]
    )
    objdiff_result = preprocess_for_embedding("arm", objdiff_asm)

    assert "ldr r0, [pool]" in raw_result
    assert "ldr r1, [pool]" in raw_result
    assert "ldr r0, [pool]" in objdiff_result
    assert "ldr r1, [pool]" in objdiff_result

    assert "_08001010" not in raw_result
    assert "_08001014" not in raw_result

    assert ".word gData" in raw_result
    assert ".word gData" in objdiff_result
