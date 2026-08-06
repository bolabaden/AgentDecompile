"""Tests for asm_utils.py, ported from the upstream indexer's asm-utils spec.

The upstream module keys platform via specific console targets (e.g. 'gba',
'n64'); this port takes the ISA family directly ('arm' / 'mips') since that's
all the parsing logic actually branches on.
"""

from __future__ import annotations

import pytest

from agentdecompile_recovery.asm_utils import (
    count_body_lines_from_asm_function,
    extract_asm_function_body,
    extract_function_calls_from_assembly,
    list_functions_from_asm_module,
    strip_commentaries,
)

pytestmark = pytest.mark.unit


class TestExtractFunctionCallsFromAssembly:
    def test_extracts_bl_calls(self):
        asm = "push {lr}\nbl sub_08001234\npop {r0}\nbx r0"
        calls = extract_function_calls_from_assembly("arm", asm)
        assert "sub_08001234" in calls

    def test_extracts_at_comment_references(self):
        asm = "ldr r0, [pc]\n@ =gSomeGlobal"
        calls = extract_function_calls_from_assembly("arm", asm)
        assert "gSomeGlobal" in calls

    def test_extracts_direct_references_in_ldr_add_mov(self):
        asm = "ldr r0, =MyFunc"
        calls = extract_function_calls_from_assembly("arm", asm)
        assert "MyFunc" in calls

    def test_deduplicates_calls(self):
        asm = "bl foo\nbl foo\nbl foo"
        calls = extract_function_calls_from_assembly("arm", asm)
        assert len([c for c in calls if c == "foo"]) == 1

    def test_extracts_jal_calls(self):
        asm = "jal func_80001000\nnop"
        calls = extract_function_calls_from_assembly("mips", asm)
        assert "func_80001000" in calls

    def test_extracts_semicolon_comment_references(self):
        asm = "lui $at, %hi(SomeFunc) ; =SomeFunc"
        calls = extract_function_calls_from_assembly("mips", asm)
        assert "SomeFunc" in calls

    def test_skips_glabel_endlabel_lines(self):
        asm = "glabel func_80001000\njal helper\nnop"
        calls = extract_function_calls_from_assembly("mips", asm)
        assert "helper" in calls
        assert "func_80001000" not in calls

    def test_raises_for_unsupported_platform(self):
        with pytest.raises(ValueError, match="Unsupported platform"):
            extract_function_calls_from_assembly("saturn", "nop")


class TestListFunctionsFromAsmModule:
    def test_lists_functions_with_thumb_markers(self):
        asm = "\n".join(
            [
                "\tthumb_func_start FuncA",
                "FuncA: @ 0x08001000",
                "\tpush {lr}",
                "\tbx lr",
                "\tthumb_func_end FuncA",
                "",
                "\tthumb_func_start FuncB",
                "FuncB: @ 0x08001010",
                "\tmov r0, #1",
                "\tbx lr",
                "\tthumb_func_end FuncB",
            ]
        )

        funcs = list_functions_from_asm_module("arm", asm)
        assert len(funcs) == 2
        assert funcs[0]["name"] == "FuncA"
        assert funcs[1]["name"] == "FuncB"
        assert "push {lr}" in funcs[0]["code"]

    def test_handles_functions_without_explicit_end_markers(self):
        asm = "\n".join(
            [
                "\tthumb_func_start FuncA",
                "FuncA:",
                "\tpush {lr}",
                "\tbx lr",
                "\tthumb_func_start FuncB",
                "FuncB:",
                "\tmov r0, #1",
                "\tbx lr",
            ]
        )

        funcs = list_functions_from_asm_module("arm", asm)
        assert len(funcs) == 2
        assert funcs[0]["name"] == "FuncA"
        assert funcs[1]["name"] == "FuncB"

    def test_returns_empty_list_for_empty_input(self):
        assert list_functions_from_asm_module("arm", "") == []

    def test_lists_mips_functions_with_glabel_markers(self):
        asm = "\n".join(
            [
                "glabel func_80001000",
                "/* 000000 80001000 27BDFFD0 */  addiu $sp, $sp, -0x30",
                "/* 000004 80001004 03E00008 */  jr    $ra",
                ".size func_80001000, . - func_80001000",
                "",
                "glabel func_80002000",
                "/* 000000 80002000 27BDFFD0 */  addiu $sp, $sp, -0x20",
                "/* 000004 80002004 03E00008 */  jr    $ra",
                ".size func_80002000, . - func_80002000",
            ]
        )

        funcs = list_functions_from_asm_module("mips", asm)
        assert len(funcs) == 2
        assert funcs[0]["name"] == "func_80001000"
        assert funcs[1]["name"] == "func_80002000"


class TestExtractAsmFunctionBody:
    def test_strips_thumb_markers_and_function_label(self):
        asm = "\n".join(
            [
                "\tthumb_func_start MyFunc",
                "MyFunc: @ 0x08001000",
                "\tpush {r4, lr}",
                "\tmov r0, #1",
                "\tpop {r4}",
                "\tbx lr",
                "\tthumb_func_end MyFunc",
            ]
        )

        body = extract_asm_function_body("arm", asm)
        assert "thumb_func_start" not in body
        assert "thumb_func_end" not in body
        assert "MyFunc:" not in body
        assert "push {r4, lr}" in body
        assert "mov r0, #1" in body

    def test_strips_align_directives(self):
        asm = "\n".join(
            [
                "\tthumb_func_start MyFunc",
                "MyFunc:",
                "\t.align 2, 0",
                "\tpush {lr}",
                "\tbx lr",
                "\tthumb_func_end MyFunc",
            ]
        )

        body = extract_asm_function_body("arm", asm)
        assert ".align" not in body
        assert "push {lr}" in body

    def test_returns_empty_string_for_function_with_no_instructions(self):
        asm = "\tthumb_func_start Empty\nEmpty:\n\tthumb_func_end Empty"
        assert extract_asm_function_body("arm", asm) == ""

    def test_strips_mips_glabel_and_size_directives(self):
        asm = "\n".join(
            [
                "glabel func_80001000",
                "/* 000000 80001000 27BDFFD0 */  addiu $sp, $sp, -0x30",
                "/* 000004 80001004 03E00008 */  jr    $ra",
                ".size func_80001000, . - func_80001000",
            ]
        )

        body = extract_asm_function_body("mips", asm)
        assert "glabel" not in body
        assert ".size" not in body
        assert "addiu $sp, $sp, -0x30" in body

    def test_strips_mips_semicolon_comments_and_normalizes_spacing(self):
        asm = "\n".join(
            [
                "glabel func_80001000",
                "/* 000000 80001000 27BDFFD0 */  addiu $sp, $sp, -0x30 ; comment here",
            ]
        )

        body = extract_asm_function_body("mips", asm)
        assert "; comment" not in body


class TestStripCommentaries:
    def test_strips_arm_at_comments(self):
        assert strip_commentaries("mov r0, #1 @ load constant") == "mov r0, #1"

    def test_strips_mips_semicolon_comments(self):
        assert strip_commentaries("addiu $sp, $sp, -0x30 ; stack frame") == "addiu $sp, $sp, -0x30"

    def test_strips_c_style_block_comments(self):
        assert strip_commentaries("/* 000000 80001000 27BDFFD0 */  addiu $sp, $sp, -0x30") == "  addiu $sp, $sp, -0x30"

    def test_strips_double_slash_comments(self):
        assert strip_commentaries("nop // no-op") == "nop"

    def test_preserves_line_structure(self):
        result = strip_commentaries("line1 @ comment\nline2 @ comment\nline3")
        assert len(result.split("\n")) == 3


class TestCountBodyLinesFromAsmFunction:
    def test_counts_non_empty_body_lines_for_arm(self):
        asm = "\n".join(
            [
                "\tthumb_func_start MyFunc",
                "MyFunc:",
                "\tpush {r4, lr}",
                "\tmov r0, #1",
                "\tpop {r4}",
                "\tbx lr",
                "\tthumb_func_end MyFunc",
            ]
        )
        assert count_body_lines_from_asm_function("arm", asm) == 4

    def test_returns_zero_for_empty_function(self):
        asm = "\tthumb_func_start Empty\nEmpty:\n\tthumb_func_end Empty"
        assert count_body_lines_from_asm_function("arm", asm) == 0

    def test_counts_mips_lines(self):
        asm = "\n".join(
            [
                "glabel func_80001000",
                "/* 000000 80001000 27BDFFD0 */  addiu $sp, $sp, -0x30",
                "/* 000004 80001004 03E00008 */  jr    $ra",
                "/* 000008 80001008 27BD0030 */   addiu $sp, $sp, 0x30",
                ".size func_80001000, . - func_80001000",
            ]
        )
        assert count_body_lines_from_asm_function("mips", asm) == 3
