"""Tests for craft_prompt.py, ported from the upstream craft-prompt spec."""

from __future__ import annotations

import pytest

from agentdecompile_recovery.craft_prompt import craft_prompt, strip_trailing_asm_lines
from agentdecompile_recovery.craft_prompt import SamplingCFunction

pytestmark = pytest.mark.unit


class TestStripTrailingAsmLines:
    def test_strips_section_separator_comment_and_blank_lines_after_arm_function(self):
        asm = "\n".join(
            [
                "    thumb_func_start TaskDestructor_CharacterSelect",
                "TaskDestructor_CharacterSelect: @ 0x0809B758",
                "    push {lr}",
                "    ldrh r0, [r0, #6]",
                "    ldr r1, _0809B76C @ =0x030000C4",
                "    adds r0, r0, r1",
                "    ldr r0, [r0]",
                "    bl VramFree",
                "    pop {r0}",
                "    bx r0",
                "    .align 2, 0",
                "_0809B76C: .4byte 0x030000C4",
                "",
                "@ --- End of Character Select ---",
                "",
                "",
            ]
        )

        expected = "\n".join(
            [
                "    thumb_func_start TaskDestructor_CharacterSelect",
                "TaskDestructor_CharacterSelect: @ 0x0809B758",
                "    push {lr}",
                "    ldrh r0, [r0, #6]",
                "    ldr r1, _0809B76C @ =0x030000C4",
                "    adds r0, r0, r1",
                "    ldr r0, [r0]",
                "    bl VramFree",
                "    pop {r0}",
                "    bx r0",
                "    .align 2, 0",
                "_0809B76C: .4byte 0x030000C4",
            ]
        )

        assert strip_trailing_asm_lines(asm) == expected

    def test_preserves_inline_comments_on_instruction_lines(self):
        asm = "\n".join(["func: @ 0x08001000", "    push {lr} @ save return address", "    bx lr"])
        assert strip_trailing_asm_lines(asm) == asm

    def test_does_not_strip_mid_function_comment_lines(self):
        asm = "\n".join(["    push {lr}", "@ mid-function comment", "    bx lr"])
        assert strip_trailing_asm_lines(asm) == asm

    def test_strips_trailing_lines_after_a_mips_function(self):
        asm = "\n".join(
            [
                "glabel my_function",
                "/* 0040A0 */ addiu $sp, $sp, -0x18",
                "/* 0040A8 */ jr    $ra",
                "/* 0040AC */  nop",
                "",
                "# End of my_function",
                "",
            ]
        )

        expected = "\n".join(
            [
                "glabel my_function",
                "/* 0040A0 */ addiu $sp, $sp, -0x18",
                "/* 0040A8 */ jr    $ra",
                "/* 0040AC */  nop",
            ]
        )

        assert strip_trailing_asm_lines(asm) == expected

    def test_strips_trailing_semicolon_comments(self):
        asm = "\n".join(["    push {lr}", "    bx lr", "; end of section", ""])
        assert strip_trailing_asm_lines(asm) == "    push {lr}\n    bx lr"

    def test_returns_asm_unchanged_when_there_is_no_trailing_junk(self):
        asm = "    push {lr}\n    bx lr"
        assert strip_trailing_asm_lines(asm) == asm

    def test_handles_empty_string(self):
        assert strip_trailing_asm_lines("") == ""


class TestCraftPrompt:
    def test_includes_target_function_name_and_platform_info(self):
        prompt = craft_prompt(
            platform="win32",
            module_path="src/main.c",
            asm_name="FUN_00401000",
            asm_code="push ebp\nmov ebp, esp\nret",
            called_functions_declarations={},
            sampling=[],
            type_definitions=[],
        )

        assert "FUN_00401000" in prompt
        assert "Windows (32-bit)" in prompt
        assert "x86" in prompt
        assert "src/main.c" in prompt

    def test_includes_examples_that_do_not_call_the_target(self):
        sampling = [SamplingCFunction(name="helper", c_code="int helper() { return 1; }", asm_code="mov r0, #1", calls_target=False)]
        prompt = craft_prompt(
            platform="gba",
            module_path="src/a.c",
            asm_name="target",
            asm_code="bx lr",
            called_functions_declarations={},
            sampling=sampling,
            type_definitions=[],
        )

        assert "# Examples" in prompt
        assert "helper" in prompt

    def test_separates_callers_of_the_target_from_examples(self):
        sampling = [SamplingCFunction(name="caller", c_code="void caller() { target(); }", asm_code="bl target", calls_target=True)]
        prompt = craft_prompt(
            platform="gba",
            module_path="src/a.c",
            asm_name="target",
            asm_code="bx lr",
            called_functions_declarations={},
            sampling=sampling,
            type_definitions=[],
        )

        assert "# Functions that call the target assembly" in prompt
        assert "caller" in prompt
        assert "# Examples" not in prompt

    def test_includes_called_function_declarations(self):
        prompt = craft_prompt(
            platform="gba",
            module_path="src/a.c",
            asm_name="target",
            asm_code="bx lr",
            called_functions_declarations={"sub1": "void sub1(void)"},
            sampling=[],
            type_definitions=[],
        )

        assert "void sub1(void)" in prompt

    def test_includes_type_definitions(self):
        prompt = craft_prompt(
            platform="gba",
            module_path="src/a.c",
            asm_name="target",
            asm_code="bx lr",
            called_functions_declarations={},
            sampling=[],
            type_definitions=["struct Foo { int x; };"],
        )

        assert "struct Foo { int x; };" in prompt

    def test_strips_trailing_junk_from_asm_code_before_embedding(self):
        prompt = craft_prompt(
            platform="gba",
            module_path="src/a.c",
            asm_name="target",
            asm_code="push {lr}\nbx lr\n\n@ --- End ---\n",
            called_functions_declarations={},
            sampling=[],
            type_definitions=[],
        )

        assert "@ --- End ---" not in prompt
        assert "push {lr}" in prompt


class TestExemplarOutcomeLabels:
    """Examples carry the objdiff outcome they achieved.

    An example with no outcome and an example proven byte-exact are worth very
    different amounts as evidence, and the prompt has to say which is which.
    """

    def test_verified_example_is_labelled_verified(self):
        prompt = craft_prompt(
            platform="win32",
            module_path="asm/x.s",
            asm_name="target",
            asm_code="ret",
            called_functions_declarations={},
            sampling=[
                SamplingCFunction(
                    name="worked", c_code="void worked(void){}", asm_code="ret",
                    calls_target=False, match_percent=100.0,
                )
            ],
            type_definitions=[],
        )
        assert "verified: this C compiles to the assembly below, byte for byte" in prompt

    def test_partial_example_states_its_percentage(self):
        prompt = craft_prompt(
            platform="win32",
            module_path="asm/x.s",
            asm_name="target",
            asm_code="ret",
            called_functions_declarations={},
            sampling=[
                SamplingCFunction(
                    name="close", c_code="void close(void){}", asm_code="ret",
                    calls_target=False, match_percent=91.25,
                )
            ],
            type_definitions=[],
        )
        assert "91.2% of instructions match" in prompt

    def test_example_without_an_outcome_gets_no_claim(self):
        prompt = craft_prompt(
            platform="win32",
            module_path="asm/x.s",
            asm_name="target",
            asm_code="ret",
            called_functions_declarations={},
            sampling=[
                SamplingCFunction(name="plain", c_code="void plain(void){}", asm_code="ret", calls_target=False)
            ],
            type_definitions=[],
        )
        assert "## `plain`\n" in prompt
        assert "verified" not in prompt
        assert "% of instructions match" not in prompt


class TestExampleLimit:
    def test_default_keeps_five_examples(self):
        sampling = [
            SamplingCFunction(name=f"f{i}", c_code=f"void f{i}(void){{}}", asm_code="ret", calls_target=False)
            for i in range(8)
        ]
        prompt = craft_prompt(
            platform="win32", module_path="asm/x.s", asm_name="target", asm_code="ret",
            called_functions_declarations={}, sampling=sampling, type_definitions=[],
        )
        assert prompt.count("## `f") == 5

    def test_limit_is_configurable(self):
        sampling = [
            SamplingCFunction(name=f"f{i}", c_code=f"void f{i}(void){{}}", asm_code="ret", calls_target=False)
            for i in range(8)
        ]
        prompt = craft_prompt(
            platform="win32", module_path="asm/x.s", asm_name="target", asm_code="ret",
            called_functions_declarations={}, sampling=sampling, type_definitions=[], example_limit=2,
        )
        assert prompt.count("## `f") == 2

    def test_ranking_order_is_preserved_by_the_slice(self):
        # get_func_context ranks; craft_prompt must take the head, not resort.
        sampling = [
            SamplingCFunction(name="best", c_code="void best(void){}", asm_code="ret",
                              calls_target=False, match_percent=100.0),
            SamplingCFunction(name="worst", c_code="void worst(void){}", asm_code="ret",
                              calls_target=False, match_percent=5.0),
        ]
        prompt = craft_prompt(
            platform="win32", module_path="asm/x.s", asm_name="target", asm_code="ret",
            called_functions_declarations={}, sampling=sampling, type_definitions=[], example_limit=1,
        )
        assert "## `best`" in prompt
        assert "## `worst`" not in prompt


class TestUnknownPlatform:
    def test_unknown_platform_raises_a_clear_error(self):
        # Previously an unguarded dict index, so an out-of-table platform
        # surfaced as a bare KeyError from deep inside the template code.
        with pytest.raises(ValueError, match="Unsupported platform: sega32x"):
            craft_prompt(
                platform="sega32x", module_path="asm/x.s", asm_name="target", asm_code="ret",
                called_functions_declarations={}, sampling=[], type_definitions=[],
            )

    def test_x86_targets_are_in_the_table(self):
        prompt = craft_prompt(
            platform="win32", module_path="asm/x.s", asm_name="target", asm_code="ret",
            called_functions_declarations={}, sampling=[], type_definitions=[],
        )
        assert "x86" in prompt
        assert "Windows (32-bit)" in prompt
