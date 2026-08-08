"""Unit tests for rewrite context-pack assembly and prompt rendering.

These cover the two defects that made the rewrite lane ineffective: prompts
that omitted the target instructions entirely, and an output space that left
inline assembly as the cheapest way to satisfy objdiff.
"""

from __future__ import annotations

import pytest

from agentdecompile_recovery.rewrite_context import (
    BANNED_CONSTRUCT_REASON,
    build_context_pack,
    check_rewrite_content,
    extract_code_block,
    render_rewrite_prompt,
)

pytestmark = pytest.mark.unit


ALIGNED = [
    {"index": 0, "target": "push ebp", "candidate": "push ebp", "differs": False, "diffKind": None},
    {"index": 1, "target": "add eax, eax", "candidate": "shl eax, 1", "differs": True, "diffKind": "DIFF_REPLACE"},
]


def _pack(**overrides):
    base = dict(
        function_name="FUN_004a23b0",
        entry="0x4a23b0",
        candidate_source="void FUN_004a23b0(void) { gCounter += 1; }",
        aligned_diff=ALIGNED,
        mismatch_class="opcode-replacement",
        mismatch_histogram={"REPLACEMENT": 2},
    )
    base.update(overrides)
    return build_context_pack(**base)


def test_pack_carries_the_aligned_diff() -> None:
    pack = _pack()

    assert pack["alignedDiff"] == ALIGNED
    assert pack["functionName"] == "FUN_004a23b0"


def test_prompt_shows_target_instructions() -> None:
    """The whole point: the model must see what it is matching against."""

    text = render_rewrite_prompt(_pack())

    assert "add eax, eax" in text
    assert "shl eax, 1" in text


def test_prompt_includes_candidate_source() -> None:
    text = render_rewrite_prompt(_pack())

    assert "gCounter += 1" in text


def test_prompt_forbids_inline_assembly_with_a_reason() -> None:
    """Without this the loop converges on __asm, which passes objdiff and
    defeats the readable-C deliverable."""

    text = render_rewrite_prompt(_pack())

    assert "__asm" in text
    assert "readable" in text.lower()


def test_prompt_includes_compiler_profile_when_known() -> None:
    text = render_rewrite_prompt(_pack(compiler_profile="msvc 12.0 /O2 /Gd"))

    assert "/O2" in text


def test_prompt_lists_prior_attempts_so_they_are_not_repeated() -> None:
    text = render_rewrite_prompt(
        _pack(prior_attempts=[{"source": "void f(void){ gCounter++; }", "differences": 4}])
    )

    assert "gCounter++" in text
    assert "4" in text


def test_prompt_includes_exemplars_when_available() -> None:
    text = render_rewrite_prompt(
        _pack(
            exemplars=[
                {
                    "mismatchClass": "opcode-replacement",
                    "sourceBefore": "x = y * 2;",
                    "sourceAfter": "x = y + y;",
                }
            ]
        )
    )

    assert "y + y" in text


def test_prompt_includes_codebase_exemplars_when_available() -> None:
    text = render_rewrite_prompt(
        _pack(
            codebase_exemplars=[
                {
                    "name": "sub_7bde0",
                    "cCode": "void sub_7bde0(char *dst) { *dst = 0; }",
                    "matchPercent": 100.0,
                    "callsTarget": False,
                }
            ]
        )
    )

    assert "Worked examples from similar functions" in text
    assert "sub_7bde0" in text
    assert "*dst = 0" in text
    assert "100.0% match" in text


def test_pack_carries_codebase_exemplars() -> None:
    samples = [{"name": "neighbour", "cCode": "int neighbour(void){ return 1; }"}]
    pack = _pack(codebase_exemplars=samples)

    assert pack["codebaseExemplars"] == samples


def test_prompt_omits_empty_sections() -> None:
    text = render_rewrite_prompt(_pack())

    assert "Previous attempts" not in text
    assert "Verified transformations" not in text
    assert "Worked examples from similar functions" not in text


def test_prompt_requests_a_single_fenced_block() -> None:
    text = render_rewrite_prompt(_pack())

    assert "```" in text


@pytest.mark.parametrize(
    "banned",
    [
        "void f(void){ __asm { nop } }",
        "void f(void){ _asm nop; }",
        "__declspec(naked) void f(void){}",
        "#include <stdio.h>\nvoid f(void){}",
        "#pragma optimize(\"\", off)\nvoid f(void){}",
        'void f(void){ __emit(0x90); }',
    ],
)
def test_content_check_rejects_banned_constructs(banned: str) -> None:
    reason = check_rewrite_content(banned)

    assert reason is not None
    assert reason == BANNED_CONSTRUCT_REASON or "banned" in reason.lower() or reason


def test_content_check_accepts_plain_c() -> None:
    assert check_rewrite_content("void f(void){ gCounter += 1; }") is None


def test_content_check_rejects_empty() -> None:
    assert check_rewrite_content("   ") is not None


def test_content_check_does_not_flag_identifiers_containing_asm() -> None:
    """`asm` as a substring of a normal identifier is not inline assembly."""

    assert check_rewrite_content("void f(void){ int plasmaCount = 1; (void)plasmaCount; }") is None


def test_extract_code_block_takes_fenced_content() -> None:
    response = "Here you go:\n```c\nvoid f(void){ return; }\n```\nDone."

    assert extract_code_block(response) == "void f(void){ return; }"


def test_extract_code_block_handles_bare_fence() -> None:
    assert extract_code_block("```\nint x;\n```") == "int x;"


def test_extract_code_block_returns_none_without_fence() -> None:
    assert extract_code_block("I cannot help with that.") is None
