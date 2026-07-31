"""Tests for the de-Ghidra-ification readability pass (U11).

One test per pattern class from the research catalogue, a test proving
genuinely ambiguous patterns are left alone with an explanatory comment
rather than guessed, and a measured before/after test against a real
function from the swkotor candidate.c corpus.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from agentdecompile_recovery.readability_rewrite import rewrite_source, rewrite_verified_tree

REPO_ROOT = Path(__file__).resolve().parents[1]
# Real captured Ghidra output for sub_108c50_508c50, copied into fixtures/
# (target/ is gitignored generated output, per the tests/test_mismatch_
# attempt_metadata.py fixture-copy convention) so this test is reproducible
# without a local `target/agentdecompile-reconstruct/...` build present.
CORPUS_FILE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "readability"
    / "sub_108c50_508c50-candidate.c"
)


# ---------------------------------------------------------------------------
# undefinedN family
# ---------------------------------------------------------------------------


def test_undefined1_becomes_uint8_t():
    src = "undefined1 auStack_98 [8];\n"
    out, stats = rewrite_source(src)
    assert out == "uint8_t auStack_98 [8];\n"
    assert stats.types_replaced == {"undefined1": 1}


def test_undefined2_becomes_uint16_t():
    src = "undefined2 uVar2;\n"
    out, stats = rewrite_source(src)
    assert out == "uint16_t uVar2;\n"
    assert stats.types_replaced == {"undefined2": 1}


def test_undefined4_becomes_uint32_t():
    src = "undefined4 local_e8;\n"
    out, stats = rewrite_source(src)
    assert out == "uint32_t local_e8;\n"
    assert stats.types_replaced == {"undefined4": 1}


def test_undefined8_becomes_uint64_t():
    src = "undefined8 local_18;\n"
    out, stats = rewrite_source(src)
    assert out == "uint64_t local_18;\n"
    assert stats.types_replaced == {"undefined8": 1}


def test_bare_undefined_becomes_unsigned_char():
    src = "undefined4 *unaff_FS_OFFSET;\nundefined uVarX;\n"
    out, _stats = rewrite_source(src)
    assert "unsigned char uVarX;" in out
    # The undefined4 on the same snippet must independently become uint32_t,
    # proving bare `undefined` isn't accidentally matched as a prefix of
    # `undefined4` (tokenizer treats them as distinct identifier tokens).
    assert "uint32_t *unaff_FS_OFFSET;" in out


# ---------------------------------------------------------------------------
# Ghidra scalar typedefs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ghidra_type", "expected"),
    [
        ("uint", "uint32_t"),
        ("ushort", "uint16_t"),
        ("uchar", "uint8_t"),
        ("ulong", "uint32_t"),
        ("byte", "uint8_t"),
        ("sbyte", "int8_t"),
    ],
)
def test_ghidra_scalar_typedefs_become_stdint(ghidra_type, expected):
    src = f"{ghidra_type} uVar6;\n"
    out, stats = rewrite_source(src)
    assert out == f"{expected} uVar6;\n"
    assert stats.types_replaced == {ghidra_type: 1}


def test_type_tokens_inside_comments_and_strings_are_untouched():
    src = 'uint uVar1; // uint stays here\nchar *s = "uint";\n'
    out, stats = rewrite_source(src)
    assert out == 'uint32_t uVar1; // uint stays here\nchar *s = "uint";\n'
    assert stats.types_replaced == {"uint": 1}


# ---------------------------------------------------------------------------
# in_XXX / unaff_XXX / extraout_XXX register-artifact family
# ---------------------------------------------------------------------------


def test_in_ecx_this_pointer_left_unrenamed_with_comment():
    src = (
        "void sub_ccf60(undefined4 param_1)\n\n{\n"
        "  int in_ECX;\n\n"
        "  *(uint *)(in_ECX + 0x1fc) = *(uint *)(in_ECX + 0x1fc) | 1;\n"
        "  *(undefined4 *)(in_ECX + 0xd4) = param_1;\n"
        "  return;\n}\n"
    )
    out, stats = rewrite_source(src)
    # Identifier text itself is never renamed -- no `this` declaration or
    # assignment was invented (the word may still appear inside the
    # explanatory comment's prose, which is fine).
    assert "in_ECX" in out
    assert "int in_ECX;  // U11:" in out
    # Declaration line got exactly one explanatory comment appended.
    lines = out.split("\n")
    decl_line = next(line_ for line_ in lines if "int in_ECX;" in line_)
    assert "U11: in_ECX --" in decl_line
    assert "in_ECX" in stats.artifacts_annotated
    # Second, later occurrence is not re-annotated.
    usage_lines = [line_ for line_ in lines if "in_ECX + 0x1fc" in line_]
    assert all("U11:" not in line_ for line_ in usage_lines)
    assert stats.comments_added == 1


def test_unaff_fs_offset_left_unrenamed_with_comment():
    src = "undefined4 *unaff_FS_OFFSET;\n*unaff_FS_OFFSET = in_stack_0000005c;\n"
    out, stats = rewrite_source(src)
    assert "unaff_FS_OFFSET" in out
    decl_line, _rest = out.split("\n", 1)
    assert "U11: unaff_FS_OFFSET --" in decl_line
    assert "in_stack_0000005c" in stats.artifacts_annotated


def test_extraout_eax_suffixed_variants_each_get_own_comment():
    src = (
        "uint extraout_EAX;\n"
        "uint extraout_EAX_00;\n"
        "return extraout_EAX & 0xffffff00;\n"
        "return extraout_EAX_00 & 0xffffff00;\n"
    )
    out, stats = rewrite_source(src)
    assert set(stats.artifacts_annotated) >= {"extraout_EAX", "extraout_EAX_00"}
    lines = out.split("\n")
    assert "U11: extraout_EAX --" in lines[0]
    assert "U11: extraout_EAX_00 --" in lines[1]
    assert stats.comments_added == 2


# ---------------------------------------------------------------------------
# CONCAT / SUB pseudo-ops
# ---------------------------------------------------------------------------


def test_concat44_left_unrewritten_with_comment():
    src = "_pcStack_110 = (double)CONCAT44(local_e4,local_f8);\n"
    out, stats = rewrite_source(src)
    assert "CONCAT44(local_e4,local_f8)" in out
    assert "U11: CONCAT44(...) --" in out
    assert "CONCAT44" in stats.artifacts_annotated


def test_sub41_left_unrewritten_with_comment():
    src = "uVar5 = SUB41(unaff_EBX,0);\n"
    out, stats = rewrite_source(src)
    assert "SUB41(unaff_EBX,0)" in out
    assert "U11: SUB41(...) --" in out
    assert "SUB41" in stats.artifacts_annotated
    # unaff_EBX also gets its own, separate annotation.
    assert "unaff_EBX" in stats.artifacts_annotated


# ---------------------------------------------------------------------------
# Ghidra bitfield pseudo-access syntax
# ---------------------------------------------------------------------------


def test_bitfield_subaccess_left_unrewritten_with_comment():
    src = "local_c._0_1_ = 1;\nparam_1._1_3_ = 0;\n"
    out, stats = rewrite_source(src)
    assert "local_c._0_1_ = 1;" in out.split("\n")[0]
    assert "U11:" in out.split("\n")[0]
    assert "<bitfield-access>" in stats.artifacts_annotated
    # Second occurrence is not re-annotated.
    assert "U11:" not in out.split("\n")[1]
    assert stats.comments_added == 1


# ---------------------------------------------------------------------------
# float10 (no portable stdint equivalent)
# ---------------------------------------------------------------------------


def test_float10_left_unrewritten_with_comment():
    src = "float10 extraout_ST0;\n"
    out, stats = rewrite_source(src)
    assert out.startswith("float10 extraout_ST0;")
    assert "U11: float10 has no portable" in out or "float10" in stats.artifacts_annotated
    assert "float10" in stats.artifacts_annotated


# ---------------------------------------------------------------------------
# Ambiguous patterns are never guessed -- explicit, general assertion.
# ---------------------------------------------------------------------------


def test_ambiguous_patterns_are_never_renamed_only_annotated():
    src = (
        "int in_ECX;\n"
        "undefined4 *unaff_FS_OFFSET;\n"
        "float10 extraout_ST0;\n"
        "x = CONCAT44(a,b);\n"
    )
    out, stats = rewrite_source(src)
    for token in ("in_ECX", "unaff_FS_OFFSET", "float10", "CONCAT44"):
        assert token in out, f"{token} identifier/type spelling must survive unchanged"
    # Every ambiguous token recorded got a real explanation, not a blank
    # placeholder or a guessed rename target.
    for token, comment in stats.artifacts_annotated.items():
        assert comment.startswith("U11:")
        assert len(comment) > len("U11: ") + 10


# ---------------------------------------------------------------------------
# Real-corpus measured before/after test.
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not CORPUS_FILE.exists(), reason="swkotor candidate.c corpus not present")
def test_real_corpus_function_measured_drop():
    original = CORPUS_FILE.read_text(encoding="utf-8")
    rewritten, stats = rewrite_source(original)

    undefined_re = re.compile(r"\bundefined\d*\b")
    in_upper_re = re.compile(r"\bin_[A-Z][A-Za-z0-9_]*\b")
    trailing_comment_re = re.compile(r"//.*$", re.MULTILINE)

    def strip_trailing_comments(text: str) -> str:
        # The rewrite appends `// U11: <identifier> -- ...` explanations
        # that legitimately re-mention the annotated identifier by name;
        # strip those before counting *code* occurrences so the measured
        # counts reflect real code, not documentation of that code.
        return trailing_comment_re.sub("", text)

    before_undefined = len(undefined_re.findall(strip_trailing_comments(original)))
    after_undefined = len(undefined_re.findall(strip_trailing_comments(rewritten)))
    before_in = len(in_upper_re.findall(strip_trailing_comments(original)))
    after_in = len(in_upper_re.findall(strip_trailing_comments(rewritten)))

    # Sanity: this fixture actually exercises both families.
    assert before_undefined > 0
    assert before_in > 0

    # All undefinedN/undefined type keywords are fully eliminated -- these
    # are the safe, unconditional replacements.
    assert after_undefined == 0
    assert before_undefined > after_undefined

    # in_XXX identifiers are intentionally never renamed (context-dependent,
    # see module docstring), so raw occurrence count is unchanged...
    assert after_in == before_in
    # ...but every distinct in_XXX identifier present is now annotated
    # exactly once, which is the measured "readability improved without
    # guessing" signal for this family.
    in_identifiers = {m.group(0) for m in in_upper_re.finditer(original)}
    for ident in in_identifiers:
        assert ident in stats.artifacts_annotated, f"{ident} should be annotated"

    assert stats.comments_added >= len(in_identifiers)
    assert "undefined4" in stats.types_replaced
    assert "undefined1" in stats.types_replaced


# -- typedef preamble regression (found in review, reproduced against a real
# verified/*.c fixture) --------------------------------------------------
#
# Every real recovered file carries a Ghidra type-header preamble
# (`typedef unsigned char undefined;`, `typedef unsigned int uint;`, ...)
# before any function body. A blanket token substitution that doesn't
# distinguish "the name being defined" from "a use of the type" rewrites the
# preamble's own declarations into themselves: `typedef unsigned char
# undefined;` becomes `typedef unsigned char unsigned char;`, a hard C
# compile failure. This was missed by every other test in this file because
# none of their fixtures included the preamble.

_GHIDRA_TYPEDEF_PREAMBLE = """\
typedef unsigned char byte;
typedef unsigned char undefined;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined4;
typedef unsigned long long undefined8;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef unsigned short ushort;
typedef unsigned char bool;
typedef int code();

"""


def test_typedef_preamble_declarations_are_never_rewritten() -> None:
    rewritten, _stats = rewrite_source(_GHIDRA_TYPEDEF_PREAMBLE)

    assert rewritten == _GHIDRA_TYPEDEF_PREAMBLE
    assert "unsigned char unsigned char" not in rewritten
    assert "uint32_t uint32_t" not in rewritten


def test_typedef_target_name_is_preserved_while_usages_are_still_rewritten() -> None:
    """The exclusion must be narrow: only the declaration's own target name is
    spared -- every real *use* of that type elsewhere still gets rewritten,
    otherwise the fix would silently disable the whole feature."""

    source = (
        "typedef unsigned int undefined4;\n"
        "undefined4 sub_1000(undefined4 param_1)\n"
        "{\n"
        "  undefined4 local_4;\n"
        "  local_4 = param_1;\n"
        "  return local_4;\n"
        "}\n"
    )

    rewritten, stats = rewrite_source(source)

    assert "typedef unsigned int undefined4;" in rewritten
    assert "uint32_t sub_1000(uint32_t param_1)" in rewritten
    assert "uint32_t local_4;" in rewritten
    assert stats.types_replaced["undefined4"] == 3


def test_real_verified_fixture_typedef_preamble_survives_rewrite() -> None:
    """End-to-end reproduction of the exact bug found in review, against the
    exact real file that exposed it."""

    fixture = (
        Path(__file__).resolve().parents[1]
        / "target/agentdecompile-reconstruct/swkotor-parity/verified/sub_15a0_4015a0.c"
    )
    if not fixture.is_file():
        pytest.skip("real verified/*.c fixture unavailable")

    source = fixture.read_text()
    rewritten, _stats = rewrite_source(source)

    assert "typedef unsigned char unsigned char;" not in rewritten
    for line in rewritten.splitlines():
        if line.strip().startswith("typedef "):
            # A valid typedef line never has its base type and its own new
            # name spelled identically.
            words = line.strip().rstrip(";").split()
            if len(words) >= 3:
                assert words[-1] != words[-2], f"self-referential typedef: {line!r}"


# ---------------------------------------------------------------------------
# rewrite_verified_tree (U13): distinct readable/ tier, sibling to verified/
# ---------------------------------------------------------------------------


def test_rewrite_verified_tree_skips_cleanly_when_verified_dir_missing(tmp_path: Path) -> None:
    receipt = rewrite_verified_tree(tmp_path / "verified", tmp_path / "readable")

    assert receipt["status"] == "skipped"
    assert receipt["reason"] == "no-verified-dir"
    assert not (tmp_path / "readable").exists()


def test_rewrite_verified_tree_skips_cleanly_when_verified_dir_empty(tmp_path: Path) -> None:
    verified = tmp_path / "verified"
    verified.mkdir()

    receipt = rewrite_verified_tree(verified, tmp_path / "readable")

    assert receipt["status"] == "skipped"
    assert receipt["reason"] == "verified-dir-empty"
    assert not (tmp_path / "readable").exists()


def test_rewrite_verified_tree_never_writes_into_verified_dir(tmp_path: Path) -> None:
    """verified/ is the byte-exact proof tier; readable/ must be a separate sibling."""

    verified = tmp_path / "verified"
    verified.mkdir()
    (verified / "sub_1000.c").write_text("undefined4 sub_1000(void) { return 0; }\n", encoding="utf-8")
    before = (verified / "sub_1000.c").read_text(encoding="utf-8")

    readable = tmp_path / "readable"
    receipt = rewrite_verified_tree(verified, readable)

    assert receipt["status"] == "complete"
    assert receipt["fileCount"] == 1
    # verified/ itself is untouched.
    assert (verified / "sub_1000.c").read_text(encoding="utf-8") == before
    # readable/ mirrors the relative path and carries the rewritten content.
    rewritten = (readable / "sub_1000.c").read_text(encoding="utf-8")
    assert "uint32_t sub_1000(void)" in rewritten
    assert rewritten != before


def test_rewrite_verified_tree_mirrors_nested_directories(tmp_path: Path) -> None:
    verified = tmp_path / "verified"
    (verified / "code-slice").mkdir(parents=True)
    (verified / "sub_1000.c").write_text("undefined4 sub_1000(void) { return 0; }\n", encoding="utf-8")
    (verified / "code-slice" / "sub_2000.c").write_text("undefined1 x;\n", encoding="utf-8")

    receipt = rewrite_verified_tree(verified, tmp_path / "readable")

    assert receipt["status"] == "complete"
    assert receipt["fileCount"] == 2
    assert (tmp_path / "readable" / "sub_1000.c").is_file()
    assert (tmp_path / "readable" / "code-slice" / "sub_2000.c").is_file()
