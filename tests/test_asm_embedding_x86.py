"""x86 embedding normalization and the dependency-free structural backend.

The point of the normalization is that the same function reaches the same
vector whether it arrived as a `cl /FAs` listing or as objdiff disassembly,
and that two structurally similar functions land near each other despite
calling different callees. Both fixtures are real captures of the *same*
function through the two paths, so the dialect-folding claim is testable.
"""

from __future__ import annotations

import math
from pathlib import Path

import pytest

from agentdecompile_recovery.asm_embedding import (
    preprocess_for_embedding,
    structural_embedding_backend,
)

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "x86"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def cosine(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


class TestNormalization:
    def test_branch_and_call_targets_become_placeholders(self):
        # These are intra-object offsets in this corpus, not callee identities.
        out = preprocess_for_embedding("x86", "    je short 0x20\n    call 0x223d30")
        assert out == "je <target>\ncall <target>"

    def test_memory_displacements_are_preserved(self):
        # `[esi+0x10]` is real structure -- erasing it would make every
        # field access look alike.
        assert "[esi+0x10]" in preprocess_for_embedding("x86", "    mov eax, [esi+0x10]")

    def test_masm_and_objdiff_radix_agree(self):
        masm = preprocess_for_embedding("x86", "\tmov\teax, DWORD PTR [esi+16]")
        objdiff = preprocess_for_embedding("x86", "    mov eax, dword ptr [esi+0x10]")
        assert masm == objdiff == "mov eax, dword ptr [esi+0x10]"

    def test_offset_flat_folds_to_offset(self):
        out = preprocess_for_embedding("x86", "\tmov\tDWORD PTR [esi], OFFSET FLAT:_PTR_sub_d6660_007465a4")
        assert "offset _PTR_sub_d6660_x" in out

    def test_address_tails_of_generated_names_are_erased(self):
        # Two functions with identical shape calling different globals must
        # not be pushed apart by the address baked into the symbol name.
        first = preprocess_for_embedding("x86", "    mov eax, [_DAT_007a6990]")
        second = preprocess_for_embedding("x86", "    mov eax, [_DAT_0078e528]")
        assert first == second

    def test_local_labels_collapse(self):
        assert preprocess_for_embedding("x86", "\tje\tSHORT $L562") == "je <target>"

    def test_directives_and_comments_are_gone(self):
        out = preprocess_for_embedding("x86", fixture("sub_d6660-msvc71-listing.asm"))
        assert "TITLE" not in out
        assert "; Line" not in out
        assert out.split("\n")[0] == "push esi"


class TestDialectFolding:
    def test_the_same_function_through_both_paths_is_highly_similar(self):
        backend = structural_embedding_backend("x86")
        masm, objdiff = backend(
            [fixture("sub_d6660-msvc71-listing.asm"), fixture("sub_d6660-objdiff-candidate.s")]
        )
        # Not 1.0: the MASM listing is pre-relocation (it still spells stack
        # slots as `_param_1$[esp]`) and came from a different compiler
        # generation than the objdiff capture. Structure still dominates.
        assert cosine(masm, objdiff) > 0.6

    def test_unrelated_functions_are_far_apart(self):
        backend = structural_embedding_backend("x86")
        teardown, x87 = backend([fixture("sub_d6660-objdiff-target.s"), fixture("x87-objdiff-candidate.s")])
        assert cosine(teardown, x87) < 0.3


class TestStructuralBackend:
    def test_vectors_are_unit_length(self):
        backend = structural_embedding_backend("x86")
        for vector in backend([fixture("sub_d6660-objdiff-target.s"), fixture("x87-objdiff-candidate.s")]):
            assert math.isclose(math.sqrt(sum(v * v for v in vector)), 1.0, rel_tol=1e-9)

    def test_identical_input_gives_identical_output(self):
        backend = structural_embedding_backend("x86")
        first, second = backend([fixture("x87-objdiff-candidate.s")] * 2)
        assert first == second

    def test_deterministic_across_backend_instances(self):
        text = fixture("rep-string-ops-objdiff-candidate.s")
        assert structural_embedding_backend("x86")([text]) == structural_embedding_backend("x86")([text])

    def test_dimension_is_configurable(self):
        assert len(structural_embedding_backend("x86", 64)([fixture("x87-objdiff-candidate.s")])[0]) == 64

    def test_zero_dimensions_is_rejected(self):
        with pytest.raises(ValueError, match="dimensions must be positive"):
            structural_embedding_backend("x86", 0)

    def test_empty_input_yields_a_zero_vector_not_a_crash(self):
        vector = structural_embedding_backend("x86")([""])[0]
        assert vector == [0.0] * 512

    def test_works_for_arm_too(self):
        backend = structural_embedding_backend("arm")
        vectors = backend(["\tthumb_func_start f\nf:\n\tpush {lr}\n\tbx lr\n\tthumb_func_end f"])
        assert math.isclose(math.sqrt(sum(v * v for v in vectors[0])), 1.0, rel_tol=1e-9)
