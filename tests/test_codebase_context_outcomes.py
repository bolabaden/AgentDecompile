"""Outcome-aware exemplar selection in get_func_context.

The retrieval layer's job is not just "find similar functions" but "find
similar functions whose decompilation is known to have worked". These pin the
ranking and filtering that difference implies.
"""

from __future__ import annotations

import pytest

from agentdecompile_recovery.codebase_context import get_func_context
from agentdecompile_recovery.decomp_function_corpus import (
    CorpusDump,
    DecompFunctionCorpus,
    DecompFunctionDoc,
    VectorEntry,
)

pytestmark = pytest.mark.unit


def _doc(id_: str, *, match_percent: float | None, calls: list[str] | None = None) -> DecompFunctionDoc:
    return DecompFunctionDoc(
        id=id_,
        name=id_,
        c_code=f"void {id_}(void) {{ }}",
        c_module_path=f"src/{id_}.c",
        asm_code="ret",
        asm_module_path=f"asm/{id_}.s",
        calls_functions=calls or [],
        match_percent=match_percent,
    )


def _corpus() -> DecompFunctionCorpus:
    # Similarity to `target` decreases down the list; match outcome increases.
    # Any ranking that respected similarity alone would return them in the
    # opposite order to one that respects outcome, so the two are separable.
    return DecompFunctionCorpus.from_dump(
        CorpusDump(
            platform="x86",
            functions=[
                DecompFunctionDoc(id="target", name="target", asm_code="ret", asm_module_path="asm/t.s"),
                _doc("near_unverified", match_percent=None),
                _doc("near_zero", match_percent=0.0),
                _doc("mid_partial", match_percent=60.0),
                _doc("far_verified", match_percent=100.0),
            ],
            vectors=[
                VectorEntry(id="target", embedding=[1.0, 0.0]),
                VectorEntry(id="near_unverified", embedding=[0.99, 0.14]),
                VectorEntry(id="near_zero", embedding=[0.97, 0.24]),
                VectorEntry(id="mid_partial", embedding=[0.87, 0.5]),
                VectorEntry(id="far_verified", embedding=[0.6, 0.8]),
            ],
        )
    )


class TestRanking:
    def test_match_outcome_outranks_raw_similarity(self):
        context = get_func_context(_corpus(), "target")
        assert [sample.name for sample in context.sampling] == [
            "far_verified",
            "mid_partial",
            "near_zero",
            "near_unverified",
        ]

    def test_unverified_ranks_below_a_verified_zero(self):
        # "never compiled" and "compiled and matched nothing" are different
        # facts; the second is still evidence, the first is not.
        context = get_func_context(_corpus(), "target")
        names = [sample.name for sample in context.sampling]
        assert names.index("near_zero") < names.index("near_unverified")

    def test_match_percent_is_carried_onto_the_sample(self):
        context = get_func_context(_corpus(), "target")
        by_name = {sample.name: sample.match_percent for sample in context.sampling}
        assert by_name["far_verified"] == 100.0
        assert by_name["near_unverified"] is None


class TestFiltering:
    def test_min_match_percent_drops_weak_examples(self):
        context = get_func_context(_corpus(), "target", min_match_percent=50.0)
        assert [sample.name for sample in context.sampling] == ["far_verified", "mid_partial"]

    def test_min_match_percent_drops_unverified_examples(self):
        context = get_func_context(_corpus(), "target", min_match_percent=0.0)
        assert "near_unverified" not in [sample.name for sample in context.sampling]

    def test_no_floor_keeps_everything(self):
        assert len(get_func_context(_corpus(), "target").sampling) == 4

    def test_exemplar_limit_caps_after_ranking(self):
        context = get_func_context(_corpus(), "target", exemplar_limit=2)
        assert [sample.name for sample in context.sampling] == ["far_verified", "mid_partial"]

    def test_exemplar_limit_zero_returns_nothing(self):
        assert get_func_context(_corpus(), "target", exemplar_limit=0).sampling == []


class TestCallers:
    def test_caller_is_appended_and_marked(self):
        dump = CorpusDump(
            platform="x86",
            functions=[
                DecompFunctionDoc(id="target", name="target", asm_code="ret", asm_module_path="asm/t.s"),
                _doc("caller", match_percent=90.0, calls=["target"]),
            ],
            vectors=[VectorEntry(id="target", embedding=[1.0, 0.0])],
        )
        context = get_func_context(DecompFunctionCorpus.from_dump(dump), "target")
        assert [(s.name, s.calls_target) for s in context.sampling] == [("caller", True)]

    def test_caller_below_the_floor_is_dropped(self):
        dump = CorpusDump(
            platform="x86",
            functions=[
                DecompFunctionDoc(id="target", name="target", asm_code="ret", asm_module_path="asm/t.s"),
                _doc("caller", match_percent=10.0, calls=["target"]),
            ],
            vectors=[VectorEntry(id="target", embedding=[1.0, 0.0])],
        )
        context = get_func_context(DecompFunctionCorpus.from_dump(dump), "target", min_match_percent=80.0)
        assert context.sampling == []


class TestBackCompat:
    def test_corpus_without_outcomes_still_ranks_by_similarity(self):
        dump = CorpusDump(
            platform="arm",
            functions=[
                DecompFunctionDoc(id="target", name="target", asm_code="bx lr", asm_module_path="asm/t.s"),
                _doc("closer", match_percent=None),
                _doc("farther", match_percent=None),
            ],
            vectors=[
                VectorEntry(id="target", embedding=[1.0, 0.0]),
                VectorEntry(id="closer", embedding=[0.99, 0.14]),
                VectorEntry(id="farther", embedding=[0.6, 0.8]),
            ],
        )
        context = get_func_context(DecompFunctionCorpus.from_dump(dump), "target")
        assert [sample.name for sample in context.sampling] == ["closer", "farther"]
