"""Tests for decomp_function_corpus.py, ported from the upstream reference spec."""

from __future__ import annotations

import pytest

from agentdecompile_recovery.decomp_function_corpus import (
    CorpusDump,
    DecompFunctionCorpus,
    DecompFunctionDoc,
    VectorEntry,
)

pytestmark = pytest.mark.unit


def _make_dump(**overrides) -> CorpusDump:
    defaults = dict(
        platform="arm",
        functions=[
            DecompFunctionDoc(
                id="fn1",
                name="func_a",
                c_code="int func_a(void) { return 1; }",
                c_module_path="src/main.c",
                asm_code="mov r0, #1\nbx lr",
                asm_module_path="asm/main.s",
                calls_functions=["fn2"],
            ),
            DecompFunctionDoc(
                id="fn2",
                name="func_b",
                asm_code="mov r0, #2\nbx lr",
                asm_module_path="asm/util.s",
                calls_functions=[],
            ),
            DecompFunctionDoc(
                id="fn3",
                name="func_c",
                c_code="int func_c(void) { return 3; }",
                c_module_path="src/util.c",
                asm_code="mov r0, #3\nbx lr",
                asm_module_path="asm/util.s",
                calls_functions=["fn1"],
            ),
        ],
        vectors=[
            VectorEntry(id="fn1", embedding=[1, 0, 0]),
            VectorEntry(id="fn2", embedding=[0, 1, 0]),
            VectorEntry(id="fn3", embedding=[0.7, 0.7, 0]),
        ],
    )
    defaults.update(overrides)
    return CorpusDump(**defaults)


class TestFromDump:
    def test_parses_a_dump_correctly(self):
        corpus = DecompFunctionCorpus.from_dump(_make_dump())
        assert len(corpus.functions) == 3
        assert len(corpus.vectors) == 3

    def test_exposes_the_platform(self):
        corpus = DecompFunctionCorpus.from_dump(_make_dump(platform="mips"))
        assert corpus.platform == "mips"


class TestGetStats:
    def test_returns_correct_counts(self):
        corpus = DecompFunctionCorpus.from_dump(_make_dump())
        stats = corpus.get_stats()

        assert stats.total_functions == 3
        assert stats.decompiled_functions == 2
        assert stats.asm_only_functions == 1
        assert stats.total_vectors == 3
        assert stats.embedding_dimension == 3


class TestGetFunctionById:
    def test_returns_the_function_for_a_known_id(self):
        corpus = DecompFunctionCorpus.from_dump(_make_dump())
        fn = corpus.get_function_by_id("fn2")
        assert fn is not None
        assert fn.name == "func_b"

    def test_returns_none_for_an_unknown_id(self):
        corpus = DecompFunctionCorpus.from_dump(_make_dump())
        assert corpus.get_function_by_id("nonexistent") is None


class TestGetCalledBy:
    def test_returns_callers_of_a_function(self):
        corpus = DecompFunctionCorpus.from_dump(_make_dump())
        callers = corpus.get_called_by("fn2")
        assert len(callers) == 1
        assert callers[0].id == "fn1"

    def test_returns_multiple_callers(self):
        corpus = DecompFunctionCorpus.from_dump(
            _make_dump(
                functions=[
                    DecompFunctionDoc(id="a", name="a", asm_code="", asm_module_path="", calls_functions=["c"]),
                    DecompFunctionDoc(id="b", name="b", asm_code="", asm_module_path="", calls_functions=["c"]),
                    DecompFunctionDoc(id="c", name="c", asm_code="", asm_module_path="", calls_functions=[]),
                ],
                vectors=[],
            )
        )
        callers = corpus.get_called_by("c")
        ids = sorted(fn.id for fn in callers)
        assert ids == ["a", "b"]

    def test_returns_empty_list_for_a_function_with_no_callers(self):
        corpus = DecompFunctionCorpus.from_dump(_make_dump())
        assert corpus.get_called_by("fn3") == []

    def test_returns_empty_list_for_unknown_id(self):
        corpus = DecompFunctionCorpus.from_dump(_make_dump())
        assert corpus.get_called_by("nonexistent") == []

    def test_caches_the_reverse_index_across_calls(self):
        corpus = DecompFunctionCorpus.from_dump(_make_dump())
        first = corpus.get_called_by("fn2")
        second = corpus.get_called_by("fn2")
        assert first == second


class TestFindSimilar:
    def test_returns_results_sorted_by_descending_similarity(self):
        corpus = DecompFunctionCorpus.from_dump(_make_dump())
        results = corpus.find_similar("fn1")

        assert len(results) > 0
        for i in range(1, len(results)):
            assert results[i - 1].similarity >= results[i].similarity

    def test_excludes_the_query_id_from_results(self):
        corpus = DecompFunctionCorpus.from_dump(_make_dump())
        results = corpus.find_similar("fn1")
        ids = [r.function.id for r in results]
        assert "fn1" not in ids

    def test_fn3_is_most_similar_to_fn1(self):
        corpus = DecompFunctionCorpus.from_dump(_make_dump())
        results = corpus.find_similar("fn1")
        assert results[0].function.id == "fn3"

    def test_respects_the_limit_parameter(self):
        corpus = DecompFunctionCorpus.from_dump(_make_dump())
        results = corpus.find_similar("fn1", limit=1)
        assert len(results) == 1

    def test_returns_empty_list_for_unknown_id(self):
        corpus = DecompFunctionCorpus.from_dump(_make_dump())
        assert corpus.find_similar("nonexistent") == []


class TestNormalizedVectors:
    def test_self_dot_product_is_approximately_one(self):
        corpus = DecompFunctionCorpus.from_dump(_make_dump())
        for vec in corpus.vectors.values():
            dot = sum(v * v for v in vec)
            assert dot == pytest.approx(1.0, abs=1e-10)


class TestEmptyDump:
    def test_handles_empty_functions_and_vectors(self):
        corpus = DecompFunctionCorpus.from_dump(CorpusDump(platform="arm", functions=[], vectors=[]))
        assert corpus.functions == []
        assert corpus.vectors == {}
        stats = corpus.get_stats()
        assert stats.total_functions == 0
        assert stats.decompiled_functions == 0
        assert stats.asm_only_functions == 0
        assert stats.total_vectors == 0
        assert stats.embedding_dimension == 0


class TestMissingVectorEdgeCase:
    def test_find_similar_still_works_when_function_has_no_vector(self):
        corpus = DecompFunctionCorpus.from_dump(_make_dump(vectors=[VectorEntry(id="fn1", embedding=[1, 0, 0])]))

        assert corpus.find_similar("fn2") == []
        assert corpus.find_similar("fn1") == []


def _make_fn_with_asm(id_: str, instr_count: int, c_code: str | None = None) -> DecompFunctionDoc:
    lines = [f"\tmov r{i % 8}, #{i}" for i in range(instr_count)]
    return DecompFunctionDoc(
        id=id_,
        name=id_,
        asm_code="\n".join(lines),
        asm_module_path="asm/test.s",
        calls_functions=[],
        c_code=c_code,
        c_module_path="src/test.c" if c_code else None,
    )


class TestDifficultyTiers:
    def test_splits_functions_into_three_tiers_at_tertile_boundaries(self):
        functions = [
            _make_fn_with_asm("a", 2, "int a() {}"),
            _make_fn_with_asm("b", 3, "int b() {}"),
            _make_fn_with_asm("c", 4, "int c() {}"),
            _make_fn_with_asm("d", 10),
            _make_fn_with_asm("e", 15),
            _make_fn_with_asm("f", 20),
            _make_fn_with_asm("g", 30),
            _make_fn_with_asm("h", 40),
            _make_fn_with_asm("i", 50),
        ]

        corpus = DecompFunctionCorpus.from_dump(CorpusDump(platform="arm", functions=functions, vectors=[]))
        tiers = corpus.get_difficulty_tiers()

        assert len(tiers.tiers) == 9
        assert tiers.thresholds[0] <= tiers.thresholds[1]

        counts = {"easy": 0, "medium": 0, "hard": 0}
        for tier in tiers.tiers.values():
            counts[tier] += 1

        assert counts["easy"] >= 1
        assert counts["medium"] >= 1
        assert counts["hard"] >= 1
        assert sum(counts.values()) == 9

    def test_get_difficulty_scores_returns_scores_for_all_functions(self):
        functions = [_make_fn_with_asm("a", 5, "int a() {}"), _make_fn_with_asm("b", 10), _make_fn_with_asm("c", 20)]

        corpus = DecompFunctionCorpus.from_dump(CorpusDump(platform="arm", functions=functions, vectors=[]))
        scores = corpus.get_difficulty_scores()

        assert len(scores) == 3
        for ds in scores.values():
            assert 0 <= ds.score <= 1
            assert ds.metrics.instruction_count > 0

    def test_exposes_the_trained_model_via_difficulty_model(self):
        functions = [_make_fn_with_asm("a", 5, "int a() {}"), _make_fn_with_asm("b", 10)]

        corpus = DecompFunctionCorpus.from_dump(CorpusDump(platform="arm", functions=functions, vectors=[]))
        model = corpus.difficulty_model

        assert len(model.means) == 3
        assert len(model.stds) == 3
        assert len(model.coefficients) == 3
        assert isinstance(model.intercept, float)
