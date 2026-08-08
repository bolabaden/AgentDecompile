"""Tests for decomp_atlas.py's optional embedding-based semantic_search path."""

from __future__ import annotations

import pytest

from agentdecompile_recovery.decomp_atlas import run_decomp_atlas, semantic_search
from agentdecompile_recovery.decomp_function_corpus import (
    CorpusDump,
    DecompFunctionCorpus,
    DecompFunctionDoc,
    VectorEntry,
)
from agentdecompile_recovery.semantic_embedder import SemanticEmbedder

pytestmark = pytest.mark.unit


def _corpus() -> DecompFunctionCorpus:
    return DecompFunctionCorpus.from_dump(
        CorpusDump(
            platform="arm",
            functions=[
                DecompFunctionDoc(id="fn1", name="close_match", c_code="int a(void){}", c_module_path="a.c", asm_code="", asm_module_path="a.s"),
                DecompFunctionDoc(id="fn2", name="far_match", c_code="int b(void){}", c_module_path="b.c", asm_code="", asm_module_path="b.s"),
            ],
            vectors=[
                VectorEntry(id="fn1", embedding=[1.0, 0.0]),
                VectorEntry(id="fn2", embedding=[0.0, 1.0]),
            ],
        )
    )


def _embedder_returning(vector: list[float]) -> SemanticEmbedder:
    return SemanticEmbedder(backend=lambda texts: [vector for _ in texts])


class TestSemanticSearch:
    def test_ranks_by_cosine_similarity_descending(self):
        corpus = _corpus()
        embedder = _embedder_returning([1.0, 0.0])

        results = semantic_search("query text", corpus, embedder, top_k=5)

        assert results[0]["name"] == "close_match"
        assert results[0]["similarity"] == pytest.approx(1.0)
        assert results[-1]["name"] == "far_match"
        assert results[-1]["similarity"] == pytest.approx(0.0)

    def test_respects_top_k(self):
        corpus = _corpus()
        embedder = _embedder_returning([1.0, 0.0])

        results = semantic_search("query text", corpus, embedder, top_k=1)

        assert len(results) == 1

    def test_returns_empty_list_when_corpus_has_no_vectors(self):
        empty_corpus = DecompFunctionCorpus.from_dump(CorpusDump(platform="arm", functions=[], vectors=[]))
        embedder = _embedder_returning([1.0, 0.0])

        assert semantic_search("q", empty_corpus, embedder, top_k=5) == []

    def test_skips_vectors_with_mismatched_dimension(self):
        corpus = _corpus()
        embedder = _embedder_returning([1.0, 0.0, 0.0])  # 3-dim query vs 2-dim corpus vectors

        assert semantic_search("q", corpus, embedder, top_k=5) == []


class TestRunDecompAtlasSemanticIntegration:
    def test_omits_semantic_results_when_corpus_and_embedder_not_supplied(self, tmp_path):
        receipt = run_decomp_atlas(
            prompt_name=None,
            query="close_match",
            prompts_dir=tmp_path / "prompts",
            index_root=tmp_path / "index",
            top_k=5,
        )
        assert "semanticResults" not in receipt

    def test_adds_semantic_results_when_corpus_and_embedder_supplied(self, tmp_path):
        corpus = _corpus()
        embedder = _embedder_returning([1.0, 0.0])

        receipt = run_decomp_atlas(
            prompt_name=None,
            query="close_match",
            prompts_dir=tmp_path / "prompts",
            index_root=tmp_path / "index",
            top_k=5,
            corpus=corpus,
            embedder=embedder,
        )

        assert "semanticResults" in receipt
        assert receipt["semanticResults"][0]["name"] == "close_match"

    def test_existing_token_overlap_results_unaffected_by_semantic_params(self, tmp_path):
        corpus = _corpus()
        embedder = _embedder_returning([1.0, 0.0])

        without_semantic = run_decomp_atlas(
            prompt_name=None, query="nothing matches", prompts_dir=tmp_path / "prompts", index_root=tmp_path / "index", top_k=5
        )
        with_semantic = run_decomp_atlas(
            prompt_name=None,
            query="nothing matches",
            prompts_dir=tmp_path / "prompts",
            index_root=tmp_path / "index",
            top_k=5,
            corpus=corpus,
            embedder=embedder,
        )

        assert without_semantic["status"] == with_semantic["status"]
        assert without_semantic["results"] == with_semantic["results"]
