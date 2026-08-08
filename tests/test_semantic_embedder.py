"""Tests for semantic_embedder.py's in-process embedding batching."""

from __future__ import annotations

import pytest

from agentdecompile_recovery import semantic_embedder as semantic_embedder_module
from agentdecompile_recovery.semantic_embedder import SemanticEmbedder, default_embedding_backend

pytestmark = pytest.mark.unit


def _fake_backend(texts: list[str]) -> list[list[float]]:
    return [[float(len(text)), 0.0] for text in texts]


def test_embed_batch_delegates_to_backend():
    embedder = SemanticEmbedder(backend=_fake_backend)
    result = embedder.embed_batch(["ab", "abc"])
    assert result == [[2.0, 0.0], [3.0, 0.0]]


def test_embed_batch_empty_input_returns_empty_list():
    calls: list[list[str]] = []

    def backend(texts: list[str]) -> list[list[float]]:
        calls.append(texts)
        return []

    embedder = SemanticEmbedder(backend=backend)
    assert embedder.embed_batch([]) == []
    assert calls == []


def test_embed_all_batches_in_fixed_size_chunks():
    seen_batches: list[list[str]] = []

    def backend(texts: list[str]) -> list[list[float]]:
        seen_batches.append(list(texts))
        return [[1.0] for _ in texts]

    embedder = SemanticEmbedder(backend=backend)
    texts = [f"t{i}" for i in range(10)]

    result = embedder.embed_all(texts, batch_size=4)

    assert len(result) == 10
    assert [len(batch) for batch in seen_batches] == [4, 4, 2]


def test_default_embedding_backend_raises_when_chromadb_unavailable():
    if semantic_embedder_module.embedding_functions is not None:
        pytest.skip("chromadb is installed in this environment; default backend does not raise")
    with pytest.raises(ImportError, match="chromadb"):
        default_embedding_backend()
