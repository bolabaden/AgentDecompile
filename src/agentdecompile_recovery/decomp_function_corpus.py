"""In-memory corpus of decompiled/undecompiled functions with vector search.

Ports the upstream reference function-corpus module: a dump-loaded, read-mostly index over a decomp
project's functions offering call-graph lookups (getCalledBy), a brute-force
cosine-similarity nearest-neighbor search (findSimilar) over externally
supplied embedding vectors, and difficulty scoring via logistic_regression.py.

This module does not compute embeddings itself -- callers supply precomputed
vectors in the dump (e.g. from a chromadb collection, or any other embedder).
That mirrors the upstream split: the reference corpus class only ever consumed vectors that
Embedder produced elsewhere; it never called the model directly.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from .asm_metrics import count_asm_metrics
from .logistic_regression import (
    DifficultyModel,
    DifficultyTier,
    apply_difficulty_model,
    train_difficulty_model,
)

DECOMP_FUNCTION_CORPUS_VERSION = 1

Platform = str  # "arm" | "mips" | "x86" | "x86_64"


@dataclass
class DecompFunctionDoc:
    id: str
    name: str
    asm_code: str
    asm_module_path: str
    calls_functions: list[str] = field(default_factory=list)
    rom_address: int | None = None
    c_code: str | None = None
    c_module_path: str | None = None
    # objdiff similarity of `c_code` compiled against `asm_code`, 0-100, when a
    # verification produced one. `None` means "never verified", which is not the
    # same as 0.0 ("verified and matched nothing"). Retrieval ranks on this:
    # a decompilation that provably reached (or nearly reached) the target is
    # worth far more as a worked example than one nobody ever compiled.
    match_percent: float | None = None


@dataclass
class VectorEntry:
    id: str
    embedding: list[float]


@dataclass
class CorpusDump:
    platform: Platform
    functions: list[DecompFunctionDoc]
    vectors: list[VectorEntry] = field(default_factory=list)
    version: int = DECOMP_FUNCTION_CORPUS_VERSION


@dataclass
class DifficultyScore:
    score: float
    metrics: Any


@dataclass
class DifficultyTiers:
    tiers: dict[str, DifficultyTier]
    thresholds: tuple[float, float]


@dataclass
class CorpusStats:
    total_functions: int
    decompiled_functions: int
    asm_only_functions: int
    total_vectors: int
    embedding_dimension: int


@dataclass
class SimilarResult:
    function: DecompFunctionDoc
    similarity: float


class DecompFunctionCorpus:
    """Use `DecompFunctionCorpus.from_dump()` instead of the constructor directly."""

    def __init__(
        self,
        functions: list[DecompFunctionDoc],
        vector_ids: list[str],
        normalized_vectors: list[list[float]],
        dimension: int,
        platform: Platform,
    ) -> None:
        self._functions = functions
        self._function_by_id = {fn.id: fn for fn in functions}
        self._vector_ids = vector_ids
        self._normalized_vectors = normalized_vectors
        self._dimension = dimension
        self._platform = platform
        self._called_by_index: dict[str, list[str]] | None = None
        self._difficulty_model_cache: DifficultyModel | None = None
        self._difficulty_scores_cache: dict[str, DifficultyScore] | None = None
        self._difficulty_tiers_cache: DifficultyTiers | None = None

    @staticmethod
    def from_dump(data: CorpusDump) -> "DecompFunctionCorpus":
        functions = data.functions
        platform = data.platform
        vector_ids: list[str] = []
        dimension = len(data.vectors[0].embedding) if data.vectors else 0

        normalized_vectors: list[list[float]] = []
        for vec in data.vectors:
            vector_ids.append(vec.id)
            embedding = vec.embedding
            norm = math.sqrt(sum(value * value for value in embedding))
            if norm > 0:
                normalized_vectors.append([value / norm for value in embedding])
            else:
                normalized_vectors.append([0.0] * dimension)

        return DecompFunctionCorpus(functions, vector_ids, normalized_vectors, dimension, platform)

    @property
    def platform(self) -> Platform:
        return self._platform

    @property
    def functions(self) -> list[DecompFunctionDoc]:
        return self._functions

    @property
    def vectors(self) -> dict[str, list[float]]:
        return dict(zip(self._vector_ids, self._normalized_vectors))

    @property
    def difficulty_model(self) -> DifficultyModel:
        if self._difficulty_model_cache is None:
            self._difficulty_model_cache = train_difficulty_model(self._functions, self._platform)
        return self._difficulty_model_cache

    def get_function_by_id(self, id_: str) -> DecompFunctionDoc | None:
        return self._function_by_id.get(id_)

    def get_called_by(self, id_: str) -> list[DecompFunctionDoc]:
        if self._called_by_index is None:
            index: dict[str, list[str]] = {}
            for fn in self._functions:
                for callee_id in fn.calls_functions:
                    index.setdefault(callee_id, []).append(fn.id)
            self._called_by_index = index

        caller_ids = self._called_by_index.get(id_, [])
        return [self._function_by_id[caller_id] for caller_id in caller_ids if caller_id in self._function_by_id]

    def get_stats(self) -> CorpusStats:
        decompiled = sum(1 for fn in self._functions if fn.c_code)
        return CorpusStats(
            total_functions=len(self._functions),
            decompiled_functions=decompiled,
            asm_only_functions=len(self._functions) - decompiled,
            total_vectors=len(self._vector_ids),
            embedding_dimension=self._dimension,
        )

    def get_difficulty_scores(self) -> dict[str, DifficultyScore]:
        if self._difficulty_scores_cache is None:
            model = self.difficulty_model
            scores: dict[str, DifficultyScore] = {}
            for fn in self._functions:
                metrics = count_asm_metrics(fn.asm_code, self._platform)
                if self._platform == "arm" and metrics.arm_encoding is None and fn.c_code:
                    metrics.arm_encoding = "thumb"
                score = apply_difficulty_model(metrics, model)
                scores[fn.id] = DifficultyScore(score=score, metrics=metrics)
            self._difficulty_scores_cache = scores
        return self._difficulty_scores_cache

    def get_difficulty_tiers(self) -> DifficultyTiers:
        if self._difficulty_tiers_cache is None:
            scores = self.get_difficulty_scores()
            sorted_scores = sorted(ds.score for ds in scores.values())

            n = len(sorted_scores)
            p33 = sorted_scores[n // 3] if n > 0 else 0.0
            p66 = sorted_scores[(2 * n) // 3] if n > 0 else 0.0

            tiers: dict[str, DifficultyTier] = {}
            for id_, ds in scores.items():
                if ds.score <= p33:
                    tiers[id_] = "easy"
                elif ds.score <= p66:
                    tiers[id_] = "medium"
                else:
                    tiers[id_] = "hard"

            self._difficulty_tiers_cache = DifficultyTiers(tiers=tiers, thresholds=(p33, p66))
        return self._difficulty_tiers_cache

    def find_similar(self, id_: str, limit: int = 10) -> list[SimilarResult]:
        try:
            query_index = self._vector_ids.index(id_)
        except ValueError:
            return []

        query_vec = self._normalized_vectors[query_index]
        results: list[tuple[str, float]] = []
        for i, vector_id in enumerate(self._vector_ids):
            if i == query_index:
                continue
            other_vec = self._normalized_vectors[i]
            dot = sum(a * b for a, b in zip(query_vec, other_vec))
            results.append((vector_id, dot))

        results.sort(key=lambda item: item[1], reverse=True)

        top_results: list[SimilarResult] = []
        for vector_id, similarity in results[: max(0, limit)]:
            fn = self._function_by_id.get(vector_id)
            if fn is not None:
                top_results.append(SimilarResult(function=fn, similarity=similarity))
        return top_results
