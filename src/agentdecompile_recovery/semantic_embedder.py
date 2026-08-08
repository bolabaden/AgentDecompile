"""In-process text embedding for the decomp-atlas semantic search path.

The upstream Embedder spawns a long-running Python subprocess (with its own
auto-provisioned venv) to load jina-embeddings-v2-base-code, because it is
called from a Node/TypeScript host. This project is already Python, so that
subprocess/venv-bootstrap layer doesn't apply -- we call an embedding
function in-process instead, reusing this project's existing optional
`chromadb` dependency (see `agentdecompile[semantic]` in pyproject.toml and
the same guarded-import pattern used by agentdecompile_cli.context) rather
than adding a second ML stack (torch + transformers + a ~300MB model) on top
of it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable

try:
    from chromadb.utils import embedding_functions  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
except Exception:
    if not TYPE_CHECKING:
        embedding_functions = None

EmbeddingBackend = Callable[[list[str]], list[list[float]]]

_DEFAULT_BATCH_SIZE = 8


def default_embedding_backend() -> EmbeddingBackend:
    """The default chromadb embedding function, wrapped to this module's callable shape."""
    if embedding_functions is None:
        raise ImportError(
            "chromadb is not installed; install agentdecompile[semantic] for embedding-based decomp-atlas search."
        )
    fn = embedding_functions.DefaultEmbeddingFunction()

    def backend(texts: list[str]) -> list[list[float]]:
        return [list(vector) for vector in fn(texts)]

    return backend


class SemanticEmbedder:
    """Embeds text batches. Backend is injectable for testing without chromadb installed."""

    def __init__(self, backend: EmbeddingBackend | None = None) -> None:
        self._backend = backend or default_embedding_backend()

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        return self._backend(texts)

    def embed_all(self, texts: list[str], batch_size: int = _DEFAULT_BATCH_SIZE) -> list[list[float]]:
        results: list[list[float]] = []
        for i in range(0, len(texts), batch_size):
            results.extend(self.embed_batch(texts[i : i + batch_size]))
        return results
