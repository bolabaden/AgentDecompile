"""Captures streaming text while capping memory usage.

Keeps the first and last `limit` characters; middle content is replaced with
a truncation marker showing how much was dropped. Useful for capturing
stdout/stderr from long-running subprocesses (e.g. decomp-permuter) where
only the beginning (setup/errors) and end (final results) matter.
"""

from __future__ import annotations


class CappedOutput:
    def __init__(self, limit: int = 32 * 1024) -> None:
        self._head: list[str] = []
        self._tail: list[str] = []
        self._head_size = 0
        self._tail_size = 0
        self._total_size = 0
        self._limit = limit

    def push(self, text: str) -> None:
        self._total_size += len(text)

        if self._head_size < self._limit:
            self._head.append(text)
            self._head_size += len(text)
            return

        self._tail.append(text)
        self._tail_size += len(text)

        while self._tail_size - len(self._tail[0]) >= self._limit:
            self._tail_size -= len(self._tail.pop(0))

    @property
    def total_size(self) -> int:
        return self._total_size

    @property
    def truncated(self) -> bool:
        return self._total_size > self._head_size + self._tail_size

    def __str__(self) -> str:
        head = "".join(self._head)
        tail = "".join(self._tail)
        dropped_bytes = self._total_size - len(head) - len(tail)
        if dropped_bytes <= 0:
            return head + tail
        dropped_mb = dropped_bytes / (1024 * 1024)
        return f"{head}\n\n... [truncated {dropped_mb:.1f} MB] ...\n\n{tail}"
