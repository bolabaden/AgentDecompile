"""Bounded parallel compile/objdiff workers for matching recovery."""

from __future__ import annotations

import os
import sys
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from typing import Callable, Iterable, TypeVar

T = TypeVar("T")
R = TypeVar("R")

DEFAULT_WORKERS = min(8, max(2, (os.cpu_count() or 4)))

_MISSING = object()


def resolve_workers(requested: int | None) -> int:
    if requested is None or requested <= 0:
        return DEFAULT_WORKERS
    return max(1, min(int(requested), 32))


def map_parallel(
    items: Iterable[T],
    fn: Callable[[T], R],
    *,
    workers: int | None = None,
    on_error: Callable[[T, BaseException], R] | None = None,
) -> list[R]:
    """Run ``fn`` over ``items`` with a bounded thread pool; preserve input order.

    A worker exception does not discard sibling results: by default it is
    re-raised after all futures settle, but callers that pass ``on_error`` get an
    error record per failed item instead so completed proofs are never lost.
    """

    material = list(items)
    if not material:
        return []
    count = resolve_workers(workers)
    if count == 1 or len(material) == 1:
        out: list[R] = []
        for item in material:
            try:
                out.append(fn(item))
            except BaseException as exc:  # noqa: BLE001 - surface or convert below
                if on_error is None:
                    raise
                out.append(on_error(item, exc))
        return out
    results: list[object] = [_MISSING] * len(material)
    first_error: tuple[int, BaseException] | None = None
    with ThreadPoolExecutor(max_workers=count) as pool:
        futures: dict[Future[R], int] = {
            pool.submit(fn, item): index for index, item in enumerate(material)
        }
        for future in as_completed(futures):
            index = futures[future]
            try:
                results[index] = future.result()
            except BaseException as exc:  # noqa: BLE001 - isolate per worker
                if on_error is not None:
                    results[index] = on_error(material[index], exc)
                else:
                    if first_error is None:
                        first_error = (index, exc)
                    print(
                        f"verify_pool: worker {index} failed: {exc}",
                        file=sys.stderr,
                        flush=True,
                    )
    if first_error is not None and on_error is None:
        raise first_error[1]
    return [item for item in results if item is not _MISSING]  # type: ignore[misc]
