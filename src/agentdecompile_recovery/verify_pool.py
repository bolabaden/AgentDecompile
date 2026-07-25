"""Bounded parallel compile/objdiff workers for matching recovery."""

from __future__ import annotations

import os
import sys
import threading
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from itertools import count
from typing import Callable, Iterable, TypeVar

T = TypeVar("T")
R = TypeVar("R")

DEFAULT_WORKERS = min(8, max(2, (os.cpu_count() or 4)))

_MISSING = object()
_worker_local = threading.local()
_worker_id_lock = threading.Lock()
_worker_ids: dict[int, int] = {}
_worker_counter = count()


def resolve_workers(requested: int | None) -> int:
    if requested is None or requested <= 0:
        return DEFAULT_WORKERS
    return max(1, min(int(requested), 32))


def get_worker_index() -> int | None:
    value = getattr(_worker_local, "worker_index", None)
    return int(value) if value is not None else None


def _assign_worker_index(pool_size: int) -> int:
    thread_id = threading.get_ident()
    with _worker_id_lock:
        if thread_id not in _worker_ids:
            _worker_ids[thread_id] = next(_worker_counter) % max(pool_size, 1)
        return _worker_ids[thread_id]


def map_parallel(
    items: Iterable[T],
    fn: Callable[[T], R],
    *,
    workers: int | None = None,
    on_error: Callable[[T, BaseException], R] | None = None,
    worker_env_factory: Callable[[int], dict[str, str]] | None = None,
) -> list[R]:
    """Run ``fn`` over ``items`` with a bounded thread pool; preserve input order.

    A worker exception does not discard sibling results: by default it is
    re-raised after all futures settle, but callers that pass ``on_error`` get an
    error record per failed item instead so completed proofs are never lost.
    """

    material = list(items)
    if not material:
        return []
    count_workers = resolve_workers(workers)
    if count_workers == 1 or len(material) == 1:
        out: list[R] = []
        for item in material:
            try:
                out.append(_call_with_worker_env(fn, item, worker_index=0, worker_env_factory=worker_env_factory))
            except BaseException as exc:  # noqa: BLE001 - surface or convert below
                if on_error is None:
                    raise
                out.append(on_error(item, exc))
        return out

    def _wrapped(item: T) -> R:
        worker_index = _assign_worker_index(count_workers)
        return _call_with_worker_env(fn, item, worker_index=worker_index, worker_env_factory=worker_env_factory)

    results: list[object] = [_MISSING] * len(material)
    first_error: tuple[int, BaseException] | None = None
    with ThreadPoolExecutor(max_workers=count_workers) as pool:
        futures: dict[Future[R], int] = {
            pool.submit(_wrapped, item): index for index, item in enumerate(material)
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


def _call_with_worker_env(
    fn: Callable[[T], R],
    item: T,
    *,
    worker_index: int,
    worker_env_factory: Callable[[int], dict[str, str]] | None,
) -> R:
    _worker_local.worker_index = worker_index
    if worker_env_factory is None:
        return fn(item)
    overlay = worker_env_factory(worker_index)
    saved: dict[str, str | None] = {}
    for key, value in overlay.items():
        saved[key] = os.environ.get(key)
        os.environ[key] = value
    try:
        return fn(item)
    finally:
        for key, previous in saved.items():
            if previous is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = previous
