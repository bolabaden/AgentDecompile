"""Unit tests for compile/objdiff cache and verify pool worker prefixes."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from agentdecompile_recovery.compile_cache import (
    cache_dir,
    cache_key,
    lookup,
    store,
    target_slice_sha256,
)
from agentdecompile_recovery.verify_pool import map_parallel

pytestmark = pytest.mark.unit


def test_compile_cache_hit_on_identical_digest(tmp_path: Path) -> None:
    root = cache_dir(tmp_path / "work")
    row = {"targetSlice": {"bytes": "deadbeef"}, "name": "fn"}
    key = cache_key(
        target_slice_sha=target_slice_sha256(row),
        source_sha="abc123",
        compiler_profile="default",
    )
    records = [{"status": "matched", "differences": 0, "name": "fn"}]
    store(root, key, records=records)
    hit = lookup(root, key)
    assert hit is not None
    assert hit["records"][0]["status"] == "matched"

    other_key = cache_key(
        target_slice_sha=target_slice_sha256({"targetSlice": {"bytes": "beeffeed"}}),
        source_sha="abc123",
        compiler_profile="default",
    )
    assert lookup(root, other_key) is None


def test_map_parallel_worker_env_factory(tmp_path: Path) -> None:
    seen: list[str] = []

    def worker_env_factory(worker_index: int) -> dict[str, str]:
        prefix = tmp_path / f"worker-{worker_index}"
        prefix.mkdir(parents=True, exist_ok=True)
        return {"WINEPREFIX": str(prefix)}

    def capture(_item: int) -> str:
        seen.append(os.environ.get("WINEPREFIX", ""))
        return seen[-1]

    results = map_parallel([0, 1, 2, 3], capture, workers=2, worker_env_factory=worker_env_factory)
    assert len(results) == 4
    assert all(path for path in results)
    assert len(set(results)) >= 1
