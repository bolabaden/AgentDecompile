"""Retrieval wiring: plugin_pipeline loads structural neighbours when indexed."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.decomp_function_corpus import (
    CorpusDump,
    DecompFunctionDoc,
    VectorEntry,
)
from agentdecompile_recovery.decomp_indexer import DECOMP_INDEX_FILENAME, write_index
from agentdecompile_recovery.plugin_pipeline import PluginPipeline

pytestmark = pytest.mark.unit


def _unit(n: int, dim: int = 4) -> list[float]:
    vec = [0.0] * dim
    vec[n % dim] = 1.0
    return vec


def _write_tiny_index(work_dir: Path) -> None:
    functions = [
        DecompFunctionDoc(
            id="target_fn",
            name="target_fn",
            asm_code="mov eax, 1\nret",
            asm_module_path="a.asm",
            c_code="int target_fn(void){ return 1; }",
            match_percent=40.0,
        ),
        DecompFunctionDoc(
            id="near_verified",
            name="near_verified",
            asm_code="mov eax, 1\nret",
            asm_module_path="b.asm",
            c_code="int near_verified(void){ return 1; }",
            match_percent=100.0,
        ),
        DecompFunctionDoc(
            id="mid_partial",
            name="mid_partial",
            asm_code="mov eax, 2\nret",
            asm_module_path="c.asm",
            c_code="int mid_partial(void){ return 2; }",
            match_percent=82.0,
        ),
        DecompFunctionDoc(
            id="low_miss",
            name="low_miss",
            asm_code="xor eax, eax\nret",
            asm_module_path="d.asm",
            c_code="int low_miss(void){ return 0; }",
            match_percent=10.0,
        ),
    ]
    # Identical asm embedding for target and near_verified so similarity is high.
    vectors = [
        VectorEntry(id="target_fn", embedding=_unit(0)),
        VectorEntry(id="near_verified", embedding=_unit(0)),
        VectorEntry(id="mid_partial", embedding=_unit(1)),
        VectorEntry(id="low_miss", embedding=_unit(2)),
    ]
    dump = CorpusDump(platform="x86", functions=functions, vectors=vectors)
    write_index(work_dir, dump, {fn.id: fn.id for fn in functions})


def test_retrieve_codebase_exemplars_returns_high_match_neighbours(tmp_path: Path) -> None:
    _write_tiny_index(tmp_path)

    samples = PluginPipeline._retrieve_codebase_exemplars(tmp_path, "target_fn")

    names = [s["name"] for s in samples]
    assert "near_verified" in names
    assert "low_miss" not in names
    assert all(s["cCode"] for s in samples)
    assert all((s["matchPercent"] or 0) >= 80.0 for s in samples)


def test_retrieve_codebase_exemplars_empty_without_index(tmp_path: Path) -> None:
    assert PluginPipeline._retrieve_codebase_exemplars(tmp_path, "missing") == []


def test_retrieve_codebase_exemplars_empty_for_unknown_function(tmp_path: Path) -> None:
    _write_tiny_index(tmp_path)
    assert PluginPipeline._retrieve_codebase_exemplars(tmp_path, "not_in_index") == []


def test_index_filename_constant_matches_on_disk(tmp_path: Path) -> None:
    _write_tiny_index(tmp_path)
    assert (tmp_path / DECOMP_INDEX_FILENAME).is_file()
    payload = json.loads((tmp_path / DECOMP_INDEX_FILENAME).read_text(encoding="utf-8"))
    assert payload["platform"] == "x86"
