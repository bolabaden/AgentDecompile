"""Unit tests for readability repair queue and vacuum seed preference."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.critical_path import build_next_actions
from agentdecompile_recovery.module_resolver import infer_repair_class
from agentdecompile_recovery.proof_ladder import build_proof_ladder
from agentdecompile_recovery.pyghidra_enrich import readability_score
from agentdecompile_recovery.readability_repair import (
    build_readability_repair_queue,
    write_readability_repair_queue,
)
from agentdecompile_recovery.source_dump import dump_source_tree
from agentdecompile_recovery.state import atomic_write_json
from agentdecompile_recovery.vacuum_queue import seed_vacuum_queue_from_work_dir

pytestmark = pytest.mark.unit


def _write_facts(work: Path, rows: list[dict]) -> Path:
    facts_dir = work / "facts"
    facts_dir.mkdir(parents=True, exist_ok=True)
    path = facts_dir / "function-facts.jsonl"
    path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n", encoding="utf-8")
    return path


def _write_module_map(work: Path, entries: dict[str, dict]) -> None:
    atomic_write_json(
        work / "facts" / "module-map.json",
        {"schema": "agentdecompile.module-map.v1", "entries": entries},
    )


def test_readability_score_and_gate_alignment() -> None:
    score = readability_score(name="LoadArea", module="game/clientcore", provenance="assert-string")
    assert score >= 0.8
    assert infer_repair_class(name="LoadArea", module="game/clientcore", module_provenance="assert-string") == "re-enrich"


def test_infer_repair_class_rename_and_module_refresh() -> None:
    assert infer_repair_class(name="FUN_00401000", module="game/x", module_provenance="assert-string") == "rename"
    assert (
        infer_repair_class(name="LoadArea", module="recovered/unmapped", module_provenance="fallback")
        == "module-refresh"
    )


def test_repair_queue_ranks_fun_first(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    _write_facts(
        work,
        [
            {
                "name": "LoadArea",
                "entry": "00402000",
                "readabilityScore": 0.8,
                "decompiled": "int LoadArea(void) { return 0; }",
            },
            {
                "name": "FUN_00401000",
                "entry": "00401000",
                "readabilityScore": 0.0,
                "decompiled": "void FUN_00401000(void) {}",
            },
        ],
    )
    _write_module_map(
        work,
        {
            "00401000": {"module": "recovered/unmapped", "moduleProvenance": "fallback", "score": 0.0},
            "00402000": {"module": "game/clientcore", "moduleProvenance": "assert-string", "score": 1.0},
        },
    )
    queue = build_readability_repair_queue(work)
    assert queue["queueCount"] == 1
    assert queue["portReadyCount"] == 1
    assert queue["entries"][0]["name"] == "FUN_00401000"
    assert queue["entries"][0]["repairClass"] == "rename"


def test_write_repair_queue_receipt(tmp_path: Path) -> None:
    work = tmp_path / "write"
    work.mkdir()
    _write_facts(work, [{"name": "FUN_001", "entry": "001", "decompiled": "void x(){}"}])
    _write_module_map(work, {"00000001": {"module": "recovered/unmapped", "moduleProvenance": "fallback"}})
    payload = write_readability_repair_queue(work)
    receipt = work / "facts" / "readability-repair-queue.json"
    assert receipt.is_file()
    assert payload["queueCount"] == 1
    assert payload["entries"][0]["claimBoundary"] == "readability-repair-advisory"


def test_dump_manifest_includes_repair_summary(tmp_path: Path) -> None:
    work = tmp_path / "dump-work"
    work.mkdir()
    facts = _write_facts(
        work,
        [{"name": "FUN_00401000", "entry": "00401000", "decompiled": "void f(){}"}],
    )
    _write_module_map(
        work,
        {"00401000": {"module": "recovered/unmapped", "moduleProvenance": "fallback"}},
    )
    write_readability_repair_queue(work)
    out = tmp_path / "out"
    manifest = dump_source_tree(
        out_dir=out,
        summaries=[],
        ghidra_facts=facts,
        layers="port,advisory",
        module_hints=json.loads((work / "facts" / "module-map.json").read_text())["entries"],
    )
    block = manifest.get("readabilityRepairQueue") or {}
    assert block.get("queueCount") == 1
    assert manifest.get("readabilityExcludedFromPort", 0) >= 1


def test_critical_path_readability_repair_ready(tmp_path: Path) -> None:
    work = tmp_path / "cp"
    work.mkdir()
    _write_facts(work, [{"name": "FUN_001", "entry": "001", "decompiled": "void x(){}"}])
    _write_module_map(work, {"00000001": {"module": "recovered/unmapped", "moduleProvenance": "fallback"}})
    write_readability_repair_queue(work)
    action = next(row for row in build_next_actions(work) if row["id"] == "readability-repair")
    assert action["status"] == "ready"
    assert action["counts"]["queueCount"] == 1


def test_vacuum_seed_excludes_readability_only_from_synthesis(tmp_path: Path) -> None:
    work = tmp_path / "vac"
    work.mkdir()
    _write_facts(
        work,
        [
            {"name": "FUN_bad", "entry": "00401000", "decompiled": "void a(){}"},
            {"name": "Helper", "entry": "00402000", "decompiled": "void b(){}"},
        ],
    )
    _write_module_map(
        work,
        {
            "00401000": {"module": "recovered/unmapped", "moduleProvenance": "fallback"},
            "00402000": {"module": "game/core", "moduleProvenance": "assert-string"},
        },
    )
    write_readability_repair_queue(work)
    tasks = work / "source-generation" / "tasks.jsonl"
    tasks.parent.mkdir(parents=True)
    tasks.write_text(
        json.dumps(
            {
                "name": "Helper",
                "entry": "00402000",
                "source": "/tmp/helper.c",
                "status": "generated-unverified",
                "semanticSource": True,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    receipt = seed_vacuum_queue_from_work_dir(work, limit=1)
    assert receipt.get("readabilityQueueExcludedFromVacuum") is True
    assert receipt["seeded"][0]["reason"] == "seeded from source-generation/tasks.jsonl"
    assert receipt["seeded"][0]["name"] == "Helper"


def test_proof_ladder_unchanged_by_queue(tmp_path: Path) -> None:
    work = tmp_path / "proof"
    work.mkdir()
    atomic_write_json(
        work / "function-candidates.json",
        {"candidates": [{"name": "fn", "address": 0x401000, "size": 16}], "summary": {"count": 1}},
    )
    _write_facts(work, [{"name": "LoadArea", "entry": "00401000", "readabilityScore": 1.0, "decompiled": "x"}])
    _write_module_map(
        work,
        {"00401000": {"module": "game/core", "moduleProvenance": "assert-string"}},
    )
    write_readability_repair_queue(work)
    before = build_proof_ladder(work)
    after = build_proof_ladder(work)
    assert before["numerator"] == after["numerator"] == 0
    assert before["denominator"] == after["denominator"] == 1
