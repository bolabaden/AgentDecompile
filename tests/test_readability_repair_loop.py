"""Unit tests for readability repair loop closure (executor + autonomous branch)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.proof_ladder import build_proof_ladder
from agentdecompile_recovery.readability_repair import (
    build_readability_repair_queue,
    execute_readability_repair,
    readability_repair_blocks_vacuum,
    run_readability_repair,
    write_readability_repair_queue,
)
from agentdecompile_recovery.state import atomic_write_json
from agentdecompile_recovery.vacuum_queue import seed_vacuum_queue_from_work_dir

pytestmark = pytest.mark.unit


def _write_facts(work: Path, rows: list[dict]) -> None:
    facts_dir = work / "facts"
    facts_dir.mkdir(parents=True, exist_ok=True)
    path = facts_dir / "function-facts.jsonl"
    path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n", encoding="utf-8")


def _write_module_map(work: Path, entries: dict[str, dict]) -> None:
    atomic_write_json(
        work / "facts" / "module-map.json",
        {"schema": "agentdecompile.module-map.v1", "entries": entries},
    )


def test_repair_executor_rename_tool_seq(tmp_path: Path) -> None:
    work = tmp_path / "exec"
    work.mkdir()
    _write_facts(work, [{"name": "FUN_00401000", "entry": "00401000", "decompiled": "void x(){}"}])
    _write_module_map(work, {"00401000": {"module": "recovered/unmapped", "moduleProvenance": "fallback"}})
    write_readability_repair_queue(work)
    receipt = run_readability_repair(work, limit=1)
    assert receipt["status"] == "ready"
    assert receipt["claimBoundary"]
    head = receipt["topEntry"]
    assert head["repairClass"] == "rename"
    assert head["toolSeq"][0]["name"] == "manage-function"
    assert head["toolSeq"][0]["arguments"]["mode"] == "rename"
    assert (work / "state" / "readability-repair-run.json").is_file()


def test_readability_blocks_vacuum_when_no_source_task(tmp_path: Path) -> None:
    work = tmp_path / "block"
    work.mkdir()
    _write_facts(work, [{"name": "FUN_bad", "entry": "00401000", "decompiled": "void x(){}"}])
    _write_module_map(work, {"00401000": {"module": "recovered/unmapped", "moduleProvenance": "fallback"}})
    write_readability_repair_queue(work)
    assert readability_repair_blocks_vacuum(work) is True
    seed = seed_vacuum_queue_from_work_dir(work, limit=1)
    assert seed.get("seededCount", 0) == 0
    assert seed.get("readabilityQueueExcludedFromVacuum") is True


def test_queue_rebuild_after_rename_facts(tmp_path: Path) -> None:
    work = tmp_path / "rebuild"
    work.mkdir()
    _write_facts(work, [{"name": "FUN_00401000", "entry": "00401000", "decompiled": "void x(){}"}])
    _write_module_map(
        work,
        {"00401000": {"module": "game/core", "moduleProvenance": "assert-string"}},
    )
    before = build_readability_repair_queue(work)
    assert before["queueCount"] == 1

    _write_facts(
        work,
        [{"name": "LoadArea", "entry": "00401000", "readabilityScore": 0.8, "decompiled": "void x(){}"}],
    )
    after = build_readability_repair_queue(work)
    assert after["queueCount"] == 0
    assert after["portReadyCount"] == 1


def test_proof_ladder_unchanged_by_repair_run(tmp_path: Path) -> None:
    work = tmp_path / "proof"
    work.mkdir()
    atomic_write_json(
        work / "function-candidates.json",
        {"candidates": [{"name": "fn", "address": 0x401000, "size": 16}], "summary": {"count": 1}},
    )
    _write_facts(work, [{"name": "FUN_001", "entry": "001", "decompiled": "x"}])
    _write_module_map(work, {"00000001": {"module": "recovered/unmapped", "moduleProvenance": "fallback"}})
    write_readability_repair_queue(work)
    before = build_proof_ladder(work)
    run_readability_repair(work, limit=1)
    after = build_proof_ladder(work)
    assert before["numerator"] == after["numerator"] == 0
    assert before["denominator"] == after["denominator"] == 1


def test_execute_readability_repair_mock_mcp(tmp_path: Path) -> None:
    work = tmp_path / "exec2"
    work.mkdir()
    _write_facts(work, [{"name": "FUN_00401000", "entry": "00401000", "decompiled": "void x(){}"}])
    _write_module_map(work, {"00401000": {"module": "recovered/unmapped", "moduleProvenance": "fallback"}})
    write_readability_repair_queue(work)

    def fake_tool_seq(steps, *, work_dir, **kwargs):
        return {"status": "complete", "toolsInvoked": ["rename-function"], "steps": [{"name": "rename-function", "ok": True}]}

    receipt = execute_readability_repair(
        work,
        limit=1,
        run_tool_seq_fn=fake_tool_seq,
        run_enrich_refresh_fn=lambda _wd: {"status": "skipped"},
    )
    assert receipt["mcpStatus"] == "complete"
    assert receipt["toolsInvoked"] == ["rename-function"]
    before = build_proof_ladder(work)
    after = build_proof_ladder(work)
    assert before["numerator"] == after["numerator"] == 0

