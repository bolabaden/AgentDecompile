"""Unit tests for Phase 5b PE critical-path receipts."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.critical_path import (
    PE_CRITICAL_PATH_STOP_AFTER,
    build_critical_path,
    write_critical_path,
)
from agentdecompile_recovery.recovery_status import build_recovery_status
from agentdecompile_recovery.state import atomic_write_json

pytestmark = pytest.mark.unit


def _write_minimal_target(work: Path) -> None:
    atomic_write_json(
        work / "target.json",
        {
            "schema": "agentdecompile.target.v1",
            "inputPath": "/tmp/game.exe",
            "binaryPath": "/tmp/game.exe",
            "sha256": "abc",
            "size": 100,
            "format": "pe",
            "architectureHint": "x86",
            "stableId": "test-stable",
        },
    )


def _write_capabilities(work: Path, *, objdiff: bool = True, clang: bool = True) -> None:
    atomic_write_json(
        work / "capabilities.json",
        {
            "schema": "agentdecompile.recovery.capabilities.v1",
            "tools": {
                "objdiff": {"available": objdiff},
                "clang": {"available": clang},
                "objcopy": {"available": True},
                "objdump": {"available": True},
                "wine": {"available": False},
            },
            "localSurfaces": {
                "swkotorInventorySlice": True,
                "verifyObjdiff": True,
            },
        },
    )


def test_critical_path_ready_for_vacuum_checkpoint_chain(tmp_path: Path) -> None:
    work = tmp_path / "ready"
    work.mkdir()
    _write_minimal_target(work)
    _write_capabilities(work)
    atomic_write_json(
        work / "analysis-target.json",
        {
            "schema": "agentdecompile.analysis-target.v1",
            "status": "transformed",
            "transform": "steamless-unpacked-pe",
            "analysisBinaryPath": "/tmp/game.unpacked.exe",
        },
    )
    atomic_write_json(work / "binary-inventory.json", {"schema": "x", "format": "pe", "status": "complete"})
    atomic_write_json(
        work / "function-candidates.json",
        {
            "schema": "agentdecompile.function-candidates.v1",
            "candidates": [{"name": "fn_a", "address": 0x401000}],
            "summary": {"count": 1},
        },
    )
    path = build_critical_path(work)
    assert path["schema"] == "agentdecompile.critical-path.v1"
    assert path["readiness"] == "candidates-ready"
    assert path["peCriticalPathStopAfter"] == list(PE_CRITICAL_PATH_STOP_AFTER)
    by_name = {row["name"]: row for row in path["checkpoints"]}
    assert by_name["prepare-analysis-image"]["status"] == "complete"
    assert by_name["discover-functions"]["functionCandidateCount"] == 1
    action_ids = {row["id"] for row in path["nextActions"]}
    assert "synthesize-source-tasks" in action_ids
    assert "vacuum-seed" in action_ids


def test_critical_path_steamless_soft_fail(tmp_path: Path) -> None:
    work = tmp_path / "blocked"
    work.mkdir()
    _write_minimal_target(work)
    _write_capabilities(work)
    atomic_write_json(
        work / "analysis-target.json",
        {
            "schema": "agentdecompile.analysis-target.v1",
            "status": "blocked",
            "terminalStatus": "blocked:toolchain",
            "transformAttempted": "steamless-unpacked-pe",
            "transformResult": "mono-or-steamless-unavailable",
            "packedDetected": True,
        },
    )
    path = build_critical_path(work)
    assert path["readiness"] == "blocked:toolchain"
    analysis = next(row for row in path["checkpoints"] if row["name"] == "prepare-analysis-image")
    assert analysis["status"] == "blocked:toolchain"
    assert analysis["softFail"]["transformResult"] == "mono-or-steamless-unavailable"


def test_critical_path_missing_inventory(tmp_path: Path) -> None:
    work = tmp_path / "analysis-only"
    work.mkdir()
    _write_minimal_target(work)
    atomic_write_json(
        work / "analysis-target.json",
        {"schema": "x", "status": "original", "analysisBinaryPath": "/tmp/game.exe"},
    )
    path = build_critical_path(work)
    assert path["readiness"] == "analysis-ready"
    inventory = next(row for row in path["checkpoints"] if row["name"] == "inventory-binary")
    assert inventory["status"] == "missing"


def test_write_critical_path_and_status(tmp_path: Path) -> None:
    work = tmp_path / "status"
    work.mkdir()
    _write_minimal_target(work)
    _write_capabilities(work, objdiff=False, clang=False)
    atomic_write_json(
        work / "analysis-target.json",
        {"schema": "x", "status": "original", "analysisBinaryPath": "/tmp/game.exe"},
    )
    atomic_write_json(work / "binary-inventory.json", {"format": "pe", "status": "complete"})
    atomic_write_json(
        work / "function-candidates.json",
        {"candidates": [{"name": "fn"}], "summary": {"count": 1}},
    )
    write_critical_path(work)
    assert (work / "critical-path.json").is_file()
    status = build_recovery_status(work)
    assert status["criticalPath"]["readiness"] == "candidates-ready"
    assert status["paths"]["criticalPath"] is not None
    synth = next(row for row in status["criticalPath"]["nextActions"] if row["id"] == "synthesize-source-tasks")
    assert synth["status"] == "blocked"
    assert "objdiff" in synth["reason"]
