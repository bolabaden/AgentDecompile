"""Unit tests for Phase 6a propose-labels from placed context seeds."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.context_propose import build_propose_labels, write_propose_labels
from agentdecompile_recovery.recovery_status import build_recovery_status
from agentdecompile_recovery.state import atomic_write_json

pytestmark = pytest.mark.unit


def test_propose_labels_empty_work_dir(tmp_path: Path) -> None:
    work = tmp_path / "empty"
    work.mkdir()
    receipt = build_propose_labels(work)
    assert receipt["schema"] == "agentdecompile.propose-labels.v1"
    assert receipt["status"] == "empty"
    assert receipt["counts"]["proposed"] == 0
    assert "objdiff" in receipt["claimBoundary"] or "proof" in receipt["claimBoundary"]


def test_propose_labels_ready_from_seed_excludes_unplaced(tmp_path: Path) -> None:
    work = tmp_path / "seeds"
    work.mkdir()
    atomic_write_json(
        work / "acquisition" / "placement.json",
        {
            "counts": {"placed": 1, "unplaced": 1},
            "unplaced": [{"address": 0x402000, "reason": "no-va"}],
        },
    )
    seed_dir = work / "advisory" / "context-seeds"
    seed_dir.mkdir(parents=True)
    atomic_write_json(
        seed_dir / "CSWMinigame_401000.json",
        {
            "name": "CSWMinigame",
            "address": 0x401000,
            "sourceKind": "source-dump",
            "authorityClass": "advisory-decompiler",
        },
    )
    atomic_write_json(
        seed_dir / "UnplacedNote_402000.json",
        {
            "name": "UnplacedNote",
            "address": 0x402000,
            "sourceKind": "source-dump",
        },
    )
    receipt = write_propose_labels(work)
    assert receipt["status"] == "complete"
    assert receipt["counts"]["ready"] == 1
    assert receipt["counts"]["unplacedExcluded"] == 1
    assert len(receipt["proposals"]) == 1
    assert receipt["proposals"][0]["proposedName"] == "CSWMinigame"
    assert receipt["proposals"][0]["status"] == "ready"
    assert (work / "acquisition" / "propose-labels.json").is_file()

    status = build_recovery_status(work)
    assert status["proposeLabels"]["ready"] == 1
    assert status["paths"]["proposeLabels"] is not None


def test_propose_labels_marks_address_conflicts(tmp_path: Path) -> None:
    work = tmp_path / "conflicts"
    work.mkdir()
    seed_dir = work / "advisory" / "context-seeds"
    seed_dir.mkdir(parents=True)
    atomic_write_json(seed_dir / "a_401000.json", {"name": "Alpha", "address": 0x401000})
    atomic_write_json(seed_dir / "b_401000.json", {"name": "Beta", "address": 0x401000})
    receipt = build_propose_labels(work)
    assert receipt["counts"]["conflicts"] == 1
    assert all(row["status"] == "conflict" for row in receipt["proposals"])
    assert "Do not auto-pick" in receipt["nextStep"]
