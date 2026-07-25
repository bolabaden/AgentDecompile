"""Unit tests for near-miss repair lane."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from agentdecompile_recovery.near_miss_repair import run_near_miss_repair, select_near_miss_targets
from agentdecompile_recovery.state import atomic_write_json

pytestmark = pytest.mark.unit


def test_select_near_miss_targets(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    atomic_write_json(
        work / "facts" / "proof-target-queue.json",
        {
            "entries": [
                {"name": "fn_a", "score": 100, "nearMissBestDifference": 3},
                {"name": "fn_b", "score": 200, "nearMissBestDifference": 20},
            ]
        },
    )
    targets = select_near_miss_targets(work, threshold=8, limit=5)
    assert len(targets) == 1
    assert targets[0]["name"] == "fn_a"


def test_near_miss_repair_runs_vacuum_with_shape_search(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    atomic_write_json(
        work / "facts" / "proof-target-queue.json",
        {
            "entries": [{"name": "target_fn", "score": 50, "nearMissBestDifference": 2}],
        },
    )
    tasks = work / "source-generation" / "tasks.jsonl"
    tasks.parent.mkdir(parents=True, exist_ok=True)
    source = work / "target_fn.c"
    source.write_text("int target_fn(void){return 0;}\n", encoding="utf-8")
    tasks.write_text(
        json.dumps({"name": "target_fn", "entry": "00401000", "source": str(source)}) + "\n",
        encoding="utf-8",
    )

    with patch("agentdecompile_recovery.near_miss_repair.run_vacuum_prompt") as mock_vacuum:
        mock_vacuum.return_value = {"status": "unmatched", "exitCode": 1}
        receipt = run_near_miss_repair(work, limit=1)
    mock_vacuum.assert_called_once()
    assert mock_vacuum.call_args.kwargs.get("source_shape_search") is True
    assert receipt["status"] == "near-miss"
    assert (work / "state" / "near-miss-repair-run.json").is_file()
