"""Unit tests for context apply executor."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.context_apply import run_context_apply
from agentdecompile_recovery.state import atomic_write_json

pytestmark = pytest.mark.unit


def test_context_apply_skips_without_ready(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    atomic_write_json(
        work / "acquisition" / "propose-labels.json",
        {
            "schema": "agentdecompile.propose-labels.v1",
            "status": "complete",
            "proposals": [{"addressHex": "0x401000", "proposedName": "A", "status": "conflict"}],
            "counts": {"ready": 0, "conflicts": 1, "proposed": 1},
        },
    )
    receipt = run_context_apply(work)
    assert receipt["status"] == "skipped:no-ready"
    assert receipt["skippedConflict"] == 1


def test_context_apply_mock_mcp(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    atomic_write_json(
        work / "acquisition" / "propose-labels.json",
        {
            "schema": "agentdecompile.propose-labels.v1",
            "status": "complete",
            "proposals": [
                {"addressHex": "0x401000", "proposedName": "Alpha", "status": "ready"},
                {"addressHex": "0x402000", "proposedName": "Beta", "status": "ready"},
                {"addressHex": "0x403000", "proposedName": "Gamma", "status": "conflict"},
            ],
            "counts": {"ready": 2, "conflicts": 1, "proposed": 3},
        },
    )

    def fake_tool_seq(steps, *, work_dir, **kwargs):
        return {
            "status": "complete",
            "toolsInvoked": [s["name"] for s in steps],
            "steps": [{"name": s["name"], "ok": True} for s in steps],
        }

    receipt = run_context_apply(work, run_tool_seq_fn=fake_tool_seq)
    assert receipt["status"] == "complete"
    assert receipt["applied"] == 2
    assert receipt["skippedConflict"] >= 1
