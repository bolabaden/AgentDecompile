"""Unit tests for monotonic campaign checkpoints."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.campaign_checkpoint import (
    ingest_attempts_jsonl,
    load_checkpoint_index,
    record_attempt_checkpoint,
)

pytestmark = pytest.mark.unit


def test_record_attempt_checkpoint_monotonic(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    first = record_attempt_checkpoint(work, name="LoadArea", entry="0x401000", differences=5)
    assert first["updated"] is True
    worse = record_attempt_checkpoint(work, name="LoadArea", entry="0x401000", differences=8)
    assert worse["updated"] is False
    better = record_attempt_checkpoint(work, name="LoadArea", entry="0x401000", differences=3, mismatch_class="operand")
    assert better["updated"] is True
    index = load_checkpoint_index(work)
    assert index["entries"]["LoadArea"]["bestDifference"] == 3


def test_ingest_attempts_jsonl(tmp_path: Path) -> None:
    work = tmp_path / "work"
    synth = work / "source-synthesis"
    synth.mkdir(parents=True)
    rows = [
        {"name": "Foo", "entry": "0x1000", "differences": 4, "mismatchClass": "opcode"},
        {"name": "Foo", "entry": "0x1000", "differences": 2, "mismatchClass": "opcode"},
    ]
    (synth / "attempts.jsonl").write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    summary = ingest_attempts_jsonl(work)
    assert summary["scanned"] == 2
    assert summary["updated"] >= 1
    assert load_checkpoint_index(work)["entries"]["Foo"]["bestDifference"] == 2
