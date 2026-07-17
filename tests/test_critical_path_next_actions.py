"""Unit tests for critical-path nextActions glue."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.critical_path import build_next_actions
from agentdecompile_recovery.state import atomic_write_json

pytestmark = pytest.mark.unit


def _capabilities(work: Path) -> None:
    atomic_write_json(
        work / "capabilities.json",
        {
            "tools": {
                "objdiff": {"available": True},
                "clang": {"available": True},
                "objcopy": {"available": True},
                "objdump": {"available": True},
            },
            "localSurfaces": {"swkotorInventorySlice": True, "verifyObjdiff": True},
        },
    )


def test_next_actions_vacuum_ready_with_tasks(tmp_path: Path) -> None:
    work = tmp_path / "vacuum"
    work.mkdir()
    _capabilities(work)
    atomic_write_json(work / "binary-inventory.json", {"format": "pe"})
    atomic_write_json(work / "function-candidates.json", {"candidates": [{"name": "fn"}], "summary": {"count": 1}})
    tasks = work / "source-generation" / "tasks.jsonl"
    tasks.parent.mkdir(parents=True)
    tasks.write_text('{"name":"fn","score":1}\n', encoding="utf-8")
    actions = build_next_actions(work)
    vacuum = next(row for row in actions if row["id"] == "vacuum-seed")
    assert vacuum["status"] == "ready"
    assert "--autonomous" in vacuum.get("commandHint", "")


def test_next_actions_profile_corpus_blocked_without_verified(tmp_path: Path) -> None:
    work = tmp_path / "corpus"
    work.mkdir()
    _capabilities(work)
    actions = build_next_actions(work)
    corpus = next(row for row in actions if row["id"] == "profile-corpus")
    assert corpus["status"] == "blocked"


def test_next_actions_reloc_slice_ready_for_pe(tmp_path: Path) -> None:
    work = tmp_path / "reloc"
    work.mkdir()
    _capabilities(work)
    atomic_write_json(work / "binary-inventory.json", {"format": "pe", "status": "complete"})
    atomic_write_json(work / "function-candidates.json", {"candidates": [{"name": "fn"}], "summary": {"count": 1}})
    actions = build_next_actions(work)
    reloc = next(row for row in actions if row["id"] == "reloc-slice")
    assert reloc["status"] == "ready"
    assert "swkotor-inventory-slice" in reloc.get("commandHint", "")
    slice_verify = next(row for row in actions if row["id"] == "slice-verify")
    assert slice_verify["status"] == "blocked"
    assert "ELF/Mach-O" in slice_verify["reason"]


def test_next_actions_slice_verify_ready_for_elf(tmp_path: Path) -> None:
    work = tmp_path / "elf"
    work.mkdir()
    _capabilities(work)
    atomic_write_json(work / "binary-inventory.json", {"format": "elf", "status": "complete"})
    atomic_write_json(
        work / "function-candidates.json",
        {"candidates": [{"name": "slice_fn", "size": 16, "source": "elf-symbol"}], "summary": {"count": 1}},
    )
    actions = build_next_actions(work)
    slice_verify = next(row for row in actions if row["id"] == "slice-verify")
    assert slice_verify["status"] == "ready"
    assert "discover-functions" in slice_verify.get("commandHint", "")
    reloc = next(row for row in actions if row["id"] == "reloc-slice")
    assert reloc["status"] == "blocked"


def test_next_actions_slice_verify_complete_when_matched(tmp_path: Path) -> None:
    work = tmp_path / "matched"
    work.mkdir()
    _capabilities(work)
    atomic_write_json(work / "binary-inventory.json", {"format": "elf"})
    atomic_write_json(work / "function-candidates.json", {"candidates": [{"name": "fn"}], "summary": {"count": 1}})
    summary = work / "slice-verify" / "summary.json"
    summary.parent.mkdir(parents=True)
    atomic_write_json(summary, {"status": "matched", "verificationTier": "code-slice"})
    actions = build_next_actions(work)
    slice_verify = next(row for row in actions if row["id"] == "slice-verify")
    assert slice_verify["status"] == "complete"
