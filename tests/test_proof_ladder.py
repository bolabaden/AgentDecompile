"""Unit tests for Phase 5 proof ladder."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.claim_report import build_claim_report
from agentdecompile_recovery.proof_ladder import (
    RUNGS,
    build_proof_ladder,
    write_proof_ladder,
)
from agentdecompile_recovery.recovery_status import build_recovery_status
from agentdecompile_recovery.state import atomic_write_json

pytestmark = pytest.mark.unit


def _write_candidates(work: Path, count: int) -> None:
    rows = [{"name": f"fn_{i}", "address": 0x401000 + i, "source": "test"} for i in range(count)]
    path = work / "function-candidates.json"
    atomic_write_json(
        path,
        {
            "schema": "agentdecompile.function-candidates.v1",
            "status": "complete",
            "candidates": rows,
            "summary": {"count": count},
        },
    )


def _write_objdiff_receipt(work: Path, name: str) -> None:
    verified = work / "verified"
    verified.mkdir(parents=True, exist_ok=True)
    (verified / f"{name}.c").write_text("int x(void){return 0;}\n", encoding="utf-8")
    atomic_write_json(
        verified / f"{name}.json",
        {
            "status": "matched",
            "differences": 0,
            "proofTier": "target-object-objdiff-match",
            "name": name,
        },
    )


def test_proof_ladder_rung_thresholds(tmp_path: Path) -> None:
    work = tmp_path / "run"
    work.mkdir()
    _write_candidates(work, 100)
    _write_objdiff_receipt(work, "fn_0")
    ladder = build_proof_ladder(work)
    assert ladder["schema"] == "agentdecompile.proof-ladder.v1"
    assert ladder["denominator"] == 100
    assert ladder["numerator"] == 1
    assert ladder["coverage"] == pytest.approx(0.01)
    assert ladder["rung"] == "1%"
    assert ladder["rungs"] == [name for name, _ in RUNGS]
    assert "objdiff" in ladder["claimBoundary"].lower()
    assert "whole-binary" in ladder["claimBoundary"]
    assert "verified/" in ladder["claimBoundary"] or "bare verified" in ladder["claimBoundary"]


def test_proof_ladder_rung_5_and_20(tmp_path: Path) -> None:
    work = tmp_path / "run5"
    work.mkdir()
    _write_candidates(work, 100)
    for i in range(5):
        _write_objdiff_receipt(work, f"fn_{i}")
    assert build_proof_ladder(work)["rung"] == "5%"

    work20 = tmp_path / "run20"
    work20.mkdir()
    _write_candidates(work20, 100)
    for i in range(20):
        _write_objdiff_receipt(work20, f"fn_{i}")
    assert build_proof_ladder(work20)["rung"] == "20%"


def test_proof_ladder_empty_and_bare_verified(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    ladder = build_proof_ladder(empty)
    assert ladder["status"] in {"empty", "no-inventory"}
    assert ladder["denominator"] == 0
    assert ladder["numerator"] == 0
    assert ladder["rung"] == "below-1"

    bare = tmp_path / "bare"
    bare.mkdir()
    _write_candidates(bare, 10)
    verified = bare / "verified"
    verified.mkdir()
    (verified / "fn_0.c").write_text("int x(void){return 0;}\n", encoding="utf-8")
    ladder = build_proof_ladder(bare)
    assert ladder["numerator"] == 0
    assert ladder["rung"] == "below-1"


def test_proof_ladder_skips_corrupt_candidate_file(tmp_path: Path) -> None:
    work = tmp_path / "corrupt"
    work.mkdir()
    (work / "function-candidates.json").write_text("{not-json", encoding="utf-8")
    _write_objdiff_receipt(work, "fn_0")
    ladder = build_proof_ladder(work)
    assert ladder["denominator"] == 0
    assert ladder["status"] in {"empty", "no-inventory"}


def test_claim_report_embeds_proof_ladder(tmp_path: Path) -> None:
    work = tmp_path / "claim"
    work.mkdir()
    _write_candidates(work, 100)
    _write_objdiff_receipt(work, "fn_0")
    write_proof_ladder(work)
    report = build_claim_report(work_dir=work)
    assert report["proofLadder"]["rung"] == "1%"
    assert report["proofLadder"]["numerator"] == 1
    assert report["counts"]["objdiffVerified"] == 1


def test_recovery_status_includes_proof_ladder(tmp_path: Path) -> None:
    work = tmp_path / "status"
    work.mkdir()
    _write_candidates(work, 100)
    _write_objdiff_receipt(work, "fn_0")
    write_proof_ladder(work)
    status = build_recovery_status(work)
    assert status["proofLadder"]["rung"] == "1%"
    assert status["proofLadder"]["coverage"] == pytest.approx(0.01)
    assert status["paths"]["proofLadder"] is not None
    assert "objdiff" in status["proofLadder"]["claimBoundary"].lower()


def test_recovery_status_null_when_ladder_missing(tmp_path: Path) -> None:
    work = tmp_path / "noladder"
    work.mkdir()
    status = build_recovery_status(work)
    assert status["proofLadder"] is None
