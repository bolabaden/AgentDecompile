"""Unit tests for verified/ vs advisory/ artifact segregation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.artifact_layout import (
    CODE_SLICE_DIR_NAME,
    OBJDIFF_PROOF_TIER,
    is_code_slice_accept,
    is_objdiff_zero_accept,
    publish_advisory_artifact,
    publish_verified_artifact,
)
from agentdecompile_recovery.claim_report import build_claim_report
from agentdecompile_recovery.state import atomic_write_json
from agentdecompile_recovery.windows import promote_source_parity_accepts

pytestmark = pytest.mark.unit


def test_publish_verified_and_advisory_trees(tmp_path: Path) -> None:
    run = tmp_path / "run"
    src = tmp_path / "fn.c"
    src.write_text("int fn(void){return 0;}\n", encoding="utf-8")

    verified = publish_verified_artifact(
        run,
        stem="fn_00401000",
        source=src,
        metadata={"name": "fn", "entry": "0x401000", "differences": 0},
    )
    advisory = publish_advisory_artifact(
        run,
        stem="fn_00401000",
        source=src,
        metadata={"name": "fn", "status": "generated-unverified"},
    )

    assert Path(verified["source"]).is_file()
    assert Path(verified["receipt"]).is_file()
    assert Path(advisory["source"]).is_file()
    report = build_claim_report(work_dir=run, terminal_status="partial")
    assert report["counts"]["objdiffVerified"] >= 1
    assert any(c["class"] == "objdiff-verified-semantic" for c in report["claims"])
    assert any(c["class"] == "advisory-decompiler" for c in report["claims"])


def test_verified_receipt_tracks_caller_supplied_weaker_tier(tmp_path: Path) -> None:
    """Receipt must not restamp a weaker caller tier as full target-object parity."""

    run = tmp_path / "run"
    src = tmp_path / "fn.c"
    src.write_text("int fn(void){return 0;}\n", encoding="utf-8")
    weaker = "synthetic-target-coff-objdiff"

    published = publish_verified_artifact(
        run,
        stem="fn_00401430",
        source=src,
        metadata={
            "name": "fn",
            "entry": "0x401430",
            "differences": 0,
            "status": "code-slice-matched",
            "proofTier": weaker,
        },
    )

    metadata = json.loads(Path(published["metadata"]).read_text(encoding="utf-8"))
    receipt = json.loads(Path(published["receipt"]).read_text(encoding="utf-8"))
    assert metadata["proofTier"] == weaker
    assert receipt["proofTier"] == weaker
    assert receipt["proofTier"] == metadata["proofTier"]


def test_verified_receipt_defaults_to_objdiff_tier_when_caller_omits_it(tmp_path: Path) -> None:
    run = tmp_path / "run"
    src = tmp_path / "fn.c"
    src.write_text("int fn(void){return 0;}\n", encoding="utf-8")

    published = publish_verified_artifact(
        run,
        stem="fn_00401000",
        source=src,
        metadata={"name": "fn", "entry": "0x401000", "differences": 0},
    )

    metadata = json.loads(Path(published["metadata"]).read_text(encoding="utf-8"))
    receipt = json.loads(Path(published["receipt"]).read_text(encoding="utf-8"))
    assert metadata["proofTier"] == OBJDIFF_PROOF_TIER
    assert receipt["proofTier"] == OBJDIFF_PROOF_TIER


def test_code_slice_artifact_lands_under_verified_code_slice(tmp_path: Path) -> None:
    """Slice proofs belong in verified/code-slice/, not the full-object verified/ root."""

    run = tmp_path / "run"
    src = tmp_path / "fn.c"
    src.write_text("int fn(void){return 0;}\n", encoding="utf-8")

    published = publish_verified_artifact(
        run,
        stem="fn_00401430",
        source=src,
        metadata={
            "name": "fn",
            "entry": "0x401430",
            "differences": 0,
            "status": "code-slice-matched",
            "proofTier": "synthetic-target-coff-objdiff",
        },
    )

    slice_dir = run / "verified" / CODE_SLICE_DIR_NAME
    assert Path(published["source"]).parent == slice_dir
    assert Path(published["metadata"]).parent == slice_dir
    assert Path(published["receipt"]).parent == slice_dir
    assert not list((run / "verified").glob("fn_00401430*"))


@pytest.mark.parametrize(
    "tier",
    ["synthetic-target-object-objdiff", "synthetic-target-coff-objdiff"],
)
def test_both_synthetic_lanes_route_to_code_slice(tmp_path: Path, tier: str) -> None:
    """Both slice lanes file at verified/code-slice/, so neither claims the full-object slot."""

    run = tmp_path / tier
    src = tmp_path / "fn.c"
    src.write_text("int fn(void){return 0;}\n", encoding="utf-8")

    published = publish_verified_artifact(
        run,
        stem="fn_00401430",
        source=src,
        metadata={
            "name": "fn",
            "entry": "0x401430",
            "differences": 0,
            "status": "code-slice-matched",
            "proofTier": tier,
        },
    )

    assert Path(published["metadata"]).parent == run / "verified" / CODE_SLICE_DIR_NAME
    assert build_claim_report(work_dir=run)["counts"]["objdiffVerified"] == 0


def test_full_object_artifact_stays_at_verified_root(tmp_path: Path) -> None:
    run = tmp_path / "run"
    src = tmp_path / "fn.c"
    src.write_text("int fn(void){return 0;}\n", encoding="utf-8")

    published = publish_verified_artifact(
        run,
        stem="fn_00401000",
        source=src,
        metadata={"name": "fn", "entry": "0x401000", "differences": 0, "status": "matched"},
    )

    assert Path(published["source"]).parent == run / "verified"


def test_publish_never_weakens_caller_claim_boundary(tmp_path: Path) -> None:
    """Publish may add a limit; it must never drop the caller's own, stronger one."""

    run = tmp_path / "run"
    src = tmp_path / "fn.c"
    src.write_text("int fn(void){return 0;}\n", encoding="utf-8")
    caller_boundary = (
        "objdiff compares candidate MSVC COFF to a synthetic COFF object made from "
        "target slice bytes; this is code-slice evidence, not full target-object source parity"
    )

    published = publish_verified_artifact(
        run,
        stem="fn_00401430",
        source=src,
        metadata={
            "name": "fn",
            "entry": "0x401430",
            "differences": 0,
            "status": "code-slice-matched",
            "proofTier": "synthetic-target-coff-objdiff",
            "claimBoundary": caller_boundary,
        },
    )

    metadata = json.loads(Path(published["metadata"]).read_text(encoding="utf-8"))
    assert caller_boundary in metadata["claimBoundary"]
    assert "code-slice evidence" in metadata["claimBoundary"]


def test_publish_claim_boundary_is_idempotent(tmp_path: Path) -> None:
    run = tmp_path / "run"
    src = tmp_path / "fn.c"
    src.write_text("int fn(void){return 0;}\n", encoding="utf-8")
    metadata = {"name": "fn", "entry": "0x401000", "differences": 0}

    first = publish_verified_artifact(run, stem="fn_00401000", source=src, metadata=metadata)
    boundary = json.loads(Path(first["metadata"]).read_text(encoding="utf-8"))["claimBoundary"]
    second = publish_verified_artifact(
        run,
        stem="fn_00401000",
        source=src,
        metadata={**metadata, "claimBoundary": boundary},
    )

    assert json.loads(Path(second["metadata"]).read_text(encoding="utf-8"))["claimBoundary"] == boundary


def test_is_code_slice_accept() -> None:
    assert is_code_slice_accept({"status": "code-slice-matched", "differences": 0})
    assert not is_code_slice_accept({"status": "code-slice-matched", "differences": 2})
    assert not is_code_slice_accept({"status": "matched", "differences": 0})
    assert not is_code_slice_accept({"status": "mismatched", "differences": 3})


def test_is_objdiff_zero_accept() -> None:
    assert is_objdiff_zero_accept({"status": "matched", "differences": 0})
    assert is_objdiff_zero_accept(
        {"status": "source-parity-accepted", "proofTier": OBJDIFF_PROOF_TIER}
    )
    assert not is_objdiff_zero_accept({"status": "matched", "differences": 1})
    assert not is_objdiff_zero_accept({"status": "code-slice-matched", "differences": 0})


def test_promote_source_parity_accepts_writes_verified(tmp_path: Path) -> None:
    run = tmp_path / "run"
    package = run / "recovered-source"
    functions = package / "functions"
    functions.mkdir(parents=True)
    accepted = run / "accepted.jsonl"
    candidate = tmp_path / "accepted.c"
    candidate.write_text("int accepted(void){return 1;}\n", encoding="utf-8")
    accepted.write_text(
        json.dumps(
            {
                "status": "matched",
                "differences": 0,
                "name": "accepted",
                "entry": "0x401100",
                "source": str(candidate),
            }
        )
        + "\n",
        encoding="utf-8",
    )
    atomic_write_json(
        package / "manifest.json",
        {
            "status": "partial",
            "functions": [],
            "functionCount": 0,
            "factCount": 0,
            "taskCount": 0,
            "claimBoundary": "test package",
        },
    )

    result = promote_source_parity_accepts(
        {"packageDir": str(package)},
        {"enabled": True, "acceptedPath": str(accepted)},
    )
    assert result["promotedFunctions"] == 1
    verified_files = list((run / "verified").glob("accepted_*"))
    assert verified_files
    assert any(path.suffix == ".c" for path in verified_files)
    assert any("objdiff-verified" in path.name for path in (run / "verified").iterdir())
