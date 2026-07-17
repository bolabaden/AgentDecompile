"""Unit tests for verified/ vs advisory/ artifact segregation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.artifact_layout import (
    OBJDIFF_PROOF_TIER,
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
