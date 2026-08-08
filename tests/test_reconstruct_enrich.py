"""Unit tests for reconstruct enrich stage helpers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.pipeline import RecoveryConfig, RecoveryRunner, default_function_facts_path
from agentdecompile_recovery.curated_project import CURATED_SIGNATURES_FILENAME
from agentdecompile_recovery.reconstruct_enrich import (
    boundaries_from_candidates,
    run_reconstruct_enrich,
    trusted_curated_signatures,
)

pytestmark = pytest.mark.unit


def test_boundaries_from_candidates_maps_address_and_size() -> None:
    rows = boundaries_from_candidates(
        {
            "candidates": [
                {"name": "Foo", "address": 0x401000, "size": 32, "source": "export"},
                {"name": "Bar", "rva": 0x2000, "source": "rva-only"},
                {"name": "bad"},
            ]
        }
    )
    assert rows[0]["entry"] == 0x401000
    assert rows[0]["length"] == 32
    assert rows[0]["name"] == "Foo"
    assert rows[1]["entry"] == 0x2000
    assert len(rows) == 2


def test_run_reconstruct_enrich_skip_writes_receipt(tmp_path: Path) -> None:
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x00" * 16)
    receipt = run_reconstruct_enrich(
        binary=binary,
        work_dir=tmp_path,
        candidates_payload={"candidates": [{"address": 0x1000, "name": "x"}]},
        skip=True,
    )
    assert receipt["status"] == "skipped"
    assert receipt["reason"] == "skip-enrichment"
    assert (tmp_path / "facts" / "enrich-receipt.json").is_file()


def test_run_reconstruct_enrich_no_candidates(tmp_path: Path) -> None:
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x00" * 16)
    receipt = run_reconstruct_enrich(
        binary=binary,
        work_dir=tmp_path,
        candidates_payload={"candidates": []},
        skip=False,
    )
    assert receipt["status"] == "skipped"
    assert receipt["reason"] == "no-function-candidates"


def test_default_function_facts_path_prefers_facts_dir(tmp_path: Path) -> None:
    facts = tmp_path / "facts"
    facts.mkdir()
    preferred = facts / "function-facts.jsonl"
    preferred.write_text("{}\n", encoding="utf-8")
    (tmp_path / "function-facts.jsonl").write_text("{}\n", encoding="utf-8")
    assert default_function_facts_path(tmp_path) == preferred


def test_pipeline_includes_enrich_stage(tmp_path: Path) -> None:
    config = RecoveryConfig(
        input_path=tmp_path / "x.bin",
        work_dir=tmp_path / "work",
        skip_enrichment=True,
    )
    runner = RecoveryRunner(config)
    names = [stage.name for stage in runner.stages]
    assert "enrich-decompile" in names
    assert names.index("analyze-functions") < names.index("enrich-decompile")
    assert names.index("enrich-decompile") < names.index("generate-source-candidates")


def test_stage_enrich_decompile_skip(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    (work / "function-candidates.json").write_text(
        json.dumps({"candidates": [{"address": 0x1000, "name": "Foo", "size": 8}]}),
        encoding="utf-8",
    )
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x00" * 32)
    (work / "analysis-target.json").write_text(
        json.dumps({"analysisBinaryPath": str(binary)}),
        encoding="utf-8",
    )
    config = RecoveryConfig(input_path=binary, work_dir=work, skip_enrichment=True)
    runner = RecoveryRunner(config)
    stage = next(s for s in runner.stages if s.name == "enrich-decompile")
    summary = runner.stage_enrich_decompile(stage)
    assert summary["status"] == "skipped"
    assert (work / "facts" / "enrich-receipt.json").is_file()


# -- trusted_curated_signatures ------------------------------------------------


def _write_signatures(work_dir: Path, payload: dict[str, dict[str, object]]) -> None:
    (work_dir / CURATED_SIGNATURES_FILENAME).write_text(json.dumps(payload), encoding="utf-8")


def test_trusted_curated_signatures_drops_records_the_arity_gate_rejected(tmp_path: Path) -> None:
    """A contradicted prototype must never reach candidate generation.

    `curated_enrichment` reports the contradiction by emitting `signature:
    null` while keeping the name; this is the consumer side of that contract.
    """

    _write_signatures(
        tmp_path,
        {
            "00401060": {"name": "Kept", "arityCheck": "match", "signature": "void Kept(int)"},
            "00401380": {"name": "Dropped", "arityCheck": "contradicted", "signature": None},
        },
    )

    trusted = trusted_curated_signatures(
        tmp_path, [{"entry": 0x401060}, {"entry": 0x401380}]
    )

    assert list(trusted) == [0x401060]


def test_trusted_curated_signatures_ignores_entries_this_run_will_not_decompile(
    tmp_path: Path,
) -> None:
    _write_signatures(
        tmp_path,
        {
            "00401060": {"name": "InRun", "arityCheck": "match", "signature": "void InRun(void)"},
            "00999000": {"name": "Elsewhere", "arityCheck": "match", "signature": "void E(void)"},
        },
    )

    trusted = trusted_curated_signatures(tmp_path, [{"entry": 0x401060}])

    assert list(trusted) == [0x401060]


def test_trusted_curated_signatures_is_empty_without_a_curated_project(tmp_path: Path) -> None:
    assert trusted_curated_signatures(tmp_path, [{"entry": 0x401060}]) == {}
