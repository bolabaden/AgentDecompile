"""Unit tests for pyghidra enrich fact writing."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.pyghidra_enrich import FakeEnrichProgram, run_enrich_pipeline

pytestmark = pytest.mark.unit


def test_run_enrich_pipeline_writes_facts(tmp_path: Path) -> None:
    out = tmp_path / "facts.jsonl"
    summary = run_enrich_pipeline(
        boundaries=[{"entry": 0x1000, "length": 8}],
        corpus=None,
        rtti_classes=[],
        out_facts=out,
        program_factory=FakeEnrichProgram,
    )
    assert out.exists()
    assert summary["functionCount"] == 1
    assert (tmp_path / "enrich-receipt.json").exists() or (out.parent / "enrich-receipt.json").exists()


def test_build_names_by_entry_prefers_ghidra_symbols() -> None:
    from agentdecompile_recovery.pyghidra_enrich import build_names_by_entry

    names = build_names_by_entry(
        discovered=[
            {"entry": 0x1000, "name": "FUN_001000"},
            {"entry": 0x2000, "name": "LoadArea"},
        ]
    )
    assert 0x1000 not in names
    assert names[0x2000] == ("LoadArea", "ghidra-symbol")
