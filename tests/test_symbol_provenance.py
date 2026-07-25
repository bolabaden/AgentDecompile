"""Unit tests for symbol provenance ingest."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.symbol_provenance import ingest_symbol_provenance

pytestmark = pytest.mark.unit


def test_symbol_provenance_skips_without_binary(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    receipt = ingest_symbol_provenance(work)
    assert receipt["status"] == "skipped:no-binary"


def test_symbol_provenance_skips_pe_without_exports(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    binary = work / "game.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 100)
    (work / "analysis-target.json").write_text(
        f'{{"analysisBinaryPath": "{binary}"}}',
        encoding="utf-8",
    )
    receipt = ingest_symbol_provenance(work)
    assert receipt["status"] == "skipped:no-symbols"
    assert receipt.get("reason") == "pe-no-export-or-pdb"

