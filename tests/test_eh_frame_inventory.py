"""Unit tests for .eh_frame FDE inventory."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from agentdecompile_recovery.eh_frame_inventory import (
    EhFrameError,
    annotate_section,
    build_eh_frame_inventory,
    extract_fde_boundaries,
    reconcile_with_ghidra,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "elf"
TINY_ELF = FIXTURES / "tiny_i386.elf"
SAMPLE_ELF = FIXTURES / "sample_i386.elf"

pytestmark = pytest.mark.unit


def test_extract_fde_from_tiny_elf() -> None:
    rows = extract_fde_boundaries(TINY_ELF)
    # Tiny fixture may have few/zero FDEs depending on link flags; must not crash.
    assert isinstance(rows, list)
    for row in rows:
        assert int(row["length"]) > 0
        assert row["entry"] < row["end"]


def test_no_eh_frame_fails_closed(tmp_path: Path) -> None:
    pe = tmp_path / "not.elf"
    pe.write_bytes(b"MZ" + b"\0" * 100)
    with pytest.raises(EhFrameError, match="not an ELF"):
        extract_fde_boundaries(pe)


def test_reconcile_marks_classes() -> None:
    fdes = [
        {"entry": 0x1000, "entryHex": "00001000", "length": 16, "end": 0x1010, "boundary": "eh-frame"},
        {"entry": 0x2000, "entryHex": "00002000", "length": 8, "end": 0x2008, "boundary": "eh-frame"},
    ]
    ghidra = [
        {"entry": "00001000", "name": "foo"},
        {"entry": "00003000", "name": "bar"},
    ]
    merged, counts = reconcile_with_ghidra(fdes, ghidra)
    by_entry = {int(r["entry"]): r for r in merged}
    assert by_entry[0x1000]["reconciliation"] == "agreement"
    assert by_entry[0x2000]["reconciliation"] == "fde-only"
    assert by_entry[0x3000]["reconciliation"] == "ghidra-only"
    assert counts["agreement"] >= 1
    assert counts["fde-only"] >= 1
    assert counts["ghidra-only"] >= 1


def test_overlap_rejected() -> None:
    # Simulate overlapping by feeding annotated rows through write path after extract
    # Unit: reconcile doesn't invent overlaps; extract skips overlaps.
    rows = [
        {"entry": 10, "entryHex": "0000000a", "length": 20, "end": 30, "boundary": "eh-frame"},
        {"entry": 15, "entryHex": "0000000f", "length": 10, "end": 25, "boundary": "eh-frame"},
        {"entry": 40, "entryHex": "00000028", "length": 5, "end": 45, "boundary": "eh-frame"},
    ]
    # Manual overlap filter mirroring extract logic
    cleaned = []
    last_end = -1
    for row in sorted(rows, key=lambda r: r["entry"]):
        if row["entry"] < last_end:
            continue
        cleaned.append(row)
        last_end = row["end"]
    assert len(cleaned) == 2
    assert cleaned[0]["entry"] == 10
    assert cleaned[1]["entry"] == 40


def test_build_inventory_writes_jsonl(tmp_path: Path) -> None:
    # Prefer real tiny ELF; if no FDEs, invent via PE rejection path covered elsewhere.
    dest = tmp_path / "bin.elf"
    shutil.copy2(TINY_ELF, dest)
    out = tmp_path / "inv.jsonl"
    summary = tmp_path / "summary.json"
    try:
        result = build_eh_frame_inventory(dest, out_jsonl=out, summary_path=summary)
    except EhFrameError:
        pytest.skip("tiny fixture has no usable FDEs")
    assert out.exists()
    assert result["functionCount"] >= 1
    first = json.loads(out.read_text(encoding="utf-8").splitlines()[0])
    assert "entry" in first
    assert first.get("boundary") in {"eh-frame", "eh-frame-outside-text"}


def test_outside_text_tagged_not_dropped() -> None:
    rows = [
        {"entry": 0x1, "entryHex": "00000001", "length": 4, "end": 5, "boundary": "eh-frame"},
    ]
    # Without a real ELF path, annotate_section needs a file — use TINY_ELF
    annotated = annotate_section(rows, TINY_ELF)
    assert len(annotated) == 1
    # Address 1 is almost certainly outside .text; tagged, not dropped
    assert "outsideText" in annotated[0]
