"""Authoritative function boundaries from ELF `.eh_frame` FDEs."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any, Iterable

from elftools.dwarf.callframe import CIE, CallFrameInfo, FDE
from elftools.dwarf.structs import DWARFStructs
from elftools.elf.elffile import ELFFile

from .elf_target import elf_section_rows


class EhFrameError(RuntimeError):
    """Raised when `.eh_frame` inventory cannot be produced."""


def _dwarf_structs_for_elf(elf: ELFFile) -> DWARFStructs:
    elfclass = elf.elfclass
    address_size = 8 if elfclass == 64 else 4
    little = elf.little_endian
    return DWARFStructs(
        little_endian=little,
        dwarf_format=32,
        address_size=address_size,
        dwarf_version=4,
    )


def extract_fde_boundaries(path: Path) -> list[dict[str, Any]]:
    """Return sorted unique FDE ranges: start, length, end (virtual addresses)."""
    with path.open("rb") as fh:
        if fh.read(4) != b"\x7fELF":
            raise EhFrameError(f"not an ELF binary: {path}")
        fh.seek(0)
        elf = ELFFile(fh)
        eh = elf.get_section_by_name(".eh_frame")
        if eh is None:
            raise EhFrameError(f"no .eh_frame section in {path}")
        data = eh.data()
        if not data:
            raise EhFrameError(f"empty .eh_frame section in {path}")
        structs = _dwarf_structs_for_elf(elf)
        cfi = CallFrameInfo(
            io.BytesIO(data),
            len(data),
            int(eh["sh_addr"]),
            structs,
            for_eh_frame=True,
        )
        rows: list[dict[str, Any]] = []
        seen: set[tuple[int, int]] = set()
        for entry in cfi.get_entries():
            if isinstance(entry, CIE):
                continue
            if not isinstance(entry, FDE):
                continue
            header = entry.header
            start = int(header["initial_location"])
            length = int(header["address_range"])
            if length <= 0:
                continue
            key = (start, length)
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "entry": start,
                    "entryHex": f"{start:08x}",
                    "length": length,
                    "end": start + length,
                    "boundary": "eh-frame",
                    "provenance": "eh-frame",
                }
            )
    rows.sort(key=lambda row: int(row["entry"]))
    # Reject overlapping ranges (keep first / longest preference: first by address).
    cleaned: list[dict[str, Any]] = []
    last_end = -1
    for row in rows:
        start = int(row["entry"])
        end = int(row["end"])
        if start < last_end:
            # Overlap with previous — skip the overlapping one.
            continue
        cleaned.append(row)
        last_end = end
    return cleaned


def text_section_bounds(path: Path) -> tuple[int, int] | None:
    """Return (start, end) VA for `.text` or primary executable section."""
    rows = elf_section_rows(path)
    by_name = {str(r["name"]): r for r in rows}
    section = by_name.get(".text")
    if section is None:
        exec_rows = [r for r in rows if r.get("executable")]
        if not exec_rows:
            return None
        section = max(exec_rows, key=lambda r: int(r.get("size") or 0))
    start = int(section["addr"])
    size = int(section["size"])
    return start, start + size


def annotate_section(rows: list[dict[str, Any]], path: Path) -> list[dict[str, Any]]:
    """Tag rows with section name; mark out-of-.text without dropping."""
    bounds = text_section_bounds(path)
    section_rows = elf_section_rows(path)
    out: list[dict[str, Any]] = []
    for row in rows:
        entry = int(row["entry"])
        section_name = ""
        for sec in section_rows:
            s = int(sec["addr"])
            e = s + int(sec["size"])
            if s <= entry < e:
                section_name = str(sec["name"])
                break
        annotated = dict(row)
        annotated["section"] = section_name or None
        if bounds is not None:
            lo, hi = bounds
            if not (lo <= entry < hi):
                annotated["outsideText"] = True
                annotated["boundary"] = "eh-frame-outside-text"
            else:
                annotated["outsideText"] = False
                if not annotated.get("section"):
                    annotated["section"] = ".text"
        out.append(annotated)
    return out


def reconcile_with_ghidra(
    fde_rows: list[dict[str, Any]],
    ghidra_rows: Iterable[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Merge FDE inventory with Ghidra discoveries.

    FDE entries are authoritative. Ghidra-only entries are kept and tagged.
    """
    by_entry: dict[int, dict[str, Any]] = {}
    for row in fde_rows:
        by_entry[int(row["entry"])] = dict(row)

    counts = {"agreement": 0, "fde-only": 0, "ghidra-only": 0}
    ghidra_entries: set[int] = set()
    for grow in ghidra_rows:
        raw = grow.get("entry") or grow.get("entryOffset") or grow.get("address")
        if raw is None:
            continue
        try:
            if isinstance(raw, str):
                text = raw.strip().lower().replace("0x", "")
                entry = int(text, 16)
            else:
                entry = int(raw)
        except (TypeError, ValueError):
            continue
        ghidra_entries.add(entry)
        if entry in by_entry:
            existing = by_entry[entry]
            existing["reconciliation"] = "agreement"
            if grow.get("name") and not existing.get("name"):
                existing["name"] = grow.get("name")
            if grow.get("section") and not existing.get("section"):
                existing["section"] = grow.get("section")
            counts["agreement"] += 1
        else:
            by_entry[entry] = {
                "entry": entry,
                "entryHex": f"{entry:08x}",
                "length": grow.get("bodyBytes") or grow.get("length") or grow.get("size"),
                "name": grow.get("name"),
                "section": grow.get("section"),
                "boundary": "ghidra-only",
                "provenance": "ghidra",
                "reconciliation": "ghidra-only",
                "outsideText": False,
            }
            counts["ghidra-only"] += 1

    for entry, row in by_entry.items():
        if row.get("reconciliation"):
            continue
        if entry in ghidra_entries:
            row["reconciliation"] = "agreement"
            counts["agreement"] += 1
        else:
            row["reconciliation"] = "fde-only"
            counts["fde-only"] += 1

    merged = sorted(by_entry.values(), key=lambda r: int(r["entry"]))
    return merged, counts


def write_inventory_jsonl(
    path: Path,
    rows: list[dict[str, Any]],
    *,
    summary_path: Path | None = None,
    extra_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Write inventory JSONL and optional summary JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            payload = {
                "entry": row.get("entryHex") or f"{int(row['entry']):08x}",
                "entryOffset": int(row["entry"]),
                "name": row.get("name") or f"FUN_{int(row['entry']):08x}",
                "section": row.get("section"),
                "bodyBytes": row.get("length"),
                "length": row.get("length"),
                "boundary": row.get("boundary"),
                "provenance": row.get("provenance"),
                "reconciliation": row.get("reconciliation"),
                "outsideText": row.get("outsideText", False),
            }
            fh.write(json.dumps(payload, sort_keys=True) + "\n")
    summary = {
        "schema": "agentdecompile.eh-frame-inventory.v1",
        "functionCount": len(rows),
        "source": str(path),
        **(extra_summary or {}),
    }
    if summary_path is not None:
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def build_eh_frame_inventory(
    binary: Path,
    *,
    ghidra_jsonl: Path | None = None,
    out_jsonl: Path,
    summary_path: Path | None = None,
) -> dict[str, Any]:
    """Extract FDEs, optionally reconcile with Ghidra JSONL, write inventory."""
    fdes = annotate_section(extract_fde_boundaries(binary), binary)
    if not fdes:
        raise EhFrameError(f"no usable FDEs in {binary}")
    ghidra_rows: list[dict[str, Any]] = []
    if ghidra_jsonl is not None and ghidra_jsonl.exists():
        with ghidra_jsonl.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    ghidra_rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    merged, counts = reconcile_with_ghidra(fdes, ghidra_rows)
    summary = write_inventory_jsonl(
        out_jsonl,
        merged,
        summary_path=summary_path,
        extra_summary={
            "binaryPath": str(binary),
            "fdeCount": len(fdes),
            "reconciliation": counts,
            "textSection": ".text",
        },
    )
    return summary
