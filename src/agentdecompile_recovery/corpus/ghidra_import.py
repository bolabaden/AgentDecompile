"""Apply a name/source map onto a live Ghidra program. Names only — no bytes."""

from __future__ import annotations

from typing import Any


def apply_names(program, rows: list[dict[str, Any]]) -> dict[str, int]:
    """Rename functions at ``addr`` when the incoming name is stronger than placeholder."""
    from ghidra.program.model.symbol import SourceType

    fm = program.getFunctionManager()
    space = program.getAddressFactory().getDefaultAddressSpace()
    renamed = skipped = missing = 0
    for row in rows:
        addr = row.get("addr")
        name = (row.get("name") or row.get("stabs_name") or "").strip()
        if addr is None or not name:
            skipped += 1
            continue
        func = fm.getFunctionAt(space.getAddress(int(addr)))
        if func is None:
            missing += 1
            continue
        current = str(func.getName())
        if current == name:
            skipped += 1
            continue
        func.setName(name, SourceType.USER_DEFINED)
        renamed += 1
    return {"renamed": renamed, "skipped": skipped, "missing": missing}
