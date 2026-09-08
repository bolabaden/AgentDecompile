"""Apply a jsonl annotation set to a Ghidra program.

Dry-run by default. Refuses to rename a function whose current name is not a
Ghidra default, so an accidental apply cannot destroy hand-written work.
``program`` is a required Ghidra path — there is no product-repo default.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import ghidra_env as ge

DEFAULT_PREFIXES = ("FUN_", "SUB_", "thunk_FUN_", "UndefinedFunction_")


def load_records(
    jsonl: Path | str,
    *,
    min_confidence: float = 0.95,
    status: str = "auto",
) -> list[dict]:
    path = Path(jsonl)
    allowed = {s.strip() for s in status.split(",") if s.strip()}
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [
        row
        for row in records
        if float(row["confidence"]) >= min_confidence and row["status"] in allowed
    ]


def apply_annotations(
    jsonl: Path | str,
    program: str,
    *,
    apply: bool = False,
    min_confidence: float = 0.95,
    status: str = "auto",
    comments: bool = True,
) -> dict:
    """Filter *jsonl* and optionally write names onto *program*.

    *program* is required (Ghidra repository path or local ``ghidra:`` URL).
    Default is a dry run.
    """
    if not program:
        raise ValueError("program is required (Ghidra path); there is no default")
    records = load_records(jsonl, min_confidence=min_confidence, status=status)
    preview = [
        {
            "address": row.get("address"),
            "canonical": row.get("canonical") or row.get("name"),
            "confidence": row.get("confidence"),
        }
        for row in records[:10]
    ]
    result: dict = {
        "program": program,
        "candidates": len(records),
        "dry_run": not apply,
        "preview": preview,
    }
    if not apply:
        return result

    if not ge.start():
        result["error"] = "ghidra unavailable"
        result["applied"] = 0
        result["skipped"] = 0
        return result

    from ghidra.program.model.symbol import SourceType

    df = ge.domain_file(program)
    if df.isReadOnly() or df.isVersioned() and not df.isCheckedOut():
        result["error"] = "repository copy is read-only; check the program out first"
        result["applied"] = 0
        result["skipped"] = 0
        return result

    program_obj = df.getDomainObject(ge.consumer(), True, False, ge.monitor())
    tx = program_obj.startTransaction("corpus annotations")
    applied = skipped = 0
    try:
        space = program_obj.getAddressFactory().getDefaultAddressSpace()
        fm = program_obj.getFunctionManager()
        st = program_obj.getSymbolTable()
        for row in records:
            addr = space.getAddress(int(row["address"], 16))
            func = fm.getFunctionAt(addr)
            if func is None or not str(func.getName()).startswith(DEFAULT_PREFIXES):
                skipped += 1
                continue
            ns = None
            if row.get("namespace"):
                ns = st.getNamespace(row["namespace"], None)
                if ns is None:
                    ns = st.createClass(None, row["namespace"], SourceType.IMPORTED)
            func.setName(row["name"], SourceType.IMPORTED)
            if ns is not None:
                func.setParentNamespace(ns)
            if comments and row.get("plate_comment"):
                func.setComment(row["plate_comment"])
            applied += 1
        program_obj.endTransaction(tx, True)
        df.save(ge.monitor())
    except Exception:
        program_obj.endTransaction(tx, False)
        raise
    finally:
        program_obj.release(ge.consumer())
    result["applied"] = applied
    result["skipped"] = skipped
    return result
