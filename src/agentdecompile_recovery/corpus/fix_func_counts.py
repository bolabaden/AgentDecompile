"""Separate "functions Ghidra knows a name for" from "functions with code".

Adds ``code_func_count`` alongside ``func_count``. Stub rows stay: they carry
real names. Callers pass the store and the report path.
"""

from __future__ import annotations

import json
from pathlib import Path


def measure(con) -> list[dict]:
    rows = []
    for binary in con.execute("SELECT id, slug, repo_path, func_count FROM binary ORDER BY slug"):
        code = con.execute(
            "SELECT COUNT(*) FROM func WHERE binary_id=? AND n_instr>0 AND size>0",
            (binary["id"],),
        ).fetchone()[0]
        stubs = con.execute(
            "SELECT COUNT(*) FROM func WHERE binary_id=? AND (n_instr IS NULL OR n_instr=0)",
            (binary["id"],),
        ).fetchone()[0]
        named_stubs = con.execute(
            "SELECT COUNT(*) FROM func WHERE binary_id=? AND (n_instr IS NULL OR n_instr=0) "
            "AND name IS NOT NULL AND name <> '' "
            "AND name NOT LIKE 'FUN_%' AND name NOT LIKE 'sub_%' "
            "AND name NOT LIKE 'LAB_%' AND name NOT LIKE 'Unwind%'",
            (binary["id"],),
        ).fetchone()[0]
        total = binary["func_count"] or 0
        rows.append(
            {
                "binary_id": binary["id"],
                "slug": binary["slug"],
                "repo_path": binary["repo_path"],
                "func_count": total,
                "code_func_count": code,
                "stub_count": stubs,
                "named_stub_count": named_stubs,
                "stub_pct": round(stubs / total * 100, 1) if total else 0.0,
            }
        )
    return rows


def apply(con, rows: list[dict]) -> None:
    cols = {r[1] for r in con.execute("PRAGMA table_info(binary)")}
    if "code_func_count" not in cols:
        con.execute("ALTER TABLE binary ADD COLUMN code_func_count INTEGER")
    for row in rows:
        con.execute(
            "UPDATE binary SET code_func_count=? WHERE id=?",
            (row["code_func_count"], row["binary_id"]),
        )
    con.commit()


def write_report(rows: list[dict], dest: Path | str) -> Path:
    """Write the audit JSON to *dest* (required)."""
    path = Path(dest)
    path.parent.mkdir(parents=True, exist_ok=True)
    totals = {
        "func_count": sum(r["func_count"] for r in rows),
        "code_func_count": sum(r["code_func_count"] for r in rows),
        "stub_count": sum(r["stub_count"] for r in rows),
        "named_stub_count": sum(r["named_stub_count"] for r in rows),
    }
    path.write_text(json.dumps({"binaries": rows, "totals": totals}, indent=1), encoding="utf-8")
    return path


def audit(con, *, apply_counts: bool = False, report_path: Path | str | None = None) -> dict:
    rows = measure(con)
    if apply_counts:
        apply(con, rows)
    written = write_report(rows, report_path) if report_path is not None else None
    return {"binaries": rows, "applied": apply_counts, "report": str(written) if written else None}
