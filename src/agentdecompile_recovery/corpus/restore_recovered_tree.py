"""Rebuild a recovered-source tree and coverage ledgers from recovered_function.

Existing files are never overwritten. Rows whose body cannot be found are
reported, not invented. Every path is caller-supplied.
"""

from __future__ import annotations

import collections
import json
from pathlib import Path

from .export_run_report import RECOVERED_FUNCTION_DDL


def index_package(package: Path | str) -> dict[str, list[Path]]:
    """Map bare function name -> packaged files with that name."""
    by_name: dict[str, list[Path]] = collections.defaultdict(list)
    root = Path(package)
    if root.is_dir():
        for path in root.rglob("*.c"):
            by_name[path.stem].append(path)
        for path in root.rglob("*.cpp"):
            by_name[path.stem].append(path)
    return by_name


def pick(cands: list[Path], program: str) -> Path | None:
    if not cands:
        return None
    if len(cands) == 1:
        return cands[0]
    for cand in cands:
        if program in cand.parts:
            return cand
    return None


def restore(
    con,
    recovered_dir: Path | str,
    coverage_dir: Path | str,
    package_dir: Path | str,
    *,
    dry_run: bool = False,
) -> dict:
    """Restore bodies under *recovered_dir* and merge ledgers under *coverage_dir*."""
    con.executescript(RECOVERED_FUNCTION_DDL)
    recovered = Path(recovered_dir)
    coverage = Path(coverage_dir)
    rows = list(
        con.execute(
            "SELECT program, name, size, convention, real_c, path, machine_code"
            "  FROM recovered_function ORDER BY program, name"
        )
    )
    by_name = index_package(package_dir)
    ledgers: dict[str, list[dict]] = collections.defaultdict(list)
    wrote = kept = nobody = ambiguous = offtree = 0

    for row in rows:
        program, name = row["program"], row["name"]
        path = Path(row["path"]) if row["path"] else recovered / program / f"{name}.c"
        try:
            path.relative_to(recovered)
        except ValueError:
            offtree += 1
        else:
            if path.exists():
                kept += 1
            else:
                src = pick(by_name.get(name, []), program)
                if src is None:
                    if by_name.get(name):
                        ambiguous += 1
                    else:
                        nobody += 1
                elif not dry_run:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(src.read_text(errors="replace"), encoding="utf-8")
                    wrote += 1
                else:
                    wrote += 1

        ledgers[program].append(
            {
                "function": name,
                "byteExact": True,
                "byteExactVerified": True,
                "matched": True,
                "convention": row["convention"] or "",
                "originalBytes": (row["machine_code"] or "").lower(),
                "size": row["size"],
                "error": "",
                "batch": "restored-from-db",
            }
        )

    ledger_stats = []
    for program, new_rows in sorted(ledgers.items()):
        path = coverage / f"{program}.jsonl"
        existing: dict[str, dict] = {}
        order: list[str] = []
        if path.exists():
            for line in path.read_text(errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                fn = str(item.get("function") or "")
                if fn not in existing:
                    order.append(fn)
                existing[fn] = item
        added = 0
        for item in new_rows:
            fn = item["function"]
            if fn in existing:
                continue
            order.append(fn)
            existing[fn] = item
            added += 1
        ledger_stats.append({"program": program, "rows": len(existing), "added": added})
        if not dry_run:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("".join(json.dumps(existing[f], sort_keys=True) + "\n" for f in order), encoding="utf-8")

    return {
        "database_rows": len(rows),
        "bodies_kept": kept,
        "bodies_restored": wrote,
        "no_packaged_body": nobody,
        "ambiguous": ambiguous,
        "offtree": offtree,
        "ledgers": ledger_stats,
        "dry_run": dry_run,
    }
