"""Aggregate byte-exact coverage across supervised recovery run ledgers."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path


def load_inventory_totals(inventory_path: Path | None) -> dict[str, int]:
    if inventory_path is None or not Path(inventory_path).is_file():
        return {}
    try:
        rows = json.loads(Path(inventory_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(rows, list):
        return {}
    out = {}
    for row in rows:
        if isinstance(row, dict) and row.get("name"):
            try:
                out[str(row["name"])] = int(row.get("functions") or 0)
            except (TypeError, ValueError):
                continue
    return out


def summarize(
    coverage_dir: Path,
    *,
    inventory_path: Path | None = None,
) -> dict:
    """Read ``*.jsonl`` ledgers and return structured coverage stats."""
    cov = Path(coverage_dir)
    totals = load_inventory_totals(inventory_path)
    rows = []
    grand: dict[str, int] = defaultdict(int)
    band_stats: dict[str, list[int]] = defaultdict(lambda: [0, 0])

    if not cov.is_dir():
        return {"error": f"no coverage directory: {cov}", "rows": [], "grand": {}}

    for path in sorted(cov.glob("*.jsonl")):
        program = path.stem
        attempted = matched = exact = infra = 0
        failures: dict[str, int] = defaultdict(int)
        seen: set[str] = set()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            key = row.get("function")
            if not key or key in seen:
                continue
            seen.add(str(key))
            attempted += 1
            if row.get("infraError"):
                infra += 1
                continue
            if row.get("matched"):
                matched += 1
            if row.get("byteExact"):
                exact += 1
            else:
                failures[(row.get("error") or "unknown")[:40]] += 1
            size = int(row.get("size") or 0)
            if size <= 8:
                band = "<=8"
            elif size <= 16:
                band = "<=16"
            elif size <= 32:
                band = "<=32"
            elif size <= 128:
                band = "<=128"
            elif size <= 512:
                band = "<=512"
            else:
                band = ">512"
            band_stats[band][0] += 1
            if row.get("byteExact"):
                band_stats[band][1] += 1
        attempted -= infra
        top = sorted(failures.items(), key=lambda kv: -kv[1])[:1]
        suspect = matched >= 10 and exact == 0
        note = (
            "SUSPECT: matched>0 but zero byte-exact and no reason recorded"
            if suspect
            else (top[0][0] if top else "")
        )
        rows.append(
            {
                "program": program,
                "attempted": attempted,
                "matched": matched,
                "exact": exact,
                "corpus_total": totals.get(program, 0),
                "note": note,
                "suspect": suspect,
                "infra_excluded": infra,
            }
        )
        if suspect:
            grand["suspect_programs"] += 1
            grand["suspect_rows"] += attempted
            continue
        grand["attempted"] += attempted
        grand["matched"] += matched
        grand["exact"] += exact

    return {
        "rows": rows,
        "grand": dict(grand),
        "band_stats": {k: {"tried": v[0], "exact": v[1]} for k, v in band_stats.items()},
        "corpus_functions": sum(totals.values()),
        "corpus_programs": len(totals),
    }


def format_report(summary: dict) -> str:
    rows = summary.get("rows") or []
    grand = summary.get("grand") or {}
    if summary.get("error"):
        return str(summary["error"])
    w = max([len(r["program"]) for r in rows] + [20])
    lines = [f"{'program':{w}s} {'tried':>7s} {'objdiff':>8s} {'BYTE-EXACT':>11s} {'of total':>10s}  note"]
    for row in rows:
        a, m, e = row["attempted"], row["matched"], row["exact"]
        pct = "--" if row["suspect"] else (f"{100.0 * e / a:.0f}%" if a else "-")
        infra_note = f" [+{row['infra_excluded']} infra-error, excluded]" if row["infra_excluded"] else ""
        lines.append(
            f"{row['program']:{w}s} {a:7d} {m:8d} {e:11d} {row['corpus_total']:10d}  {pct:>4s} {row['note']}{infra_note}"
        )
    lines.append("-" * (w + 45))
    a, m, e = grand.get("attempted", 0), grand.get("matched", 0), grand.get("exact", 0)
    pct = f"{100.0 * e / a:.1f}%" if a else "-"
    lines.append(f"{'TOTAL':{w}s} {a:7d} {m:8d} {e:11d}   byte-exact rate {pct}")
    if grand.get("suspect_programs"):
        lines.append(
            f"EXCLUDED from the total: {grand['suspect_programs']} program(s), "
            f"{grand.get('suspect_rows', 0)} rows, whose ledgers are suspect (see note)."
        )
    corpus = summary.get("corpus_functions") or 0
    if corpus:
        lines.append(
            f"corpus: {corpus} functions across {summary.get('corpus_programs', 0)} programs; "
            f"byte-exact coverage of corpus = {100.0 * e / corpus:.4f}%"
        )
    band_stats = summary.get("band_stats") or {}
    if band_stats:
        lines.append("\nby function size:")
        for band in ["<=8", "<=16", "<=32", "<=128", "<=512", ">512"]:
            stats = band_stats.get(band)
            if stats and stats["tried"]:
                tried, ok = stats["tried"], stats["exact"]
                lines.append(f"  {band:>6s}  {ok:5d}/{tried:<5d} byte-exact  ({100.0 * ok / tried:.0f}%)")
    return "\n".join(lines)
