"""Export structurally matched functions whose independent method names disagree."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


def export_sibling_conflicts(con, outdir: Path) -> dict[str, int]:
    named = {
        (row["binary_id"], row["addr"]): dict(row)
        for row in con.execute(
            """SELECT binary_id, addr, canon_class, canon_method, canon_key
                 FROM func NOT INDEXED
                WHERE canon_class IS NOT NULL AND canon_class<>''
                  AND canon_method IS NOT NULL"""
        )
    }
    slugs = {row["id"]: row["slug"] for row in con.execute("SELECT id, slug FROM binary")}
    records = []
    auto_name_conflicts = 0
    for match in con.execute(
        """SELECT id, status, score, margin, src_binary, src_addr,
                  dst_binary, dst_addr
             FROM match NOT INDEXED
            WHERE status IN ('auto', 'verify')"""
    ):
        src = named.get((match["src_binary"], match["src_addr"]))
        dst = named.get((match["dst_binary"], match["dst_addr"]))
        if not src or not dst:
            continue
        if match["status"] == "auto" and src["canon_key"] != dst["canon_key"]:
            auto_name_conflicts += 1
        if src["canon_class"] != dst["canon_class"]:
            continue
        if src["canon_method"] == dst["canon_method"]:
            continue
        records.append({
            "id": match["id"],
            "status": match["status"],
            "score": match["score"],
            "margin": match["margin"],
            "cls": src["canon_class"],
            "src_m": src["canon_method"],
            "dst_m": dst["canon_method"],
            "src_key": src["canon_key"],
            "dst_key": dst["canon_key"],
            "src_slug": slugs[match["src_binary"]],
            "dst_slug": slugs[match["dst_binary"]],
            "src_addr": match["src_addr"],
            "dst_addr": match["dst_addr"],
        })
    records.sort(key=lambda row: (row["status"], -row["score"], row["id"]))

    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    grouped = {"auto": [], "verify": []}
    for row in records:
        rec = dict(row)
        rec["src_addr"] = f"{rec['src_addr']:08x}"
        rec["dst_addr"] = f"{rec['dst_addr']:08x}"
        grouped[rec["status"]].append(rec)

    for status, items in grouped.items():
        path = outdir / f"sibling_{status}.jsonl"
        with path.open("w", encoding="utf-8") as fh:
            for rec in items:
                fh.write(json.dumps(rec) + "\n")

    summary = dict(Counter({status: len(items) for status, items in grouped.items()}))
    summary["auto_name_conflicts"] = auto_name_conflicts
    (outdir / "sibling_conflicts_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    return summary
