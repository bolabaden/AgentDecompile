"""Derive acceptance thresholds from measured ground truth."""

from __future__ import annotations

from collections import defaultdict

SCORE_GRID = [0.70, 0.75, 0.80, 0.84, 0.86, 0.88, 0.90, 0.92, 0.94, 0.96, 0.98]
MARGIN_GRID = [0.0, 0.04, 0.06, 0.08, 0.12]


def sweep(rows, margin_min: float, content_min: int):
    """rows: (score, margin, content, compunit, correct)."""
    out = []
    for thr in SCORE_GRID:
        sel = [
            r
            for r in rows
            if r[0] >= thr and r[1] >= margin_min and (r[2] or 0) >= content_min and r[3] != 0.0
        ]
        n = len(sel)
        correct = sum(r[4] for r in sel)
        out.append(
            {
                "score_min": thr,
                "accepted": n,
                "precision": round(correct / n, 4) if n else None,
                "recall_of_gt": round(correct / len(rows), 4) if rows else None,
            }
        )
    return out


def calibrate_evaluations(records: list[dict]) -> dict:
    by_class = defaultdict(list)
    per_pair = {}
    for rec in records:
        raw = rec.get("raw_decisions")
        if not raw:
            continue
        cls = rec.get("pair_class", "unknown")
        by_class[cls] += raw
        per_pair[f"{rec.get('src_slug')} -> {rec.get('dst_slug')}"] = {
            "pair_class": cls,
            "gt": rec.get("gt_pairs"),
        }
    sweeps = {}
    for cls, rows in by_class.items():
        sweeps[cls] = {
            f"margin>={m}_content>={c}": sweep(rows, m, c)
            for m in MARGIN_GRID
            for c in (0, 1, 2)
        }
    return {"by_class": sweeps, "pairs": per_pair}
