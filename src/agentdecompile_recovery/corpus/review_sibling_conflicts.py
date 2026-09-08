"""Conservatively resolve the independent-name sibling review queue."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


def game_of_slug(slug: str) -> str:
    """Game is the operator-supplied prefix before ``__`` on a binary slug."""
    return slug.split("__", 1)[0]


def classify(row: dict) -> dict:
    """Reject same-game name contradictions; retain cross-game rename cases."""
    decision = dict(row)
    if game_of_slug(row["src_slug"]) == game_of_slug(row["dst_slug"]):
        decision.update(
            decision="rejected",
            reason="independent_same_game_names_disagree",
        )
    else:
        decision.update(
            decision="verify",
            reason="cross_game_rename_requires_evidence",
        )
    return decision


def run(queue_path: Path, outdir: Path, con=None, *, apply: bool = False) -> dict:
    rows = [json.loads(line) for line in Path(queue_path).read_text(encoding="utf-8").splitlines() if line]
    decisions = [classify(row) for row in rows]
    rejected_ids = [row["id"] for row in decisions if row["decision"] == "rejected"]
    changed = 0
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    if apply:
        if con is None:
            raise ValueError("apply=True requires an open store connection")
        con.execute("BEGIN IMMEDIATE")
        try:
            before = con.total_changes
            con.executemany(
                "UPDATE match SET status='rejected' WHERE id=? AND status='verify'",
                [(match_id,) for match_id in rejected_ids],
            )
            changed = con.total_changes - before
            con.commit()
        except Exception:
            con.rollback()
            raise

    (outdir / "sibling_decisions.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in decisions), encoding="utf-8"
    )
    if apply:
        (outdir / "sibling_verify.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in rows if classify(row)["decision"] == "verify"),
            encoding="utf-8",
        )
        (outdir / "sibling_rejected.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in decisions if row["decision"] == "rejected"),
            encoding="utf-8",
        )
    counts = Counter(row["decision"] for row in decisions)
    summary = {
        "queue_rows": len(decisions),
        "rejected": counts["rejected"],
        "verify": counts["verify"],
        "database_rows_changed": changed,
        "applied": apply,
    }
    (outdir / "sibling_decisions_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary
