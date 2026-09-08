from __future__ import annotations

import json
from pathlib import Path

from agentdecompile_recovery.corpus.review_cross_game_conflicts import classify, load_candidates
from agentdecompile_recovery.corpus.review_sibling_conflicts import classify as classify_sibling


def test_same_game_independent_name_conflict_is_rejected() -> None:
    decision = classify_sibling(
        {"src_slug": "G1__win.exe", "dst_slug": "G1__mac.app", "src_key": "C::Enable", "dst_key": "C::Disable"}
    )
    assert decision["decision"] == "rejected"
    assert decision["reason"] == "independent_same_game_names_disagree"


def test_cross_game_name_conflict_stays_verify() -> None:
    decision = classify_sibling(
        {"src_slug": "G1__win.exe", "dst_slug": "G2__win.exe", "src_key": "C::OldName", "dst_key": "C::NewName"}
    )
    assert decision["decision"] == "verify"
    assert decision["reason"] == "cross_game_rename_requires_evidence"


def test_reviewed_name_pair_is_rejected_with_auditable_reason() -> None:
    decision = classify({"src_key": "Gob::GetPartLocalPosition", "dst_key": "Gob::SetPartLocalPosition"})
    assert decision["decision"] == "rejected"
    assert decision["reason"] == "independent_cross_game_names_and_semantics_disagree"
    assert "accessor and mutator" in decision["review_rationale"]


def test_unreviewed_name_pair_stays_verify() -> None:
    decision = classify({"src_key": "Example::OldName", "dst_key": "Example::NewName"})
    assert decision["decision"] == "verify"
    assert decision["reason"] == "cross_game_rename_requires_evidence"


def test_completed_queue_reuses_persisted_cross_game_ledger(tmp_path: Path) -> None:
    queue = tmp_path / "queue.jsonl"
    decisions = tmp_path / "decisions.jsonl"
    queue.write_text("")
    decisions.write_text(
        json.dumps(
            {
                "id": 1,
                "src_key": "Gob::GetPartLocalPosition",
                "dst_key": "Gob::SetPartLocalPosition",
                "decision": "rejected",
            }
        )
        + "\n"
    )
    rows = load_candidates(queue, decisions)
    assert len(rows) == 1
    assert rows[0]["id"] == 1
