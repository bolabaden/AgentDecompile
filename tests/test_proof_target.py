"""Unit tests for proof-target queue and campaign receipts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.proof_campaign import write_proof_campaign
from agentdecompile_recovery.proof_ladder import build_proof_ladder
from agentdecompile_recovery.proof_target import (
    build_proof_target_queue,
    load_near_miss_maps,
    near_miss_score_bonus,
    plugin_attempt_paths,
    proof_target_vacuum_entries,
    write_proof_target_queue,
)
from agentdecompile_recovery.state import atomic_write_json
from agentdecompile_recovery.vacuum_queue import seed_vacuum_queue_from_work_dir

pytestmark = pytest.mark.unit


def _write_candidates(work: Path, rows: list[dict]) -> None:
    atomic_write_json(
        work / "function-candidates.json",
        {
            "schema": "agentdecompile.function-candidates.v1",
            "candidates": rows,
            "summary": {"count": len(rows)},
        },
    )


def _write_verified(work: Path, name: str, *, entry: str = "00403000") -> None:
    verified = work / "verified"
    verified.mkdir(parents=True, exist_ok=True)
    atomic_write_json(
        verified / f"{name}.json",
        {
            "status": "matched",
            "differences": 0,
            "proofTier": "target-object-objdiff-match",
            "name": name,
            "entry": entry,
        },
    )


def test_proof_target_queue_ranks_unverified(tmp_path: Path) -> None:
    work = tmp_path / "queue"
    work.mkdir()
    _write_candidates(
        work,
        [
            {"name": "big_fn", "entry": "00401000", "bodyBytes": 512},
            {"name": "small_fn", "entry": "00402000", "bodyBytes": 32, "semanticSource": True},
            {"name": "verified_fn", "entry": "00403000", "bodyBytes": 16},
        ],
    )
    _write_verified(work, "verified_fn", entry="00403000")
    tasks = work / "source-generation" / "tasks.jsonl"
    tasks.parent.mkdir(parents=True)
    tasks.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "name": "small_fn",
                        "entry": "00402000",
                        "status": "generated-unverified",
                        "source": str(work / "small.c"),
                        "semanticSource": True,
                    }
                ),
                json.dumps(
                    {
                        "name": "big_fn",
                        "entry": "00401000",
                        "status": "generated-unverified",
                        "source": str(work / "big.c"),
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (work / "small.c").write_text("int small(void){return 1;}\n", encoding="utf-8")
    (work / "big.c").write_text("int big(void){return 2;}\n", encoding="utf-8")

    queue = build_proof_target_queue(work)
    assert queue["status"] == "complete"
    assert queue["queueCount"] == 2
    assert queue["entries"][0]["name"] == "small_fn"
    assert queue["entries"][0]["synthesisEligible"] is True
    assert queue["entries"][0]["claimBoundary"] == "proof-target-advisory"


def test_proof_target_queue_skipped_when_empty(tmp_path: Path) -> None:
    work = tmp_path / "empty"
    work.mkdir()
    queue = build_proof_target_queue(work)
    assert queue["status"] == "skipped"
    assert queue["queueCount"] == 0


def test_vacuum_seed_prefers_proof_targets(tmp_path: Path) -> None:
    work = tmp_path / "seed"
    work.mkdir()
    _write_candidates(
        work,
        [
            {"name": "alpha", "entry": "00401000", "bodyBytes": 256},
            {"name": "beta", "entry": "00402000", "bodyBytes": 16, "semanticSource": True},
        ],
    )
    tasks = work / "source-generation" / "tasks.jsonl"
    tasks.parent.mkdir(parents=True)
    tasks.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "name": "alpha",
                        "entry": "00401000",
                        "status": "generated-unverified",
                        "source": str(work / "alpha.c"),
                    }
                ),
                json.dumps(
                    {
                        "name": "beta",
                        "entry": "00402000",
                        "status": "generated-unverified",
                        "source": str(work / "beta.c"),
                        "semanticSource": True,
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (work / "alpha.c").write_text("int alpha(void){return 0;}\n", encoding="utf-8")
    (work / "beta.c").write_text("int beta(void){return 1;}\n", encoding="utf-8")
    write_proof_target_queue(work)

    receipt = seed_vacuum_queue_from_work_dir(work, limit=1, prefer_proof_targets=True)
    assert receipt["proofTargetFirst"] is True
    assert receipt["seededCount"] == 1
    assert receipt["seeded"][0]["name"] == "beta"
    vacuum_rows = proof_target_vacuum_entries(work, limit=1)
    assert vacuum_rows[0]["functionName"] == "beta"


def test_proof_campaign_near_miss_does_not_increment_numerator(tmp_path: Path) -> None:
    work = tmp_path / "campaign"
    work.mkdir()
    _write_candidates(work, [{"name": "fn", "entry": "00401000"}])
    before = build_proof_ladder(work)
    attempts = work / "source-synthesis" / "attempts.jsonl"
    attempts.parent.mkdir(parents=True)
    attempts.write_text(
        json.dumps({"status": "mismatched", "differences": 3, "name": "fn"}) + "\n",
        encoding="utf-8",
    )
    campaign = write_proof_campaign(
        work,
        before=before,
        status="bridged",
        reason="test near-miss",
        attempted=1,
    )
    after = build_proof_ladder(work)
    assert campaign["status"] == "near-miss"
    assert campaign["accepts"] == 0
    assert campaign["nearMisses"] == 1
    assert campaign["bestDifference"] == 3
    assert after["numerator"] == before["numerator"]


def test_near_miss_map_picks_best_difference(tmp_path: Path) -> None:
    work = tmp_path / "near-miss-map"
    work.mkdir()
    attempts = work / "source-synthesis" / "attempts.jsonl"
    attempts.parent.mkdir(parents=True)
    attempts.write_text(
        "\n".join(
            [
                json.dumps({"status": "mismatched", "differences": 5, "name": "fn_a"}),
                json.dumps({"status": "mismatched", "differences": 2, "name": "fn_a"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    maps = load_near_miss_maps(work)
    assert maps.by_name["fn_a"] == 2
    assert near_miss_score_bonus(2) == 80
    assert near_miss_score_bonus(6) == 40
    assert near_miss_score_bonus(20) == 0


def test_near_miss_map_reads_plugin_attempts(tmp_path: Path) -> None:
    work = tmp_path / "plugin-map"
    plugin_attempts = work / "source-synthesis" / "vacuum" / "fn_a" / "plugin-attempts.jsonl"
    plugin_attempts.parent.mkdir(parents=True)
    plugin_attempts.write_text(
        json.dumps(
            {
                "status": "mismatched",
                "differences": 4,
                "name": "fn_a",
                "mismatchClass": "operand",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    maps = load_near_miss_maps(work)
    assert maps.by_name["fn_a"] == 4
    assert maps.class_by_name["fn_a"] == "operand"


def _write_attempts_row(path: Path, **row: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")


def test_plugin_attempt_paths_skips_the_case_compile_tree(tmp_path: Path) -> None:
    """A recursive walk of source-synthesis/ costs an hour on a real work dir.

    ``source-synthesis/cases/`` holds one directory per compile attempt --
    thousands of them, several levels deep. Only the synthesis root and the
    per-function vacuum directories ever receive ``plugin-attempts.jsonl``, so
    reintroducing ``source-synthesis/**/plugin-attempts.jsonl`` here would pick
    up the decoy below and stall the ``report`` stage again.
    """

    work = tmp_path / "case-tree"
    synthesis = work / "source-synthesis"
    _write_attempts_row(synthesis / "plugin-attempts.jsonl", status="mismatched", differences=3, name="root_fn")
    _write_attempts_row(
        synthesis / "vacuum" / "fn_a" / "plugin-attempts.jsonl", status="mismatched", differences=4, name="vacuum_fn"
    )
    _write_attempts_row(
        synthesis / "cases" / "0x401000_sub_1000_packaged" / "profile_00_O2" / "plugin-attempts.jsonl",
        status="mismatched",
        differences=5,
        name="decoy_fn",
    )

    paths = plugin_attempt_paths(work)

    assert paths == [
        synthesis / "plugin-attempts.jsonl",
        synthesis / "vacuum" / "fn_a" / "plugin-attempts.jsonl",
    ]
    maps = load_near_miss_maps(work)
    assert maps.by_name == {"root_fn": 3, "vacuum_fn": 4}


def test_load_near_miss_maps_issues_no_recursive_glob(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    work = tmp_path / "no-recursive-glob"
    _write_attempts_row(
        work / "source-synthesis" / "vacuum" / "fn_a" / "plugin-attempts.jsonl",
        status="mismatched",
        differences=4,
        name="fn_a",
    )
    patterns: list[str] = []
    real_glob = Path.glob

    def recording_glob(self: Path, pattern: str, *args: object, **kwargs: object):
        patterns.append(pattern)
        return real_glob(self, pattern, *args, **kwargs)

    def rejecting_rglob(self: Path, pattern: str, *args: object, **kwargs: object):
        patterns.append(f"**/{pattern}")
        return iter(())

    monkeypatch.setattr(Path, "glob", recording_glob)
    monkeypatch.setattr(Path, "rglob", rejecting_rglob)

    maps = load_near_miss_maps(work)

    assert maps.by_name == {"fn_a": 4}
    assert [pattern for pattern in patterns if "**" in pattern] == []


def test_proof_target_queue_boosts_near_miss_retry(tmp_path: Path) -> None:
    work = tmp_path / "near-miss-rank"
    work.mkdir()
    _write_candidates(
        work,
        [
            {"name": "cold_fn", "entry": "00401000", "bodyBytes": 32},
            {"name": "warm_fn", "entry": "00402000", "bodyBytes": 32},
        ],
    )
    tasks = work / "source-generation" / "tasks.jsonl"
    tasks.parent.mkdir(parents=True)
    tasks.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "name": "cold_fn",
                        "entry": "00401000",
                        "status": "generated-unverified",
                        "source": str(work / "cold.c"),
                    }
                ),
                json.dumps(
                    {
                        "name": "warm_fn",
                        "entry": "00402000",
                        "status": "generated-unverified",
                        "source": str(work / "warm.c"),
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (work / "cold.c").write_text("int cold(void){return 0;}\n", encoding="utf-8")
    (work / "warm.c").write_text("int warm(void){return 1;}\n", encoding="utf-8")
    attempts = work / "source-synthesis" / "attempts.jsonl"
    attempts.parent.mkdir(parents=True, exist_ok=True)
    attempts.write_text(
        json.dumps({"status": "mismatched", "differences": 2, "name": "warm_fn"}) + "\n",
        encoding="utf-8",
    )

    before = build_proof_ladder(work)
    queue = build_proof_target_queue(work)
    after = build_proof_ladder(work)

    assert queue["entries"][0]["name"] == "warm_fn"
    assert queue["entries"][0]["nearMissBestDifference"] == 2
    assert queue["nearMissRetryCount"] == 1
    assert after["numerator"] == before["numerator"] == 0
