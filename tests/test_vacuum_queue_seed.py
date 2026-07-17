"""Unit tests for vacuum queue seeding from reconstruct tasks."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_recovery.recovery_status import build_recovery_status
from agentdecompile_recovery.vacuum_queue import seed_vacuum_queue_from_work_dir

pytestmark = pytest.mark.unit


def _write_tasks(work: Path, rows: list[dict]) -> None:
    tasks = work / "source-generation"
    tasks.mkdir(parents=True)
    (tasks / "tasks.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def test_seed_vacuum_queue_prefers_semantic_and_respects_limit(tmp_path: Path) -> None:
    work = tmp_path / "run"
    src_a = tmp_path / "a.c"
    src_b = tmp_path / "b.c"
    src_a.write_text("int a(void){return 0;}\n", encoding="utf-8")
    src_b.write_text("int b(void){return 1;}\n", encoding="utf-8")
    _write_tasks(
        work,
        [
            {
                "name": "beta",
                "status": "generated-unverified",
                "source": str(src_b),
                "semanticSource": False,
                "sourceQuality": "inline-asm-c",
                "bodyBytes": 200,
            },
            {
                "name": "alpha",
                "status": "generated-unverified",
                "source": str(src_a),
                "semanticSource": True,
                "sourceQuality": "high-level-c",
                "bodyBytes": 32,
                "entry": "0x401000",
            },
            {
                "name": "fragment",
                "status": "not-generated-fragment",
            },
        ],
    )

    receipt = seed_vacuum_queue_from_work_dir(work, limit=1)
    assert receipt["seededCount"] == 1
    assert receipt["seeded"][0]["name"] == "alpha"
    queue = json.loads((work / "state" / "queue.json").read_text(encoding="utf-8"))
    assert len(queue["pending"]) == 1
    assert queue["pending"][0]["name"] == "alpha"
    assert (work / "prompts" / "alpha" / "case.yaml").is_file()
    assert (work / "prompts" / "alpha" / "candidate.c").is_file()


def test_seed_skips_verified_and_existing_pending(tmp_path: Path) -> None:
    work = tmp_path / "run"
    src = tmp_path / "fn.c"
    src.write_text("int fn(void){return 0;}\n", encoding="utf-8")
    _write_tasks(
        work,
        [
            {"name": "already", "status": "generated-unverified", "source": str(src), "semanticSource": True},
            {"name": "fresh", "status": "generated-unverified", "source": str(src), "semanticSource": True},
        ],
    )
    (work / "verified").mkdir(parents=True)
    (work / "verified" / "already.c").write_text("int already(void){return 0;}\n", encoding="utf-8")
    (work / "state").mkdir(parents=True)
    (work / "state" / "queue.json").write_text(
        json.dumps(
            {
                "schema": "agentdecompile.vacuum-queue.v1",
                "pending": [{"name": "fresh", "score": 1}],
                "matched": [],
                "integrated": [],
                "failed": [],
                "difficult": [],
                "attempts": {},
            }
        ),
        encoding="utf-8",
    )

    receipt = seed_vacuum_queue_from_work_dir(work, limit=5)
    assert receipt["seededCount"] == 0
    queue = json.loads((work / "state" / "queue.json").read_text(encoding="utf-8"))
    assert len(queue["pending"]) == 1


def test_status_includes_seed_receipt(tmp_path: Path) -> None:
    work = tmp_path / "run"
    src = tmp_path / "fn.c"
    src.write_text("int fn(void){return 0;}\n", encoding="utf-8")
    _write_tasks(
        work,
        [{"name": "fn", "status": "generated-unverified", "source": str(src), "semanticSource": True}],
    )
    seed_vacuum_queue_from_work_dir(work, limit=1)
    status = build_recovery_status(work)
    assert status["vacuum"]["seededCount"] == 1
    assert status["vacuum"]["seedStatus"] == "seeded"
    assert status["vacuum"]["queueCounts"]["pending"] == 1
