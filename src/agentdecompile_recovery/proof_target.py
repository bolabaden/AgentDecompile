"""Proof-target queue: rank unverified inventoried functions for objdiff matching."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import claim_report as claim_report_mod
from .mismatch_classify import near_miss_class_score_bonus
from .proof_ladder import build_proof_ladder
from .readability_repair import normalize_entry_hex
from .vacuum_queue import slugify_function_name
from .state import atomic_write_json, now

SCHEMA = "agentdecompile.proof-target-queue.v1"
CLAIM_BOUNDARY = (
    "proof-target queue ranks advisory matching priorities only; "
    "objdiff-verified-semantic accepts under verified/ remain the proof ladder numerator"
)
NEAR_MISS_MAX_DIFF = 8
NEAR_MISS_BOOST_TIGHT = 80
NEAR_MISS_BOOST_LOOSE = 40


@dataclass(frozen=True)
class NearMissMaps:
    by_name: dict[str, int]
    by_entry: dict[str, int]
    class_by_name: dict[str, str]
    class_by_entry: dict[str, str]


def resolve_queue_path(work_dir: Path) -> Path:
    return work_dir.resolve() / "facts" / "proof-target-queue.json"


def _synthesis_eligible_from_task_maps(
    *,
    name: str,
    entry_hex: str,
    task: dict[str, Any] | None,
    tasks_by_name: dict[str, dict[str, Any]],
    tasks_by_entry: dict[str, dict[str, Any]],
) -> bool:
    """O(1) synthesis eligibility using preloaded task maps (not per-candidate jsonl scan)."""

    if task is not None:
        return True
    if name in tasks_by_name or entry_hex in tasks_by_entry:
        return True
    alt = slugify_function_name(name)
    return alt != name and alt in tasks_by_name


def write_proof_target_queue(work_dir: Path) -> dict[str, Any]:
    payload = build_proof_target_queue(work_dir)
    atomic_write_json(resolve_queue_path(work_dir), payload)
    return payload


def build_proof_target_queue(work_dir: Path) -> dict[str, Any]:
    work_dir = work_dir.resolve()
    ladder = build_proof_ladder(work_dir)
    candidates_path = work_dir / "function-candidates.json"
    if not candidates_path.is_file():
        return {
            "schema": SCHEMA,
            "status": "skipped",
            "reason": "missing-function-candidates",
            "writtenAt": now(),
            "workDir": str(work_dir),
            "queueCount": 0,
            "functionsToNextRung": int(ladder.get("functionsToNextRung") or 0),
            "nextRung": ladder.get("nextRung"),
            "nextRungTargetNumerator": ladder.get("nextRungTargetNumerator"),
            "claimBoundary": CLAIM_BOUNDARY,
        }

    try:
        data = json.loads(candidates_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return {
            "schema": SCHEMA,
            "status": "skipped",
            "reason": "invalid-function-candidates",
            "writtenAt": now(),
            "workDir": str(work_dir),
            "queueCount": 0,
            "claimBoundary": CLAIM_BOUNDARY,
        }

    raw_candidates = data.get("candidates") if isinstance(data, dict) else None
    if not isinstance(raw_candidates, list) or not raw_candidates:
        return {
            "schema": SCHEMA,
            "status": "skipped",
            "reason": "empty-candidates",
            "writtenAt": now(),
            "workDir": str(work_dir),
            "queueCount": 0,
            "functionsToNextRung": int(ladder.get("functionsToNextRung") or 0),
            "claimBoundary": CLAIM_BOUNDARY,
        }

    verified_names, verified_entries = _verified_keys(work_dir)
    tasks_by_name, tasks_by_entry = _load_source_tasks(work_dir)
    match_hints = _load_match_hints(work_dir)
    near_miss_maps = load_near_miss_maps(work_dir)

    entries: list[dict[str, Any]] = []
    for row in raw_candidates:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "").strip()
        if not name:
            continue
        entry_hex = normalize_entry_hex(row.get("entry") or row.get("address"))
        if name in verified_names or entry_hex in verified_entries:
            continue
        task = tasks_by_name.get(name) or tasks_by_entry.get(entry_hex)
        hints = match_hints.get(name) or match_hints.get(entry_hex) or {}
        near_miss = near_miss_maps.by_name.get(name)
        if near_miss is None:
            near_miss = near_miss_maps.by_entry.get(entry_hex)
        near_miss_class = near_miss_maps.class_by_name.get(name)
        if near_miss_class is None:
            near_miss_class = near_miss_maps.class_by_entry.get(entry_hex)
        score = _score_candidate(
            row,
            task=task,
            hints=hints,
            near_miss_best_difference=near_miss,
            near_miss_mismatch_class=near_miss_class,
        )
        synthesis_eligible = _synthesis_eligible_from_task_maps(
            name=name,
            entry_hex=entry_hex,
            task=task,
            tasks_by_name=tasks_by_name,
            tasks_by_entry=tasks_by_entry,
        )
        entry_payload: dict[str, Any] = {
            "name": name,
            "entry": entry_hex,
            "score": score,
            "bodyBytes": row.get("bodyBytes") or row.get("bytes"),
            "semanticSource": bool(row.get("semanticSource") or (task or {}).get("semanticSource")),
            "synthesisEligible": synthesis_eligible,
            "matchHints": hints or None,
            "sourceTaskStatus": (task or {}).get("status"),
            "claimBoundary": "proof-target-advisory",
        }
        if near_miss is not None:
            entry_payload["nearMissBestDifference"] = near_miss
        if near_miss_class:
            entry_payload["nearMissMismatchClass"] = near_miss_class
        entries.append(entry_payload)

    entries.sort(key=lambda item: (-int(item.get("score") or 0), str(item.get("name") or "")))

    near_miss_retry_count = sum(
        1
        for row in entries
        if row.get("nearMissBestDifference") is not None
        and int(row["nearMissBestDifference"]) <= NEAR_MISS_MAX_DIFF
    )

    return {
        "schema": SCHEMA,
        "status": "complete",
        "writtenAt": now(),
        "workDir": str(work_dir),
        "queueCount": len(entries),
        "synthesisEligibleCount": sum(1 for row in entries if row.get("synthesisEligible")),
        "functionsToNextRung": int(ladder.get("functionsToNextRung") or 0),
        "nextRung": ladder.get("nextRung"),
        "nextRungTargetNumerator": ladder.get("nextRungTargetNumerator"),
        "numerator": ladder.get("numerator"),
        "denominator": ladder.get("denominator"),
        "nearMissRetryCount": near_miss_retry_count,
        "entries": entries,
        "claimBoundary": CLAIM_BOUNDARY,
    }


def proof_target_vacuum_entries(work_dir: Path, *, limit: int = 0) -> list[dict[str, Any]]:
    """Map proof-target queue rows into vacuum pending entry shape (proof order)."""

    from .vacuum_queue import slugify_function_name

    payload = build_proof_target_queue(work_dir)
    tasks_by_name, tasks_by_entry = _load_source_tasks(work_dir)
    rows: list[dict[str, Any]] = []
    for entry in payload.get("entries") or []:
        if not isinstance(entry, dict):
            continue
        if not entry.get("synthesisEligible"):
            continue
        name = str(entry.get("name") or "unnamed")
        entry_hex = str(entry.get("entry") or "")
        task = tasks_by_name.get(name) or tasks_by_entry.get(entry_hex)
        rows.append(
            {
                "name": slugify_function_name(name),
                "functionName": name,
                "score": int(entry.get("score") or 0),
                "reason": "proof-target-queue",
                "entry": entry_hex,
                "status": "proof-target",
                "source": (task or {}).get("source"),
                "sourceQuality": (task or {}).get("sourceQuality"),
                "semanticSource": bool(entry.get("semanticSource")),
                "sourceTaskStatus": entry.get("sourceTaskStatus"),
            }
        )
    if limit > 0:
        return rows[:limit]
    return rows


def _verified_keys(work_dir: Path) -> tuple[set[str], set[str]]:
    names: set[str] = set()
    entries: set[str] = set()
    search_roots = (
        work_dir / "verified",
        work_dir / "recovered-source" / "functions",
    )
    for root in search_roots:
        if not root.is_dir():
            continue
        for path in root.rglob("*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError, TypeError, ValueError):
                continue
            if not isinstance(data, dict) or not claim_report_mod._is_objdiff_receipt(data, path=path):
                continue
            if data.get("name"):
                names.add(str(data["name"]))
            if data.get("entry"):
                entries.add(normalize_entry_hex(data["entry"]))
    return names, entries


def _load_source_tasks(work_dir: Path) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    by_name: dict[str, dict[str, Any]] = {}
    by_entry: dict[str, dict[str, Any]] = {}
    tasks_path = work_dir / "source-generation" / "tasks.jsonl"
    if not tasks_path.is_file():
        return by_name, by_entry
    for line in tasks_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            task = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(task, dict):
            continue
        name = str(task.get("name") or "").strip()
        if name:
            by_name[name] = task
        entry = task.get("entry") or task.get("address")
        if entry is not None:
            by_entry[normalize_entry_hex(entry)] = task
    return by_name, by_entry


def _load_match_hints(work_dir: Path) -> dict[str, dict[str, Any]]:
    hints: dict[str, dict[str, Any]] = {}
    paths: list[Path] = [
        work_dir / "trivial-matches" / "summary.jsonl",
        work_dir / "reloc-wrapper-matches" / "summary.jsonl",
        work_dir / "source-synthesis" / "accepted.jsonl",
        work_dir / "source-synthesis" / "code-slice-matches.jsonl",
    ]
    for pattern in (
        "*-trivial-matches/summary.jsonl",
        "*-reloc-wrapper-matches/summary.jsonl",
    ):
        paths.extend(work_dir.parent.glob(pattern))
        paths.extend(work_dir.glob(pattern))

    seen: set[Path] = set()
    for path in paths:
        if not path.is_file() or path in seen:
            continue
        seen.add(path)
        kind = "reloc" if "reloc" in path.as_posix() else "trivial" if "trivial" in path.as_posix() else "match"
        for row in _iter_jsonl(path):
            name = str(row.get("name") or "").strip()
            entry = normalize_entry_hex(row.get("entry") or row.get("address")) if row.get("entry") or row.get("address") else None
            payload = {"kind": kind, "status": row.get("status"), "differences": row.get("differences")}
            if name:
                hints.setdefault(name, {}).update(payload)
            if entry:
                hints.setdefault(entry, {}).update(payload)
    return hints


def _iter_jsonl(path: Path):
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            yield row


def load_near_miss_maps(work_dir: Path) -> NearMissMaps:
    """Return best positive objdiff difference and latest mismatch class per function."""

    by_name: dict[str, int] = {}
    by_entry: dict[str, int] = {}
    class_by_name: dict[str, str] = {}
    class_by_entry: dict[str, str] = {}
    work_dir = work_dir.resolve()
    attempt_paths = [work_dir / "source-synthesis" / "attempts.jsonl"]
    attempt_paths.extend(sorted(work_dir.glob("source-synthesis/**/plugin-attempts.jsonl")))
    seen_paths: set[Path] = set()
    for attempts in attempt_paths:
        if not attempts.is_file() or attempts in seen_paths:
            continue
        seen_paths.add(attempts)
        for row in _iter_jsonl(attempts):
            _ingest_near_miss_row(row, by_name, by_entry, class_by_name, class_by_entry)
    return NearMissMaps(by_name, by_entry, class_by_name, class_by_entry)


def _ingest_near_miss_row(
    row: dict[str, Any],
    by_name: dict[str, int],
    by_entry: dict[str, int],
    class_by_name: dict[str, str],
    class_by_entry: dict[str, str],
) -> None:
    status = str(row.get("status") or "")
    try:
        differences = int(row.get("differences", -1))
    except (TypeError, ValueError):
        differences = -1
    name = str(row.get("name") or "").strip()
    entry = row.get("entry") or row.get("address")
    entry_hex = normalize_entry_hex(entry) if entry is not None else None
    mismatch_class = row.get("mismatchClass")
    if mismatch_class:
        if name:
            class_by_name[name] = str(mismatch_class)
        if entry_hex:
            class_by_entry[entry_hex] = str(mismatch_class)
    if status not in {"mismatched", "matched"} or differences <= 0:
        return
    if name:
        by_name[name] = differences if name not in by_name else min(by_name[name], differences)
    if entry_hex:
        by_entry[entry_hex] = differences if entry_hex not in by_entry else min(by_entry[entry_hex], differences)


def near_miss_score_bonus(best_difference: int | None) -> int:
    if best_difference is None or best_difference <= 0:
        return 0
    if best_difference <= 4:
        return NEAR_MISS_BOOST_TIGHT
    if best_difference <= NEAR_MISS_MAX_DIFF:
        return NEAR_MISS_BOOST_LOOSE
    return 0


def _score_candidate(
    row: dict[str, Any],
    *,
    task: dict[str, Any] | None,
    hints: dict[str, Any],
    near_miss_best_difference: int | None = None,
    near_miss_mismatch_class: str | None = None,
) -> int:
    score = 10
    kind = str(hints.get("kind") or "")
    if kind in {"trivial", "reloc"}:
        score += 100
    if row.get("semanticSource") or (task or {}).get("semanticSource"):
        score += 50
    if task and (task.get("source") or task.get("status") in {"generated-unverified", "queued-no-source"}):
        score += 25
    body = row.get("bodyBytes") or row.get("bytes")
    if body is None and task:
        body = task.get("bodyBytes") or (task.get("targetSlice") or {}).get("bodyBytes")
    try:
        score -= min(40, int(body or 0) // 64)
    except (TypeError, ValueError):
        pass
    score += near_miss_score_bonus(near_miss_best_difference)
    score += near_miss_class_score_bonus(near_miss_mismatch_class)
    return score
