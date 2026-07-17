"""Seed reconstruct work-dir vacuum queues from source-generation tasks."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .autonomy_budget import ensure_vacuum_queue
from .state import atomic_write_json, now

SCHEMA = "agentdecompile.vacuum-queue-seed.v1"
CLAIM_BOUNDARY = (
    "queue seeding schedules autonomy work only; it does not establish "
    "objdiff-verified-semantic recovery"
)


def seed_vacuum_queue_from_work_dir(
    work_dir: Path,
    *,
    limit: int = 1,
    queue_path: Path | None = None,
    prompts_dir: Path | None = None,
) -> dict[str, Any]:
    """Populate ``state/queue.json`` pending entries from source-generation tasks.

    Prefer generated-unverified tasks that are not already represented under
    ``verified/`` or an existing queue bucket. Optionally write minimal prompt
    stubs so vacuum ``--prompts-dir`` resolves.
    """

    work_dir = work_dir.resolve()
    limit = max(0, int(limit))
    queue_path = ensure_vacuum_queue(queue_path or (work_dir / "state" / "queue.json"))
    prompts_dir = prompts_dir or (work_dir / "prompts")
    queue = _load_queue(queue_path)
    occupied = _occupied_names(queue)
    verified_names = _verified_names(work_dir / "verified")
    occupied |= verified_names

    candidates = _candidate_entries(work_dir / "source-generation" / "tasks.jsonl")
    seeded: list[dict[str, Any]] = []
    for entry in candidates:
        if len(seeded) >= limit:
            break
        name = str(entry["name"])
        if name in occupied:
            continue
        queue["pending"].append(entry)
        occupied.add(name)
        _write_prompt_stub(prompts_dir, entry, work_dir=work_dir)
        seeded.append(entry)

    atomic_write_json(queue_path, queue)
    receipt = {
        "schema": SCHEMA,
        "status": "seeded" if seeded else "empty",
        "writtenAt": now(),
        "workDir": str(work_dir),
        "queue": str(queue_path),
        "promptsDir": str(prompts_dir),
        "limit": limit,
        "seededCount": len(seeded),
        "pendingCount": len(queue.get("pending") or []),
        "seeded": [{"name": row["name"], "score": row.get("score"), "reason": row.get("reason")} for row in seeded],
        "claimBoundary": CLAIM_BOUNDARY,
    }
    atomic_write_json(work_dir / "state" / "vacuum-queue-seed.json", receipt)
    return receipt


def _load_queue(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    queue = {
        "schema": "agentdecompile.vacuum-queue.v1",
        "pending": list(data.get("pending") or []),
        "matched": list(data.get("matched") or []),
        "integrated": list(data.get("integrated") or []),
        "failed": list(data.get("failed") or []),
        "difficult": list(data.get("difficult") or []),
        "attempts": dict(data.get("attempts") or {}),
    }
    return queue


def _occupied_names(queue: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for key in ("pending", "matched", "integrated", "failed", "difficult"):
        for row in queue.get(key) or []:
            if isinstance(row, dict) and row.get("name"):
                names.add(str(row["name"]))
            elif isinstance(row, str) and row:
                names.add(row)
    return names


def _verified_names(verified_dir: Path) -> set[str]:
    if not verified_dir.is_dir():
        return set()
    names: set[str] = set()
    for path in verified_dir.rglob("*"):
        if path.suffix.lower() in {".c", ".cpp", ".cc", ".h", ".hpp"}:
            names.add(path.stem)
            # Common stem pattern: name_00401000
            if "_" in path.stem:
                names.add(path.stem.rsplit("_", 1)[0])
    return names


def _candidate_entries(tasks_path: Path) -> list[dict[str, Any]]:
    if not tasks_path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in tasks_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            task = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(task, dict):
            continue
        status = str(task.get("status") or "")
        if status in {"not-generated-fragment"}:
            continue
        name = str(task.get("name") or "").strip()
        if not name:
            continue
        if not task.get("source") and status not in {"generated-unverified", "queued-no-source"}:
            continue
        safe_name = _slugify(name)
        score = _score_task(task)
        rows.append(
            {
                "name": safe_name,
                "functionName": name,
                "score": score,
                "reason": "seeded from source-generation/tasks.jsonl",
                "entry": task.get("entry") or task.get("address"),
                "status": status or "generated-unverified",
                "source": task.get("source"),
                "sourceQuality": task.get("sourceQuality"),
                "semanticSource": bool(task.get("semanticSource")),
            }
        )
    rows.sort(key=lambda row: (-int(row.get("score") or 0), str(row.get("name") or "")))
    return rows


def _score_task(task: dict[str, Any]) -> int:
    score = 10
    if task.get("semanticSource"):
        score += 100
    quality = str(task.get("sourceQuality") or "")
    if quality == "high-level-c":
        score += 40
    elif quality == "inline-asm-c":
        score += 20
    if task.get("source"):
        score += 25
    status = str(task.get("status") or "")
    if status == "generated-unverified":
        score += 15
    body = task.get("bodyBytes") or (task.get("targetSlice") or {}).get("bodyBytes")
    try:
        score -= min(40, int(body or 0) // 64)
    except (TypeError, ValueError):
        pass
    return score


def _write_prompt_stub(prompts_dir: Path, entry: dict[str, Any], *, work_dir: Path) -> Path:
    prompts_dir.mkdir(parents=True, exist_ok=True)
    # Directory basename must equal queue entry name (vacuum resolves prompts/<name>).
    prompt_name = str(entry["name"])
    prompt_dir = prompts_dir / prompt_name
    prompt_dir.mkdir(parents=True, exist_ok=True)
    source = entry.get("source")
    function_name = str(entry.get("functionName") or prompt_name)
    source_line = f"candidateSourcePath: {source}\n" if source else ""
    case_yaml = (
        f"caseId: {prompt_name}\n"
        f"functionName: '{function_name}'\n"
        f"status: pending\n"
        f"entry: '{entry.get('entry') or ''}'\n"
        f"{source_line}"
        f"seededFrom: {work_dir / 'source-generation' / 'tasks.jsonl'}\n"
        "claimBoundary: 'prompt stub seeded from reconstruct tasks; not objdiff proof'\n"
    )
    (prompt_dir / "case.yaml").write_text(case_yaml, encoding="utf-8")
    settings_yaml = (
        f"functionName: '{function_name}'\n"
        "asm: |\n"
        f"  ; seeded stub for {function_name}\n"
    )
    (prompt_dir / "settings.yaml").write_text(settings_yaml, encoding="utf-8")
    if source and Path(str(source)).is_file():
        candidate = prompt_dir / "candidate.c"
        if not candidate.exists():
            try:
                candidate.write_text(Path(str(source)).read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
            except OSError:
                pass
    return prompt_dir


def slugify_function_name(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip()).strip("._-")
    return slug or "unnamed"


def _slugify(value: str) -> str:
    return slugify_function_name(value)
