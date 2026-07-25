"""Advisory readability repair queue from enrich function facts."""

from __future__ import annotations

import hashlib
import json
import statistics
from pathlib import Path
from typing import Any

from .module_resolver import FALLBACK_MODULE, infer_repair_class, passes_readability_gate
from .pyghidra_enrich import readability_score
from .state import atomic_write_json, now
from .vacuum_queue import slugify_function_name

SCHEMA = "agentdecompile.readability-repair-queue.v1"
CLAIM_BOUNDARY = (
    "readability repair queue ranks advisory Port gate failures only; "
    "objdiff-verified-semantic accepts under verified/ remain the proof ladder numerator"
)

_SCORE_BANDS: tuple[tuple[str, float, float], ...] = (
    ("0.0-0.3", 0.0, 0.3),
    ("0.3-0.6", 0.3, 0.6),
    ("0.6-0.8", 0.6, 0.8),
    ("0.8-1.0", 0.8, 1.01),
)


def normalize_entry_hex(raw: Any) -> str:
    if raw is None:
        return "00000000"
    if isinstance(raw, int):
        return f"{raw:08x}"
    text = str(raw).strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    try:
        return f"{int(text, 16):08x}"
    except (TypeError, ValueError):
        return text.zfill(8)[-8:]


def _load_source_tasks(work_dir: Path) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    """Load source-generation tasks into O(1) lookup maps (by name and by entry)."""
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


def entry_has_source_task(
    work_dir: Path,
    *,
    name: str,
    entry: str | None = None,
    tasks_by_name: dict[str, dict[str, Any]] | None = None,
    tasks_by_entry: dict[str, dict[str, Any]] | None = None,
) -> bool:
    """Check if a source-generation task exists for the given function.

    Pass preloaded `tasks_by_name` and `tasks_by_entry` maps to avoid repeated
    file scans. If not provided, falls back to loading from disk.

    Matches the legacy behavior: checks name and slugified name variants only.
    Entry matching is intentionally NOT performed here (unlike proof-target queue).
    """
    if tasks_by_name is None:
        tasks_by_name, _ = _load_source_tasks(work_dir)

    if name in tasks_by_name:
        return True
    # Also check slugified name variant (legacy behavior from find_source_task)
    alt = slugify_function_name(name)
    if alt != name and alt in tasks_by_name:
        return True
    return False


def resolve_facts_path(work_dir: Path) -> Path | None:
    work_dir = work_dir.resolve()
    for candidate in (
        work_dir / "facts" / "function-facts.jsonl",
        work_dir / "function-facts.jsonl",
    ):
        if candidate.is_file():
            return candidate
    return None


def resolve_queue_path(work_dir: Path) -> Path:
    return work_dir.resolve() / "facts" / "readability-repair-queue.json"


def load_module_hints(work_dir: Path) -> dict[str, dict[str, Any]]:
    for candidate in (
        work_dir / "facts" / "module-map.json",
        work_dir / "unpack" / "facts" / "module-map.json",
    ):
        if not candidate.is_file():
            continue
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            continue
        entries = payload.get("entries")
        if isinstance(entries, dict):
            return {normalize_entry_hex(key): dict(value) for key, value in entries.items() if isinstance(value, dict)}
    return {}


def iter_facts_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def facts_sha256(path: Path | None) -> str | None:
    if path is None or not path.is_file():
        return None
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def score_distribution_bands(scores: list[float]) -> dict[str, int]:
    bands = {label: 0 for label, _, _ in _SCORE_BANDS}
    for score in scores:
        for label, low, high in _SCORE_BANDS:
            if low <= score < high:
                bands[label] += 1
                break
    return bands


def build_readability_repair_queue(work_dir: Path) -> dict[str, Any]:
    work_dir = work_dir.resolve()
    facts_path = resolve_facts_path(work_dir)
    if facts_path is None:
        return {
            "schema": SCHEMA,
            "status": "skipped",
            "reason": "missing-function-facts",
            "writtenAt": now(),
            "workDir": str(work_dir),
            "queueCount": 0,
            "portReadyCount": 0,
            "entries": [],
            "claimBoundary": CLAIM_BOUNDARY,
        }

    module_hints = load_module_hints(work_dir)
    facts = iter_facts_rows(facts_path)
    scores: list[float] = []
    queue: list[dict[str, Any]] = []
    port_ready = 0

    for row in facts:
        entry = normalize_entry_hex(row.get("entryOffset") or row.get("entry"))
        hint = module_hints.get(entry) or {}
        name = str(row.get("name") or f"FUN_{entry}")
        module = str(row.get("module") or hint.get("module") or FALLBACK_MODULE)
        module_provenance = str(hint.get("moduleProvenance") or row.get("moduleProvenance") or "fallback")
        try:
            score = float(row.get("readabilityScore"))
        except (TypeError, ValueError):
            score = readability_score(name=name, module=module, provenance=module_provenance)
        scores.append(score)

        if passes_readability_gate(name=name, module=module, module_provenance=module_provenance):
            port_ready += 1
            continue

        queue.append(
            {
                "entry": entry,
                "name": name,
                "module": module,
                "moduleProvenance": module_provenance,
                "readabilityScore": score,
                "repairClass": infer_repair_class(
                    name=name,
                    module=module,
                    module_provenance=module_provenance,
                ),
                "claimBoundary": "readability-repair-advisory",
            }
        )

    queue.sort(key=lambda row: (float(row.get("readabilityScore") or 0.0), str(row.get("entry") or "")))

    median_score = round(statistics.median(scores), 3) if scores else 0.0
    return {
        "schema": SCHEMA,
        "status": "complete" if queue else "empty",
        "writtenAt": now(),
        "workDir": str(work_dir),
        "factsPath": str(facts_path),
        "factsSha256": facts_sha256(facts_path),
        "functionCount": len(facts),
        "portReadyCount": port_ready,
        "queueCount": len(queue),
        "medianScore": median_score,
        "scoreBands": score_distribution_bands(scores),
        "entries": queue,
        "claimBoundary": CLAIM_BOUNDARY,
    }


def write_readability_repair_queue(work_dir: Path) -> dict[str, Any]:
    payload = build_readability_repair_queue(work_dir)
    path = resolve_queue_path(work_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(path, payload)
    payload["queuePath"] = str(path)
    return payload


def load_repair_queue_summary(work_dir: Path) -> dict[str, Any] | None:
    work_dir = work_dir.resolve()
    path = resolve_queue_path(work_dir)
    if path.is_file():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            payload = None
        if isinstance(payload, dict):
            return {
                "queuePath": str(path),
                "status": payload.get("status"),
                "portReadyCount": payload.get("portReadyCount"),
                "queueCount": payload.get("queueCount"),
                "medianScore": payload.get("medianScore"),
                "scoreBands": payload.get("scoreBands"),
                "topEntries": (payload.get("entries") or [])[:5],
                "claimBoundary": payload.get("claimBoundary") or CLAIM_BOUNDARY,
            }

    if resolve_facts_path(work_dir) is None:
        return None
    payload = build_readability_repair_queue(work_dir)
    return {
        "queuePath": str(path),
        "status": payload.get("status"),
        "portReadyCount": payload.get("portReadyCount"),
        "queueCount": payload.get("queueCount"),
        "medianScore": payload.get("medianScore"),
        "scoreBands": payload.get("scoreBands"),
        "topEntries": (payload.get("entries") or [])[:5],
        "claimBoundary": payload.get("claimBoundary") or CLAIM_BOUNDARY,
    }


RUN_SCHEMA = "agentdecompile.readability-repair-run.v1"
RUN_CLAIM_BOUNDARY = (
    "readability repair run emits MCP/reconstruct guidance only; applying changes does not "
    "establish objdiff-verified-semantic recovery"
)


def resolve_repair_run_path(work_dir: Path) -> Path:
    return work_dir.resolve() / "state" / "readability-repair-run.json"


def build_repair_tool_seq(entry: dict[str, Any]) -> list[dict[str, Any]]:
    repair_class = str(entry.get("repairClass") or "re-enrich")
    name = str(entry.get("name") or "")
    entry_hex = str(entry.get("entry") or "")
    address = f"0x{entry_hex.lstrip('0') or '0'}"

    if repair_class == "rename":
        suggested = name.removeprefix("FUN_") if name.startswith("FUN_") else name
        if not suggested or suggested == name:
            suggested = "RecoveredFunction"
        return [
            {
                "name": "manage-function",
                "arguments": {
                    "mode": "rename",
                    "addressOrSymbol": address,
                    "newName": suggested,
                },
            }
        ]
    if repair_class == "module-refresh":
        return [
            {
                "name": "manage-comments",
                "arguments": {
                    "addressOrSymbol": address,
                    "action": "set",
                    "commentType": "plate",
                    "comment": (
                        "Module hint: refresh assert-string / RTTI evidence for module-map; "
                        "then reconstruct --resume --stop-after enrich-decompile"
                    ),
                },
            }
        ]
    return []


def build_repair_command_hint(entry: dict[str, Any]) -> str:
    repair_class = str(entry.get("repairClass") or "re-enrich")
    if repair_class == "rename":
        return (
            "Apply toolSeq via agentdecompile-cli tool-seq, then "
            "reconstruct <target> --resume --stop-after enrich-decompile"
        )
    if repair_class == "module-refresh":
        return (
            "Add module evidence (assert paths / RTTI) via MCP or inventory refresh, then "
            "reconstruct <target> --resume --stop-after enrich-decompile"
        )
    return "reconstruct <target> --resume --stop-after enrich-decompile"


def execute_readability_repair(
    work_dir: Path,
    *,
    limit: int = 1,
    run_tool_seq_fn=None,
    run_enrich_refresh_fn=None,
) -> dict[str, Any]:
    """Run MCP tool-seq for readability repair queue head, then optional enrich refresh."""

    from .agent_closure import run_enrich_refresh_subprocess
    from .mcp_tool_seq import run_tool_seq

    work_dir = work_dir.resolve()
    hint_receipt = run_readability_repair(work_dir, limit=limit)
    if hint_receipt.get("status") not in {"ready"}:
        return hint_receipt

    top = hint_receipt.get("topEntry") if isinstance(hint_receipt.get("topEntry"), dict) else {}
    tool_seq = top.get("toolSeq") if isinstance(top.get("toolSeq"), list) else []
    if not tool_seq:
        hint_receipt["mcpStatus"] = "skipped:empty-tool-seq"
        atomic_write_json(resolve_repair_run_path(work_dir), hint_receipt)
        return hint_receipt

    executor = run_tool_seq_fn or run_tool_seq
    mcp_result = executor(tool_seq, work_dir=work_dir, timeout=1800)
    mcp_status = str(mcp_result.get("status") or "unknown")
    enrich_refresh: dict[str, Any] | None = None
    repair_class = str(top.get("repairClass") or "")
    if mcp_status == "complete" and repair_class == "rename":
        refresh = run_enrich_refresh_fn or run_enrich_refresh_subprocess
        enrich_refresh = refresh(work_dir)

    receipt = {
        **hint_receipt,
        "status": "executed" if mcp_status == "complete" else mcp_status,
        "mcpStatus": mcp_status,
        "toolsInvoked": mcp_result.get("toolsInvoked") or [],
        "stepResults": mcp_result.get("steps") or [],
        "enrichRefresh": enrich_refresh,
        "claimBoundary": RUN_CLAIM_BOUNDARY,
    }
    atomic_write_json(resolve_repair_run_path(work_dir), receipt)
    return receipt


def run_readability_repair(work_dir: Path, *, limit: int = 1) -> dict[str, Any]:
    """Emit advisory repair guidance for the top queue entries."""

    work_dir = work_dir.resolve()
    limit = max(0, int(limit))
    queue_payload = build_readability_repair_queue(work_dir)
    queue_count_before = int(queue_payload.get("queueCount") or 0)
    entries = [row for row in (queue_payload.get("entries") or []) if isinstance(row, dict)]

    if limit == 0 or queue_count_before == 0:
        receipt = {
            "schema": RUN_SCHEMA,
            "status": "empty" if queue_count_before == 0 else "skipped",
            "reason": "budget-zero" if limit == 0 else "empty-repair-queue",
            "writtenAt": now(),
            "workDir": str(work_dir),
            "queueCountBefore": queue_count_before,
            "attempted": [],
            "claimBoundary": RUN_CLAIM_BOUNDARY,
        }
        atomic_write_json(resolve_repair_run_path(work_dir), receipt)
        return receipt

    # Preload task maps once for O(1) lookups instead of O(n) per entry
    tasks_by_name, tasks_by_entry = _load_source_tasks(work_dir)

    attempted: list[dict[str, Any]] = []
    for entry in entries[:limit]:
        name = str(entry.get("name") or "")
        has_task = entry_has_source_task(
            work_dir,
            name=name,
            entry=str(entry.get("entry") or ""),
            tasks_by_name=tasks_by_name,
            tasks_by_entry=tasks_by_entry,
        )
        attempted.append(
            {
                "entry": entry.get("entry"),
                "name": name,
                "repairClass": entry.get("repairClass"),
                "readabilityScore": entry.get("readabilityScore"),
                "hasSourceTask": has_task,
                "toolSeq": build_repair_tool_seq(entry),
                "commandHint": build_repair_command_hint(entry),
                "synthesisEligible": has_task,
                "claimBoundary": "readability-repair-advisory",
            }
        )

    head = attempted[0]
    status = "ready"
    if head.get("synthesisEligible"):
        status = "deferred-to-synthesis"

    receipt = {
        "schema": RUN_SCHEMA,
        "status": status,
        "writtenAt": now(),
        "workDir": str(work_dir),
        "queuePath": str(resolve_queue_path(work_dir)),
        "queueCountBefore": queue_count_before,
        "attempted": attempted,
        "topEntry": head,
        "claimBoundary": RUN_CLAIM_BOUNDARY,
    }
    atomic_write_json(resolve_repair_run_path(work_dir), receipt)
    return receipt


def readability_repair_blocks_vacuum(work_dir: Path) -> bool:
    """True when the top repair-queue head has no source task (MCP lane, not synthesis)."""

    queue_payload = build_readability_repair_queue(work_dir)
    entries = queue_payload.get("entries") or []
    if not entries:
        return False
    head = entries[0] if isinstance(entries[0], dict) else {}
    name = str(head.get("name") or "")
    # Preload task maps for O(1) lookup
    tasks_by_name, tasks_by_entry = _load_source_tasks(work_dir)
    return not entry_has_source_task(
        work_dir,
        name=name,
        entry=str(head.get("entry") or ""),
        tasks_by_name=tasks_by_name,
        tasks_by_entry=tasks_by_entry,
    )


def repair_queue_vacuum_entries(work_dir: Path, *, limit: int = 0) -> list[dict[str, Any]]:
    """Map repair queue rows into vacuum pending entry shape (worst readability first)."""

    from .vacuum_queue import slugify_function_name

    payload = build_readability_repair_queue(work_dir)
    rows: list[dict[str, Any]] = []
    for entry in payload.get("entries") or []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or entry.get("entry") or "unnamed")
        entry_hex = str(entry.get("entry") or "")
        try:
            score_f = float(entry.get("readabilityScore") or 0.0)
        except (TypeError, ValueError):
            score_f = 0.0
        rows.append(
            {
                "name": slugify_function_name(name),
                "functionName": name,
                "score": int(round((1.0 - score_f) * 1000)),
                "reason": "readability-repair-queue",
                "entry": entry_hex,
                "status": "readability-repair",
                "repairClass": entry.get("repairClass"),
            }
        )
    if limit > 0:
        return rows[:limit]
    return rows