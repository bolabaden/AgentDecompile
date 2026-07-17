"""PE critical-path readiness: stop-after checkpoints and next actions.

Documents the Steamless → inventory → synthesis/vacuum loop without adding peer
CLIs. ``critical-path.json`` is advisory orchestration metadata — it does not
establish semantic recovery claims.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .state import atomic_write_json, now

SCHEMA = "agentdecompile.critical-path.v1"
CLAIM_BOUNDARY = (
    "critical path readiness summarizes orchestration receipts and tool "
    "availability only; objdiff-verified-semantic accepts under verified/ "
    "remain the proof ladder numerator"
)

# Ordered stop-after checkpoints for hard PE targets (swkotor-class).
PE_CRITICAL_PATH_STOP_AFTER: tuple[str, ...] = (
    "prepare-analysis-image",
    "inventory-binary",
    "discover-functions",
    "generate-source-candidates",
    "synthesize-source-tasks",
)

_CHECKPOINTS: tuple[tuple[str, str], ...] = (
    ("discover", "target.json"),
    ("inspect-capabilities", "capabilities.json"),
    ("prepare-analysis-image", "analysis-target.json"),
    ("inventory-binary", "binary-inventory.json"),
    ("discover-functions", "function-candidates.json"),
    ("generate-source-candidates", "source-generation/summary.json"),
    ("synthesize-source-tasks", "source-synthesis/summary.json"),
)


def build_critical_path(work_dir: Path) -> dict[str, Any]:
    """Assess critical-path readiness from work-dir receipts."""

    work_dir = work_dir.resolve()
    checkpoints = [_assess_checkpoint(work_dir, name, artifact) for name, artifact in _CHECKPOINTS]
    readiness = _readiness_from_checkpoints(checkpoints, work_dir)
    next_actions = build_next_actions(work_dir)
    return {
        "schema": SCHEMA,
        "writtenAt": now(),
        "workDir": str(work_dir),
        "readiness": readiness,
        "peCriticalPathStopAfter": list(PE_CRITICAL_PATH_STOP_AFTER),
        "checkpoints": checkpoints,
        "nextActions": next_actions,
        "claimBoundary": CLAIM_BOUNDARY,
    }


def write_critical_path(work_dir: Path) -> dict[str, Any]:
    payload = build_critical_path(work_dir)
    atomic_write_json(work_dir / "critical-path.json", payload)
    return payload


def build_next_actions(work_dir: Path) -> list[dict[str, Any]]:
    """List budget-gated next stages without auto-running them."""

    work_dir = work_dir.resolve()
    capabilities = _load_json(work_dir / "capabilities.json") or {}
    tools = capabilities.get("tools") if isinstance(capabilities.get("tools"), dict) else {}
    local = capabilities.get("localSurfaces") if isinstance(capabilities.get("localSurfaces"), dict) else {}

    actions: list[dict[str, Any]] = []

    candidates_path = work_dir / "function-candidates.json"
    tasks_path = work_dir / "source-generation" / "tasks.jsonl"
    synth_summary = _load_json(work_dir / "source-synthesis" / "summary.json")
    queue_seed = _load_json(work_dir / "state" / "vacuum-queue-seed.json")
    verified_dir = work_dir / "verified"

    actions.append(_action_synthesize_source_tasks(work_dir, candidates_path, tasks_path, tools))
    actions.append(_action_vacuum_seed(work_dir, tasks_path, queue_seed))
    actions.append(_action_profile_corpus(work_dir, synth_summary, verified_dir, tools, local))
    actions.append(_action_reloc_slice(work_dir, candidates_path, tools, local))
    actions.append(_action_slice_verify(work_dir, candidates_path, tools))
    return actions


def _action_synthesize_source_tasks(
    work_dir: Path,
    candidates_path: Path,
    tasks_path: Path,
    tools: dict[str, Any],
) -> dict[str, Any]:
    action_id = "synthesize-source-tasks"
    if synth_summary_complete(work_dir):
        return {
            "id": action_id,
            "status": "complete",
            "reason": "source-synthesis summary exists",
            "paths": {"summary": str(work_dir / "source-synthesis" / "summary.json")},
        }
    if not candidates_path.is_file():
        return {
            "id": action_id,
            "status": "blocked",
            "reason": "missing function-candidates.json; run through discover-functions first",
            "paths": {"candidates": str(candidates_path)},
            "stopAfterHint": "discover-functions",
        }
    blocked_reasons: list[str] = []
    if not _tool_available(tools, "objdiff"):
        blocked_reasons.append("objdiff unavailable")
    if not (_tool_available(tools, "clang") or _tool_available(tools, "wine")):
        blocked_reasons.append("clang or wine unavailable for synthesis lane")
    if blocked_reasons:
        return {
            "id": action_id,
            "status": "blocked",
            "reason": "; ".join(blocked_reasons),
            "paths": {"tasks": str(tasks_path) if tasks_path.is_file() else None},
            "stopAfterHint": "generate-source-candidates",
        }
    return {
        "id": action_id,
        "status": "ready",
        "reason": "function candidates present; resume reconstruct through synthesize-source-tasks",
        "paths": {
            "candidates": str(candidates_path),
            "tasks": str(tasks_path) if tasks_path.is_file() else None,
        },
        "stopAfterHint": "synthesize-source-tasks",
    }


def _action_vacuum_seed(
    work_dir: Path,
    tasks_path: Path,
    queue_seed: dict[str, Any] | None,
) -> dict[str, Any]:
    action_id = "vacuum-seed"
    if queue_seed and int(queue_seed.get("seededCount") or 0) > 0:
        return {
            "id": action_id,
            "status": "complete",
            "reason": "vacuum queue already seeded",
            "paths": {
                "seed": str(work_dir / "state" / "vacuum-queue-seed.json"),
                "queue": str(work_dir / "state" / "queue.json"),
            },
        }
    if not tasks_path.is_file():
        return {
            "id": action_id,
            "status": "blocked",
            "reason": "no source-generation/tasks.jsonl; generate source candidates first",
            "paths": {"tasks": str(tasks_path)},
            "commandHint": "reconstruct <target> --work-dir <dir> --stop-after generate-source-candidates",
        }
    return {
        "id": action_id,
        "status": "ready",
        "reason": "source-generation tasks exist; seed with --autonomous (budget-gated)",
        "paths": {"tasks": str(tasks_path), "queue": str(work_dir / "state" / "queue.json")},
        "commandHint": "reconstruct <target> --work-dir <dir> --autonomous --autonomous-max-functions 1",
    }


def _action_profile_corpus(
    work_dir: Path,
    synth_summary: dict[str, Any] | None,
    verified_dir: Path,
    tools: dict[str, Any],
    local: dict[str, Any],
) -> dict[str, Any]:
    action_id = "profile-corpus"
    objdiff_count = 0
    if verified_dir.is_dir():
        for path in verified_dir.rglob("*.json"):
            try:
                row = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError, TypeError, ValueError):
                continue
            if isinstance(row, dict) and int(row.get("differences") or -1) == 0:
                objdiff_count += 1
    if objdiff_count == 0:
        accepted = 0
        if synth_summary:
            accepted = int(synth_summary.get("acceptedCandidates") or synth_summary.get("accepted") or 0)
        if accepted == 0:
            return {
                "id": action_id,
                "status": "blocked",
                "reason": "no objdiff-verified accepts yet; corpus forensics requires matched examples",
                "paths": {"verified": str(verified_dir) if verified_dir.is_dir() else None},
            }
    blocked: list[str] = []
    if not _tool_available(tools, "wine") and not _tool_available(tools, "clang"):
        blocked.append("MSVC/clang toolchain unavailable")
    if not local.get("verifyObjdiff") and not _tool_available(tools, "objdiff"):
        blocked.append("objdiff unavailable")
    if blocked:
        return {
            "id": action_id,
            "status": "blocked",
            "reason": "; ".join(blocked),
            "paths": {"verified": str(verified_dir)},
        }
    return {
        "id": action_id,
        "status": "ready",
        "reason": "matched examples available for compiler-profile corpus sweep (legacy recover subcommand)",
        "paths": {"verified": str(verified_dir)},
        "commandHint": "agentdecompile recover compiler-profile-corpus --work-dir <dir>",
    }


def _action_slice_verify(
    work_dir: Path,
    candidates_path: Path,
    tools: dict[str, Any],
) -> dict[str, Any]:
    """ELF/Mach-O symbolized byte-roundtrip readiness (weaker than PE objdiff)."""

    action_id = "slice-verify"
    inventory = _load_json(work_dir / "binary-inventory.json") or {}
    fmt = str(inventory.get("format") or "")
    summary_path = work_dir / "slice-verify" / "summary.json"
    summary = _load_json(summary_path)
    if summary is not None:
        status = str(summary.get("status") or "")
        if status == "matched":
            return {
                "id": action_id,
                "status": "complete",
                "reason": "symbolized slice verify matched (code-slice tier; not proof-ladder numerator)",
                "paths": {"summary": str(summary_path)},
            }
        if status == "unsupported-slice-verify":
            return {
                "id": action_id,
                "status": "blocked",
                "reason": str(summary.get("reason") or "unsupported-slice-verify"),
                "paths": {"summary": str(summary_path)},
            }
        if status in {"blocked:toolchain", "compile-failed", "extract-failed", "mismatch"}:
            return {
                "id": action_id,
                "status": "blocked",
                "reason": f"prior slice verify {status}: {summary.get('reason') or status}",
                "paths": {"summary": str(summary_path)},
            }

    if fmt not in {"elf", "macho"}:
        return {
            "id": action_id,
            "status": "blocked",
            "reason": "slice verify is ELF/Mach-O only; use reloc-slice for PE",
            "paths": {"inventory": str(work_dir / "binary-inventory.json") if inventory else None},
        }
    if not candidates_path.is_file():
        return {
            "id": action_id,
            "status": "blocked",
            "reason": "missing function-candidates.json; run through discover-functions first",
            "paths": {"candidates": str(candidates_path)},
            "stopAfterHint": "discover-functions",
        }
    blocked: list[str] = []
    if not _tool_available(tools, "clang"):
        blocked.append("clang unavailable")
    if not _tool_available(tools, "objcopy"):
        blocked.append("objcopy unavailable")
    if blocked:
        return {
            "id": action_id,
            "status": "blocked",
            "reason": "; ".join(blocked),
            "paths": {"candidates": str(candidates_path)},
            "stopAfterHint": "discover-functions",
        }
    return {
        "id": action_id,
        "status": "ready",
        "reason": "ELF/Mach-O candidates present; reconstruct --stop-after discover-functions runs slice verify",
        "paths": {
            "inventory": str(work_dir / "binary-inventory.json"),
            "candidates": str(candidates_path),
            "summary": str(summary_path),
        },
        "commandHint": "reconstruct <elf|macho> --work-dir <dir> --stop-after discover-functions",
        "stopAfterHint": "discover-functions",
    }


def _action_reloc_slice(
    work_dir: Path,
    candidates_path: Path,
    tools: dict[str, Any],
    local: dict[str, Any],
) -> dict[str, Any]:
    action_id = "reloc-slice"
    inventory = _load_json(work_dir / "binary-inventory.json") or {}
    if inventory.get("format") != "pe":
        return {
            "id": action_id,
            "status": "blocked",
            "reason": "reloc target objects are PE-oriented; inventory is not PE",
            "paths": {"inventory": str(work_dir / "binary-inventory.json")},
        }
    if not candidates_path.is_file():
        return {
            "id": action_id,
            "status": "blocked",
            "reason": "missing function candidates for slice selection",
            "paths": {"candidates": str(candidates_path)},
        }
    blocked: list[str] = []
    if not _tool_available(tools, "objcopy"):
        blocked.append("objcopy unavailable")
    if not _tool_available(tools, "objdump"):
        blocked.append("objdump unavailable")
    if not local.get("swkotorInventorySlice"):
        blocked.append("swkotor-inventory-slice helper script missing")
    if blocked:
        return {
            "id": action_id,
            "status": "blocked",
            "reason": "; ".join(blocked),
            "paths": {"inventory": str(work_dir / "binary-inventory.json")},
        }
    return {
        "id": action_id,
        "status": "ready",
        "reason": "PE inventory + candidates ready for per-function reloc target object extraction",
        "paths": {
            "inventory": str(work_dir / "binary-inventory.json"),
            "candidates": str(candidates_path),
        },
        "commandHint": "scripts/swkotor-inventory-slice.py --inventory <jsonl> --function <name> --out-dir <dir>",
    }


def synth_summary_complete(work_dir: Path) -> bool:
    summary_path = work_dir / "source-synthesis" / "summary.json"
    if not summary_path.is_file():
        return False
    summary = _load_json(summary_path)
    return bool(summary and summary.get("status") not in {None, "missing", "skipped"})


def _assess_checkpoint(work_dir: Path, name: str, artifact: str) -> dict[str, Any]:
    path = work_dir / artifact
    row: dict[str, Any] = {
        "name": name,
        "artifact": artifact,
        "path": str(path),
        "present": path.is_file(),
        "status": "missing",
    }
    if not path.is_file():
        return row

    payload = _load_json(path)
    row["status"] = "complete"
    if name == "prepare-analysis-image" and payload:
        analysis_status = str(payload.get("status") or "")
        terminal = str(payload.get("terminalStatus") or "")
        if analysis_status == "blocked" or terminal.startswith("blocked:toolchain"):
            row["status"] = "blocked:toolchain"
            row["softFail"] = {
                "transformResult": payload.get("transformResult"),
                "transformAttempted": payload.get("transformAttempted"),
                "packedDetected": payload.get("packedDetected"),
                "detail": payload.get("transformDetail") or payload.get("transformResult"),
            }
        elif payload.get("transform") == "steamless-unpacked-pe":
            row["softFail"] = None
            row["transform"] = payload.get("transform")
    elif name == "discover-functions" and payload:
        summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
        candidates = payload.get("candidates")
        count = len(candidates) if isinstance(candidates, list) else int(summary.get("count") or 0)
        row["functionCandidateCount"] = count
    return row


def _readiness_from_checkpoints(checkpoints: list[dict[str, Any]], work_dir: Path) -> str:
    by_name = {row["name"]: row for row in checkpoints}
    analysis = by_name.get("prepare-analysis-image") or {}
    if analysis.get("status") == "blocked:toolchain":
        return "blocked:toolchain"
    if not (by_name.get("discover") or {}).get("present"):
        return "not-started"
    if not analysis.get("present"):
        return "discovered"
    if analysis.get("status") != "complete":
        return "blocked:toolchain"
    if not (by_name.get("inventory-binary") or {}).get("present"):
        return "analysis-ready"
    if not (by_name.get("discover-functions") or {}).get("present"):
        return "inventory-ready"
    if synth_summary_complete(work_dir):
        return "ready-for-vacuum"
    if (by_name.get("generate-source-candidates") or {}).get("present"):
        return "ready-for-synthesis"
    count = int((by_name.get("discover-functions") or {}).get("functionCandidateCount") or 0)
    if count > 0:
        return "candidates-ready"
    return "inventory-ready"


def _tool_available(tools: dict[str, Any], name: str) -> bool:
    row = tools.get(name)
    return bool(isinstance(row, dict) and row.get("available"))


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None
    return data if isinstance(data, dict) else None
