"""Pattern memory keyed by mismatch signature for near-miss repair hints."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .state import atomic_write_json, now

SCHEMA = "agentdecompile.pattern-memory.v1"
CLAIM_BOUNDARY = (
    "pattern memory stores advisory repair hints from verified accepts; "
    "it does not promote source without objdiff-zero verification"
)


def memory_path(work_dir: Path) -> Path:
    return work_dir.resolve() / "facts" / "pattern-memory.json"


def load_pattern_memory(work_dir: Path) -> dict[str, Any]:
    path = memory_path(work_dir)
    if not path.is_file():
        return {"schema": SCHEMA, "patterns": [], "claimBoundary": CLAIM_BOUNDARY}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return {"schema": SCHEMA, "patterns": [], "claimBoundary": CLAIM_BOUNDARY}
    if not isinstance(payload, dict):
        return {"schema": SCHEMA, "patterns": [], "claimBoundary": CLAIM_BOUNDARY}
    payload.setdefault("schema", SCHEMA)
    payload.setdefault("patterns", [])
    payload.setdefault("claimBoundary", CLAIM_BOUNDARY)
    return payload


def _signature(*, compiler: str, arch: str, mismatch_class: str | None, fix_shape: str | None) -> str:
    return "|".join(
        [
            compiler or "unknown",
            arch or "unknown",
            mismatch_class or "unclassified",
            fix_shape or "unknown",
        ]
    )


def store_verified_pattern(
    work_dir: Path,
    *,
    compiler: str = "msvc",
    arch: str = "x86",
    mismatch_class: str | None = None,
    fix_shape: str | None = None,
    function_name: str | None = None,
    entry: str | None = None,
) -> dict[str, Any]:
    """Record a verified accept pattern for later retrieval."""

    work_dir = work_dir.resolve()
    payload = load_pattern_memory(work_dir)
    patterns = [row for row in (payload.get("patterns") or []) if isinstance(row, dict)]
    sig = _signature(compiler=compiler, arch=arch, mismatch_class=mismatch_class, fix_shape=fix_shape)
    row = {
        "signature": sig,
        "compiler": compiler,
        "arch": arch,
        "mismatchClass": mismatch_class,
        "fixShape": fix_shape,
        "functionName": function_name,
        "entry": entry,
        "storedAt": now(),
        "claimBoundary": CLAIM_BOUNDARY,
    }
    patterns = [existing for existing in patterns if existing.get("signature") != sig]
    patterns.append(row)
    payload["patterns"] = patterns[-500:]
    payload["writtenAt"] = now()
    atomic_write_json(memory_path(work_dir), payload)
    return row


def retrieve_patterns(
    work_dir: Path,
    *,
    compiler: str = "msvc",
    arch: str = "x86",
    mismatch_class: str | None = None,
) -> list[dict[str, Any]]:
    payload = load_pattern_memory(work_dir)
    matches: list[dict[str, Any]] = []
    for row in payload.get("patterns") or []:
        if not isinstance(row, dict):
            continue
        if row.get("compiler") not in {compiler, None, ""}:
            continue
        if row.get("arch") not in {arch, None, ""}:
            continue
        if mismatch_class and row.get("mismatchClass") not in {mismatch_class, None, ""}:
            continue
        matches.append(row)
    return matches


def ingest_verified_directory(work_dir: Path) -> dict[str, Any]:
    """Best-effort store patterns from verified/ artifacts."""

    work_dir = work_dir.resolve()
    verified = work_dir / "verified"
    stored = 0
    if not verified.is_dir():
        return {"stored": 0, "status": "missing"}
    for path in verified.rglob("*.json"):
        try:
            row = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            continue
        if not isinstance(row, dict):
            continue
        if int(row.get("differences") or 0) != 0:
            continue
        store_verified_pattern(
            work_dir,
            mismatch_class=str(row.get("mismatchClass") or "") or None,
            fix_shape=str(row.get("routedPlaybook") or row.get("sourceQuality") or "") or None,
            function_name=str(row.get("name") or path.stem),
            entry=str(row.get("entry") or "") or None,
        )
        stored += 1
    return {"stored": stored, "status": "complete"}
