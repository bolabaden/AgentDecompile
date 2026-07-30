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

# Per signature, not global. Signatures here are coarse (a few mismatch classes
# times a few fix shapes), so a global cap would let one busy class evict every
# exemplar of a rare one.
MAX_PATTERNS_PER_SIGNATURE = 25


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
    source_before: str | None = None,
    source_after: str | None = None,
) -> dict[str, Any]:
    """Record a verified accept pattern for later retrieval.

    Patterns accumulate within a signature rather than replacing it. The
    signature space here is coarse -- a handful of mismatch classes times a
    handful of fix shapes -- so replacing on collision meant the store held
    about one row per class and every accept erased the previous exemplar for
    its class, which is the opposite of memory.

    ``source_before``/``source_after`` are the part a later prompt can actually
    use. A row of labels says a transformation happened; only the pair says
    what it was.
    """

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
        "sourceBefore": source_before,
        "sourceAfter": source_after,
        "storedAt": now(),
        "claimBoundary": CLAIM_BOUNDARY,
    }

    # Deduplicate on the transformation itself, not the signature: the same
    # before/after pair re-observed on another function teaches nothing new,
    # but a different pair in the same class is exactly what we want to keep.
    identity = (sig, source_before, source_after, None if source_after else function_name)
    kept = [existing for existing in patterns if _identity(existing) != identity]

    same_signature = [existing for existing in kept if existing.get("signature") == sig]
    if len(same_signature) >= MAX_PATTERNS_PER_SIGNATURE:
        oldest = same_signature[0]
        kept = [existing for existing in kept if existing is not oldest]

    kept.append(row)
    payload["patterns"] = kept
    payload["writtenAt"] = now()
    atomic_write_json(memory_path(work_dir), payload)
    return row


def _identity(row: dict[str, Any]) -> tuple[Any, ...]:
    after = row.get("sourceAfter")
    return (
        row.get("signature"),
        row.get("sourceBefore"),
        after,
        None if after else row.get("functionName"),
    )


def retrieve_patterns(
    work_dir: Path,
    *,
    compiler: str = "msvc",
    arch: str = "x86",
    mismatch_class: str | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Exemplars for this mismatch class, most useful first.

    Rows carrying an actual before/after transformation rank ahead of
    label-only rows: a prompt can copy a transformation, but learns nothing
    from a bare class name. Newest wins within each group.
    """

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
    # Stored in append order, so reversing gives newest-first; the sort below is
    # stable, so that ordering survives inside each rank.
    matches.reverse()
    matches.sort(key=lambda row: 0 if (row.get("sourceBefore") and row.get("sourceAfter")) else 1)
    return matches[:limit] if limit is not None and limit >= 0 else matches


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
