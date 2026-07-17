"""Phase 6a: propose Ghidra label renames from placed context seeds.

Propose-only: never mutates Ghidra. Agents apply via rename-function /
manage-comments + resolve-modification-conflict. Unplaced pieces are excluded.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .state import atomic_write_json, now

SCHEMA = "agentdecompile.propose-labels.v1"
CLAIM_BOUNDARY = (
    "proposed labels are address-keyed context hints only; applying them via "
    "MCP rename/comment tools does not establish objdiff-verified-semantic proof "
    "and must honor the modification-conflict protocol"
)


def build_propose_labels(work_dir: Path) -> dict[str, Any]:
    """Build propose-labels receipt from placed seeds / facts (no unplaced VAs)."""

    work_dir = work_dir.resolve()
    placement = _load_json(work_dir / "acquisition" / "placement.json") or {}
    unplaced_addrs = _unplaced_addresses(placement)
    proposals: list[dict[str, Any]] = []
    by_address: dict[int, list[dict[str, Any]]] = {}

    seed_dir = work_dir / "advisory" / "context-seeds"
    if seed_dir.is_dir():
        for meta_path in sorted(seed_dir.glob("*.json")):
            if meta_path.name == "manifest.json":
                continue
            row = _load_json(meta_path)
            if not row:
                continue
            addr = _coerce_int(row.get("address") or row.get("entryOffset"))
            name = row.get("name")
            if addr is None or not name or not str(name).strip():
                continue
            if addr in unplaced_addrs:
                continue
            proposal = {
                "address": addr,
                "addressHex": f"0x{addr:x}",
                "proposedName": str(name).strip(),
                "sourceKind": row.get("sourceKind") or "context-seed",
                "authorityClass": row.get("authorityClass") or "advisory-decompiler",
                "seedMeta": str(meta_path),
                "applyHint": (
                    "rename-function or manage-symbols rename at this address; "
                    "on conflictId call resolve-modification-conflict"
                ),
            }
            by_address.setdefault(addr, []).append(proposal)

    facts_path = _facts_path(work_dir)
    if facts_path is not None:
        for line in facts_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                fact = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(fact, dict):
                continue
            addr = _coerce_int(fact.get("entryOffset") or fact.get("address"))
            name = fact.get("name")
            if addr is None or not name or not str(name).strip():
                continue
            if addr in unplaced_addrs:
                continue
            # Prefer seed proposals already collected for this address.
            if addr in by_address:
                continue
            proposal = {
                "address": addr,
                "addressHex": f"0x{addr:x}",
                "proposedName": str(name).strip(),
                "sourceKind": fact.get("sourceKind") or "function-fact",
                "authorityClass": "context-hint",
                "applyHint": (
                    "rename-function or manage-symbols rename at this address; "
                    "on conflictId call resolve-modification-conflict"
                ),
            }
            by_address.setdefault(addr, []).append(proposal)

    conflict_count = 0
    for addr, rows in sorted(by_address.items()):
        names = {str(r.get("proposedName")) for r in rows}
        if len(rows) > 1 or len(names) > 1:
            conflict_count += 1
            for row in rows:
                proposals.append({**row, "status": "conflict", "conflictPeers": len(rows)})
        else:
            proposals.append({**rows[0], "status": "ready"})

    status = "empty" if not proposals else "complete"
    return {
        "schema": SCHEMA,
        "status": status,
        "writtenAt": now(),
        "workDir": str(work_dir),
        "counts": {
            "proposed": len(proposals),
            "ready": sum(1 for row in proposals if row.get("status") == "ready"),
            "conflicts": conflict_count,
            "unplacedExcluded": len(unplaced_addrs),
        },
        "proposals": proposals[:500],
        "claimBoundary": CLAIM_BOUNDARY,
        "nextStep": (
            "Apply ready proposals via MCP rename-function / manage-symbols; "
            "use resolve-modification-conflict when a conflictId is returned. "
            "Do not auto-pick among status=conflict rows."
        ),
    }


def write_propose_labels(work_dir: Path) -> dict[str, Any]:
    payload = build_propose_labels(work_dir)
    out_dir = work_dir / "acquisition"
    out_dir.mkdir(parents=True, exist_ok=True)
    atomic_write_json(out_dir / "propose-labels.json", payload)
    return payload


def _facts_path(work_dir: Path) -> Path | None:
    candidates = [
        work_dir / "acquisition" / "context-pack" / "function-facts.jsonl",
        work_dir / "function-facts.jsonl",
    ]
    acquire = _load_json(work_dir / "acquisition" / "acquire.json") or {}
    snap = acquire.get("snapshotDir")
    if snap:
        candidates.insert(0, Path(str(snap)) / "context-pack" / "function-facts.jsonl")
    pack = (acquire.get("contextPack") or {}) if isinstance(acquire.get("contextPack"), dict) else {}
    if pack.get("factsJsonl"):
        candidates.insert(0, Path(str(pack["factsJsonl"])))
    for path in candidates:
        if path.is_file():
            return path
    return None


def _unplaced_addresses(placement: dict[str, Any]) -> set[int]:
    addrs: set[int] = set()
    for row in placement.get("unplaced") or []:
        if isinstance(row, dict):
            value = _coerce_int(row.get("address") or row.get("entryOffset") or row.get("va"))
            if value is not None:
                addrs.add(value)
        else:
            value = _coerce_int(row)
            if value is not None:
                addrs.add(value)
    return addrs


def _coerce_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        if isinstance(value, str):
            return int(value, 0)
        return int(value)
    except (TypeError, ValueError):
        return None


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None
    return data if isinstance(data, dict) else None
