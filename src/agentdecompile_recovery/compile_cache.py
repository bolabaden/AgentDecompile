"""Compile/objdiff artifact cache keyed by target slice digest and compiler profile."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

SCHEMA = "agentdecompile.compile-cache-entry.v1"


def cache_dir(work_dir: Path) -> Path:
    return work_dir.resolve() / "source-synthesis" / "compile-cache"


def cache_key(
    *,
    target_slice_sha: str,
    source_sha: str,
    compiler_profile: str,
    compiler_lane: str = "c",
    flags: str = "",
) -> str:
    material = "|".join(
        [
            target_slice_sha or "",
            source_sha or "",
            compiler_profile or "default",
            compiler_lane or "c",
            flags or "",
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def entry_path(cache_root: Path, key: str) -> Path:
    return cache_root / f"{key}.json"


def lookup(cache_root: Path, key: str) -> dict[str, Any] | None:
    path = entry_path(cache_root, key)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        return None
    records = data.get("records")
    if not isinstance(records, list):
        return None
    return data


def store(
    cache_root: Path,
    key: str,
    *,
    records: list[dict[str, Any]],
    metadata: dict[str, Any] | None = None,
) -> Path:
    cache_root.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": SCHEMA,
        "cacheKey": key,
        "records": records,
        "metadata": metadata or {},
    }
    path = entry_path(cache_root, key)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def target_slice_sha256(row: dict[str, Any]) -> str:
    target_slice = row.get("targetSlice") if isinstance(row.get("targetSlice"), dict) else {}
    for key in ("sha256", "targetSha256", "bodySha256"):
        value = target_slice.get(key) or row.get(key)
        if value:
            return str(value)
    body = target_slice.get("bytes") or row.get("bytes") or row.get("bodyBytes")
    if body is None:
        return ""
    if isinstance(body, str):
        try:
            body_bytes = bytes.fromhex(body.replace(" ", ""))
        except ValueError:
            body_bytes = body.encode("utf-8", errors="replace")
    elif isinstance(body, (bytes, bytearray)):
        body_bytes = bytes(body)
    else:
        body_bytes = str(body).encode("utf-8", errors="replace")
    return hashlib.sha256(body_bytes).hexdigest()
