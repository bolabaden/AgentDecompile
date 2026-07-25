"""Proven-match cache: skip Wine/MSVC rematch when objdiff already reported 0.

Cache key: (targetSha256, entry, sourceSha256, compilerProfile). A hit with
differences==0 and no fallback is authoritative unless --force-rematch is set.
targetSha256 is the analysis-image digest; without it, rows cannot authorize skip.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "agentdecompile.match-cache.v1"


def source_sha256(source: str | bytes) -> str:
    if isinstance(source, str):
        source = source.encode("utf-8")
    return hashlib.sha256(source).hexdigest()


def cache_key(
    *,
    entry: str,
    source_sha: str,
    compiler_profile: str = "default",
    target_sha: str = "",
) -> str:
    return f"{target_sha}|{entry}|{source_sha}|{compiler_profile}"


def is_proven_zero(row: dict[str, Any]) -> bool:
    """True only for real objdiff-0 receipts — never objdump fallbacks."""

    if row.get("fallback"):
        return False
    status = str(row.get("status") or "")
    try:
        differences = int(row.get("differences", -1))
    except (TypeError, ValueError):
        return False
    return differences == 0 and status in {
        "matched",
        "code-slice-matched",
        "source-shape-code-slice-matched",
    }


def _row_target_sha(row: dict[str, Any]) -> str:
    for key in ("targetSha256", "analysisBinarySha256", "binarySha256"):
        value = row.get(key)
        if value:
            return str(value)
    return ""


def iter_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)


class MatchCache:
    """In-memory index of proven objdiff-0 receipts."""

    def __init__(self) -> None:
        self.by_key: dict[str, dict[str, Any]] = {}
        self.by_entry: dict[str, dict[str, Any]] = {}
        self.by_name_entry: set[tuple[str, str]] = set()

    def load_jsonl(self, paths: Iterable[Path]) -> int:
        loaded = 0
        for path in paths:
            for row in iter_jsonl(path):
                if self.ingest(row):
                    loaded += 1
        return loaded

    def load_cache_file(self, path: Path) -> int:
        if not path.exists():
            return 0
        data = json.loads(path.read_text(encoding="utf-8"))
        rows = data.get("entries") if isinstance(data, dict) else data
        if not isinstance(rows, list):
            return 0
        loaded = 0
        for row in rows:
            if isinstance(row, dict) and self.ingest(row):
                loaded += 1
        return loaded

    def ingest(self, row: dict[str, Any]) -> bool:
        if not is_proven_zero(row):
            return False
        entry = str(row.get("entry") or "")
        name = str(row.get("name") or "")
        source_sha = str(row.get("sourceSha256") or "")
        if not source_sha:
            source_path = row.get("source")
            if source_path and Path(str(source_path)).is_file():
                source_sha = hashlib.sha256(Path(str(source_path)).read_bytes()).hexdigest()
        profile = str(
            row.get("compilerProfileName")
            or row.get("compilerProfile")
            or "default"
        )
        target_sha = _row_target_sha(row)
        if not (entry and source_sha and target_sha):
            # Without entry, source hash, and analysis-image identity we cannot
            # form a safe skip key across binaries / unpacks.
            return False
        self.by_key[
            cache_key(
                entry=entry,
                source_sha=source_sha,
                compiler_profile=profile,
                target_sha=target_sha,
            )
        ] = row
        prior = self.by_entry.get(entry)
        if prior is None or is_proven_zero(row):
            self.by_entry[entry] = row
        if name and entry:
            self.by_name_entry.add((name, entry))
        return True

    def lookup(
        self,
        *,
        entry: str,
        source_sha: str,
        compiler_profile: str = "default",
        target_sha: str = "",
    ) -> dict[str, Any] | None:
        if not target_sha:
            return None
        # Exact key only: a different compiler profile is not evidence for skip.
        return self.by_key.get(
            cache_key(
                entry=entry,
                source_sha=source_sha,
                compiler_profile=compiler_profile,
                target_sha=target_sha,
            )
        )

    def has_entry(self, entry: str) -> bool:
        return entry in self.by_entry

    def has_name_entry(self, name: str, entry: str) -> bool:
        return (name, entry) in self.by_name_entry

    def proven_rows(self) -> list[dict[str, Any]]:
        # Prefer key-indexed rows (source-specific); fall back to entry map.
        seen: set[str] = set()
        out: list[dict[str, Any]] = []
        for row in self.by_key.values():
            key = f"{row.get('entry')}|{row.get('sourceSha256')}|{row.get('name')}|{_row_target_sha(row)}"
            if key in seen:
                continue
            seen.add(key)
            out.append(row)
        return out

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": SCHEMA,
            "entryCount": len(self.by_entry),
            "keyCount": len(self.by_key),
            "entries": self.proven_rows(),
            "claimBoundary": (
                "Cache entries are prior objdiff differences==0 receipts keyed by "
                "analysis-image digest. They authorize skip-rematch only; they are "
                "not whole-program parity. Fallback/objdump rows are never cached."
            ),
        }
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def default_cache_path(work_dir: Path) -> Path:
    return work_dir / "match-cache.json"
