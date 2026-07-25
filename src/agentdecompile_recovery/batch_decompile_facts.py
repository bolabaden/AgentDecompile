"""Project ghidrecomp batch decompile outputs into function-facts JSONL."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .source_dump import normalize_entry_hex

SCHEMA = "agentdecompile.batch-decompile-facts.v1"
_ENTRY_RE = re.compile(r"(?:0x)?([0-9a-fA-F]{6,8})")


def entry_and_name_from_decomp_path(path: Path) -> tuple[str, str]:
    stem = path.stem
    match = _ENTRY_RE.search(stem)
    if not match:
        return "", stem
    entry = normalize_entry_hex(match.group(1))
    lowered = stem.lower()
    if stem.upper().startswith("FUN_"):
        return entry, stem
    if entry and f"_{entry}" in lowered:
        parts = stem.split("_")
        name = "_".join(p for p in parts if normalize_entry_hex(p) != entry) or f"FUN_{entry}"
        return entry, name
    if entry and (lowered.endswith(f"-{entry}") or lowered.endswith(f"-0x{entry}")):
        name = stem[: stem.rfind("-")] or f"FUN_{entry}"
        return entry, name
    return entry, f"FUN_{entry}"


def project_decompiled_files_to_facts(
    decompiled_files: list[str | Path],
    *,
    out_jsonl: Path,
    target_sha: str = "",
) -> dict[str, Any]:
    """Write function-facts JSONL rows with embedded decompiled text for dump."""

    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    digest = str(target_sha or "").strip()
    with out_jsonl.open("w", encoding="utf-8") as fh:
        for raw in decompiled_files:
            path = Path(raw)
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if not text.strip():
                continue
            entry, name = entry_and_name_from_decomp_path(path)
            if not entry:
                continue
            row: dict[str, Any] = {
                "schema": "agentdecompile.function-fact.v1",
                "name": name,
                "entry": entry,
                "entryOffset": entry,
                "decompiled": text,
                "decompilationStatus": "complete",
                "entityKind": "function",
                "tool": "ghidrecomp-batch-decompile",
                "sourcePath": str(path),
            }
            if digest:
                row["analysisBinarySha256"] = digest
                row["targetSha256"] = digest
            fh.write(json.dumps(row, sort_keys=True) + "\n")
            written += 1

    return {
        "schema": SCHEMA,
        "status": "complete",
        "factsJsonl": str(out_jsonl),
        "written": written,
        "analysisBinarySha256": digest or None,
        "claimBoundary": "advisory decompilation facts only; objdiff 0 still required for verified/",
    }
