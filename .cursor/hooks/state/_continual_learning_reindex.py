"""One-off reindex for continual-learning; run from repo root."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

root = Path(r"C:\Users\boden\.cursor\projects\c-GitHub-agentdecompile\agent-transcripts")
idx_path = Path(__file__).resolve().parent / "continual-learning-index.json"


def utc_iso_now() -> str:
    dt = datetime.now(timezone.utc)
    ms = dt.microsecond // 1000
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms:03d}Z"


old: dict = {}
if idx_path.exists():
    old = json.loads(idx_path.read_text(encoding="utf-8")).get("transcripts", {})

on_disk: dict[str, int] = {}
for p in root.rglob("*.jsonl"):
    try:
        on_disk[str(p)] = int(p.stat().st_mtime_ns // 1_000_000)
    except OSError:
        pass

processed: set[str] = set()
for path, m_new in on_disk.items():
    prev = old.get(path)
    if prev is None:
        processed.add(path)
    elif m_new > prev.get("mtimeMs", 0):
        processed.add(path)

new_transcripts: dict[str, dict] = {}
now = utc_iso_now()
for path, mtime_ms in sorted(on_disk.items()):
    prev = old.get(path, {})
    new_transcripts[path] = {
        "mtimeMs": mtime_ms,
        "lastProcessedAt": now if path in processed else prev.get("lastProcessedAt", now),
    }

out = {"version": 1, "transcripts": new_transcripts}
idx_path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print("entries", len(new_transcripts), "lastProcessedAt_bumped", len(processed))
