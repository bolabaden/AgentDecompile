import json
from pathlib import Path
from datetime import datetime, timezone

root = Path(r"C:\Users\boden\.cursor\projects\c-GitHub-agentdecompile\agent-transcripts")
idx_path = Path(__file__).resolve().parent / "continual-learning-index.json"
now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

with open(idx_path, encoding="utf-8") as f:
    data = json.load(f)
old = dict(data.get("transcripts", {}))

new_transcripts: dict[str, dict] = {}
for p in sorted(root.rglob("*.jsonl")):
    ap = str(p.resolve())
    try:
        mtime_ms = int(p.stat().st_mtime * 1000)
    except OSError:
        continue
    prev = old.get(ap)
    if prev and prev.get("mtimeMs") == mtime_ms:
        new_transcripts[ap] = prev
    else:
        new_transcripts[ap] = {"mtimeMs": mtime_ms, "lastProcessedAt": now}

out = {"version": 1, "transcripts": new_transcripts}
with open(idx_path, "w", encoding="utf-8") as f:
    json.dump(out, f, indent=2)
    f.write("\n")
print("entries", len(new_transcripts))
