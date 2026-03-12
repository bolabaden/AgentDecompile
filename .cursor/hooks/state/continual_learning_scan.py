"""One-off: list transcript paths, mtimes, and whether to process (new or mtime newer than index)."""
import os
import json

root = r"C:\Users\boden\.cursor\projects\c-GitHub-agentdecompile\agent-transcripts"
index_path = r"C:\GitHub\agentdecompile\.cursor\hooks\state\continual-learning-index.json"

with open(index_path) as f:
    index = json.load(f)
trans = index.get("transcripts", {})

to_process = []
all_current = {}
for dirpath, _, filenames in os.walk(root):
    for n in filenames:
        if not n.endswith(".jsonl"):
            continue
        path = os.path.join(dirpath, n)
        path_backslash = path.replace("/", "\\")
        mtime_ms = int(os.path.getmtime(path) * 1000)
        all_current[path_backslash] = mtime_ms
        entry = trans.get(path_backslash) or trans.get(path.replace("\\", "/"))
        old_ms = (entry or {}).get("mtimeMs", 0)
        if path_backslash not in trans and path.replace("\\", "/") not in trans:
            to_process.append((path_backslash, mtime_ms))
        elif mtime_ms > old_ms:
            to_process.append((path_backslash, mtime_ms))

for p, m in sorted(to_process, key=lambda x: x[0]):
    print("PROCESS", p, m)
print("---")
for p, m in sorted(all_current.items(), key=lambda x: x[0]):
    print("MTIME", p, m)
