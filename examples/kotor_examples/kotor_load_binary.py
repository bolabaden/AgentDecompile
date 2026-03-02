"""KotOR Phase 2: Load a binary into Ghidra.

Steps:
1. list-project-binaries to see what's already imported
2. manage-files list various paths to find binaries on the filesystem
3. Open or import whatever we find
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

sys.path.insert(0, r"C:\GitHub\agentdecompile\src")
from agentdecompile_cli.bridge import RawMcpHttpBackend

BACKEND = "http://170.9.241.140:8080/mcp/message"
OUT_DIR = r"C:\GitHub\agentdecompile\tmp\kotor_results"
os.makedirs(OUT_DIR, exist_ok=True)


def extract_text(result: dict) -> str:
    content = result.get("content", [])
    texts = []
    for c in content:
        if isinstance(c, dict) and "text" in c:
            texts.append(c["text"])
    return "\n".join(texts)


async def call(backend, tool, args, label):
    print(f"\n{'=' * 60}")
    print(f"[{label}] {tool}({json.dumps(args, default=str)})")
    print(f"{'=' * 60}")
    try:
        result = await backend.call_tool(tool, args)
        text = extract_text(result)
        if text:
            try:
                parsed = json.loads(text)
                print(json.dumps(parsed, indent=2, default=str)[:3000])
                return parsed
            except json.JSONDecodeError:
                print(text[:3000])
                return {"_raw_text": text}
        else:
            print(json.dumps(result, indent=2, default=str)[:3000])
            return result
    except Exception as e:
        print(f"  ERROR: {type(e).__name__}: {e}")
        return {"_error": str(e)}


async def main():
    backend = RawMcpHttpBackend(BACKEND, connect_timeout=15.0, op_timeout=300.0)
    print("Initializing backend connection...")
    await backend.initialize()
    print(f"Connected! Session: {backend._session_id}\n")

    # 1. List project binaries
    r = await call(backend, "list-project-binaries", {}, "LIST_BINARIES")

    # 2. List project files
    r = await call(backend, "list-project-files", {}, "LIST_PROJECT_FILES")

    # 3. Explore filesystem - look for binaries
    paths_to_check = [
        "/",
        "/ghidra",
        "/ghidra/agentdecompile_projects",
        "/ghidra/agentdecompile_projects/my_project.rep",
        "/ghidra/agentdecompile_projects/my_project.rep/idata",
        "/ghidra/agentdecompile_projects/agentdecompile",
        "/home",
        "/home/ubuntu",
        "/tmp",
        "/opt",
        "/data",
        "/binaries",
        "/ghidra/binaries",
    ]

    for path in paths_to_check:
        r = await call(backend, "manage-files", {"action": "list", "path": path}, f"LS_{path}")

    # 4. Try to open from the project - attempt various common program names
    program_paths_to_try = [
        "/swkotor.exe",
        "swkotor.exe",
        "/swkotor",
        "swkotor",
        "/kotor",
        "/bin.exe",
        "/main",
    ]

    for prog_path in program_paths_to_try:
        r = await call(backend, "open", {"programPath": prog_path}, f"OPEN_{prog_path}")
        # If we got success, stop trying
        if isinstance(r, dict) and r.get("success"):
            print(f"\n*** SUCCESS! Opened {prog_path} ***")
            break

    # 5. Try a function count to see if anything is loaded now
    r = await call(backend, "get-functions", {"mode": "count"}, "FUNC_COUNT_CHECK")

    print("\n\nDone. Check output above to determine next steps.")


asyncio.run(main())
