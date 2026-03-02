"""KotOR Phase 2b: Deep filesystem search for binaries & try shared project sync."""

from __future__ import annotations

import asyncio
import json
import sys

sys.path.insert(0, r"C:\GitHub\agentdecompile\src")
from agentdecompile_cli.bridge import RawMcpHttpBackend

BACKEND = "http://170.9.241.140:8080/mcp/message"


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

    # Explore more filesystem paths
    paths_to_check = [
        "/projects",
        "/work",
        "/ghidra/repositories",
        "/ghidra/agentdecompile_projects/agentdecompile/gzfs",
        "/home/ghidra",
        "/root",
        "/srv",
        "/mnt",
    ]

    for path in paths_to_check:
        r = await call(backend, "manage-files", {"action": "list", "path": path}, f"LS_{path}")

    # Check if manage-files has a search/find capability
    r = await call(backend, "manage-files", {"action": "search", "pattern": "*.exe", "path": "/"}, "SEARCH_EXE")
    r = await call(backend, "manage-files", {"action": "search", "pattern": "*.gzf", "path": "/"}, "SEARCH_GZF")
    r = await call(backend, "manage-files", {"action": "search", "pattern": "swkotor", "path": "/"}, "SEARCH_SWKOTOR")
    r = await call(backend, "manage-files", {"action": "find", "pattern": "*.exe"}, "FIND_EXE")

    # Try to import from a URL or common location
    # Try the import-binary tool with the Ghidra project path
    r = await call(backend, "import-binary", {"path": "/ghidra/agentdecompile_projects/my_project.rep", "recursive": True}, "IMPORT_FROM_REP")

    # List tools to check if there's a sync or connect tool
    tools = await backend.list_tools()
    tool_names = sorted([t["name"] for t in tools])
    print(f"\n\nAll tools: {tool_names}")

    # Check for any sync/connect/shared project tools
    sync_tools = [t for t in tool_names if any(k in t.lower() for k in ["sync", "connect", "shared", "server", "remote", "repo"])]
    print(f"Sync/server tools: {sync_tools}")

    # Try sync-shared-project if it exists
    r = await call(
        backend, "sync-shared-project", {"host": "170.9.241.140", "port": 13100, "user": "OpenKotOR", "password": "MuchaShakaPaka", "repository": "Odyssey"}, "SYNC_SHARED"
    )

    print("\nDone.")


asyncio.run(main())
