"""KotOR Save/Load Investigation — Phase 1: Discovery.

Uses RawMcpHttpBackend to call tools directly against the remote backend.
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


def save(name: str, data):
    path = os.path.join(OUT_DIR, f"{name}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"  -> saved {path}")


def extract_text(result: dict) -> str:
    """Extract text content from a CallToolResult-shaped dict."""
    content = result.get("content", [])
    texts = []
    for c in content:
        if isinstance(c, dict) and "text" in c:
            texts.append(c["text"])
    return "\n".join(texts)


async def call(backend: RawMcpHttpBackend, tool: str, args: dict, label: str) -> dict:
    print(f"\n{'=' * 60}")
    print(f"[{label}] {tool}({json.dumps(args, default=str)[:120]})")
    print(f"{'=' * 60}")
    try:
        result = await backend.call_tool(tool, args)
        text = extract_text(result)
        if text:
            # Try to parse as JSON for pretty print
            try:
                parsed = json.loads(text)
                print(json.dumps(parsed, indent=2, default=str)[:2000])
                return parsed
            except json.JSONDecodeError:
                print(text[:2000])
                return {"_raw_text": text}
        else:
            print(json.dumps(result, indent=2, default=str)[:2000])
            return result
    except Exception as e:
        print(f"  ERROR: {type(e).__name__}: {e}")
        return {"_error": str(e)}


async def main():
    backend = RawMcpHttpBackend(BACKEND, connect_timeout=15.0, op_timeout=120.0)
    print("Initializing backend connection...")
    await backend.initialize()
    print(f"Connected! Session: {backend._session_id}\n")

    # ======================================================================
    # 1. List tools available
    # ======================================================================
    tools = await backend.list_tools()
    tool_names = [t["name"] for t in tools]
    print(f"Available tools ({len(tools)}): {tool_names}")
    save("00_available_tools", tool_names)

    # ======================================================================
    # 2. List project files
    # ======================================================================
    r = await call(backend, "list-project-files", {}, "LIST_PROJECT_FILES")
    save("01_project_files", r)

    # ======================================================================
    # 3. Manage files - list root
    # ======================================================================
    r = await call(backend, "manage-files", {"action": "list"}, "MANAGE_FILES_ROOT")
    save("02_files_root", r)

    # ======================================================================
    # 4. Manage files - list project dir
    # ======================================================================
    r = await call(backend, "manage-files", {"action": "list", "path": "/ghidra/agentdecompile_projects"}, "MANAGE_FILES_PROJECTS")
    save("03_files_projects", r)

    # ======================================================================
    # 5. Search for save-related symbols
    # ======================================================================
    for pattern in ["Save", "save", "GFF", "gff", "Serialize", "serialize", "Write", "CExoFile"]:
        r = await call(backend, "search-symbols-by-name", {"pattern": pattern, "max_results": 50}, f"SEARCH_{pattern}")
        save(f"04_search_{pattern}", r)

    # ======================================================================
    # 6. Search for load-related symbols
    # ======================================================================
    for pattern in ["Load", "load", "Read", "Deserialize", "deserialize", "CRes", "Resource"]:
        r = await call(backend, "search-symbols-by-name", {"pattern": pattern, "max_results": 50}, f"SEARCH_{pattern}")
        save(f"05_search_{pattern}", r)

    # ======================================================================
    # 7. List functions (get overview)
    # ======================================================================
    r = await call(backend, "list-functions", {"offset": 0, "limit": 100}, "LIST_FUNCTIONS_0")
    save("06_functions_first100", r)

    # ======================================================================
    # 8. Get function count
    # ======================================================================
    r = await call(backend, "get-functions", {"mode": "count"}, "FUNC_COUNT")
    save("07_function_count", r)

    # ======================================================================
    # 9. Search functions matching save/load patterns
    # ======================================================================
    for pat in ["SaveGame", "LoadGame", "SaveGFF", "LoadGFF", "WriteGFF", "ReadGFF", "CSaveGameFile", "CLoadGameFile", "CGFFStruct", "CExoFile", "Serialize", "Deserialize"]:
        r = await call(backend, "get-functions", {"mode": "search", "search": pat, "limit": 30}, f"FUNC_SEARCH_{pat}")
        save(f"08_func_search_{pat}", r)

    # ======================================================================
    # 10. List strings related to save/load
    # ======================================================================
    for pat in ["save", "load", ".gff", ".sav", "serialize", "SAVEGAME", "GFF"]:
        r = await call(backend, "manage-strings", {"action": "search", "pattern": pat, "max_results": 50}, f"STRINGS_{pat}")
        save(f"09_strings_{pat}", r)

    # ======================================================================
    # 11. List data types
    # ======================================================================
    r = await call(backend, "manage-data-types", {"action": "list", "category": "/"}, "DATA_TYPES_ROOT")
    save("10_data_types_root", r)

    # ======================================================================
    # 12. Search structures
    # ======================================================================
    for pat in ["GFF", "Save", "Load", "CExo", "Struct", "Field", "Resource"]:
        r = await call(backend, "manage-structures", {"action": "search", "pattern": pat}, f"STRUCT_SEARCH_{pat}")
        save(f"11_struct_search_{pat}", r)

    # ======================================================================
    # 13. Manage symbols - list imports
    # ======================================================================
    r = await call(backend, "manage-symbols", {"mode": "imports", "max_results": 100}, "IMPORTS")
    save("12_imports", r)

    # ======================================================================
    # 14. Manage symbols - list exports
    # ======================================================================
    r = await call(backend, "manage-symbols", {"mode": "exports", "max_results": 100}, "EXPORTS")
    save("13_exports", r)

    # ======================================================================
    # 15. Manage symbols - classes
    # ======================================================================
    r = await call(backend, "manage-symbols", {"mode": "classes", "max_results": 100}, "CLASSES")
    save("14_classes", r)

    # ======================================================================
    # 16. Manage symbols - namespaces
    # ======================================================================
    r = await call(backend, "manage-symbols", {"mode": "namespaces", "max_results": 100}, "NAMESPACES")
    save("15_namespaces", r)

    print("\n\n" + "=" * 60)
    print("PHASE 1 COMPLETE - Discovery results saved to", OUT_DIR)
    print("=" * 60)

    await backend.close()


if __name__ == "__main__":
    asyncio.run(main())
