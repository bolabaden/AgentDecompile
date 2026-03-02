"""KotOR Phase 2c: Connect to Ghidra shared server and checkout a program."""

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
                print(json.dumps(parsed, indent=2, default=str)[:5000])
                return parsed
            except json.JSONDecodeError:
                print(text[:5000])
                return {"_raw_text": text}
        else:
            print(json.dumps(result, indent=2, default=str)[:5000])
            return result
    except Exception as e:
        print(f"  ERROR: {type(e).__name__}: {e}")
        return {"_error": str(e)}


async def main():
    backend = RawMcpHttpBackend(BACKEND, connect_timeout=15.0, op_timeout=300.0)
    print("Initializing backend connection...")
    await backend.initialize()
    print(f"Connected! Session: {backend._session_id}\n")

    # Step 1: Connect to the Ghidra shared server and discover repos/programs
    print("=" * 60)
    print("STEP 1: Connect to Ghidra shared server")
    print("=" * 60)
    r = await call(
        backend,
        "open",
        {
            "serverHost": "170.9.241.140",
            "serverPort": 13100,
            "serverUsername": "OpenKotOR",
            "serverPassword": "MuchaShakaPaka",
            "path": "Odyssey",
        },
        "OPEN_SHARED_SERVER",
    )

    # Save the full result
    import os

    os.makedirs(r"C:\GitHub\agentdecompile\tmp\kotor_results", exist_ok=True)
    with open(r"C:\GitHub\agentdecompile\tmp\kotor_results\shared_server_connect.json", "w") as f:
        json.dump(r, f, indent=2, default=str)

    # Check what programs/binaries are available
    if isinstance(r, dict):
        programs = r.get("programs", [])
        repo = r.get("repository")
        print(f"\nRepository: {repo}")
        print(f"Program count: {r.get('programCount', 0)}")
        print(f"Available repositories: {r.get('availableRepositories', [])}")
        print(f"Checked out program: {r.get('checkedOutProgram')}")
        print(f"Checkout error: {r.get('checkoutError')}")

        if programs:
            print(f"\nPrograms found ({len(programs)}):")
            for p in programs[:20]:
                print(f"  - {p.get('path', p.get('name', p))}")
        else:
            print("\nNo programs listed. The repository may be empty or require checkout.")

    # Step 2: If we got programs, try to checkout the main KotOR executable
    if isinstance(r, dict) and r.get("programs"):
        programs = r["programs"]
        # Look for the main KotOR executable
        kotor_candidates = []
        for p in programs:
            name = str(p.get("name", "")).lower()
            path = str(p.get("path", "")).lower()
            if any(k in name or k in path for k in ["swkotor", "kotor", ".exe"]):
                kotor_candidates.append(p)

        if kotor_candidates:
            target = kotor_candidates[0]
            target_path = target.get("path", target.get("name"))
            print(f"\nFound KotOR executable: {target_path}")
            print("Attempting checkout...")

            r2 = await call(
                backend,
                "open",
                {
                    "serverHost": "170.9.241.140",
                    "serverPort": 13100,
                    "serverUsername": "OpenKotOR",
                    "serverPassword": "MuchaShakaPaka",
                    "path": target_path,
                },
                "CHECKOUT_KOTOR",
            )
        else:
            print("\nNo KotOR executable found in programs list. Listing all:")
            for p in programs:
                print(f"  {json.dumps(p, default=str)}")

    # Step 3: Check if program is now loaded
    print("\n\n" + "=" * 60)
    print("STEP 3: Check current program status")
    print("=" * 60)
    r = await call(backend, "get-current-program", {}, "CURRENT_PROGRAM")

    # Step 4: Quick test - try function count
    r = await call(backend, "get-functions", {"mode": "count"}, "FUNC_COUNT")

    # Step 5: List project binaries
    r = await call(backend, "list-project-binaries", {}, "LIST_BINARIES")

    # Step 6: List project files
    r = await call(backend, "list-project-files", {}, "LIST_PROJECT_FILES")

    print("\n\nDone.")


asyncio.run(main())
