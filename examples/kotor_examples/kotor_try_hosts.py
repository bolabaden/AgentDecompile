"""KotOR Phase 2d: Try different Ghidra server hostnames from inside Docker."""

from __future__ import annotations

import asyncio
import json
import sys

sys.path.insert(0, r"C:\GitHub\agentdecompile\src")
from agentdecompile_cli.bridge import RawMcpHttpBackend

BACKEND = "http://170.9.241.140:8080/mcp/message"


def extract_text(result: dict) -> str:
    content = result.get("content", [])
    return "\n".join(c["text"] for c in content if isinstance(c, dict) and "text" in c)


async def call(backend, tool, args, label):
    print(f"\n{'=' * 60}")
    print(f"[{label}] {tool}({json.dumps(args, default=str)})")
    print("=" * 60)
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

    # Try different hostnames for the Ghidra server
    hostnames = [
        "biodecompwarehouse",  # Docker service name
        "localhost",  # Same container?
        "host.docker.internal",  # Host from container
        "170.9.241.140",  # External IP
    ]

    for host in hostnames:
        r = await call(
            backend,
            "open",
            {
                "serverHost": host,
                "serverPort": 13100,
                "serverUsername": "OpenKotOR",
                "serverPassword": "MuchaShakaPaka",
                "path": "Odyssey",
            },
            f"OPEN_{host}",
        )

        if isinstance(r, dict) and r.get("programs"):
            print(f"\n*** SUCCESS with host={host}! Found {len(r['programs'])} programs ***")
            for p in r["programs"][:20]:
                print(f"  - {p}")
            break
        elif isinstance(r, dict) and r.get("availableRepositories"):
            print(f"\n*** Found repos at {host}: {r['availableRepositories']} ***")

    # Also try without auth to just check reachability
    print("\n\n--- Checking reachability without specific repo ---")
    for host in hostnames:
        r = await call(
            backend,
            "open",
            {
                "serverHost": host,
                "serverPort": 13100,
            },
            f"OPEN_NOAUTH_{host}",
        )

    print("\nDone.")


asyncio.run(main())
