#!/usr/bin/env python3
"""Simple proxy test - just verify all 7 commands work."""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time


async def run_test(
    cmd_num: int,
    desc: str,
    server_url: str,
    cmd: list[str],
    expected_keys: list[str] | None = None,
) -> bool:
    """Run test command."""
    full_cmd: list[str] = ["uvx", "--from", "git+https://github.com/bolabaden/agentdecompile", "agentdecompile-cli", "--server-url", server_url] + cmd

    try:
        result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return False

        output = result.stdout.strip()
        if not output:
            return False

        try:
            if "content:" in output and "'text':" in output:
                start = output.find("'text': '") + len("'text': '")
                end = output.rfind("'")
                if start > 8 and end > start:
                    json_str = output[start:end].replace("\\'", "'")
                    data = json.loads(json_str)
                else:
                    data = json.loads(output)
            else:
                data = json.loads(output)
        except Exception:
            return False

        return expected_keys is None or all(k in data for k in expected_keys)

    except Exception:
        return False


async def main():
    """Main test."""
    remote = "http://170.9.241.140:8080/"
    local = "http://127.0.0.1:8081/"
    prog = "/K1/k1_win_gog_swkotor.exe"

    print("=" * 70)
    print("PROXY TEST: Remote vs Local")
    print("=" * 70)

    # Start proxy
    print("\nStarting local proxy on port 8081...")
    proxy = subprocess.Popen(["uvx", "--from", "git+https://github.com/bolabaden/agentdecompile", "agentdecompile-proxy", "--backend", remote, "--http", "--port", "8081"])
    print(f"Proxy PID: {proxy.pid}")
    time.sleep(2)

    try:
        tests = [
            (
                1,
                "Open",
                ["open", "--server_host", "170.9.241.140", "--server_port", "13100", "--server_username", "OpenKotOR", "--server_password", "MuchaShakaPaka", prog],
                ["serverConnected"],
            ),
            (2, "List", ["list", "project-files"], ["count"]),
            (3, "Funcs", ["get-functions", "--program_path", prog, "--limit", "5"], ["functions"]),
            (4, "Search", ["tool", "search-symbols-by-name", json.dumps({"programPath": prog, "query": "main", "maxResults": 5})], ["query"]),
            (5, "Refs", ["tool", "get-references", json.dumps({"binary": prog, "target": "WinMain", "mode": "to", "limit": 5})], ["references"]),
            (6, "Prog", ["tool", "get-current-program", json.dumps({"programPath": prog})], ["functionCount"]),
            (7, "Imp", ["tool", "list-imports", json.dumps({"programPath": prog, "limit": 5})], ["mode"]),
            (8, "Exp", ["tool", "list-exports", json.dumps({"programPath": prog, "limit": 5})], ["mode"]),
        ]

        print("\nRunning tests...")
        passed = 0

        for num, desc, cmd, expected in tests:
            r_ok = await run_test(num, desc, remote, cmd, expected)
            p_ok = await run_test(num, desc, local, cmd, expected)

            status = "OK" if (r_ok and p_ok) else "FAIL" if p_ok else "SKIP"
            print(f"  {num}. {desc:10} Remote:{str(r_ok):5} Proxy:{str(p_ok):5} [{status}]")

            if p_ok:
                passed += 1

        print(f"\nResult: {passed}/8 proxy tests passed")
        return 0 if passed == 8 else 1

    finally:
        print("\nStopping proxy...")
        proxy.terminate()
        proxy.wait(timeout=5)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()) if sys.version_info >= (3, 10) else asyncio.run(main()))
