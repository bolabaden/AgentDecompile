#!/usr/bin/env python3
"""Simple bootstrap test for all 7 CLI commands."""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys


async def run_command(
    cmd_num: int,
    description: str,
    cmd: list[str],
    expected_keys: list[str] | None = None,
) -> bool:
    """Run a command and validate output."""
    print(f"\n[*] Command {cmd_num}: {description}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode != 0:
            print(f"[-] Failed with code {result.returncode}")
            if result.stderr:
                print(f"    Error: {result.stderr[:200]}")
            return False

        # Parse JSON from output
        output = result.stdout.strip()
        if not output:
            print("[-] Empty output")
            return False

        # Try to extract JSON
        try:
            if "content:" in output and "'text':" in output:
                # Parse wrapped response format
                start = output.find("'text': '") + len("'text': '")
                end = output.rfind("'")
                if start > 8 and end > start:
                    json_str = output[start:end]
                    json_str = json_str.replace("\\'", "'")
                    data = json.loads(json_str)
                else:
                    data = json.loads(output)
            else:
                data = json.loads(output)
        except json.JSONDecodeError as e:
            print(f"[-] JSON parse error: {e}")
            print(f"    Output: {output[:300]}")
            return False

        # Check expected keys
        if expected_keys:
            for key in expected_keys:
                if key not in data:
                    print(f"[-] Missing key: {key}")
                    return False

        # Print summary
        if isinstance(data, dict):
            for key in list(data.keys())[:2]:
                val = data[key]
                if isinstance(val, (int, bool, str, type(None))):
                    print(f"    {key}: {val}")
                elif isinstance(val, list):
                    print(f"    {key}: [{len(val)} items]")

        print("[+] OK")
        return True

    except subprocess.TimeoutExpired:
        print("[-] Timeout")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False


async def main():
    """Run all 7 tests."""
    remote_url = "http://170.9.241.140:8080/"
    test_prog = "/K1/k1_win_gog_swkotor.exe"

    print("=" * 70)
    print("TESTING 7 CLI COMMANDS VIA git+https REMOTE BACKEND")
    print("=" * 70)

    results = []

    # Cmd 1: Open program
    cmd = [
        "uvx",
        "--from",
        "git+https://github.com/bolabaden/agentdecompile",
        "agentdecompile-cli",
        "--server-url",
        remote_url,
        "open",
        "--server_host",
        "170.9.241.140",
        "--server_port",
        "13100",
        "--server_username",
        "OpenKotOR",
        "--server_password",
        "MuchaShakaPaka",
        test_prog,
    ]
    ok = await run_command(1, "Open program", cmd, ["serverConnected", "programCount"])
    results.append(ok)

    # Cmd 2: List files
    cmd = [
        "uvx",
        "--from",
        "git+https://github.com/bolabaden/agentdecompile",
        "agentdecompile-cli",
        "--server-url",
        remote_url,
        "list",
        "project-files",
    ]
    ok = await run_command(2, "List files", cmd, ["count", "files"])
    results.append(ok)

    # Cmd 3: Get functions
    cmd = [
        "uvx",
        "--from",
        "git+https://github.com/bolabaden/agentdecompile",
        "agentdecompile-cli",
        "--server-url",
        remote_url,
        "get-functions",
        "--program_path",
        test_prog,
        "--limit",
        "5",
    ]
    ok = await run_command(3, "Get 5 functions", cmd, ["functions", "totalMatched"])
    results.append(ok)

    # Cmd 4: Search symbols (via tool with JSON)
    json_args = json.dumps({"programPath": test_prog, "query": "main", "maxResults": 5})
    cmd = [
        "uvx",
        "--from",
        "git+https://github.com/bolabaden/agentdecompile",
        "agentdecompile-cli",
        "--server-url",
        remote_url,
        "tool",
        "search-symbols-by-name",
        json_args,
    ]
    ok = await run_command(4, "Search symbols (query='main')", cmd, ["query", "results"])
    results.append(ok)

    # Cmd 5: Get references
    json_args = json.dumps({"binary": test_prog, "target": "WinMain", "mode": "to", "limit": 5})
    cmd = [
        "uvx",
        "--from",
        "git+https://github.com/bolabaden/agentdecompile",
        "agentdecompile-cli",
        "--server-url",
        remote_url,
        "tool",
        "get-references",
        json_args,
    ]
    ok = await run_command(5, "Get references to WinMain", cmd, ["references"])
    results.append(ok)

    # Cmd 6: Get current program
    json_args = json.dumps({"programPath": test_prog})
    cmd = [
        "uvx",
        "--from",
        "git+https://github.com/bolabaden/agentdecompile",
        "agentdecompile-cli",
        "--server-url",
        remote_url,
        "tool",
        "get-current-program",
        json_args,
    ]
    ok = await run_command(6, "Get program info", cmd, ["loaded", "functionCount"])
    results.append(ok)

    # Cmd 7a: List imports
    json_args = json.dumps({"programPath": test_prog, "limit": 5})
    cmd = [
        "uvx",
        "--from",
        "git+https://github.com/bolabaden/agentdecompile",
        "agentdecompile-cli",
        "--server-url",
        remote_url,
        "tool",
        "list-imports",
        json_args,
    ]
    ok = await run_command(7, "List imports", cmd, ["mode", "results"])
    results.append(ok)

    # Cmd 7b: List exports
    json_args = json.dumps({"programPath": test_prog, "limit": 5})
    cmd = [
        "uvx",
        "--from",
        "git+https://github.com/bolabaden/agentdecompile",
        "agentdecompile-cli",
        "--server-url",
        remote_url,
        "tool",
        "list-exports",
        json_args,
    ]
    ok = await run_command(8, "List exports", cmd, ["mode", "results"])
    results.append(ok)

    # Summary
    print("\n" + "=" * 70)
    passed = sum(results)
    total = len(results)
    print(f"SUMMARY: {passed}/{total} commands passed")
    if passed == total:
        print("[+] ALL TESTS PASSED")
        return 0
    else:
        print(f"[-] {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
