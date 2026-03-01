#!/usr/bin/env python3
"""Bootstrap script for proxy MCP server integration test.

This tests the local HTTP proxy server forwarding to remote backend.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import time
from typing import Any


async def run_command(
    cmd_num: int,
    description: str,
    server_url: str,
    cmd: list[str],
    expected_keys: list[str] | None = None,
) -> bool:
    """Run CLI command and validate output."""
    print(f"\n[*] {cmd_num}. {description}")
    print(f"    Server: {server_url.split('/')[-2]}")
    
    full_cmd = [
        "uvx",
        "--from",
        "git+https://github.com/bolabaden/agentdecompile",
        "agentdecompile-cli",
        "--server-url",
        server_url,
    ] + cmd
    
    try:
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        
        if result.returncode != 0:
            return False
        
        # Parse JSON
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
        except json.JSONDecodeError:
            return False
        
        if expected_keys and not all(k in data for k in expected_keys):
            return False
        
        return True
        
    except (subprocess.TimeoutExpired, Exception) as e:
        print(f"    Error: {str(e)[:100]}")
        return False


async def main():
    """Main test."""
    remote_url = "http://170.9.241.140:8080/"
    proxy_url = "http://127.0.0.1:8081/"
    test_prog = "/K1/k1_win_gog_swkotor.exe"
    
    print("="*70)
    print("PROXY MCP SERVER INTEGRATION TEST")
    print("="*70)
    
    # Start proxy server in background
    print("\n[*] Starting local HTTP proxy server on localhost:8081...")
    env = os.environ.copy()
    env["AGENT_DECOMPILE_BACKEND_URL"] = remote_url
    
    proxy_process = subprocess.Popen(
        [
            "uvx",
            "--from",
            "git+https://github.com/bolabaden/agentdecompile",
            "agentdecompile-proxy",
            "--backend",
            remote_url,
            "--http",
            "--port",
            "8081",
        ],
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
        env=env,
    )
    
    print(f"[+] Proxy server started (PID {proxy_process.pid})")
    print("[*] Waiting for proxy to be ready...")
    time.sleep(3)
    
    try:
        # Test commands
        tests = [
            (1, "Open", ["open", "--server_host", "170.9.241.140", "--server_port", "13100", "--server_username", "OpenKotOR", "--server_password", "MuchaShakaPaka", test_prog], ["serverConnected"]),
            (2, "List files", ["list", "project-files"], ["count"]),
            (3, "Get functions", [ "get-functions", "--program_path", test_prog, "--limit", "5"], ["functions"]),
            (4, "Search symbols", ["tool", "search-symbols-by-name", json.dumps({"programPath": test_prog, "query": "main", "maxResults": 5})], ["query"]),
            (5, "Get references", ["tool", "get-references", json.dumps({"binary": test_prog, "target": "WinMain", "mode": "to", "limit": 5})], ["references"]),
            (6, "Get program", ["tool", "get-current-program", json.dumps({"programPath": test_prog})], ["functionCount"]),
            (7, "List imports", ["tool", "list-imports", json.dumps({"programPath": test_prog, "limit": 5})], ["mode"]),
            (8, "List exports", ["tool", "list-exports", json.dumps({"programPath": test_prog, "limit": 5})], ["mode"]),
        ]
        
        print("\n" + "="*70)
        print("RUNNING TESTS: Remote vs Proxy")
        print("="*70)
        
        results_remote = []
        results_proxy = []
        
        for num, desc, cmd, expected in tests:
            remote_ok = await run_command(num, f"{desc} (remote)", remote_url, cmd, expected)
            results_remote.append(remote_ok)
            
            proxy_ok = await run_command(num, f"{desc} (proxy)", proxy_url, cmd, expected)
            results_proxy.append(proxy_ok)
            
            if remote_ok and proxy_ok:
                    print(f"    [OK] Both work")
                elif remote_ok and not proxy_ok:
                    print(f"    [FAIL] Proxy failed")
                elif not remote_ok:
                    print(f"    [SKIP] Remote failed")
        
        # Summary
        print("\n" + "="*70)
        print("SUMMARY")
        print("="*70)
        remote_pass = sum(results_remote)
        proxy_pass = sum(results_proxy)
        total = len(tests)
        
        print(f"Remote: {remote_pass}/{total} passed")
        print(f"Proxy:  {proxy_pass}/{total} passed")
        
        if proxy_pass == total and remote_pass == total:
            print("\n[OK] SUCCESS: Proxy works perfectly!")
            return 0
        elif proxy_pass == remote_pass and proxy_pass > 0:
            print(f"\n[OK] Partial success: {proxy_pass}/{total} commands work")
            return 0
        else:
            print(f"\n[FAIL] Proxy not working properly ({proxy_pass}/{total})")
            return 1
            
    finally:
        print("\n[*] Stopping proxy...")
        proxy_process.terminate()
        try:
            proxy_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy_process.kill()
        print("[+] Proxy stopped")


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
