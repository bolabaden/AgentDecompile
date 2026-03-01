#!/usr/bin/env python3
"""Bootstrap script for proxy MCP server integration testing.

This script tests that a local HTTP MCP proxy can successfully:
1. Start via agentdecompile-server with --backend-url pointing to remote
2. Accept CLI tool calls on localhost
3. Forward them to the remote MCP backend
4. Return results correctly

The test compares results from:
- Direct CLI calls to remote: http://170.9.241.140:8080/
- Proxied CLI calls to local: http://127.0.0.1:PORT/

Run: python bootstrap_proxy.py
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import time


class ProxyIntegrationTest:
    """Test local proxy forwarding to remote MCP backend."""

    def __init__(self):
        self.remote_backend_url: str = "http://170.9.241.140:8080/"
        self.local_proxy_url: str = "http://127.0.0.1:8081/"  # Local proxy on port 8081
        self.proxy_process: subprocess.Popen[bytes] | None = None
        self.proxy_port: int = 8081
        self.test_program: str = "/K1/k1_win_gog_swkotor.exe"
        self.results: list[tuple[int, str, bool]] = []

    async def start_proxy(self) -> bool:
        """Start local HTTP proxy server forwarding to remote."""
        print("[*] Starting local HTTP MCP proxy server...")
        print(f"    Remote backend: {self.remote_backend_url}")
        print(f"    Local proxy: {self.local_proxy_url}")

        env = os.environ.copy()
        env["AGENT_DECOMPILE_BACKEND_URL"] = self.remote_backend_url
        env["AGENT_DECOMPILE_GHIDRA_SERVER_HOST"] = os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_HOST", "170.9.241.140")
        env["AGENT_DECOMPILE_GHIDRA_SERVER_PORT"] = os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_PORT", "13100")
        env["AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME"] = os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME", "OpenKotOR")
        env["AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD"] = os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD", "MuchaShakaPaka")

        # Start agentdecompile-server in proxy mode with streamable-http transport
        cmd = [
            "uvx",
            "--from",
            "git+https://github.com/bolabaden/agentdecompile",
            "agentdecompile-server",
            "--transport",
            "streamable-http",
            "--backend-url",
            self.remote_backend_url,
            "--host",
            "127.0.0.1",
            "--port",
            str(self.proxy_port),
        ]

        print(f"[*] Command: {' '.join(cmd[:6])}... --port {self.proxy_port}")

        try:
            self.proxy_process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                text=False,
            )

            print(f"[+] Proxy started (PID: {self.proxy_process.pid})")

            # Wait for server to be ready
            print("[*] Waiting for proxy to be ready...")
            try:
                await self._wait_for_server_ready(timeout=15)
                print("[+] Proxy is ready!")
                return True
            except RuntimeError as e:
                print(f"[-] {e}")
                # Print stderr from process
                if self.proxy_process:
                    try:
                        self.proxy_process.terminate()
                        _, stderr = self.proxy_process.communicate(timeout=2)
                        if stderr:
                            print("\nProxy stderr:")
                            print(stderr.decode()[:1000])
                    except:
                        pass
                return False

        except Exception as e:
            print(f"[-] Failed to start proxy: {e}")
            return False

    async def _wait_for_server_ready(self, timeout: float = 15) -> bool:
        """Wait for local server to respond."""
        import httpx

        start = time.time()
        while time.time() - start < timeout:
            try:
                async with httpx.AsyncClient(timeout=2) as client:
                    resp = await client.post(
                        self.local_proxy_url,
                        json={
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "tools/listTools",
                            "params": {},
                        },
                    )
                    if 200 <= resp.status_code < 300:
                        return True
            except:
                pass

            await asyncio.sleep(0.5)

        raise RuntimeError(f"Proxy did not respond within {timeout}s")

    def stop_proxy(self) -> None:
        """Stop the proxy process."""
        if self.proxy_process:
            print("\n[*] Stopping proxy...")
            try:
                self.proxy_process.terminate()
                self.proxy_process.wait(timeout=5)
                print("[+] Proxy stopped")
            except subprocess.TimeoutExpired:
                print("[!] Killing proxy (didn't stop gracefully)")
                self.proxy_process.kill()
                self.proxy_process.wait()

    async def run_command(
        self,
        cmd_num: int,
        description: str,
        server_url: str,
        cmd_args: list[str],
        expected_keys: list[str] | None = None,
    ) -> bool:
        """Run CLI command against specified server."""
        full_cmd = [
            "uvx",
            "--from",
            "git+https://github.com/bolabaden/agentdecompile",
            "agentdecompile-cli",
            "--server-url",
            server_url,
        ] + cmd_args

        try:
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                return False

            # Parse JSON from output
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

            # Check expected keys
            if expected_keys:
                for key in expected_keys:
                    if key not in data:
                        return False

            return True

        except (subprocess.TimeoutExpired, Exception):
            return False

    async def test_both_backends(self) -> None:
        """Run same commands against both remote and proxy backends."""
        print("\n" + "=" * 70)
        print("COMPARING REMOTE vs LOCAL PROXY BACKEND")
        print("=" * 70)

        test_cases = [
            (
                1,
                "Open program",
                [
                    "open",
                    "--server_host",
                    "170.9.241.140",
                    "--server_port",
                    "13100",
                    "--server_username",
                    "OpenKotOR",
                    "--server_password",
                    "MuchaShakaPaka",
                    self.test_program,
                ],
                ["serverConnected"],
            ),
            (2, "List files", ["list", "project-files"], ["count", "files"]),
            (3, "Get 5 functions", ["get-functions", "--program_path", self.test_program, "--limit", "5"], ["functions", "totalMatched"]),
            (4, "Search symbols", ["tool", "search-symbols-by-name", json.dumps({"programPath": self.test_program, "query": "main", "maxResults": 5})], ["query", "results"]),
            (5, "Get references", ["tool", "get-references", json.dumps({"binary": self.test_program, "target": "WinMain", "mode": "to", "limit": 5})], ["references"]),
            (6, "Get program info", ["tool", "get-current-program", json.dumps({"programPath": self.test_program})], ["loaded", "functionCount"]),
            (7, "List imports", ["tool", "list-imports", json.dumps({"programPath": self.test_program, "limit": 5})], ["mode", "results"]),
            (8, "List exports", ["tool", "list-exports", json.dumps({"programPath": self.test_program, "limit": 5})], ["mode", "results"]),
        ]

        for cmd_num, desc, args, expected_keys in test_cases:
            print(f"\n[*] Test {cmd_num}: {desc}")

            # Test remote backend
            remote_ok = await self.run_command(cmd_num, desc, self.remote_backend_url, args, expected_keys)
            remote_status = "[+]" if remote_ok else "[-]"
            print(f"    Remote: {remote_status}")

            # Test proxy backend
            proxy_ok = await self.run_command(cmd_num, desc, self.local_proxy_url, args, expected_keys)
            proxy_status = "[+]" if proxy_ok else "[-]"
            print(f"    Proxy:  {proxy_status}")

            # Match result
            if remote_ok and proxy_ok:
                print("    Result: [PASS] Both backends work")
                self.results.append((cmd_num, desc, True))
            elif remote_ok and not proxy_ok:
                print("    Result: [FAIL] Proxy failed")
                self.results.append((cmd_num, desc, False))
            else:
                # Skip if both failed (likely setup issue)
                print("    Result: [SKIP] Remote failed too")

    def print_summary(self) -> bool:
        """Print test summary."""
        print("\n" + "=" * 70)
        print("SUMMARY")
        print("=" * 70)

        if not self.results:
            print("[!] No results")
            return False

        passed = sum(1 for _, _, ok in self.results if ok)
        total = len(self.results)

        for num, desc, ok in self.results:
            status = "[✓]" if ok else "[✗]"
            print(f"{status} {num}. {desc}")

        print(f"\nPassed: {passed}/{total}")

        return passed == total

    async def run(self) -> bool:
        """Run full integration test."""
        try:
            # Start proxy
            if not await self.start_proxy():
                print("[-] Failed to start proxy")
                return False

            # Test commands
            await self.test_both_backends()

            # Print summary
            return self.print_summary()

        finally:
            self.stop_proxy()


async def main():
    """Main entry point."""
    test = ProxyIntegrationTest()
    success = await test.run()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    asyncio.run(main())
