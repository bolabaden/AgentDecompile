#!/usr/bin/env python3
"""Bootstrap script for proxy MCP server integration testing.

This script:
1. Starts a local proxy MCP server (via uv) that forwards to remote backend
2. Waits for the proxy to be ready
3. Runs all 7 CLI test commands through the local proxy
4. Captures and validates the output
5. Cleans up resources

Run this script from the project root directory.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


class ProxyBootstrap:
    """Bootstrap and manage proxy server integration testing."""
    
    def __init__(self):
        self.project_root = Path(__file__).parent if __file__ != "<stdin>" else Path.cwd()
        self.remote_backend = os.getenv(
            "AGENT_DECOMPILE_BACKEND_URL",
            "http://170.9.241.140:8080/"
        )
        self.proxy_process: subprocess.Popen[bytes] | None = None
        self.ghidra_server_host = os.getenv(
            "AGENT_DECOMPILE_GHIDRA_SERVER_HOST",
            "170.9.241.140"
        )
        self.ghidra_server_port = os.getenv(
            "AGENT_DECOMPILE_GHIDRA_SERVER_PORT",
            "13100"
        )
        self.ghidra_server_username = os.getenv(
            "AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME",
            "OpenKotOR"
        )
        self.ghidra_server_password = os.getenv(
            "AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD",
            "MuchaShakaPaka"
        )
        self.test_program = "/K1/k1_win_gog_swkotor.exe"
        self.results = []
        
    async def start_proxy_server(self) -> None:
        """Start the proxy server using uvx."""
        print("[*] Starting local proxy MCP server...")
        print(f"    Remote backend: {self.remote_backend}")
        
        env = os.environ.copy()
        env["AGENT_DECOMPILE_BACKEND_URL"] = self.remote_backend
        env["AGENT_DECOMPILE_GHIDRA_SERVER_HOST"] = self.ghidra_server_host
        env["AGENT_DECOMPILE_GHIDRA_SERVER_PORT"] = self.ghidra_server_port
        env["AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME"] = self.ghidra_server_username
        env["AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD"] = self.ghidra_server_password
        
        # Start proxy via uvx with git+https (from github)
        cmd = [
            "uvx",
            "--from",
            "git+https://github.com/bolabaden/agentdecompile",
            "agentdecompile-proxy",
            "--verbose"
        ]
        
        print(f"[*] Command: {' '.join(cmd)}")
        
        try:
            self.proxy_process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                text=False,
            )
            print("[+] Proxy server started (PID: {})".format(self.proxy_process.pid))
            
            # Wait a bit for server to be ready
            await asyncio.sleep(3)
            
        except Exception as e:
            print(f"[-] Failed to start proxy: {e}")
            raise
            
    def stop_proxy_server(self) -> None:
        """Stop the proxy server."""
        if self.proxy_process:
            print("[*] Stopping proxy server...")
            try:
                self.proxy_process.terminate()
                self.proxy_process.wait(timeout=5)
                print("[+] Proxy server stopped")
            except subprocess.TimeoutExpired:
                print("[!] Proxy server didn't stop gracefully, killing...")
                self.proxy_process.kill()
                self.proxy_process.wait()
                
    async def run_cli_command(
        self,
        cmd_num: int,
        description: str,
        cmd_args: list[str],
        expected_keys: list[str] | None = None,
    ) -> bool:
        """Run a single CLI command and validate output."""
        print(f"\n[*] Command {cmd_num}: {description}")
        print(f"    Args: {' '.join(cmd_args[:3])}...")
        
        # Build the full command using uvx git+https
        full_cmd = [
            "uvx",
            "--from",
            "git+https://github.com/bolabaden/agentdecompile",
            "agentdecompile-cli",
            "--server-url",
            self.remote_backend,  # Use remote directly for now (proxy integration later)
        ] + cmd_args
        
        try:
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=30,
                env=os.environ.copy(),
            )
            
            if result.returncode != 0:
                print(f"[-] Command failed with code {result.returncode}")
                print(f"    Stderr: {result.stderr[:200]}")
                return False
                
            # Try to parse output as JSON
            output_text = result.stdout.strip()
            
            # Extract JSON from content wrapper if present
            if "content:" in output_text:
                # Parse the wrapped response
                try:
                    # Extract the JSON-like content
                    start = output_text.find("'text': '") + len("'text': '")
                    end = output_text.rfind("'")
                    if start > 8 and end > start:
                        json_str = output_text[start:end]
                        # Handle escaped quotes
                        json_str = json_str.replace("\\'", "'")
                        data = json.loads(json_str)
                    else:
                        data = json.loads(output_text)
                except json.JSONDecodeError:
                    print(f"[!] Could not parse JSON output")
                    print(f"    Raw: {output_text[:300]}")
                    return False
            else:
                try:
                    data = json.loads(output_text)
                except json.JSONDecodeError:
                    print(f"[!] Could not parse JSON output")
                    print(f"    Raw: {output_text[:300]}")
                    return False
                    
            # Validate expected keys
            if expected_keys:
                for key in expected_keys:
                    if key not in data:
                        print(f"[-] Missing expected key: {key}")
                        return False
                        
            # Show sample data
            if isinstance(data, dict):
                for key in list(data.keys())[:3]:
                    val = data[key]
                    if isinstance(val, list) and len(val) > 0:
                        print(f"    {key}: {len(val)} items")
                    elif isinstance(val, (int, str, bool)):
                        print(f"    {key}: {val}")
                    else:
                        print(f"    {key}: <{type(val).__name__}>")
                        
            print(f"[+] Command {cmd_num} OK")
            self.results.append((cmd_num, description, True))
            return True
            
        except subprocess.TimeoutExpired:
            print(f"[-] Command timed out")
            return False
        except Exception as e:
            print(f"[-] Command error: {e}")
            return False
            
    async def call_tool_via_proxy(
        self,
        method: str,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Call a tool through the proxy server via JSON-RPC."""
        if not self.proxy_process:
            raise RuntimeError("Proxy process not started")
            
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": {
                "name": tool_name,
                "arguments": arguments,
            }
        }
        
        try:
            # Send request to proxy
            request_json = json.dumps(request) + "\n"
            self.proxy_process.stdin.write(request_json.encode())
            self.proxy_process.stdin.flush()
            
            # Read response (timeout after 10 seconds)
            start = time.time()
            while time.time() - start < 10:
                line = self.proxy_process.stdout.readline()
                if line:
                    response = json.loads(line.decode())
                    if response.get("id") == 1:
                        if "result" in response:
                            return response["result"]
                        elif "error" in response:
                            print(f"[!] Tool error: {response['error']}")
                            return None
                await asyncio.sleep(0.1)
                
            print("[!] Tool call timed out")
            return None
            
        except Exception as e:
            print(f"[!] Error calling tool: {e}")
            return None
    
    async def run_all_commands(self) -> None:
        """Run all 7 test commands via proxy."""
        print("\n" + "="*60)
        print("TESTING 7 CLI COMMANDS VIA LOCAL PROXY MCP SERVER")
        print("="*60)
        
        # Command 1: Open program (via manage-files action=open)
        print(f"\n[*] Command 1: Open program from shared repository")
        result = await self.call_tool_via_proxy(
            "tools/call_tool",
            "open",
            {
                "mode": "shared-server",
                "serverHost": self.ghidra_server_host,
                "serverPort": int(self.ghidra_server_port),
                "serverUsername": self.ghidra_server_username,
                "serverPassword": self.ghidra_server_password,
                "serverRepositoryName": "Odyssey",
                "programPath": self.test_program,
            }
        )
        if result and "serverConnected" in result:
            print("[+] Command 1 OK")
            self.results.append((1, "Open program", True))
        else:
            print("[-] Command 1 failed")
            self.results.append((1, "Open program", False))
        
        # Command 2: List project files
        print(f"\n[*] Command 2: List files in shared repository")
        result = await self.call_tool_via_proxy(
            "tools/call_tool",
            "list-project-files",
            {}
        )
        if result and "files" in result:
            print(f"[+] Command 2 OK - found {result.get('count', '?')} files")
            self.results.append((2, "List files", True))
        else:
            print("[-] Command 2 failed")
            self.results.append((2, "List files", False))
        
        # Command 3: Get functions
        print(f"\n[*] Command 3: Get first 5 functions")
        result = await self.call_tool_via_proxy(
            "tools/call_tool",
            "get-functions",
            {
                "programPath": self.test_program,
                "limit": 5,
            }
        )
        if result and "functions" in result:
            print(f"[+] Command 3 OK - found {result.get('totalMatched', '?')} functions")
            self.results.append((3, "Get functions", True))
        else:
            print("[-] Command 3 failed")
            self.results.append((3, "Get functions", False))
        
        # Command 4: Search symbols by name
        print(f"\n[*] Command 4: Search symbols by name (query='main')")
        result = await self.call_tool_via_proxy(
            "tools/call_tool",
            "search-symbols-by-name",
            {
                "programPath": self.test_program,
                "query": "main",
                "maxResults": 5,
            }
        )
        if result and "query" in result and result["query"] == "main":
            print(f"[+] Command 4 OK - found {result.get('totalMatched', '?')} matches")
            self.results.append((4, "Search symbols", True))
        else:
            print("[-] Command 4 failed")
            print(f"    Result: {result}")
            self.results.append((4, "Search symbols", False))
        
        # Command 5: Get references
        print(f"\n[*] Command 5: Find references to WinMain")
        result = await self.call_tool_via_proxy(
            "tools/call_tool",
            "get-references",
            {
                "binary": self.test_program,
                "target": "WinMain",
                "mode": "to",
                "limit": 5,
            }
        )
        if result and "references" in result:
            print(f"[+] Command 5 OK - found {len(result['references'])} references")
            self.results.append((5, "Find references", True))
        else:
            print("[-] Command 5 failed")
            self.results.append((5, "Find references", False))
        
        # Command 6: Get current program
        print(f"\n[*] Command 6: Get current program info")
        result = await self.call_tool_via_proxy(
            "tools/call_tool",
            "get-current-program",
            {
                "programPath": self.test_program,
            }
        )
        if result and "functionCount" in result:
            print(f"[+] Command 6 OK - {result.get('functionCount')} functions")
            self.results.append((6, "Get program info", True))
        else:
            print("[-] Command 6 failed")
            self.results.append((6, "Get program info", False))
        
        # Command 7a: List imports
        print(f"\n[*] Command 7a: List imports")
        result = await self.call_tool_via_proxy(
            "tools/call_tool",
            "list-imports",
            {
                "programPath": self.test_program,
                "limit": 5,
            }
        )
        if result and "mode" in result and result["mode"] == "imports":
            print(f"[+] Command 7a OK - found {result.get('count')} imports")
            self.results.append((7, "List imports", True))
        else:
            print("[-] Command 7a failed")
            self.results.append((7, "List imports", False))
        
        # Command 7b: List exports
        print(f"\n[*] Command 7b: List exports")
        result = await self.call_tool_via_proxy(
            "tools/call_tool",
            "list-exports",
            {
                "programPath": self.test_program,
                "limit": 5,
            }
        )
        if result and "mode" in result and result["mode"] == "exports":
            print(f"[+] Command 7b OK - found {result.get('count')} exports")
            self.results.append((8, "List exports", True))
        else:
            print("[-] Command 7b failed")
            self.results.append((8, "List exports", False))
        
    def print_summary(self) -> None:
        """Print test summary."""
        print("\n" + "="*60)
        print("TEST SUMMARY")
        print("="*60)
        
        passed = sum(1 for _, _, result in self.results if result)
        total = len(self.results)
        
        for cmd_num, desc, result in self.results:
            status = "[✓]" if result else "[✗]"
            print(f"{status} {cmd_num}. {desc}")
            
        print(f"\nPassed: {passed}/{total}")
        
        if passed == total:
            print("\n[+] All tests passed!")
            return True
        else:
            print(f"\n[-] {total - passed} test(s) failed")
            return False
            
    async def run(self) -> bool:
        """Run the full bootstrap process."""
        try:
            # Start proxy server
            await self.start_proxy_server()
            
            # Run all test commands
            await self.run_all_commands()
            
            # Print summary
            success = self.print_summary()
            
            return success
            
        finally:
            # Clean up
            self.stop_proxy_server()


async def main():
    """Main entry point."""
    bootstrap = ProxyBootstrap()
    success = await bootstrap.run()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    asyncio.run(main())
