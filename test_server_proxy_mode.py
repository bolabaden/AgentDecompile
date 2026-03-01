#!/usr/bin/env python3
"""Simple test using agentdecompile-server in proxy mode."""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time


async def run_cmd(cmd: str, timeout=30):
    """Run command and return success."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0:
            return False

        output = r.stdout.strip()
        if "content:" in output and "'text':" in output:
            start = output.find("'text': '") + len("'text': '")
            end = output.rfind("'")
            if start > 8 and end > start:
                json_str = output[start:end].replace("\\'", "'")
                json.loads(json_str)
            else:
                json.loads(output)
        else:
            json.loads(output)
        return True
    except Exception:
        return False


async def main():
    """Test via agentdecompile-server in proxy mode."""
    print("Testing AgentDecompile proxy via server proxy mode")
    print("=" * 60)

    # Start server in proxy mode
    remote = "http://170.9.241.140:8080/"
    local = "http://127.0.0.1:8082/"

    print("\nStarting agentdecompile-server in proxy mode...")
    print(f"  Remote: {remote}")
    print(f"  Local:  {local}")

    server = subprocess.Popen(
        [
            "uvx",
            "--from",
            "git+https://github.com/bolabaden/agentdecompile",
            "agentdecompile-server",
            "--transport",
            "streamable-http",
            "--backend-url",
            remote,
            "--host",
            "127.0.0.1",
            "--port",
            "8082",
        ]
    )

    print(f"Server PID: {server.pid}")
    print("Waiting for server to start...")
    time.sleep(4)

    try:
        # Test one command against both remote and proxy
        print("\nTesting 'list project-files' command...")

        remote_cmd = ["uvx", "--from", "git+https://github.com/bolabaden/agentdecompile", "agentdecompile-cli", "--server-url", remote, "list", "project-files"]

        proxy_cmd = ["uvx", "--from", "git+https://github.com/bolabaden/agentdecompile", "agentdecompile-cli", "--server-url", local, "list", "project-files"]

        r_ok = await run_cmd(remote_cmd)
        p_ok = await run_cmd(proxy_cmd)

        print(f"  Remote: {'OK' if r_ok else 'FAIL'}")
        print(f"  Proxy:  {'OK' if p_ok else 'FAIL'}")

        if p_ok:
            print("\n[SUCCESS] Proxy server works!")
            return 0
        else:
            print("\n[FAIL] Proxy server not responding")
            return 1

    finally:
        print("\nStopping server...")
        server.terminate()
        server.wait(timeout=5)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
