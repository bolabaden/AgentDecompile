#!/usr/bin/env python3
"""Run or print a reusable CLI command matrix against an MCP backend.

This consolidates ad-hoc remote/proxy command scripts into a single configurable utility.

Examples:
  python helper_scripts/mcp_remote_matrix.py --print-cases
  python helper_scripts/mcp_remote_matrix.py --run --server-url http://127.0.0.1:8081/
  python helper_scripts/mcp_remote_matrix.py --run --uvx-from git+https://github.com/bolabaden/agentdecompile
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys

from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class CaseResult:
    label: str
    returncode: int
    ok: bool
    stdout: str
    stderr: str


def build_base_cmd(server_url: str, uvx_from: str, editable_local: bool) -> list[str]:
    if editable_local:
        return ["uvx", "--from", ".", "--with-editable", ".", "agentdecompile-cli", "--server-url", server_url]
    return ["uvx", "--from", uvx_from, "agentdecompile-cli", "--server-url", server_url]


def build_cases(program_path: str, host: str, port: int, username: str, password: str) -> list[tuple[str, list[str]]]:
    return [
        (
            "open",
            [
                "open",
                "--server_host", host,
                "--server_port", str(port),
                "--server_username", username,
                "--server_password", password,
                program_path,
            ],
        ),
        ("list project-files", ["list", "project-files"]),
        ("get-functions", ["get-functions", "--program_path", program_path, "--limit", "5"]),
        (
            "search-symbols-by-name",
            ["tool", "search-symbols-by-name", json.dumps({"programPath": program_path, "query": "main", "maxResults": 5})],
        ),
        (
            "get-references",
            ["tool", "get-references", json.dumps({"binary": program_path, "target": "WinMain", "mode": "to", "limit": 5})],
        ),
        (
            "get-current-program",
            ["tool", "get-current-program", json.dumps({"programPath": program_path})],
        ),
        ("list-imports", ["tool", "list-imports", json.dumps({"programPath": program_path, "limit": 5})]),
        ("list-exports", ["tool", "list-exports", json.dumps({"programPath": program_path, "limit": 5})]),
    ]


def run_case(cmd: list[str], timeout: int) -> CaseResult:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return CaseResult(
        label=" ".join(cmd[-3:]),
        returncode=proc.returncode,
        ok=(proc.returncode == 0),
        stdout=proc.stdout.strip(),
        stderr=proc.stderr.strip(),
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run/print a reusable AgentDecompile CLI command matrix")
    parser.add_argument("--server-url", default="http://170.9.241.140:8080/", help="Target MCP server URL")
    parser.add_argument("--program-path", default="/K1/k1_win_gog_swkotor.exe", help="Program path for tool calls")
    parser.add_argument("--ghidra-host", default="170.9.241.140", help="Ghidra shared-server host")
    parser.add_argument("--ghidra-port", type=int, default=13100, help="Ghidra shared-server port")
    parser.add_argument("--username", default="OpenKotOR", help="Ghidra shared-server username")
    parser.add_argument("--password", default="MuchaShakaPaka", help="Ghidra shared-server password")
    parser.add_argument("--uvx-from", default="git+https://github.com/bolabaden/agentdecompile", help="Value for `uvx --from` when not using local editable")
    parser.add_argument("--editable-local", action="store_true", help="Use `uvx --from . --with-editable .`")
    parser.add_argument("--run", action="store_true", help="Execute cases (default is print-only)")
    parser.add_argument("--print-cases", action="store_true", help="Print rendered command lines")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    parser.add_argument("--timeout", type=int, default=120, help="Per-command timeout seconds when running")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    base = build_base_cmd(args.server_url, args.uvx_from, args.editable_local)
    cases = build_cases(args.program_path, args.ghidra_host, args.ghidra_port, args.username, args.password)

    rendered = [{"label": label, "command": base + case} for label, case in cases]

    if args.print_cases and not args.run:
        if args.json:
            print(json.dumps({"cases": rendered}, indent=2))
        else:
            for row in rendered:
                print(f"[{row['label']}] {' '.join(row['command'])}")
        return 0

    if not args.run:
        if args.json:
            print(json.dumps({"message": "Nothing executed. Use --run or --print-cases.", "cases": rendered}, indent=2))
        else:
            print("Nothing executed. Use --run or --print-cases.")
        return 0

    results: list[dict[str, Any]] = []
    failed = 0
    for label, case in cases:
        full = base + case
        r = run_case(full, timeout=args.timeout)
        results.append({"label": label, **asdict(r), "command": full})
        if not r.ok:
            failed += 1

    payload = {
        "server_url": args.server_url,
        "total": len(cases),
        "failed": failed,
        "passed": len(cases) - failed,
        "results": results,
    }

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        for item in results:
            status = "PASS" if item["ok"] else "FAIL"
            print(f"[{status}] {item['label']} (rc={item['returncode']})")
        print(f"Summary: {payload['passed']}/{payload['total']} passed")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
