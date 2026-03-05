#!/usr/bin/env python3
"""
Unified MCP CLI testing utility combining three separate validators:
- mcp_remote_matrix.py: CLI command matrix runner (--run, --print-cases)
- validate_usage_md.py: UVX vs curl validation with full session testing
- verify_uvx_curl_equiv.py: UVX vs curl equivalence with response key verification

Usage:
  python helper_scripts/mcp_cli_testing.py matrix --print-cases
  python helper_scripts/mcp_cli_testing.py matrix --run --server-url http://127.0.0.1:8081/
  python helper_scripts/mcp_cli_testing.py validate
  python helper_scripts/mcp_cli_testing.py verify
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

# ============================================================================
# SHARED HELPERS
# ============================================================================


def run(cmd: str, timeout: int = 240) -> tuple[int, str, str]:
    """Run shell command and return (rc, stdout, stderr)."""
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout or ""), (p.stderr or "")


def run_ps(command: str, timeout: int = 300) -> tuple[int, str, str]:
    """Run PowerShell command."""
    p = subprocess.run(["powershell", "-NoProfile", "-Command", command], capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout or ""), (p.stderr or "")


def run_argv(argv: list[str], timeout: int = 300) -> tuple[int, str, str]:
    """Run command via argv array."""
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout or ""), (p.stderr or "")


def run_curl(
    payload: dict[str, Any],
    base_url: str = "http://170.9.241.140:8080/mcp/message/",
    sid: str | None = None,
    include_headers: bool = False,
    timeout: int = 300,
) -> tuple[int, str, str]:
    """Run curl MCP request."""
    data = json.dumps(payload)
    cmd = [
        "curl.exe",
        "-s",
        "-X",
        "POST",
        base_url,
        "-H",
        "Content-Type: application/json",
        "-H",
        "Accept: application/json, text/event-stream",
    ]
    if sid:
        cmd += ["-H", f"Mcp-Session-Id: {sid}"]
    if include_headers:
        cmd.insert(1, "-i")
    cmd += ["--data", data]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout or ""), (p.stderr or "")


# ============================================================================
# MATRIX MODE (from mcp_remote_matrix.py)
# ============================================================================


@dataclass
class CaseResult:
    label: str
    returncode: int
    ok: bool
    stdout: str
    stderr: str


def build_base_cmd(server_url: str, uvx_from: str, editable_local: bool, host: str = "", port: int = 0, username: str = "", password: str = "") -> list[str]:
    if editable_local:
        base = ["uvx", "--from", ".", "--with-editable", ".", "agentdecompile-cli", "--server-url", server_url]
    else:
        base = ["uvx", "--from", uvx_from, "agentdecompile-cli", "--server-url", server_url]
    # Pass Ghidra shared-server credentials globally so auto-recovery can use them
    if host:
        base += ["--ghidra-server-host", host]
    if port:
        base += ["--ghidra-server-port", str(port)]
    if username:
        base += ["--ghidra-server-username", username]
    if password:
        base += ["--ghidra-server-password", password]
    return base


def build_matrix_cases(program_path: str, host: str, port: int, username: str, password: str) -> list[tuple[str, list[str]]]:
    return [
        (
            "open",
            [
                "open",
                "--server_host",
                host,
                "--server_port",
                str(port),
                "--server_username",
                username,
                "--server_password",
                password,
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
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return CaseResult(
            label=" ".join(cmd[-3:]),
            returncode=proc.returncode,
            ok=(proc.returncode == 0),
            stdout=proc.stdout.strip(),
            stderr=proc.stderr.strip(),
        )
    except subprocess.TimeoutExpired:
        return CaseResult(
            label=" ".join(cmd[-3:]),
            returncode=-1,
            ok=False,
            stdout="",
            stderr=f"TIMEOUT after {timeout}s",
        )


def cmd_matrix(args: argparse.Namespace) -> int:
    """Run matrix test mode."""
    base = build_base_cmd(args.server_url, args.uvx_from, args.editable_local, args.ghidra_host, args.ghidra_port, args.username, args.password)
    cases = build_matrix_cases(args.program_path, args.ghidra_host, args.ghidra_port, args.username, args.password)

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


# ============================================================================
# VALIDATE MODE (from validate_usage_md.py)
# ============================================================================


def build_validate_cases(program_path: str, host: str = "170.9.241.140", port: int = 13100, username: str = "OpenKotOR", password: str = "idekanymore") -> list[dict[str, Any]]:
    """Build validation test cases."""
    uvx_prefix = (
        "uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli"
        f" --server-url http://{host}:8080/"
        f" --ghidra-server-host {host} --ghidra-server-port {port}"
        f" --ghidra-server-username {username} --ghidra-server-password {password}"
    )
    return [
        {
            "name": "open",
            "uvx": f"{uvx_prefix} open --server_host {host} --server_port {port} --server_username {username} --server_password {password} {program_path}",
            "tool": "open-project",
            "args": {
                "serverHost": host,
                "serverPort": port,
                "serverUsername": username,
                "serverPassword": password,
                "path": program_path,
            },
        },
        {"name": "list project-files", "uvx": f"{uvx_prefix} list project-files", "tool": "list-project-files", "args": {}},
        {
            "name": "get-current-program",
            "uvx": f"{uvx_prefix} get-current-program --program_path {program_path}",
            "tool": "get-current-program",
            "args": {"programPath": program_path},
        },
        {
            "name": "get-functions limit",
            "uvx": f"{uvx_prefix} get-functions --program_path {program_path} --limit 5",
            "tool": "get-functions",
            "args": {"programPath": program_path, "limit": 5},
        },
        {
            "name": "search-symbols-by-name",
            "uvx": f"{uvx_prefix} search-symbols-by-name --program_path {program_path} --query SaveGame --max_results 20",
            "tool": "search-symbols-by-name",
            "args": {"programPath": program_path, "query": "SaveGame", "maxResults": 20},
        },
        {
            "name": "references to",
            "uvx": f"{uvx_prefix} references to --binary {program_path} --target SaveGame --limit 25",
            "tool": "get-references",
            "args": {"programPath": program_path, "mode": "to", "target": "SaveGame", "limit": 25},
        },
    ]


def cmd_validate(args: argparse.Namespace) -> int:
    """Run validation mode (UVX vs curl comparison)."""
    base_url = args.base_url

    # Initialize via curl
    rc, out, err = run_curl(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "validate-cli", "version": "1.0"},
            },
        },
        base_url=base_url,
        include_headers=True,
    )

    if rc != 0:
        print(f"INIT_FAILED: {err}")
        return 1

    sid = ""
    for line in out.splitlines():
        if line.lower().startswith("mcp-session-id:"):
            sid = line.split(":", 1)[1].strip()
            break

    if not sid:
        print("INIT_NO_SID")
        print(out[:1000])
        return 1

    run_curl({"jsonrpc": "2.0", "method": "notifications/initialized"}, base_url=base_url, sid=sid)

    cases = build_validate_cases(args.program_path, args.ghidra_host, args.ghidra_port, args.username, args.password)
    summary: list[dict[str, Any]] = []
    Path("tmp").mkdir(exist_ok=True)

    for i, c in enumerate(cases, start=1):
        uvx_rc, uvx_out, uvx_err = run(c["uvx"], timeout=360)
        payload = {"jsonrpc": "2.0", "id": 100 + i, "method": "tools/call", "params": {"name": c["tool"], "arguments": c["args"]}}
        curl_rc, curl_out, curl_err = run_curl(payload, base_url=base_url, sid=sid, timeout=360)

        curl_json_ok = True
        curl_is_error = None
        try:
            parsed = json.loads(curl_out)
            if "error" in parsed:
                curl_json_ok = False
                curl_is_error = parsed["error"]
        except Exception as ex:
            curl_json_ok = False
            curl_is_error = str(ex)

        summary.append(
            {
                "index": i,
                "name": c["name"],
                "uvx_rc": uvx_rc,
                "curl_rc": curl_rc,
                "curl_json_ok": curl_json_ok,
                "curl_error": curl_is_error,
            }
        )

        Path(f"tmp/validate_uvx_{i:02d}.txt").write_text((uvx_out or "") + "\n---STDERR---\n" + (uvx_err or ""), encoding="utf-8")
        Path(f"tmp/validate_curl_{i:02d}.txt").write_text((curl_out or "") + "\n---STDERR---\n" + (curl_err or ""), encoding="utf-8")

    Path("tmp/validate_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    fail = [x for x in summary if x["uvx_rc"] != 0 or x["curl_rc"] != 0 or not x["curl_json_ok"]]
    print(f"SESSION={sid}")
    print(f"TOTAL={len(summary)} FAIL={len(fail)}")
    for f in fail:
        print(f"- {f['index']:02d} {f['name']} uvx_rc={f['uvx_rc']} curl_rc={f['curl_rc']} curl_json_ok={f['curl_json_ok']}")

    return 0 if len(fail) == 0 else 1


# ============================================================================
# VERIFY MODE (from verify_uvx_curl_equiv.py)
# ============================================================================


def build_verify_cases(program_path: str, host: str = "170.9.241.140", port: int = 13100, username: str = "OpenKotOR", password: str = "idekanymore") -> list[dict[str, Any]]:
    """Build verification test cases with response key checks."""
    uvx_prefix = (
        "uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli"
        f" --server-url http://{host}:8080/"
        f" --ghidra-server-host {host} --ghidra-server-port {port}"
        f" --ghidra-server-username {username} --ghidra-server-password {password}"
    )
    return [
        {
            "name": "open",
            "uvx": f"{uvx_prefix} open --server_host {host} --server_port {port} --server_username {username} --server_password {password} {program_path}",
            "tool": "open-project",
            "args": {
                "serverHost": host,
                "serverPort": port,
                "serverUsername": username,
                "serverPassword": password,
                "path": program_path,
            },
            "key": "checkedOutProgram",
        },
        {
            "name": "list project-files",
            "uvx": f"{uvx_prefix} list project-files",
            "tool": "list-project-files",
            "args": {},
            "key": "count",
        },
        {
            "name": "get-current-program",
            "uvx": f"{uvx_prefix} get-current-program --program_path {program_path}",
            "tool": "get-current-program",
            "args": {"programPath": program_path},
            "key": "functionCount",
        },
        {
            "name": "get-functions limit",
            "uvx": f"{uvx_prefix} get-functions --program_path {program_path} --limit 5",
            "tool": "get-functions",
            "args": {"programPath": program_path, "limit": 5},
            "key": "functions",
        },
        {
            "name": "search-symbols-by-name",
            "uvx": f"{uvx_prefix} search-symbols-by-name --program_path {program_path} --query SaveGame --max_results 20",
            "tool": "search-symbols-by-name",
            "args": {"programPath": program_path, "query": "SaveGame", "maxResults": 20},
            "key": "results",
        },
        {
            "name": "references to",
            "uvx": f"{uvx_prefix} references to --binary {program_path} --target SaveGame --limit 25",
            "tool": "get-references",
            "args": {"programPath": program_path, "mode": "to", "target": "SaveGame", "limit": 25},
            "key": "references",
        },
    ]


def cmd_verify(args: argparse.Namespace) -> int:
    """Run verify mode (UVX vs curl with key validation)."""
    base_url = args.base_url

    # Initialize via curl
    init_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "verify-cli", "version": "1.0"},
        },
    }
    rc, out, err = run_curl(init_payload, base_url=base_url, include_headers=True)
    if rc != 0:
        print("INIT_FAILED", err)
        return 1

    sid = ""
    for line in out.splitlines():
        if line.lower().startswith("mcp-session-id:"):
            sid = line.split(":", 1)[1].strip()
            break

    if not sid:
        print("INIT_NO_SID")
        print(out[:1000])
        return 1

    print(f"SESSION_ID={sid}")

    notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    run_curl(notif, base_url=base_url, sid=sid)

    cases = build_verify_cases(args.program_path, args.ghidra_host, args.ghidra_port, args.username, args.password)
    summary = []
    Path("tmp").mkdir(exist_ok=True)

    for idx, case in enumerate(cases, start=1):
        name = case["name"]
        print(f"\n=== {idx:02d} {name} ===")

        uvx_rc, uvx_out, uvx_err = run(case["uvx"], timeout=300)
        (Path("tmp") / f"verify_uvx_{idx:02d}.txt").write_text((uvx_out or "") + "\n---STDERR---\n" + (uvx_err or ""), encoding="utf-8")

        payload = {
            "jsonrpc": "2.0",
            "id": 1000 + idx,
            "method": "tools/call",
            "params": {
                "name": case["tool"],
                "arguments": case["args"],
            },
        }
        curl_rc, curl_out, curl_err = run_curl(payload, base_url=base_url, sid=sid, timeout=300)
        (Path("tmp") / f"verify_curl_{idx:02d}.txt").write_text((curl_out or "") + "\n---STDERR---\n" + (curl_err or ""), encoding="utf-8")

        curl_ok = False
        key_present = False
        curl_err_msg = ""
        try:
            resp = json.loads(curl_out)
            if "error" in resp:
                curl_err_msg = resp["error"].get("message", "error")
            else:
                curl_ok = True
                result_blob = json.dumps(resp.get("result", {}))
                key_present = case["key"] in result_blob
        except Exception as ex:
            curl_err_msg = f"json parse failed: {ex}"

        uvx_key = case["key"] in (uvx_out or "")

        print(f"UVX rc={uvx_rc} key={uvx_key} | CURL ok={curl_ok} key={key_present} err={curl_err_msg[:120]}")
        summary.append(
            {
                "idx": idx,
                "name": name,
                "uvx_rc": uvx_rc,
                "uvx_key": uvx_key,
                "curl_ok": curl_ok,
                "curl_key": key_present,
                "curl_error": curl_err_msg,
            }
        )

    Path("tmp/verify_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print("\nWrote tmp/verify_summary.json")

    failed = [s for s in summary if not (s["uvx_rc"] == 0 and s["curl_ok"])]
    print(f"TOTAL={len(summary)} FAILED={len(failed)}")
    if failed:
        print("FAILED_CASES:")
        for f in failed:
            print(f"- {f['idx']:02d} {f['name']} | uvx_rc={f['uvx_rc']} | curl_error={f['curl_error'][:120]}")

    return 0 if len(failed) == 0 else 1


# ============================================================================
# MAIN CLI
# ============================================================================


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Unified MCP CLI testing utility (matrix, validate, verify modes)")
    subparsers = parser.add_subparsers(dest="mode", help="Testing mode")

    # Matrix subcommand
    matrix_parser = subparsers.add_parser("matrix", help="CLI command matrix test")
    matrix_parser.add_argument("--server-url", default="http://170.9.241.140:8080/", help="Target MCP server URL")
    matrix_parser.add_argument("--program-path", default="/K1/k1_win_gog_swkotor.exe", help="Program path for tool calls")
    matrix_parser.add_argument("--ghidra-host", default="170.9.241.140", help="Ghidra shared-server host")
    matrix_parser.add_argument("--ghidra-port", type=int, default=13100, help="Ghidra shared-server port")
    matrix_parser.add_argument("--username", default="OpenKotOR", help="Ghidra shared-server username")
    matrix_parser.add_argument("--password", default="idekanymore", help="Ghidra shared-server password")
    matrix_parser.add_argument("--uvx-from", default="git+https://github.com/bolabaden/agentdecompile")
    matrix_parser.add_argument("--editable-local", action="store_true", help="Use local uvx package")
    matrix_parser.add_argument("--run", action="store_true", help="Execute cases")
    matrix_parser.add_argument("--print-cases", action="store_true", help="Print rendered commands")
    matrix_parser.add_argument("--json", action="store_true", help="JSON output")
    matrix_parser.add_argument("--timeout", type=int, default=120, help="Per-command timeout")
    matrix_parser.set_defaults(func=cmd_matrix)

    # Validate subcommand
    validate_parser = subparsers.add_parser("validate", help="Validate UVX vs curl equivalence")
    validate_parser.add_argument("--base-url", default="http://170.9.241.140:8080/mcp/message/", help="MCP server base URL")
    validate_parser.add_argument("--program-path", default="/K1/k1_win_gog_swkotor.exe", help="Program path")
    validate_parser.add_argument("--ghidra-host", default="170.9.241.140", help="Ghidra shared-server host")
    validate_parser.add_argument("--ghidra-port", type=int, default=13100, help="Ghidra shared-server port")
    validate_parser.add_argument("--username", default="OpenKotOR", help="Ghidra shared-server username")
    validate_parser.add_argument("--password", default="idekanymore", help="Ghidra shared-server password")
    validate_parser.set_defaults(func=cmd_validate)

    # Verify subcommand
    verify_parser = subparsers.add_parser("verify", help="Verify UVX vs curl with key checks")
    verify_parser.add_argument("--base-url", default="http://170.9.241.140:8080/mcp/message/", help="MCP server base URL")
    verify_parser.add_argument("--program-path", default="/K1/k1_win_gog_swkotor.exe", help="Program path")
    verify_parser.add_argument("--ghidra-host", default="170.9.241.140", help="Ghidra shared-server host")
    verify_parser.add_argument("--ghidra-port", type=int, default=13100, help="Ghidra shared-server port")
    verify_parser.add_argument("--username", default="OpenKotOR", help="Ghidra shared-server username")
    verify_parser.add_argument("--password", default="idekanymore", help="Ghidra shared-server password")
    verify_parser.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv or sys.argv[1:])
    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
