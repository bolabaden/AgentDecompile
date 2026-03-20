#!/usr/bin/env python3
"""
Unified MCP CLI testing utility combining three separate validators:
- mcp_remote_matrix.py: CLI command matrix runner (--run, --print-cases)
- validate_usage_md.py: UVX vs curl validation with full session testing
- verify_uvx_curl_equiv.py: UVX vs curl equivalence with response key verification
- agdec-http: Full tool sweep over agdec-http MCP server with debug logging

Usage:
  python helper_scripts/mcp_cli_testing.py matrix --print-cases
  python helper_scripts/mcp_cli_testing.py matrix --run --server-url http://127.0.0.1:8081/
  python helper_scripts/mcp_cli_testing.py validate
  python helper_scripts/mcp_cli_testing.py verify
  python helper_scripts/mcp_cli_testing.py agdec-http --server-url http://127.0.0.1:8080/mcp
  python helper_scripts/mcp_cli_testing.py agdec-http --mcp-config .cursor/mcp.json
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]

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
    base_url: str | None = None,
    sid: str | None = None,
    include_headers: bool = False,
    timeout: int = 300,
) -> tuple[int, str, str]:
    """Run curl MCP request."""
    base_url = (base_url or os.getenv("AGENT_DECOMPILE_MCP_MESSAGE_URL") or os.getenv("AGENT_DECOMPILE_MCP_SERVER_URL") or "").strip()
    if not base_url:
        raise ValueError("Missing MCP URL. Set AGENT_DECOMPILE_MCP_MESSAGE_URL (preferred) or AGENT_DECOMPILE_MCP_SERVER_URL.")
    if base_url.endswith("/") and not base_url.endswith("/mcp/message/"):
        base_url = f"{base_url}mcp/message/"
    elif not base_url.endswith("/mcp/message/"):
        base_url = f"{base_url.rstrip('/')}/mcp/message/"

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


def build_validate_cases(program_path: str, host: str, port: int, username: str, password: str) -> list[dict[str, Any]]:
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
            "tool": "open",
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


def build_verify_cases(program_path: str, host: str, port: int, username: str, password: str) -> list[dict[str, Any]]:
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
            "tool": "open",
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
# AGDEC-HTTP MODE: tool list + tool-seq with debug NDJSON logging
# ============================================================================

# Expected advertised tool count (streamable-http default per USAGE.md / test_e2e_local_terminal_contracts).
# Server may advertise 37 or 38 depending on build/env (e.g. legacy or disabled tools).
EXPECTED_ADVERTISED_TOOL_COUNT = 37
EXPECTED_ADVERTISED_TOOL_COUNT_ALT = 38


def _load_agdec_http_config(mcp_config_path: str | None) -> tuple[str, dict[str, str]]:
    """Load agdec-http URL and headers from .cursor/mcp.json. Returns (url, headers)."""
    path = (mcp_config_path or "").strip() or (Path.cwd() / ".cursor" / "mcp.json")
    if not Path(path).exists():
        return "", {}
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        servers = data.get("mcpServers") or {}
        agdec = servers.get("agdec-http")
        if not agdec or not isinstance(agdec, dict):
            return "", {}
        url = (agdec.get("url") or "").strip().rstrip("/")
        if not url:
            return "", {}
        if not url.endswith("/mcp") and not url.endswith("/mcp/message"):
            url = f"{url}/mcp" if not url.endswith("/mcp") else url
        headers = dict(agdec.get("headers") or {})
        return url, headers
    except Exception:
        return "", {}


def _normalize_mcp_url(base: str) -> str:
    """Ensure URL ends with /mcp for session endpoint; we'll POST to /mcp/message."""
    base = (base or "").strip().rstrip("/")
    if not base:
        return ""
    if "/mcp/message" in base:
        return base.split("/mcp/message")[0] + "/mcp"
    if not base.endswith("/mcp"):
        base = f"{base}/mcp"
    return base


def _agdec_http_session(
    base_url: str,
    extra_headers: dict[str, str] | None,
    timeout: float,
) -> tuple[str, dict[str, str]]:
    """Initialize MCP session; return (session_id, headers)."""
    if httpx is None:
        raise RuntimeError("httpx is required for agdec-http mode. Install with: uv pip install httpx")
    message_url = f"{base_url.rstrip('/')}/message"
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        **(extra_headers or {}),
    }
    init_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "mcp_cli_testing-agdec-http", "version": "1.0"},
        },
    }
    with httpx.Client(timeout=timeout) as client:
        resp = client.post(message_url, json=init_payload, headers=headers)
        resp.raise_for_status()
        sid = (resp.headers.get("mcp-session-id") or "").strip()
    if sid:
        headers["Mcp-Session-Id"] = sid
    return sid, headers


def _agdec_http_post(
    base_url: str,
    method: str,
    params: dict[str, Any],
    session_headers: dict[str, str],
    request_id: int,
    timeout: float,
) -> dict[str, Any]:
    """POST one JSON-RPC request to MCP message endpoint."""
    if httpx is None:
        raise RuntimeError("httpx is required")
    message_url = f"{base_url.rstrip('/')}/message"
    payload = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
    with httpx.Client(timeout=timeout) as client:
        resp = client.post(message_url, json=payload, headers=session_headers)
        resp.raise_for_status()
        return resp.json()


def _append_debug_log(log_path: str, payload: dict[str, Any]) -> None:
    """Append one NDJSON line to the debug log file."""
    payload.setdefault("timestamp", int(time.time() * 1000))
    line = json.dumps(payload, ensure_ascii=False) + "\n"
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(line)


def cmd_agdec_http(args: argparse.Namespace) -> int:
    """Run tool list + tool-seq against agdec-http MCP server and log to debug log file."""
    if httpx is None:
        print("agdec-http mode requires httpx. Install with: uv pip install httpx")
        return 2

    server_url = (args.server_url or "").strip()
    mcp_config = (args.mcp_config or "").strip()
    log_path = (args.log_file or "").strip() or "debug-cd359b.log"
    program_path = (args.program_path or "").strip() or "/K1/k1_win_gog_swkotor.exe"
    timeout = float(args.timeout or 120)
    continue_on_error = getattr(args, "continue_on_error", True)
    extra_headers: dict[str, str] = {}

    if not server_url and mcp_config:
        server_url, extra_headers = _load_agdec_http_config(mcp_config)
    elif not server_url:
        server_url = (os.getenv("AGENT_DECOMPILE_MCP_SERVER_URL") or os.getenv("AGENTDECOMPILE_MCP_SERVER_URL") or "").strip()
        if not server_url:
            config_url, config_headers = _load_agdec_http_config(None)
            if config_url:
                server_url = config_url
                extra_headers = config_headers

    base_url = _normalize_mcp_url(server_url)
    if not base_url:
        print("Missing server URL. Set AGENT_DECOMPILE_MCP_SERVER_URL or pass --server-url or --mcp-config .cursor/mcp.json")
        return 2

    session_id = "cd359b"
    run_id = getattr(args, "run_id", "agdec-http-sweep")

    try:
        sid, session_headers = _agdec_http_session(base_url, extra_headers, timeout)
    except Exception as e:
        _append_debug_log(log_path, {
            "sessionId": session_id,
            "runId": run_id,
            "hypothesisId": "H1",
            "location": "agdec-http:init",
            "message": "MCP initialize failed",
            "data": {"error": str(e), "base_url": base_url},
        })
        print(f"INIT_FAILED: {e}")
        return 1

    request_id = 10
    # H1: tools/list returns expected count
    try:
        list_resp = _agdec_http_post(base_url, "tools/list", {}, session_headers, request_id, timeout)
        request_id += 1
        tools = (list_resp.get("result") or {}).get("tools") or []
        tool_names = [t.get("name") for t in tools if isinstance(t, dict) and t.get("name")]
        count = len(tool_names)
        count_ok = count in (EXPECTED_ADVERTISED_TOOL_COUNT, EXPECTED_ADVERTISED_TOOL_COUNT_ALT)
        _append_debug_log(log_path, {
            "sessionId": session_id,
            "runId": run_id,
            "hypothesisId": "H1",
            "location": "agdec-http:tools/list",
            "message": "tools/list count",
            "data": {"count": count, "expected": EXPECTED_ADVERTISED_TOOL_COUNT, "ok": count_ok, "tool_names_sample": tool_names[:5]},
        })
        print(f"tools/list: {count} tools (expected {EXPECTED_ADVERTISED_TOOL_COUNT} or {EXPECTED_ADVERTISED_TOOL_COUNT_ALT})")
    except Exception as e:
        _append_debug_log(log_path, {
            "sessionId": session_id,
            "runId": run_id,
            "hypothesisId": "H1",
            "location": "agdec-http:tools/list",
            "message": "tools/list failed",
            "data": {"error": str(e)},
        })
        print(f"tools/list FAILED: {e}")
        return 1

    bootstrap_import = (getattr(args, "bootstrap_import", None) or "").strip()
    program_path_in_project = program_path  # used for non-bootstrap and updated from list-project-files in bootstrap
    if bootstrap_import:
        resolved_bootstrap = Path(bootstrap_import).resolve()
        if not resolved_bootstrap.exists():
            print(f"Bootstrap path does not exist: {resolved_bootstrap}")
            return 2
        program_path = resolved_bootstrap.name
        program_path_in_project = f"/{program_path}"
        # No shared-server credentials when bootstrapping a local import
        host = ""
        port = 0
        username = ""
        password = ""
    else:
        host = (args.ghidra_host or os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_HOST") or "").strip()
        port = int(args.ghidra_port or os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_PORT", "13100") or "13100")
        username = (args.username or os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME") or "").strip()
        password = (args.password or os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD") or "").strip()

    open_args: dict[str, Any] = {"path": program_path, "format": "json"}
    if host and port and username and password:
        open_args["serverHost"] = host
        open_args["serverPort"] = port
        open_args["serverUsername"] = username
        open_args["serverPassword"] = password

    if bootstrap_import:
        resolved_bootstrap = Path(bootstrap_import).resolve()
        # After list-project-files we will set this from the first program path in the response
        program_path_in_project = f"/{program_path}"
        steps = [
            ("import_binary", "import-binary", {"path": str(resolved_bootstrap), "format": "json"}),
            ("list_project_files", "list-project-files", {"format": "json"}),
            ("get_current_program", "get-current-program", {"programPath": program_path_in_project, "format": "json"}),
            ("list_functions", "list-functions", {"programPath": program_path_in_project, "limit": 5, "format": "json"}),
            ("search_symbols", "search-symbols", {"programPath": program_path_in_project, "query": "main", "limit": 5, "format": "json"}),
            ("get_references", "get-references", {"programPath": program_path_in_project, "target": "entry", "direction": "to", "limit": 5, "format": "json"}),
            ("list_imports", "list-imports", {"programPath": program_path_in_project, "limit": 5, "format": "json"}),
            ("list_exports", "list-exports", {"programPath": program_path_in_project, "limit": 5, "format": "json"}),
            ("decompile_function", "decompile-function", {"programPath": program_path_in_project, "functionIdentifier": "entry", "limit": 20, "format": "json"}),
        ]
    else:
        steps = [
            ("open", "open", open_args),
            ("list_project_files", "list-project-files", {"format": "json"}),
            ("get_current_program", "get-current-program", {"programPath": program_path, "format": "json"}),
            ("list_functions", "list-functions", {"programPath": program_path, "limit": 5, "format": "json"}),
            ("search_symbols", "search-symbols", {"programPath": program_path, "query": "main", "limit": 5, "format": "json"}),
            ("get_references", "get-references", {"programPath": program_path, "target": "WinMain", "direction": "to", "limit": 5, "format": "json"}),
            ("list_imports", "list-imports", {"programPath": program_path, "limit": 5, "format": "json"}),
            ("list_exports", "list-exports", {"programPath": program_path, "limit": 5, "format": "json"}),
            ("decompile_function", "decompile-function", {"programPath": program_path, "functionIdentifier": "WinMain", "limit": 20, "format": "json"}),
        ]

    failed = 0
    # Bootstrap: use path from list-project-files for subsequent steps
    current_program_path = program_path_in_project if bootstrap_import else program_path

    for step_name, tool_name, tool_args in steps:
        try:
            args_to_send = dict(tool_args)
            if bootstrap_import and "programPath" in args_to_send:
                args_to_send["programPath"] = current_program_path
            call_resp = _agdec_http_post(
                base_url, "tools/call",
                {"name": tool_name, "arguments": args_to_send},
                session_headers, request_id, timeout,
            )
            request_id += 1
            is_rpc_error = "error" in call_resp
            content = (call_resp.get("result") or {}).get("content") or []
            text_parts = [c.get("text", "") for c in content if isinstance(c, dict)]
            text_preview = (text_parts[0][:200] + "..." if text_parts and len(text_parts[0]) > 200 else (text_parts[0] if text_parts else ""))
            # Application-level success: tool can return 200 with content {"success": false, "error": "..."}
            app_success = True
            if text_parts:
                try:
                    parsed = json.loads(text_parts[0])
                    if isinstance(parsed, dict) and parsed.get("success") is False:
                        app_success = False
                except (json.JSONDecodeError, TypeError):
                    pass
            step_ok = not is_rpc_error and app_success
            _append_debug_log(log_path, {
                "sessionId": session_id,
                "runId": run_id,
                "hypothesisId": "H2",
                "location": f"agdec-http:tools/call:{tool_name}",
                "message": step_name,
                "data": {"tool": tool_name, "success": step_ok, "rpc_ok": not is_rpc_error, "app_success": app_success, "text_preview": str(text_preview)[:300]},
            })
            if not step_ok:
                failed += 1
                if is_rpc_error:
                    print(f"  FAIL {tool_name}: {call_resp.get('error', {})}")
                else:
                    print(f"  FAIL {tool_name}: application success=false (see log)")
                if not continue_on_error:
                    return 1
            else:
                print(f"  OK   {tool_name}")
                # Bootstrap: set program path from import or list-project-files response
                if bootstrap_import and text_parts:
                    try:
                        parsed = json.loads(text_parts[0])
                        if isinstance(parsed, dict):
                            if step_name == "import_binary":
                                progs = parsed.get("importedPrograms") or []
                                if progs and isinstance(progs[0], dict):
                                    p = progs[0].get("programPath") or progs[0].get("path")
                                    if p:
                                        current_program_path = p
                            elif step_name == "list_project_files":
                                items = parsed.get("files") or parsed.get("items") or []
                                if isinstance(items, list):
                                    for it in items:
                                        if isinstance(it, dict):
                                            t = str(it.get("type", ""))
                                            if t != "Folder" and (t == "Program" or "Program" in t or not t):
                                                p = it.get("path") or it.get("programPath")
                                                if p:
                                                    current_program_path = p
                                                    break
                    except (json.JSONDecodeError, TypeError):
                        pass
        except Exception as e:
            failed += 1
            _append_debug_log(log_path, {
                "sessionId": session_id,
                "runId": run_id,
                "hypothesisId": "H2",
                "location": f"agdec-http:tools/call:{tool_name}",
                "message": step_name + " exception",
                "data": {"tool": tool_name, "error": str(e)},
            })
            print(f"  FAIL {tool_name}: {e}")
            if not continue_on_error:
                return 1

    print(f"Log written to {log_path}. Summary: {len(steps) - failed}/{len(steps)} steps passed.")
    return 0 if failed == 0 else 1


# ============================================================================
# MAIN CLI
# ============================================================================


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Unified MCP CLI testing utility (matrix, validate, verify modes)")
    subparsers = parser.add_subparsers(dest="mode", help="Testing mode")

    # Matrix subcommand
    matrix_parser = subparsers.add_parser("matrix", help="CLI command matrix test")
    matrix_parser.add_argument(
        "--server-url",
        default=os.getenv("AGENT_DECOMPILE_MCP_SERVER_URL", ""),
        help="Target MCP server URL (defaults to AGENT_DECOMPILE_MCP_SERVER_URL)",
    )
    matrix_parser.add_argument("--program-path", default="/K1/k1_win_gog_swkotor.exe", help="Program path for tool calls")
    matrix_parser.add_argument(
        "--ghidra-host",
        default=os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_HOST", ""),
        help="Ghidra shared-server host (defaults to AGENT_DECOMPILE_GHIDRA_SERVER_HOST)",
    )
    matrix_parser.add_argument("--ghidra-port", type=int, default=13100, help="Ghidra shared-server port")
    matrix_parser.add_argument(
        "--username",
        default=os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME", ""),
        help="Ghidra shared-server username (defaults to AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME)",
    )
    matrix_parser.add_argument(
        "--password",
        default=os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD", ""),
        help="Ghidra shared-server password (defaults to AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD)",
    )
    matrix_parser.add_argument("--uvx-from", default="git+https://github.com/bolabaden/agentdecompile")
    matrix_parser.add_argument("--editable-local", action="store_true", help="Use local uvx package")
    matrix_parser.add_argument("--run", action="store_true", help="Execute cases")
    matrix_parser.add_argument("--print-cases", action="store_true", help="Print rendered commands")
    matrix_parser.add_argument("--json", action="store_true", help="JSON output")
    matrix_parser.add_argument("--timeout", type=int, default=120, help="Per-command timeout")
    matrix_parser.set_defaults(func=cmd_matrix)

    # Validate subcommand
    validate_parser = subparsers.add_parser("validate", help="Validate UVX vs curl equivalence")
    validate_parser.add_argument(
        "--base-url",
        default=os.getenv("AGENT_DECOMPILE_MCP_MESSAGE_URL", ""),
        help="MCP message URL (defaults to AGENT_DECOMPILE_MCP_MESSAGE_URL, else AGENT_DECOMPILE_MCP_SERVER_URL)",
    )
    validate_parser.add_argument("--program-path", default="/K1/k1_win_gog_swkotor.exe", help="Program path")
    validate_parser.add_argument(
        "--ghidra-host",
        default=os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_HOST", ""),
        help="Ghidra shared-server host (defaults to AGENT_DECOMPILE_GHIDRA_SERVER_HOST)",
    )
    validate_parser.add_argument("--ghidra-port", type=int, default=13100, help="Ghidra shared-server port")
    validate_parser.add_argument(
        "--username",
        default=os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME", ""),
        help="Ghidra shared-server username (defaults to AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME)",
    )
    validate_parser.add_argument(
        "--password",
        default=os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD", ""),
        help="Ghidra shared-server password (defaults to AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD)",
    )
    validate_parser.set_defaults(func=cmd_validate)

    # Verify subcommand
    verify_parser = subparsers.add_parser("verify", help="Verify UVX vs curl with key checks")
    verify_parser.add_argument(
        "--base-url",
        default=os.getenv("AGENT_DECOMPILE_MCP_MESSAGE_URL", ""),
        help="MCP message URL (defaults to AGENT_DECOMPILE_MCP_MESSAGE_URL, else AGENT_DECOMPILE_MCP_SERVER_URL)",
    )
    verify_parser.add_argument("--program-path", default="/K1/k1_win_gog_swkotor.exe", help="Program path")
    verify_parser.add_argument(
        "--ghidra-host",
        default=os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_HOST", ""),
        help="Ghidra shared-server host (defaults to AGENT_DECOMPILE_GHIDRA_SERVER_HOST)",
    )
    verify_parser.add_argument("--ghidra-port", type=int, default=13100, help="Ghidra shared-server port")
    verify_parser.add_argument(
        "--username",
        default=os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME", ""),
        help="Ghidra shared-server username (defaults to AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME)",
    )
    verify_parser.add_argument(
        "--password",
        default=os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD", ""),
        help="Ghidra shared-server password (defaults to AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD)",
    )
    verify_parser.set_defaults(func=cmd_verify)

    # agdec-http subcommand: tool list + tool-seq with debug logging
    agdec_parser = subparsers.add_parser(
        "agdec-http",
        help="Test agdec-http MCP server: list tools + run tool-seq, log to NDJSON (e.g. debug-cd359b.log)",
    )
    agdec_parser.add_argument(
        "--server-url",
        default="",
        help="MCP server base URL (e.g. http://127.0.0.1:8080/mcp). Overridden by --mcp-config if URL present.",
    )
    agdec_parser.add_argument(
        "--mcp-config",
        default="",
        help="Path to .cursor/mcp.json; agdec-http url and headers used if --server-url not set",
    )
    agdec_parser.add_argument(
        "--log-file",
        default="debug-cd359b.log",
        help="NDJSON log path (default: debug-cd359b.log)",
    )
    agdec_parser.add_argument(
        "--program-path",
        default="",
        help="Program path for tool calls (default: /K1/k1_win_gog_swkotor.exe for shared server)",
    )
    agdec_parser.add_argument(
        "--bootstrap-import",
        default="",
        help="Local file path to import first (e.g. tests/fixtures/test_x86_64); program_path becomes basename for rest of steps",
    )
    agdec_parser.add_argument("--timeout", type=float, default=120, help="HTTP timeout per request")
    agdec_parser.add_argument(
        "--continue-on-error",
        action="store_true",
        default=True,
        help="Continue tool-seq after a step fails (default: True)",
    )
    agdec_parser.add_argument(
        "--no-continue-on-error",
        action="store_false",
        dest="continue_on_error",
        help="Stop on first tool failure",
    )
    agdec_parser.add_argument(
        "--ghidra-host",
        default=os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_HOST", ""),
        help="Ghidra shared-server host for open",
    )
    agdec_parser.add_argument("--ghidra-port", type=int, default=13100, help="Ghidra shared-server port")
    agdec_parser.add_argument(
        "--username",
        default=os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME", ""),
        help="Ghidra shared-server username",
    )
    agdec_parser.add_argument(
        "--password",
        default=os.getenv("AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD", ""),
        help="Ghidra shared-server password",
    )
    agdec_parser.set_defaults(func=cmd_agdec_http)

    args = parser.parse_args(argv or sys.argv[1:])
    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    if args.mode in {"validate", "verify"}:
        if not (args.base_url or "").strip():
            args.base_url = (os.getenv("AGENT_DECOMPILE_MCP_SERVER_URL") or "").strip()
        missing: list[str] = []
        if not (args.base_url or "").strip():
            missing.append("AGENT_DECOMPILE_MCP_MESSAGE_URL or AGENT_DECOMPILE_MCP_SERVER_URL")
        if not (args.ghidra_host or "").strip():
            missing.append("AGENT_DECOMPILE_GHIDRA_SERVER_HOST")
        if not (args.username or "").strip():
            missing.append("AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME")
        if not (args.password or "").strip():
            missing.append("AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD")
        if missing:
            print("Missing required connection values. Set these env vars or pass CLI overrides:")
            for item in missing:
                print(f"- {item}")
            return 2

    if args.mode == "matrix" and args.run:
        missing = []
        if not (args.server_url or "").strip():
            missing.append("AGENT_DECOMPILE_MCP_SERVER_URL")
        if not (args.ghidra_host or "").strip():
            missing.append("AGENT_DECOMPILE_GHIDRA_SERVER_HOST")
        if not (args.username or "").strip():
            missing.append("AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME")
        if not (args.password or "").strip():
            missing.append("AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD")
        if missing:
            print("Missing required connection values for matrix --run. Set these env vars or pass CLI overrides:")
            for item in missing:
                print(f"- {item}")
            return 2

    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
