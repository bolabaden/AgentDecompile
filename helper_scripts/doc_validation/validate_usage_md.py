from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

BASE = "http://170.9.241.140:8080/mcp/message/"
PROGRAM = "/K1/k1_win_gog_swkotor.exe"
UVX_PREFIX = "uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://170.9.241.140:8080/"


def run(cmd, timeout=300):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout or "", p.stderr or ""


def run_ps(command, timeout=300):
    p = subprocess.run(["powershell", "-NoProfile", "-Command", command], capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout or "", p.stderr or ""


def run_argv(argv, timeout=300):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout or "", p.stderr or ""


def run_curl(payload, sid=None, include_headers=False, timeout=300):
    data = json.dumps(payload)
    cmd = [
        "curl.exe",
        "-s",
        "-X",
        "POST",
        BASE,
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
    return p.returncode, p.stdout or "", p.stderr or ""


# init
rc, out, err = run_curl(
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "usage-validator", "version": "1.0"},
        },
    },
    include_headers=True,
)

if rc != 0:
    raise SystemExit(f"curl init failed: {err}")

sid = ""
for line in out.splitlines():
    if line.lower().startswith("mcp-session-id:"):
        sid = line.split(":", 1)[1].strip()
        break
if not sid:
    raise SystemExit("no mcp-session-id returned")

run_curl({"jsonrpc": "2.0", "method": "notifications/initialized"}, sid=sid)

cases = [
    {
        "name": "open",
        "uvx": f"{UVX_PREFIX} open --server_host 170.9.241.140 --server_port 13100 --server_username OpenKotOR --server_password MuchaShakaPaka {PROGRAM}",
        "tool": "open",
        "args": {
            "server_host": "170.9.241.140",
            "server_port": 13100,
            "server_username": "OpenKotOR",
            "server_password": "MuchaShakaPaka",
            "repository_name": "Odyssey",
            "program_path": PROGRAM,
        },
    },
    {"name": "list project-files", "uvx": f"{UVX_PREFIX} list project-files", "tool": "list_project_files", "args": {}},
    {"name": "get-current-program", "uvx": f"{UVX_PREFIX} get-current-program --program_path {PROGRAM}", "tool": "get_current_program", "args": {"program_path": PROGRAM}},
    {
        "name": "get-functions limit",
        "uvx": f"{UVX_PREFIX} get-functions --program_path {PROGRAM} --limit 5",
        "tool": "get_functions",
        "args": {"program_path": PROGRAM, "limit": 5},
    },
    {
        "name": "search-symbols-by-name",
        "uvx": f"{UVX_PREFIX} search-symbols-by-name --program_path {PROGRAM} --query SaveGame --max_results 20",
        "tool": "search_symbols_by_name",
        "args": {"program_path": PROGRAM, "query": "SaveGame", "max_results": 20},
    },
    {
        "name": "references to",
        "uvx": f"{UVX_PREFIX} references to --binary {PROGRAM} --target SaveGame --limit 25",
        "tool": "get_references",
        "args": {"program_path": PROGRAM, "mode": "to", "target": "SaveGame", "limit": 25},
    },
    {
        "name": "get-functions info",
        "uvx": f"{UVX_PREFIX} get-functions --program_path {PROGRAM} --identifier 0x004b58a0 --view info --include_callers true --include_callees true",
        "tool": "get_functions",
        "args": {"program_path": PROGRAM, "identifier": "0x004b58a0", "view": "info", "include_callers": True, "include_callees": True},
    },
    {
        "name": "get-functions decompile",
        "uvx": f"{UVX_PREFIX} get-functions --program_path {PROGRAM} --identifier 0x004b58a0 --view decompile",
        "tool": "get_functions",
        "args": {"program_path": PROGRAM, "identifier": "0x004b58a0", "view": "decompile"},
    },
    {
        "name": "get-functions disassemble",
        "uvx": f"{UVX_PREFIX} get-functions --program_path {PROGRAM} --identifier 0x004b58a0 --view disassemble",
        "tool": "get_functions",
        "args": {"program_path": PROGRAM, "identifier": "0x004b58a0", "view": "disassemble"},
    },
    {
        "name": "get-call-graph",
        "uvx": f"{UVX_PREFIX} get-call-graph --program_path {PROGRAM} --function_identifier 0x004b58a0 --mode callees --max_depth 2",
        "tool": "get_call_graph",
        "args": {"program_path": PROGRAM, "function_identifier": "0x004b58a0", "mode": "callees", "max_depth": 2},
    },
    {
        "name": "references from",
        "uvx": f"{UVX_PREFIX} references from --binary {PROGRAM} --target 0x004b58a0 --limit 100",
        "tool": "get_references",
        "args": {"program_path": PROGRAM, "mode": "from", "target": "0x004b58a0", "limit": 100},
    },
    {
        "name": "manage-strings",
        "uvx": f'{UVX_PREFIX} manage-strings --program_path {PROGRAM} --mode regex --query "Save|Load|Module|GIT|IFO" --include_referencing_functions true --limit 100',
        "tool": "manage_strings",
        "args": {"program_path": PROGRAM, "mode": "regex", "query": "Save|Load|Module|GIT|IFO", "include_referencing_functions": True, "limit": 100},
    },
    {
        "name": "search-constants",
        "uvx": f"{UVX_PREFIX} search-constants --program_path {PROGRAM} --mode specific --value 32 --max_results 200",
        "tool": "search_constants",
        "args": {"program_path": PROGRAM, "mode": "specific", "value": 32, "max_results": 200},
    },
    {
        "name": "analyze-data-flow",
        "uvx": f"{UVX_PREFIX} analyze-data-flow --program_path {PROGRAM} --function_address 0x004b95b0 --start_address 0x004b97af --direction forward",
        "tool": "analyze_data_flow",
        "args": {"program_path": PROGRAM, "function_address": "0x004b95b0", "start_address": "0x004b97af", "direction": "forward"},
    },
    {
        "name": "manage-function rename",
        "uvx": f"{UVX_PREFIX} manage-function --program_path {PROGRAM} --mode rename --function_identifier 0x004b95b0 --new_name LoadModule",
        "tool": "manage_function",
        "args": {"program_path": PROGRAM, "mode": "rename", "function_identifier": "0x004b95b0", "new_name": "LoadModule"},
    },
    {
        "name": "manage-comments set",
        "uvx": f'{UVX_PREFIX} manage-comments --program_path {PROGRAM} --mode set --address_or_symbol 0x004b95b0 --comment_type PRE --comment "LoadModule orchestrates per-resource GFF parsing"',
        "tool": "manage_comments",
        "args": {
            "program_path": PROGRAM,
            "mode": "set",
            "address_or_symbol": "0x004b95b0",
            "comment_type": "PRE",
            "comment": "LoadModule orchestrates per-resource GFF parsing",
        },
    },
    {
        "name": "manage-function-tags add",
        "uvx": f"{UVX_PREFIX} manage-function-tags --program_path {PROGRAM} --mode add --function 0x004b95b0 --tags save-load --tags serialization",
        "tool": "manage_function_tags",
        "args": {"program_path": PROGRAM, "mode": "add", "function": "0x004b95b0", "tags": ["save-load", "serialization"]},
    },
    {
        "name": "manage-bookmarks set",
        "uvx": f'{UVX_PREFIX} manage-bookmarks --program_path {PROGRAM} --mode set --address_or_symbol 0x004b95b0 --type TODO --category "save-load" --comment "verify full GIT object-list write path"',
        "tool": "manage_bookmarks",
        "args": {
            "program_path": PROGRAM,
            "mode": "set",
            "address_or_symbol": "0x004b95b0",
            "type": "TODO",
            "category": "save-load",
            "comment": "verify full GIT object-list write path",
        },
    },
    {
        "name": "tool list-imports",
        "uvx_argv": [
            "uvx",
            "--from",
            "git+https://github.com/bolabaden/agentdecompile",
            "agentdecompile-cli",
            "--server-url",
            "http://170.9.241.140:8080/",
            "tool",
            "list-imports",
            json.dumps({"program_path": PROGRAM, "limit": 5}),
        ],
        "tool": "list_imports",
        "args": {"program_path": PROGRAM, "limit": 5},
    },
    {
        "name": "tool list-exports",
        "uvx_argv": [
            "uvx",
            "--from",
            "git+https://github.com/bolabaden/agentdecompile",
            "agentdecompile-cli",
            "--server-url",
            "http://170.9.241.140:8080/",
            "tool",
            "list-exports",
            json.dumps({"program_path": PROGRAM, "limit": 5}),
        ],
        "tool": "list_exports",
        "args": {"program_path": PROGRAM, "limit": 5},
    },
]

summary: list[dict[str, Any]] = []
Path("tmp").mkdir(exist_ok=True)

for i, c in enumerate(cases, start=1):
    if "uvx_argv" in c:
        uvx_rc, uvx_out, uvx_err = run_argv(c["uvx_argv"], timeout=360)
    elif "uvx_ps" in c:
        uvx_rc, uvx_out, uvx_err = run_ps(c["uvx_ps"], timeout=360)
    else:
        uvx_rc, uvx_out, uvx_err = run(c["uvx"], timeout=360)
    payload = {"jsonrpc": "2.0", "id": 100 + i, "method": "tools/call", "params": {"name": c["tool"], "arguments": c["args"]}}
    curl_rc, curl_out, curl_err = run_curl(payload, sid=sid, timeout=360)

    curl_json_ok = True
    curl_is_error = None
    try:
        parsed = json.loads(curl_out)
        if "error" in parsed:
            curl_json_ok = False
            curl_is_error = parsed["error"]
        else:
            # tools/call can still return business errors in result.content text.
            pass
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

    Path(f"tmp/validate_usage_uvx_{i:02d}.txt").write_text((uvx_out or "") + "\n---STDERR---\n" + (uvx_err or ""), encoding="utf-8")
    Path(f"tmp/validate_usage_curl_{i:02d}.txt").write_text((curl_out or "") + "\n---STDERR---\n" + (curl_err or ""), encoding="utf-8")

Path("tmp/validate_usage_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

fail = [x for x in summary if x["uvx_rc"] != 0 or x["curl_rc"] != 0 or not x["curl_json_ok"]]
print(f"SESSION={sid}")
print(f"TOTAL={len(summary)} FAIL={len(fail)}")
for f in fail:
    print(f"- {f['index']:02d} {f['name']} uvx_rc={f['uvx_rc']} curl_rc={f['curl_rc']} curl_json_ok={f['curl_json_ok']}")
