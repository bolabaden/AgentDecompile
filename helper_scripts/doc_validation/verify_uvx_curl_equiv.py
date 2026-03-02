import json
import subprocess
import sys
from pathlib import Path

BASE = "http://170.9.241.140:8080/mcp/message/"
PROGRAM = "/K1/k1_win_gog_swkotor.exe"
UVX_PREFIX = "uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://170.9.241.140:8080/"


def run(cmd, timeout=240):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout or ""), (p.stderr or "")


def run_curl(payload, sid=None, include_headers=False, timeout=240):
    data = json.dumps(payload)
    cmd = [
        "curl.exe", "-s",
        "-X", "POST", BASE,
        "-H", "Content-Type: application/json",
        "-H", "Accept: application/json, text/event-stream",
    ]
    if sid:
        cmd += ["-H", f"Mcp-Session-Id: {sid}"]
    if include_headers:
        cmd.insert(1, "-i")
    cmd += ["--data", data]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout or ""), (p.stderr or "")


# 1) initialize via curl
init_payload = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "curl-verify", "version": "1.0"},
    },
}
rc, out, err = run_curl(init_payload, include_headers=True)
if rc != 0:
    print("INIT_FAILED", err)
    sys.exit(1)

sid = ""
for line in out.splitlines():
    if line.lower().startswith("mcp-session-id:"):
        sid = line.split(":", 1)[1].strip()
        break

if not sid:
    print("INIT_NO_SID")
    print(out[:1000])
    sys.exit(1)

print(f"SESSION_ID={sid}")

# notifications/initialized
notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
run_curl(notif, sid=sid)

# command matrix
cases = [
    {
        "name": "open",
        "uvx": f'{UVX_PREFIX} open --server_host 170.9.241.140 --server_port 13100 --server_username OpenKotOR --server_password MuchaShakaPaka {PROGRAM}',
        "tool": "open",
        "args": {
            "server_host": "170.9.241.140",
            "server_port": 13100,
            "server_username": "OpenKotOR",
            "server_password": "MuchaShakaPaka",
            "repository_name": "Odyssey",
            "program_path": PROGRAM,
        },
        "key": "checkedOutProgram",
    },
    {
        "name": "list project-files",
        "uvx": f'{UVX_PREFIX} list project-files',
        "tool": "list_project_files",
        "args": {},
        "key": "count",
    },
    {
        "name": "get-current-program",
        "uvx": f'{UVX_PREFIX} get-current-program --program_path {PROGRAM}',
        "tool": "get_current_program",
        "args": {"program_path": PROGRAM},
        "key": "functionCount",
    },
    {
        "name": "get-functions limit",
        "uvx": f'{UVX_PREFIX} get-functions --program_path {PROGRAM} --limit 5',
        "tool": "get_functions",
        "args": {"program_path": PROGRAM, "limit": 5},
        "key": "functions",
    },
    {
        "name": "search-symbols-by-name",
        "uvx": f'{UVX_PREFIX} search-symbols-by-name --program_path {PROGRAM} --query SaveGame --max_results 20',
        "tool": "search_symbols_by_name",
        "args": {"program_path": PROGRAM, "query": "SaveGame", "max_results": 20},
        "key": "results",
    },
    {
        "name": "references to",
        "uvx": f'{UVX_PREFIX} references to --binary {PROGRAM} --target SaveGame --limit 25',
        "tool": "get_references",
        "args": {"program_path": PROGRAM, "mode": "to", "target": "SaveGame", "limit": 25},
        "key": "references",
    },
    {
        "name": "get-functions info",
        "uvx": f'{UVX_PREFIX} get-functions --program_path {PROGRAM} --identifier 0x004b58a0 --view info --include_callers true --include_callees true',
        "tool": "get_functions",
        "args": {"program_path": PROGRAM, "identifier": "0x004b58a0", "view": "info", "include_callers": True, "include_callees": True},
        "key": "address",
    },
    {
        "name": "get-functions decompile",
        "uvx": f'{UVX_PREFIX} get-functions --program_path {PROGRAM} --identifier 0x004b58a0 --view decompile',
        "tool": "get_functions",
        "args": {"program_path": PROGRAM, "identifier": "0x004b58a0", "view": "decompile"},
        "key": "decompile",
    },
    {
        "name": "get-functions disassemble",
        "uvx": f'{UVX_PREFIX} get-functions --program_path {PROGRAM} --identifier 0x004b58a0 --view disassemble',
        "tool": "get_functions",
        "args": {"program_path": PROGRAM, "identifier": "0x004b58a0", "view": "disassemble"},
        "key": "disassembly",
    },
    {
        "name": "get-call-graph",
        "uvx": f'{UVX_PREFIX} get-call-graph --program_path {PROGRAM} --function_identifier 0x004b58a0 --mode callees --max_depth 2',
        "tool": "get_call_graph",
        "args": {"program_path": PROGRAM, "function_identifier": "0x004b58a0", "mode": "callees", "max_depth": 2},
        "key": "calls",
    },
    {
        "name": "references from",
        "uvx": f'{UVX_PREFIX} references from --binary {PROGRAM} --target 0x004b58a0 --limit 100',
        "tool": "get_references",
        "args": {"program_path": PROGRAM, "mode": "from", "target": "0x004b58a0", "limit": 100},
        "key": "references",
    },
    {
        "name": "manage-strings regex",
        "uvx": f'{UVX_PREFIX} manage-strings --program_path {PROGRAM} --mode regex --query "Save|Load|Module|GIT|IFO" --include_referencing_functions true --limit 100',
        "tool": "manage_strings",
        "args": {"program_path": PROGRAM, "mode": "regex", "query": "Save|Load|Module|GIT|IFO", "include_referencing_functions": True, "limit": 100},
        "key": "results",
    },
    {
        "name": "search-constants specific",
        "uvx": f'{UVX_PREFIX} search-constants --program_path {PROGRAM} --mode specific --value 32 --max_results 200',
        "tool": "search_constants",
        "args": {"program_path": PROGRAM, "mode": "specific", "value": 32, "max_results": 200},
        "key": "results",
    },
    {
        "name": "analyze-data-flow",
        "uvx": f'{UVX_PREFIX} analyze-data-flow --program_path {PROGRAM} --function_address 0x004b95b0 --start_address 0x004b97af --direction forward',
        "tool": "analyze_data_flow",
        "args": {"program_path": PROGRAM, "function_address": "0x004b95b0", "start_address": "0x004b97af", "direction": "forward"},
        "key": "slices",
    },
    {
        "name": "manage-function rename",
        "uvx": f'{UVX_PREFIX} manage-function --program_path {PROGRAM} --mode rename --function_identifier 0x004b95b0 --new_name LoadModule',
        "tool": "manage_function",
        "args": {"program_path": PROGRAM, "mode": "rename", "function_identifier": "0x004b95b0", "new_name": "LoadModule"},
        "key": "success",
    },
    {
        "name": "manage-comments set",
        "uvx": f'{UVX_PREFIX} manage-comments --program_path {PROGRAM} --mode set --address_or_symbol 0x004b95b0 --comment_type PRE --comment "LoadModule orchestrates per-resource GFF parsing"',
        "tool": "manage_comments",
        "args": {"program_path": PROGRAM, "mode": "set", "address_or_symbol": "0x004b95b0", "comment_type": "PRE", "comment": "LoadModule orchestrates per-resource GFF parsing"},
        "key": "success",
    },
    {
        "name": "manage-function-tags add",
        "uvx": f'{UVX_PREFIX} manage-function-tags --program_path {PROGRAM} --mode add --function 0x004b95b0 --tags save-load serialization',
        "tool": "manage_function_tags",
        "args": {"program_path": PROGRAM, "mode": "add", "function": "0x004b95b0", "tags": ["save-load", "serialization"]},
        "key": "success",
    },
    {
        "name": "manage-bookmarks set",
        "uvx": f'{UVX_PREFIX} manage-bookmarks --program_path {PROGRAM} --mode set --address_or_symbol 0x004b95b0 --type TODO --category "save-load" --comment "verify full GIT object-list write path"',
        "tool": "manage_bookmarks",
        "args": {"program_path": PROGRAM, "mode": "set", "address_or_symbol": "0x004b95b0", "type": "TODO", "category": "save-load", "comment": "verify full GIT object-list write path"},
        "key": "success",
    },
    {
        "name": "tool list-imports",
        "uvx": f"{UVX_PREFIX} tool list-imports '{{\"programPath\":\"{PROGRAM}\",\"limit\":5}}'",
        "tool": "list_imports",
        "args": {"programPath": PROGRAM, "limit": 5},
        "key": "results",
    },
    {
        "name": "tool list-exports",
        "uvx": f"{UVX_PREFIX} tool list-exports '{{\"programPath\":\"{PROGRAM}\",\"limit\":5}}'",
        "tool": "list_exports",
        "args": {"programPath": PROGRAM, "limit": 5},
        "key": "results",
    },
]

summary = []
Path("tmp").mkdir(exist_ok=True)

for idx, case in enumerate(cases, start=1):
    name = case["name"]
    print(f"\n=== {idx:02d} {name} ===")

    uvx_rc, uvx_out, uvx_err = run(case["uvx"], timeout=300)
    (Path("tmp") / f"uvx_{idx:02d}.txt").write_text((uvx_out or "") + "\n---STDERR---\n" + (uvx_err or ""), encoding="utf-8")

    payload = {
        "jsonrpc": "2.0",
        "id": 1000 + idx,
        "method": "tools/call",
        "params": {
            "name": case["tool"],
            "arguments": case["args"],
        },
    }
    curl_rc, curl_out, curl_err = run_curl(payload, sid=sid, timeout=300)
    (Path("tmp") / f"curl_{idx:02d}.txt").write_text((curl_out or "") + "\n---STDERR---\n" + (curl_err or ""), encoding="utf-8")

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

    uvx_ok = uvx_rc == 0
    uvx_key = case["key"] in (uvx_out or "")

    print(f"UVX rc={uvx_rc} key={uvx_key} | CURL ok={curl_ok} key={key_present} err={curl_err_msg[:120]}")
    summary.append({
        "idx": idx,
        "name": name,
        "uvx_rc": uvx_rc,
        "uvx_key": uvx_key,
        "curl_ok": curl_ok,
        "curl_key": key_present,
        "curl_error": curl_err_msg,
        "uvx_cmd": case["uvx"],
        "curl_tool": case["tool"],
        "curl_args": case["args"],
    })

Path("tmp/uvx_curl_equivalence_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
print("\nWrote tmp/uvx_curl_equivalence_summary.json")

failed = [s for s in summary if not (s["uvx_rc"] == 0 and s["curl_ok"])]
print(f"TOTAL={len(summary)} FAILED={len(failed)}")
if failed:
    print("FAILED_CASES:")
    for f in failed:
        print(f"- {f['idx']:02d} {f['name']} | uvx_rc={f['uvx_rc']} | curl_error={f['curl_error'][:120]}")
