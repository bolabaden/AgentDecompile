# AgentDecompile Usage Log (Conversation-Derived)

This document captures **exact command patterns and tool-call patterns used in this conversation**, with sensitive values redacted.
It is intended as an operational runbook and troubleshooting reference.

## Redaction Rules Used

Sensitive values have been replaced with placeholders:

- `<REMOTE_SSH_USER>`
- `<REMOTE_SSH_HOST>`
- `<MCP_HOST>`
- `<MCP_HTTP_URL>`
- `<GHIDRA_SERVER_HOST>`
- `<GHIDRA_SERVER_PORT>`
- `<GHIDRA_SERVER_USERNAME>`
- `<GHIDRA_SERVER_PASSWORD>`
- `<GHIDRA_SERVER_REPOSITORY>`
- `<MCP_SESSION_ID>`
- `<SESSION_ID>`

---

## 1) Environment + Local Validation Commands

### 1.1 Activate virtual environment

```powershell
& c:\GitHub\agentdecompile\.venv\Scripts\Activate.ps1
```

Expected result:
- Shell activates Python environment with project dependencies.

### 1.2 Run targeted proxy bootstrap test

```powershell
python -m pytest -q tests/test_proxy_bootstrap.py::test_proxy_bootstrap_exact_commands -vv
```

Expected result:
- Test passes (exit code `0`) if bootstrap command wiring is correct.

---

## 2) Remote Docker Lifecycle + Logs

### 2.1 Build/recreate key services

```powershell
ssh <REMOTE_SSH_USER>@<REMOTE_SSH_HOST> "cd /home/ubuntu/my-media-stack && docker compose up -d --remove-orphans --build biodecompwarehouse biodecompwarehouse-mcp biodecompwarehouse-bsim-server"
```

Expected result:
- Services are rebuilt/restarted; compose reports containers as started/up.

### 2.2 Check running status

```powershell
ssh <REMOTE_SSH_USER>@<REMOTE_SSH_HOST> "cd /home/ubuntu/my-media-stack && docker compose ps biodecompwarehouse biodecompwarehouse-mcp biodecompwarehouse-bsim-server"
```

Expected result:
- Table output with container names and state (`Up`, `Restarting`, etc).

### 2.3 Tail service logs (combined)

```powershell
ssh <REMOTE_SSH_USER>@<REMOTE_SSH_HOST> "docker logs biodecompwarehouse --tail 20 2>&1 && echo '---MCP---' && docker logs biodecompwarehouse-mcp --tail 20 2>&1"
```

Expected result:
- Recent logs for both runtime and MCP containers.

### 2.4 Tail MCP-only logs

```powershell
ssh <REMOTE_SSH_USER>@<REMOTE_SSH_HOST> "docker logs biodecompwarehouse-mcp --tail 15 2>&1"
```

Expected result:
- MCP startup/runtime messages; useful for schema/tool registration checks.

---

## 3) Proxy + HTTP Health Checks

### 3.1 Poll local proxy health endpoint

```powershell
Start-Sleep -Seconds 30; $ProgressPreference='SilentlyContinue'; try { $r = Invoke-WebRequest -Uri 'http://127.0.0.1:9999/health' -UseBasicParsing -TimeoutSec 5; Write-Host "Local proxy: HTTP $($r.StatusCode)" } catch { Write-Host "Not ready yet: $($_.Exception.Message)" }
```

Expected result:
- `HTTP 200` when local proxy is ready; otherwise transient timeout/connection error text.

---

## 4) MCP Protocol Calls (Python httpx)

### 4.1 Initialize + notifications + open tool (exact pattern)

```powershell
python -c "
import httpx, json
url = 'http://127.0.0.1:9999/mcp/message/'
hdrs = {'Content-Type':'application/json','Accept':'application/json, text/event-stream'}
init = {'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-03-26','capabilities':{},'clientInfo':{'name':'test','version':'0.1'}}}
r = httpx.post(url, json=init, headers=hdrs, timeout=30)
sid = r.headers.get('mcp-session-id','')
httpx.post(url, json={'jsonrpc':'2.0','method':'notifications/initialized'}, headers={**hdrs,'mcp-session-id':sid}, timeout=10)
print('Session:', sid[:20])

# Open
call_open = {'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'open','arguments':{'server_host':'<GHIDRA_SERVER_HOST>','server_port':<GHIDRA_SERVER_PORT>,'server_username':'<GHIDRA_SERVER_USERNAME>','server_password':'<GHIDRA_SERVER_PASSWORD>','repository_name':'<GHIDRA_SERVER_REPOSITORY>','program_path':'/K1/k1_win_gog_swkotor.exe'}}}
r2 = httpx.post(url, json=call_open, headers={**hdrs,'mcp-session-id':sid}, timeout=120)
print('Open status:', r2.status_code)
print('Open CT:', r2.headers.get('content-type'))
print('Open body:', r2.text[:500])
"
```

Expected result:
- Initialization returns session header.
- `notifications/initialized` accepted.
- `open` returns JSON-RPC result payload (or descriptive error).

---

## 5) MCP Protocol Calls (PowerShell WebRequest)

### 5.1 Initialize session on remote MCP HTTP endpoint

```powershell
$h = @{"Content-Type"="application/json"; "Accept"="application/json, text/event-stream"};
$body = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}';
$r = Invoke-WebRequest -Uri "http://<MCP_HOST>:8080/mcp/message/" -Method POST -Headers $h -Body $body;
Write-Host "Status: $($r.StatusCode)";
Write-Host "Session: $($r.Headers['Mcp-Session-Id'])"
```

Expected result:
- `Status: 200`
- `Mcp-Session-Id` header present.

### 5.2 List tools for a session

```powershell
$sid = "<MCP_SESSION_ID>";
$h = @{"Content-Type"="application/json"; "Accept"="application/json, text/event-stream"; "Mcp-Session-Id"=$sid};
$body = '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}';
$r = Invoke-WebRequest -Uri "http://<MCP_HOST>:8080/mcp/message/" -Method POST -Headers $h -Body $body;
$json = $r.Content | ConvertFrom-Json -Depth 20;
$json.result.tools.Count
```

Expected result:
- Integer tool count returned (example from session: `25`).

### 5.3 Verify advertised schema fields for selected tools

```powershell
$sid = "<MCP_SESSION_ID>";
$h = @{"Content-Type"="application/json"; "Accept"="application/json, text/event-stream"; "Mcp-Session-Id"=$sid};
$body = '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}';
$resp = Invoke-WebRequest -Uri "http://<MCP_HOST>:8080/mcp/message/" -Method POST -Headers $h -Body $body;
$json = $resp.Content | ConvertFrom-Json -Depth 20;
$targets = @("manage_bookmarks","manage_comments","manage_data_types","manage_function","manage_function_tags","manage_structures","manage_symbols","manage_files");
foreach ($t in $json.result.tools) {
  if ($targets -contains $t.name) {
    $props = $t.inputSchema.properties.PSObject.Properties.Name;
    $hasMode = "mode" -in $props;
    $hasAction = "action" -in $props;
    $hasOp = "operation" -in $props;
    Write-Host "$($t.name): mode=$hasMode action=$hasAction operation=$hasOp";
  }
}
```

Expected result after schema standardization:
- `mode=True action=False operation=False` for all target tools.

### 5.4 Call a tool with `mode` argument

```powershell
$sid = "<MCP_SESSION_ID>";
$h = @{"Content-Type"="application/json"; "Accept"="application/json, text/event-stream"; "Mcp-Session-Id"=$sid};
$body = '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"manage_bookmarks","arguments":{"mode":"categories"}}}';
$resp = Invoke-WebRequest -Uri "http://<MCP_HTTP_URL>" -Method POST -Headers $h -Body $body;
$resp.Content
```

Expected result:
- JSON-RPC result payload.
- If no program loaded in session, expected functional error message like `No program loaded`.

### 5.5 Additional tool call sample (manage_comments)

```powershell
$sid = "<MCP_SESSION_ID>";
$h = @{"Content-Type"="application/json"; "Accept"="application/json, text/event-stream"; "Mcp-Session-Id"=$sid};
$body = '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"manage_comments","arguments":{"mode":"search","query":"test"}}}';
$resp = Invoke-WebRequest -Uri "http://<MCP_HTTP_URL>" -Method POST -Headers $h -Body $body;
$resp.Content.Substring(0, [Math]::Min(300, $resp.Content.Length))
```

Expected result:
- Tool dispatch succeeds at protocol level; business-level output depends on loaded program state.

---

## 6) Common MCP Error Cases Observed

### 6.1 Missing Accept header

Request without proper Accept can return:

```json
{
  "error": {
    "code": -32600,
    "message": "Not Acceptable: Client must accept application/json"
  }
}
```

### 6.2 Missing session ID

```json
{
  "error": {
    "code": -32600,
    "message": "Bad Request: Missing session ID"
  }
}
```

### 6.3 Invalid or expired session ID

```json
{
  "error": {
    "code": -32600,
    "message": "Session not found"
  }
}
```

---

## 7) Git + Release Flow Used

### 7.1 Stage and inspect

```powershell
git add -A ; git status
```

Expected result:
- Changed files staged and listed.

### 7.2 Commit (example messages from conversation)

```powershell
git commit -m "Standardize all tool schemas to use 'mode' as canonical dispatch param"
```

```powershell
git commit -m "Remove auto-injection of action/operation as advertised schema params"
```

Expected result:
- Commit created with file/line change stats.

### 7.3 Push

```powershell
git push
```

Expected result:
- Remote branch updated (`master -> master`).

---

## 8) Remote Hot-Patch Flow (Without Full No-Cache Rebuild)

### 8.1 Copy modified files to remote host temp path

```powershell
scp src/agentdecompile_cli/mcp_server/providers/bookmarks.py src/agentdecompile_cli/mcp_server/providers/comments.py src/agentdecompile_cli/mcp_server/providers/datatypes.py src/agentdecompile_cli/mcp_server/providers/getfunction.py src/agentdecompile_cli/mcp_server/providers/structures.py src/agentdecompile_cli/mcp_server/providers/symbols.py src/agentdecompile_cli/mcp_server/providers/project.py <REMOTE_SSH_USER>@<REMOTE_SSH_HOST>:/tmp/providers/
```

```powershell
scp src/agentdecompile_cli/registry.py <REMOTE_SSH_USER>@<REMOTE_SSH_HOST>:/tmp/providers/registry.py
```

Expected result:
- File transfer percent/progress shown for each file.

### 8.2 Copy files into running container

```powershell
ssh <REMOTE_SSH_USER>@<REMOTE_SSH_HOST> "for f in bookmarks.py comments.py datatypes.py getfunction.py structures.py symbols.py project.py; do docker cp /tmp/providers/$f biodecompwarehouse-mcp:/ghidra/venv/lib/python3.12/site-packages/agentdecompile_cli/mcp_server/providers/$f; done && echo DONE"
```

```powershell
ssh <REMOTE_SSH_USER>@<REMOTE_SSH_HOST> "docker cp /tmp/providers/registry.py biodecompwarehouse-mcp:/ghidra/venv/lib/python3.12/site-packages/agentdecompile_cli/registry.py && cd /home/ubuntu/my-media-stack && docker compose restart biodecompwarehouse-mcp && echo DONE"
```

Expected result:
- `DONE` printed.
- Container restarted successfully.

### 8.3 Restart MCP container only

```powershell
ssh <REMOTE_SSH_USER>@<REMOTE_SSH_HOST> "cd /home/ubuntu/my-media-stack && docker compose restart biodecompwarehouse-mcp"
```

Expected result:
- Compose reports `Restarting` then `Started`.

### 8.4 Verify startup logs

```powershell
ssh <REMOTE_SSH_USER>@<REMOTE_SSH_HOST> "docker logs biodecompwarehouse-mcp --tail 10"
```

Expected result:
- MCP service startup lines; no fatal import/syntax errors.

---

## 9) Diagnostics / Introspection Commands Used

### 9.1 Validate bridge feature exists

```powershell
python -c "from agentdecompile_cli.bridge import AgentDecompileStdioBridge; print(hasattr(AgentDecompileStdioBridge, '_auto_open_shared_server'))"
```

Expected result:
- `True` once feature is implemented.

### 9.2 Inspect MCP `ServerSession` shape

```powershell
python -c "from mcp.server.lowlevel.server import ServerSession; print([n for n in dir(ServerSession) if 'id' in n.lower() or 'session' in n.lower() or 'client' in n.lower()]); import inspect; print('annotations', getattr(ServerSession,'__annotations__',{}))"
```

Expected result:
- Property/method name list and annotations dump.

### 9.3 Run temporary debug script

```powershell
python c:\GitHub\agentdecompile\tmp\check_direct_backend_session.py
```

Expected result:
- Script-specific output for backend/session diagnosis.

### 9.4 Cleanup temporary debug scripts

```powershell
Remove-Item -Force c:\GitHub\agentdecompile\tmp\patch_remote_decompiler_wrappers.py,c:\GitHub\agentdecompile\tmp\patch_remote_linux_arm64_decompiler.py -ErrorAction SilentlyContinue
```

```powershell
Remove-Item -Force c:\GitHub\agentdecompile\tmp\validate_dual_sessions.py,c:\GitHub\agentdecompile\tmp\check_backend_session_ids.py,c:\GitHub\agentdecompile\tmp\check_direct_backend_session.py -ErrorAction SilentlyContinue
```

Expected result:
- No error if files already removed (`SilentlyContinue`).

---

## 10) Curl Equivalents (for MCP HTTP API)

These are protocol-equivalent examples to the PowerShell/Python calls used.

### 10.1 Initialize

```bash
curl -i -X POST "http://<MCP_HOST>:8080/mcp/message/" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc":"2.0",
    "id":1,
    "method":"initialize",
    "params":{
      "protocolVersion":"2024-11-05",
      "capabilities":{},
      "clientInfo":{"name":"test","version":"1.0"}
    }
  }'
```

Expected result:
- HTTP 200 + `Mcp-Session-Id` response header.

### 10.2 notifications/initialized

```bash
curl -i -X POST "http://<MCP_HOST>:8080/mcp/message/" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Mcp-Session-Id: <MCP_SESSION_ID>" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'
```

Expected result:
- HTTP 200 (notification accepted).

### 10.3 tools/list

```bash
curl -s -X POST "http://<MCP_HOST>:8080/mcp/message/" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Mcp-Session-Id: <MCP_SESSION_ID>" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
```

Expected result:
- JSON-RPC `result.tools[]` list.

### 10.4 tools/call example

```bash
curl -s -X POST "http://<MCP_HOST>:8080/mcp/message/" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Mcp-Session-Id: <MCP_SESSION_ID>" \
  -d '{
    "jsonrpc":"2.0",
    "id":3,
    "method":"tools/call",
    "params":{"name":"manage_comments","arguments":{"mode":"search","query":"test"}}
  }'
```

Expected result:
- JSON-RPC result envelope.

---

## 11) VS Code Tool Calls Used by the Agent (Redacted, Conversation-Derived)

The following tool APIs were used repeatedly in this conversation for implementation and verification.

### 11.1 Read/search/analysis tools

- `read_file`
  - Purpose: inspect provider schemas and handlers.
  - Expected result: file slice content with line ranges.

- `grep_search`
  - Purpose: locate schema keys and dispatch lookups (`mode`/`action`/`operation`).
  - Expected result: file/line match list.

- `file_search`
  - Purpose: verify file existence (for `USAGE.md`).
  - Expected result: match paths or none.

- `get_errors`
  - Purpose: check edited Python files for new errors.
  - Expected result: “No errors found” per file.

### 11.2 Edit tools

- `apply_patch`
  - Purpose: targeted text edits in provider schemas.
  - Expected result: “files were successfully edited”.

- `replace_string_in_file` / `multi_replace_string_in_file`
  - Purpose: systematic replacement across multiple providers.
  - Expected result: list of edited files.

- `create_file`
  - Purpose: create this `USAGE.md` file.
  - Expected result: file created successfully.

### 11.3 Execution and planning tools

- `run_in_terminal`
  - Purpose: git operations, SCP/SSH/docker patching, protocol verification.
  - Expected result: command stdout/stderr and exit code.

- `manage_todo_list`
  - Purpose: progress tracking of multi-step implementation.
  - Expected result: todo state updated.

- `multi_tool_use.parallel`
  - Purpose: parallel read/search retrieval.
  - Expected result: batched outputs from each tool call.

---

## 12) Practical Notes

1. Schema/client compatibility:
   - MCP clients validate against advertised JSON schema before server-side normalization.
   - Keep only `mode` advertised for dispatch params to avoid client-side rejection.

2. Runtime compatibility:
   - Server handlers should still accept legacy synonyms internally (`mode`, `action`, `operation`) via normalized key lookup.

3. Operational strategy used here:
   - Fast remote hot-patch (`scp` + `docker cp` + container restart) was used instead of full no-cache rebuild.

---

## 13) Minimal End-to-End Quickstart (Redacted)

```powershell
# 1) Start/restart services
ssh <REMOTE_SSH_USER>@<REMOTE_SSH_HOST> "cd /home/ubuntu/my-media-stack && docker compose up -d --remove-orphans --build biodecompwarehouse biodecompwarehouse-mcp biodecompwarehouse-bsim-server"

# 2) Initialize MCP session
$h = @{"Content-Type"="application/json"; "Accept"="application/json, text/event-stream"}
$init = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
$r = Invoke-WebRequest -Uri "http://<MCP_HOST>:8080/mcp/message/" -Method POST -Headers $h -Body $init
$sid = $r.Headers['Mcp-Session-Id']

# 3) List tools
$h2 = @{"Content-Type"="application/json"; "Accept"="application/json, text/event-stream"; "Mcp-Session-Id"=$sid}
$tl = '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
Invoke-WebRequest -Uri "http://<MCP_HOST>:8080/mcp/message/" -Method POST -Headers $h2 -Body $tl

# 4) Call a tool
$call = '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"manage_comments","arguments":{"mode":"search","query":"test"}}}'
Invoke-WebRequest -Uri "http://<MCP_HOST>:8080/mcp/message/" -Method POST -Headers $h2 -Body $call
```

Expected result:
- End-to-end MCP protocol roundtrip with session-scoped tool invocation.
