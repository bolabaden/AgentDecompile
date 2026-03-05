# AgentDecompile Usage — Multi-Platform (Linux, Windows, UVX)

This guide provides examples using standard HTML toggle sections so every workflow appears in three variants:

- Linux (`bash`/`zsh`)
- Windows (`PowerShell`)
- `uvx`

---

## 0) Shared constants

```text
MCP URL: http://***:8080/mcp/message/
Program: /K1/k1_win_gog_swkotor.exe
Server URL (uvx): http://***:8080/
```

Diagnostics note: HTTP request logs are hidden by default. Add `--verbose` (or `-v`) to `agentdecompile-cli` or `agentdecompile-server` when transport-level diagnostics are needed.

Parameter alias note: shared-server connection options are interchangeable with/without the `ghidra-` prefix (for example `--server-host` == `--ghidra-server-host`, same for port/username/password/repository).

Error response contract: tool failures now return actionable payloads with explicit state and next calls. Expect:

```json
{
  "success": false,
  "error": "Authentication failed for user@host:13100: ...",
  "context": {
    "state": "authentication-failed",
    "tool": "open",
    "serverHost": "***",
    "serverPort": 13100
  },
  "nextSteps": [
    "Verify serverUsername/serverPassword and retry open.",
    "If credentials are correct, verify server reachability and repository access."
  ]
}
```

Automation guidance: when `nextSteps` is present, execute those calls before falling back to broad discovery commands.

<details>
<summary><b>Linux (bash/zsh)</b></summary>

```bash
MCP_URL="http://***:8080/mcp/message/"
PROGRAM_PATH="/K1/k1_win_gog_swkotor.exe"
```

</details>
<details>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
$McpUrl = "http://***:8080/mcp/message/"
$ProgramPath = "/K1/k1_win_gog_swkotor.exe"
```

</details>
<details>
<summary><b>uvx</b></summary>

```bash
UVX_PREFIX='uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/'
PROGRAM_PATH='/K1/k1_win_gog_swkotor.exe'
export AGENT_DECOMPILE_SERVER_HOST='***'
export AGENT_DECOMPILE_SERVER_PORT='13100'
export AGENT_DECOMPILE_SERVER_USERNAME='OpenKotOR'
export AGENT_DECOMPILE_SERVER_PASSWORD='MuchaShakaPaka'
export AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY='Odyssey'
```

</details>
---

## 1) Bootstrap session / transport setup

<details>
<summary><b>Linux (bash/zsh)</b></summary>

```bash
MCP_URL="http://***:8080/mcp/message/"

INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"curl-client","version":"1.0"}}}'
RESP_HEADERS=$(mktemp)

curl -s -D "$RESP_HEADERS" -o /tmp/mcp_init_resp.json \
  -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  --data "$INIT"

SID=$(grep -i '^mcp-session-id:' "$RESP_HEADERS" | awk -F': ' '{print $2}' | tr -d '\r')

curl -s -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Mcp-Session-Id: $SID" \
  --data '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null

call_tool () {
  local id="$1"
  local name="$2"
  local args_json="$3"
  curl -s -X POST "$MCP_URL" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -H "Mcp-Session-Id: $SID" \
    --data "{\"jsonrpc\":\"2.0\",\"id\":${id},\"method\":\"tools/call\",\"params\":{\"name\":\"${name}\",\"arguments\":${args_json}}}"
}
```

</details>
<details>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
$McpUrl = "http://***:8080/mcp/message/"

$InitBody = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"ps-client","version":"1.0"}}}'
$InitResp = Invoke-WebRequest -UseBasicParsing -Uri $McpUrl -Method POST -Headers @{
  "Content-Type" = "application/json"
  "Accept"       = "application/json, text/event-stream"
} -Body $InitBody

$SID = $InitResp.Headers["mcp-session-id"]
if ($SID -is [array]) { $SID = $SID[0] }  # PowerShell 7 returns String[]

$NotifBody = '{"jsonrpc":"2.0","method":"notifications/initialized"}'
Invoke-WebRequest -UseBasicParsing -Uri $McpUrl -Method POST -Headers @{
  "Content-Type"   = "application/json"
  "Accept"         = "application/json, text/event-stream"
  "Mcp-Session-Id" = $SID
} -Body $NotifBody | Out-Null

function Invoke-McpTool {
  param(
    [string]$Name,
    [string]$ArgumentsJson,
    [int]$Id = 100
  )

  $ArgsObject = $ArgumentsJson | ConvertFrom-Json
  $Body = @{
    jsonrpc = "2.0"
    id      = $Id
    method  = "tools/call"
    params  = @{
      name      = $Name
      arguments = $ArgsObject
    }
  } | ConvertTo-Json -Depth 100 -Compress

  Invoke-WebRequest -UseBasicParsing -Uri $McpUrl -Method POST -Headers @{
    "Content-Type"   = "application/json"
    "Accept"         = "application/json, text/event-stream"
    "Mcp-Session-Id" = $SID
  } -Body $Body
}
```

</details>
<details>
<summary><b>uvx</b></summary>

```powershell
# No manual initialize/session handling required in uvx mode.
# The CLI handles transport/session lifecycle per command.

$env:AGENT_DECOMPILE_SERVER_HOST = "***"
$env:AGENT_DECOMPILE_SERVER_PORT = "13100"
$env:AGENT_DECOMPILE_SERVER_USERNAME = "OpenKotOR"
$env:AGENT_DECOMPILE_SERVER_PASSWORD = "MuchaShakaPaka"
$env:AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY = "Odyssey"

uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ list project-files --binary /K1/k1_win_gog_swkotor.exe
```

</details>
---

## 2) Command mapping (1:1 intent across all tabs)

### 2.1 Open program

Tool payload (`name=open`):

```json
{"server_host":"***","server_port":13100,"server_username":"OpenKotOR","server_password":"MuchaShakaPaka","repository_name":"Odyssey","program_path":"/K1/k1_win_gog_swkotor.exe"}
```

<details>
<summary><b>Linux (bash/zsh)</b></summary>

```bash
call_tool 101 open '{"server_host":"***","server_port":13100,"server_username":"OpenKotOR","server_password":"MuchaShakaPaka","repository_name":"Odyssey","program_path":"/K1/k1_win_gog_swkotor.exe"}'
```

</details>
<details>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
Invoke-McpTool -Id 101 -Name "open" -ArgumentsJson '{"server_host":"***","server_port":13100,"server_username":"OpenKotOR","server_password":"MuchaShakaPaka","repository_name":"Odyssey","program_path":"/K1/k1_win_gog_swkotor.exe"}'
```

</details>
<details>
<summary><b>uvx</b></summary>

```powershell
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ open --server_host *** --server_port 13100 --server_username OpenKotOR --server_password MuchaShakaPaka /K1/k1_win_gog_swkotor.exe
```

</details>
### 2.2 List project files

Tool payload (`name=list_project_files`):

```json
{"program_path":"/K1/k1_win_gog_swkotor.exe"}
```

<details>
<summary><b>Linux (bash/zsh)</b></summary>

```bash
call_tool 102 list_project_files '{"program_path":"/K1/k1_win_gog_swkotor.exe"}'
```

</details>
<details>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
Invoke-McpTool -Id 102 -Name "list_project_files" -ArgumentsJson '{"program_path":"/K1/k1_win_gog_swkotor.exe"}'
```

</details>
<details>
<summary><b>uvx</b></summary>

```powershell
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ list project-files --binary /K1/k1_win_gog_swkotor.exe
```

</details>
### 2.3 Get current program

Tool payload (`name=get_current_program`):

```json
{"program_path":"/K1/k1_win_gog_swkotor.exe"}
```

<details>
<summary><b>Linux (bash/zsh)</b></summary>

```bash
call_tool 103 get_current_program '{"program_path":"/K1/k1_win_gog_swkotor.exe"}'
```

</details>
<details>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
Invoke-McpTool -Id 103 -Name "get_current_program" -ArgumentsJson '{"program_path":"/K1/k1_win_gog_swkotor.exe"}'
```

</details>
<details>
<summary><b>uvx</b></summary>

```powershell
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ get-current-program --program_path /K1/k1_win_gog_swkotor.exe
```

</details>
### 2.4 Get functions (limit)

Tool payload (`name=get_functions`):

```json
{"program_path":"/K1/k1_win_gog_swkotor.exe","limit":5}
```

<details>
<summary><b>Linux (bash/zsh)</b></summary>

```bash
call_tool 104 get_functions '{"program_path":"/K1/k1_win_gog_swkotor.exe","limit":5}'
```

</details>
<details>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
Invoke-McpTool -Id 104 -Name "get_functions" -ArgumentsJson '{"program_path":"/K1/k1_win_gog_swkotor.exe","limit":5}'
```

</details>
<details>
<summary><b>uvx</b></summary>

```powershell
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ get-functions --program_path /K1/k1_win_gog_swkotor.exe --limit 5
```

</details>
### 2.5 Search symbols by name

Tool payload (`name=search_symbols_by_name`):

```json
{"program_path":"/K1/k1_win_gog_swkotor.exe","query":"SaveGame","max_results":20}
```

<details>
<summary><b>Linux (bash/zsh)</b></summary>

```bash
call_tool 105 search_symbols_by_name '{"program_path":"/K1/k1_win_gog_swkotor.exe","query":"SaveGame","max_results":20}'
```

</details>
<details>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
Invoke-McpTool -Id 105 -Name "search_symbols_by_name" -ArgumentsJson '{"program_path":"/K1/k1_win_gog_swkotor.exe","query":"SaveGame","max_results":20}'
```

</details>
<details>
<summary><b>uvx</b></summary>

```powershell
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ search-symbols-by-name --program_path /K1/k1_win_gog_swkotor.exe --query SaveGame --max_results 20
```

</details>
### 2.6 References to

Tool payload (`name=get_references`):

```json
{"program_path":"/K1/k1_win_gog_swkotor.exe","mode":"to","target":"WinMain","limit":25}
```

<details>
<summary><b>Linux (bash/zsh)</b></summary>

```bash
call_tool 106 get_references '{"program_path":"/K1/k1_win_gog_swkotor.exe","mode":"to","target":"WinMain","limit":25}'
```

</details>
<details>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
Invoke-McpTool -Id 106 -Name "get_references" -ArgumentsJson '{"program_path":"/K1/k1_win_gog_swkotor.exe","mode":"to","target":"WinMain","limit":25}'
```

</details>
<details>
<summary><b>uvx</b></summary>

```powershell
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ references to --binary /K1/k1_win_gog_swkotor.exe --target WinMain --limit 25
```

</details>
### 2.7 Get functions (info/decompile/disassemble)

Tool payload (info):

```json
{"program_path":"/K1/k1_win_gog_swkotor.exe","identifier":"0x004b58a0","view":"info","include_callers":true,"include_callees":true}
```

<details>
<summary><b>Linux (bash/zsh)</b></summary>

```bash
# info
call_tool 107 get_functions '{"program_path":"/K1/k1_win_gog_swkotor.exe","identifier":"0x004b58a0","view":"info","include_callers":true,"include_callees":true}'

# decompile
call_tool 108 get_functions '{"program_path":"/K1/k1_win_gog_swkotor.exe","identifier":"0x004b58a0","view":"decompile"}'

# disassemble
call_tool 109 get_functions '{"program_path":"/K1/k1_win_gog_swkotor.exe","identifier":"0x004b58a0","view":"disassemble"}'
```

</details>
<details>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
# info
Invoke-McpTool -Id 107 -Name "get_functions" -ArgumentsJson '{"program_path":"/K1/k1_win_gog_swkotor.exe","identifier":"0x004b58a0","view":"info","include_callers":true,"include_callees":true}'

# decompile
Invoke-McpTool -Id 108 -Name "get_functions" -ArgumentsJson '{"program_path":"/K1/k1_win_gog_swkotor.exe","identifier":"0x004b58a0","view":"decompile"}'

# disassemble
Invoke-McpTool -Id 109 -Name "get_functions" -ArgumentsJson '{"program_path":"/K1/k1_win_gog_swkotor.exe","identifier":"0x004b58a0","view":"disassemble"}'
```

</details>
<details>
<summary><b>uvx</b></summary>

```powershell
# info
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ get-functions --program_path /K1/k1_win_gog_swkotor.exe --identifier 0x004b58a0 --view info --include_callers true --include_callees true

# decompile
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ get-functions --program_path /K1/k1_win_gog_swkotor.exe --identifier 0x004b58a0 --view decompile

# disassemble
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ get-functions --program_path /K1/k1_win_gog_swkotor.exe --identifier 0x004b58a0 --view disassemble
```

</details>
### 2.8 Call graph + references from

<details>
<summary><b>Linux (bash/zsh)</b></summary>

```bash
# call graph
call_tool 110 get_call_graph '{"program_path":"/K1/k1_win_gog_swkotor.exe","function_identifier":"0x004b58a0","mode":"callees","max_depth":2}'

# references from
call_tool 111 get_references '{"program_path":"/K1/k1_win_gog_swkotor.exe","mode":"from","target":"0x004b58a0","limit":100}'
```

</details>
<details>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
# call graph
Invoke-McpTool -Id 110 -Name "get_call_graph" -ArgumentsJson '{"program_path":"/K1/k1_win_gog_swkotor.exe","function_identifier":"0x004b58a0","mode":"callees","max_depth":2}'

# references from
Invoke-McpTool -Id 111 -Name "get_references" -ArgumentsJson '{"program_path":"/K1/k1_win_gog_swkotor.exe","mode":"from","target":"0x004b58a0","limit":100}'
```

</details>
<details>
<summary><b>uvx</b></summary>

```powershell
# call graph
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ get-call-graph --program_path /K1/k1_win_gog_swkotor.exe --function_identifier 0x004b58a0 --mode callees --max_depth 2

# references from
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ references from --binary /K1/k1_win_gog_swkotor.exe --target 0x004b58a0 --limit 100
```

</details>
### 2.9 Strings, constants, data-flow

<details>
<summary><b>Linux (bash/zsh)</b></summary>

```bash
# strings
call_tool 112 manage_strings '{"program_path":"/K1/k1_win_gog_swkotor.exe","mode":"regex","query":"Save|Load|Module|GIT|IFO","include_referencing_functions":true,"limit":100}'

# constants
call_tool 113 search_constants '{"program_path":"/K1/k1_win_gog_swkotor.exe","mode":"specific","value":32,"max_results":200}'

# data-flow
call_tool 114 analyze_data_flow '{"program_path":"/K1/k1_win_gog_swkotor.exe","function_address":"0x004b95b0","start_address":"0x004b97af","direction":"forward"}'
```

</details>
<details>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
# strings
Invoke-McpTool -Id 112 -Name "manage_strings" -ArgumentsJson '{"program_path":"/K1/k1_win_gog_swkotor.exe","mode":"regex","query":"Save|Load|Module|GIT|IFO","include_referencing_functions":true,"limit":100}'

# constants
Invoke-McpTool -Id 113 -Name "search_constants" -ArgumentsJson '{"program_path":"/K1/k1_win_gog_swkotor.exe","mode":"specific","value":32,"max_results":200}'

# data-flow
Invoke-McpTool -Id 114 -Name "analyze_data_flow" -ArgumentsJson '{"program_path":"/K1/k1_win_gog_swkotor.exe","function_address":"0x004b95b0","start_address":"0x004b97af","direction":"forward"}'
```

</details>
<details>
<summary><b>uvx</b></summary>

```powershell
# strings
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ manage-strings --program_path /K1/k1_win_gog_swkotor.exe --mode regex --query "Save|Load|Module|GIT|IFO" --include_referencing_functions true --limit 100

# constants
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ search-constants --program_path /K1/k1_win_gog_swkotor.exe --mode specific --value 32 --max_results 200

# data-flow
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ analyze-data-flow --program_path /K1/k1_win_gog_swkotor.exe --function_address 0x004b95b0 --start_address 0x004b97af --direction forward
```

</details>
### 2.10 Rename, comment, tag, bookmark

<details>
<summary><b>Linux (bash/zsh)</b></summary>

```bash
# rename
call_tool 115 manage_function '{"program_path":"/K1/k1_win_gog_swkotor.exe","mode":"rename","function_identifier":"0x004b95b0","new_name":"LoadModule"}'

# comment
call_tool 116 manage_comments '{"program_path":"/K1/k1_win_gog_swkotor.exe","mode":"set","address_or_symbol":"0x004b95b0","comment_type":"PRE","comment":"LoadModule orchestrates per-resource GFF parsing"}'

# tags
call_tool 117 manage_function_tags '{"program_path":"/K1/k1_win_gog_swkotor.exe","mode":"add","function":"0x004b95b0","tags":["save-load","serialization"]}'

# bookmark
call_tool 118 manage_bookmarks '{"program_path":"/K1/k1_win_gog_swkotor.exe","mode":"set","address_or_symbol":"0x004b95b0","type":"TODO","category":"save-load","comment":"verify full GIT object-list write path"}'
```

</details>
<details>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
# rename
Invoke-McpTool -Id 115 -Name "manage_function" -ArgumentsJson '{"program_path":"/K1/k1_win_gog_swkotor.exe","mode":"rename","function_identifier":"0x004b95b0","new_name":"LoadModule"}'

# comment
Invoke-McpTool -Id 116 -Name "manage_comments" -ArgumentsJson '{"program_path":"/K1/k1_win_gog_swkotor.exe","mode":"set","address_or_symbol":"0x004b95b0","comment_type":"PRE","comment":"LoadModule orchestrates per-resource GFF parsing"}'

# tags
Invoke-McpTool -Id 117 -Name "manage_function_tags" -ArgumentsJson '{"program_path":"/K1/k1_win_gog_swkotor.exe","mode":"add","function":"0x004b95b0","tags":["save-load","serialization"]}'

# bookmark
Invoke-McpTool -Id 118 -Name "manage_bookmarks" -ArgumentsJson '{"program_path":"/K1/k1_win_gog_swkotor.exe","mode":"set","address_or_symbol":"0x004b95b0","type":"TODO","category":"save-load","comment":"verify full GIT object-list write path"}'
```

</details>
<details>
<summary><b>uvx</b></summary>

```powershell
# rename
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ manage-function --program_path /K1/k1_win_gog_swkotor.exe --mode rename --function_identifier 0x004b95b0 --new_name LoadModule

# comment
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ manage-comments --program_path /K1/k1_win_gog_swkotor.exe --mode set --address_or_symbol 0x004b95b0 --comment_type PRE --comment "LoadModule orchestrates per-resource GFF parsing"

# tags
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ manage-function-tags --program_path /K1/k1_win_gog_swkotor.exe --mode add --function 0x004b95b0 --tags save-load --tags serialization

# bookmark
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ manage-bookmarks --program_path /K1/k1_win_gog_swkotor.exe --mode set --address_or_symbol 0x004b95b0 --type TODO --category "save-load" --comment "verify full GIT object-list write path"
```

</details>
### 2.11 Raw tool mode examples

<details>
<summary><b>Linux (bash/zsh)</b></summary>

```bash
call_tool 119 list_imports '{"program_path":"/K1/k1_win_gog_swkotor.exe","limit":5}'
call_tool 120 list_exports '{"program_path":"/K1/k1_win_gog_swkotor.exe","limit":5}'
```

</details>
<details>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
Invoke-McpTool -Id 119 -Name "list_imports" -ArgumentsJson '{"program_path":"/K1/k1_win_gog_swkotor.exe","limit":5}'
Invoke-McpTool -Id 120 -Name "list_exports" -ArgumentsJson '{"program_path":"/K1/k1_win_gog_swkotor.exe","limit":5}'
```

</details>
<details>
<summary><b>uvx</b></summary>

```powershell
$a = '{"program_path":"/K1/k1_win_gog_swkotor.exe","limit":5}'
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ tool list-imports $a
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ tool list-exports $a
```

</details>
### 2.12 Shared sync workflow (validated)

Verified against `http://***:8080/mcp/message/` with repository `Odyssey` on 2026-03-02.

<details>
<summary><b>Linux (bash/zsh)</b></summary>

```bash
# 1) Open shared repository session
call_tool 201 open '{"server_host":"***","server_port":13100,"server_username":"OpenKotOR","server_password":"MuchaShakaPaka","repository_name":"Odyssey","program_path":"/K1/k1_win_gog_swkotor.exe"}'

# 2) Pull plan
call_tool 202 sync-shared-project '{"mode":"pull","path":"/K1","newPath":"/K1_sync_test","recursive":true,"maxResults":1,"dryRun":true}'

# 3) Push plan
call_tool 203 sync-shared-project '{"mode":"push","path":"/K1_sync_test","recursive":true,"maxResults":1,"dryRun":true}'
```

</details>
<details>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
$url = "http://***:8080/mcp/message/"
$hdr = @{ "Content-Type"="application/json"; "Accept"="application/json, text/event-stream" }

$init = @{ jsonrpc="2.0"; id=1; method="initialize"; params=@{ protocolVersion="2025-03-26"; capabilities=@{}; clientInfo=@{ name="ps-sync"; version="0.1" } } } | ConvertTo-Json -Depth 8
$r = Invoke-WebRequest -Uri $url -Method POST -Headers $hdr -Body $init -UseBasicParsing
$sid = ($r.Headers.GetEnumerator() | Where-Object { $_.Key -ieq "mcp-session-id" } | Select-Object -First 1 -ExpandProperty Value)
$hdr["mcp-session-id"] = $sid
Invoke-WebRequest -Uri $url -Method POST -Headers $hdr -Body (@{ jsonrpc="2.0"; method="notifications/initialized" } | ConvertTo-Json -Depth 5) -UseBasicParsing | Out-Null

$open = @{ jsonrpc="2.0"; id=2; method="tools/call"; params=@{ name="open"; arguments=@{ server_host="***"; server_port=13100; server_username="OpenKotOR"; server_password="MuchaShakaPaka"; repository_name="Odyssey"; program_path="/K1/k1_win_gog_swkotor.exe" } } } | ConvertTo-Json -Depth 10
Invoke-WebRequest -Uri $url -Method POST -Headers $hdr -Body $open -UseBasicParsing

$pull = @{ jsonrpc="2.0"; id=3; method="tools/call"; params=@{ name="sync-shared-project"; arguments=@{ mode="pull"; path="/K1"; newPath="/K1_ps_sync"; recursive=$true; maxResults=1; dryRun=$true } } } | ConvertTo-Json -Depth 10
Invoke-WebRequest -Uri $url -Method POST -Headers $hdr -Body $pull -UseBasicParsing

$push = @{ jsonrpc="2.0"; id=4; method="tools/call"; params=@{ name="sync-shared-project"; arguments=@{ mode="push"; path="/K1_ps_sync"; recursive=$true; maxResults=1; dryRun=$true } } } | ConvertTo-Json -Depth 10
Invoke-WebRequest -Uri $url -Method POST -Headers $hdr -Body $push -UseBasicParsing
```

</details>
<details>
<summary><b>uvx</b></summary>

```powershell
$steps = '[{"name":"open","arguments":{"server_host":"***","server_port":13100,"server_username":"OpenKotOR","server_password":"MuchaShakaPaka","repository_name":"Odyssey","program_path":"/K1/k1_win_gog_swkotor.exe"}},{"name":"sync-shared-project","arguments":{"mode":"pull","path":"/K1","newPath":"/K1_uvx_sync","recursive":true,"maxResults":1,"dryRun":true}},{"name":"sync-shared-project","arguments":{"mode":"push","path":"/K1_uvx_sync","recursive":true,"maxResults":1,"dryRun":true}}]'
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/ tool-seq $steps
```

</details>

---

## 3) Notes

- This file is intentionally organized in three tabs for each workflow: Linux, Windows, and `uvx`.
- For strict output comparability, run all HTTP calls in one session and run `open` first.
- In PowerShell `uvx ... tool <name> <json>`, pass JSON via a variable like `$a`.
- Verified behavior (2026-03-02): shared pull and push dry-runs succeed in both PowerShell and `uvx` when `open` and `sync-shared-project` run in the same MCP session.
- Verified behavior (2026-03-02): shared push actual succeeds after pull (`mode="push"`, non-dry-run).
- `checkin-program` can still fail when the active program is non-project-backed (`path` like `/Untitled`); use sync pull/push flow for shared updates.
