$ErrorActionPreference = 'Continue'
$baseUrl = 'http://***:8080/mcp/message/'
$program = '/K1/k1_win_gog_swkotor.exe'
$uvxPrefix = 'uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080/'

function New-PayloadFile {
    param([string]$Path, [object]$Object)
    $Object | ConvertTo-Json -Depth 20 -Compress | Set-Content -Path $Path -NoNewline
}

# Initialize curl MCP session
$initPayload = @{
    jsonrpc = '2.0'
    id      = 1
    method  = 'initialize'
    params  = @{
        protocolVersion = '2025-03-26'
        capabilities    = @{}
        clientInfo      = @{ name = 'usage-md-validator'; version = '1.0' }
    }
}
New-PayloadFile -Path 'tmp\mcp_init_validate.json' -Object $initPayload
curl.exe -s -D tmp\mcp_validate_headers.txt -o tmp\mcp_validate_init_resp.json -X POST $baseUrl -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' --data @tmp\mcp_init_validate.json | Out-Null

$sidLine = Get-Content tmp\mcp_validate_headers.txt | Where-Object { $_ -match '^mcp-session-id:' }
if (-not $sidLine) { throw 'Failed to get mcp-session-id from initialize response.' }
$SID = ($sidLine -split ':', 2)[1].Trim()

$notifPayload = @{ jsonrpc = '2.0'; method = 'notifications/initialized' }
New-PayloadFile -Path 'tmp\mcp_validate_initialized.json' -Object $notifPayload
curl.exe -s -X POST $baseUrl -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -H "Mcp-Session-Id: $SID" --data @tmp\mcp_validate_initialized.json | Out-Null

$cases = @(
    @{ Name = 'open'; Uvx = "$uvxPrefix open --server_host *** --server_port 13100 --server_username OpenKotOR --server_password idekanymore $program"; Tool = 'open'; Args = @{server_host = '***'; server_port = 13100; server_username = 'OpenKotOR'; server_password = 'idekanymore'; repository_name = 'Odyssey'; program_path = $program } },
    @{ Name = 'list project-files'; Uvx = "$uvxPrefix list project-files"; Tool = 'list_project_files'; Args = @{} },
    @{ Name = 'get-current-program'; Uvx = "$uvxPrefix get-current-program --program_path $program"; Tool = 'get_current_program'; Args = @{program_path = $program } },
    @{ Name = 'get-functions limit'; Uvx = "$uvxPrefix get-functions --program_path $program --limit 5"; Tool = 'get_functions'; Args = @{program_path = $program; limit = 5 } },
    @{ Name = 'search-symbols-by-name'; Uvx = "$uvxPrefix search-symbols-by-name --program_path $program --query SaveGame --max_results 20"; Tool = 'search_symbols_by_name'; Args = @{program_path = $program; query = 'SaveGame'; max_results = 20 } },
    @{ Name = 'references to'; Uvx = "$uvxPrefix references to --binary $program --target SaveGame --limit 25"; Tool = 'get_references'; Args = @{program_path = $program; mode = 'to'; target = 'SaveGame'; limit = 25 } },
    @{ Name = 'get-functions info'; Uvx = "$uvxPrefix get-functions --program_path $program --identifier 0x004b58a0 --view info --include_callers true --include_callees true"; Tool = 'get_functions'; Args = @{program_path = $program; identifier = '0x004b58a0'; view = 'info'; include_callers = $true; include_callees = $true } },
    @{ Name = 'get-functions decompile'; Uvx = "$uvxPrefix get-functions --program_path $program --identifier 0x004b58a0 --view decompile"; Tool = 'get_functions'; Args = @{program_path = $program; identifier = '0x004b58a0'; view = 'decompile' } },
    @{ Name = 'get-functions disassemble'; Uvx = "$uvxPrefix get-functions --program_path $program --identifier 0x004b58a0 --view disassemble"; Tool = 'get_functions'; Args = @{program_path = $program; identifier = '0x004b58a0'; view = 'disassemble' } },
    @{ Name = 'get-call-graph'; Uvx = "$uvxPrefix get-call-graph --program_path $program --function_identifier 0x004b58a0 --mode callees --max_depth 2"; Tool = 'get_call_graph'; Args = @{program_path = $program; function_identifier = '0x004b58a0'; mode = 'callees'; max_depth = 2 } },
    @{ Name = 'references from'; Uvx = "$uvxPrefix references from --binary $program --target 0x004b58a0 --limit 100"; Tool = 'get_references'; Args = @{program_path = $program; mode = 'from'; target = '0x004b58a0'; limit = 100 } },
    @{ Name = 'manage-strings'; Uvx = "$uvxPrefix manage-strings --program_path $program --mode regex --query \"Save | Load | Module | GIT | IFO\" --include_referencing_functions true --limit 100"; Tool='manage_strings'; Args=@ { program_path=$program; mode='regex'; query='Save|Load|Module|GIT|IFO'; include_referencing_functions=$true; limit=100 } },
    @{ Name = 'search-constants'; Uvx = "$uvxPrefix search-constants --program_path $program --mode specific --value 32 --max_results 200"; Tool = 'search_constants'; Args = @{program_path = $program; mode = 'specific'; value = 32; max_results = 200 } },
    @{ Name = 'analyze-data-flow'; Uvx = "$uvxPrefix analyze-data-flow --program_path $program --function_address 0x004b95b0 --start_address 0x004b97af --direction forward"; Tool = 'analyze_data_flow'; Args = @{program_path = $program; function_address = '0x004b95b0'; start_address = '0x004b97af'; direction = 'forward' } },
    @{ Name = 'manage-function rename'; Uvx = "$uvxPrefix manage-function --program_path $program --mode rename --function_identifier 0x004b95b0 --new_name LoadModule"; Tool = 'manage_function'; Args = @{program_path = $program; mode = 'rename'; function_identifier = '0x004b95b0'; new_name = 'LoadModule' } },
    @{ Name = 'manage-comments set'; Uvx = "$uvxPrefix manage-comments --program_path $program --mode set --address_or_symbol 0x004b95b0 --comment_type PRE --comment \"LoadModule orchestrates per-resource GFF parsing\""; Tool='manage_comments'; Args=@ { program_path=$program; mode='set'; address_or_symbol='0x004b95b0'; comment_type='PRE'; comment='LoadModule orchestrates per-resource GFF parsing' } },
    @{ Name = 'manage-function-tags add'; Uvx = "$uvxPrefix manage-function-tags --program_path $program --mode add --function 0x004b95b0 --tags save-load --tags serialization"; Tool = 'manage_function_tags'; Args = @{program_path = $program; mode = 'add'; function = '0x004b95b0'; tags = @('save-load', 'serialization') } },
    @{ Name = 'manage-bookmarks set'; Uvx = "$uvxPrefix manage-bookmarks --program_path $program --mode set --address_or_symbol 0x004b95b0 --type TODO --category save-load --comment \"verify full GIT object-list write path\""; Tool='manage_bookmarks'; Args=@ { program_path=$program; mode='set'; address_or_symbol='0x004b95b0'; type='TODO'; category='save-load'; comment='verify full GIT object-list write path' } },
    @{ Name = 'tool list-imports'; Uvx = "$a='{\"program_path\":\"$program\",\"limit\":5}'; $uvxPrefix tool list-imports $a"; Tool='list_imports'; Args=@ { program_path=$program; limit=5 }; IsScript=$true },
    @{ Name = 'tool list-exports'; Uvx = "$a='{\"program_path\":\"$program\",\"limit\":5}'; $uvxPrefix tool list-exports $a"; Tool='list_exports'; Args=@ { program_path=$program; limit=5 }; IsScript=$true }
)

$results = @()
$idx = 0
foreach ($case in $cases) {
    $idx++
    Write-Host "[$idx/$($cases.Count)] $($case.Name)"

    if ($case.IsScript) {
        $uvxOut = powershell -NoProfile -Command $case.Uvx 2>&1 | Out-String
        $uvxRc = $LASTEXITCODE
    }
    else {
        $uvxOut = Invoke-Expression $case.Uvx 2>&1 | Out-String
        $uvxRc = $LASTEXITCODE
    }

    $reqPath = "tmp\usage_case_$('{0:D2}' -f $idx).json"
    $respPath = "tmp\usage_case_resp_$('{0:D2}' -f $idx).json"
    $payload = @{ jsonrpc = '2.0'; id = (200 + $idx); method = 'tools/call'; params = @{ name = $case.Tool; arguments = $case.Args } }
    New-PayloadFile -Path $reqPath -Object $payload

    curl.exe -s -X POST $baseUrl -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -H "Mcp-Session-Id: $SID" --data "@$reqPath" > $respPath
    $curlRc = $LASTEXITCODE

    $curlJsonOk = $true
    try {
        $resp = Get-Content $respPath -Raw | ConvertFrom-Json -Depth 100
        if ($null -ne $resp.error) { $curlJsonOk = $false }
    }
    catch {
        $curlJsonOk = $false
    }

    $results += [PSCustomObject]@{
        index        = $idx
        name         = $case.Name
        uvx_rc       = $uvxRc
        curl_rc      = $curlRc
        curl_json_ok = $curlJsonOk
    }

    Set-Content -Path ("tmp\usage_uvx_out_{0:D2}.txt" -f $idx) -Value $uvxOut
}

$results | ConvertTo-Json -Depth 10 | Set-Content tmp\usage_validation_results.json
$fail = $results | Where-Object { $_.uvx_rc -ne 0 -or $_.curl_rc -ne 0 -or -not $_.curl_json_ok }
Write-Host "SESSION=$SID"
Write-Host "TOTAL=$($results.Count) FAIL=$($fail.Count)"
if ($fail.Count -gt 0) {
    $fail | Format-Table -AutoSize | Out-Host
}
