# Implements .cursor/commands/lfg.md steps 1–14:
# Shared x3 ck → MCP restart → local x3 ck → MCP restart → shared persist → MCP restart → local persist →
# MCP restart → shared 4th ck → MCP restart → pull + verify 4 revisions (same session) → push 5th + verify →
# MCP restart → local Track B L1–L3 still present.
#
# Ghidra: stock ghidraSvr.bat console blocks its host shell ("Use Ctrl-C..."). Auto-start spawns a dedicated
# PowerShell window + patched bat (`start /B` + JVM logs under $Evidence). MCP defaults to a hidden detached
# process (no -NoNewWindow); pass -StartMcpInNewWindow for a visible MCP terminal with Tee-Object logs.
# Requires: Ghidra install (GHIDRA_INSTALL_DIR), repo root .venv or uv.
param(
    [string]$RunId = "lfgcmd$(Get-Date -Format 'HHmmss')",
    [string]$ServerUrl = "http://127.0.0.1:8099",
    [string]$GhidraHost = "127.0.0.1",
    [int]$GhidraPort = 23100,
    [string]$Repo = "agentrepo",
    [string]$GhidraUser = "ghidra",
    # Plain string default for /lfg automation (avoids ConvertTo-SecureString when PS.Security module is unavailable).
    [string]$GhidraPassword = "admin",
    [string]$SharedProgramPath = "/sort_lfgpytest_b4bea676fd4f.exe",
    [string]$ImportSource = "C:/Windows/System32/sort.exe",
    [int]$McpPort = 8099,
    [string]$GhidraHome = "",
    [bool]$AutoStartGhidraServer = $true,
    [bool]$StopStartedGhidraOnExit = $true,
    # Ghidra's ghidraSvr "console" blocks its host shell; never run it with -NoNewWindow in the driver terminal.
    [bool]$StartMcpInNewWindow = $false
)

# Continue: Python writes progress to stderr; Stop would treat that as terminating errors with 2>&1.
$ErrorActionPreference = "Continue"
$RepoRoot = Split-Path $PSScriptRoot -Parent
Set-Location $RepoRoot
if (-not (Test-Path ".\pyproject.toml")) { throw "Run from agentdecompile repo root" }

$GhidraPasswordPlain = $GhidraPassword

$Evidence = Join-Path $RepoRoot ".lfg_run/lfg_cmd_$RunId"
New-Item -ItemType Directory -Force -Path $Evidence | Out-Null
$LocalDir = Join-Path $Evidence "local_gpr_dir"
New-Item -ItemType Directory -Force -Path $LocalDir | Out-Null
$LocalDirJson = ($LocalDir -replace "\\", "/")
$ImportJson = ($ImportSource -replace "\\", "/")
$McpWs = Join-Path $Evidence "mcp_workspace"
New-Item -ItemType Directory -Force -Path $McpWs | Out-Null
$McpWsJson = ($McpWs -replace "\\", "/")

# When attaching to an existing Ghidra Server only: optional env overrides (same vars as MCP shared open).
if (-not $AutoStartGhidraServer) {
    $_lfgUserEnv = $env:AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME
    if ($_lfgUserEnv -and $_lfgUserEnv.Trim()) {
        $GhidraUser = $_lfgUserEnv.Trim()
    }
    $_lfgPassEnv = $env:AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD
    if ($_lfgPassEnv) {
        $GhidraPassword = $_lfgPassEnv
        $GhidraPasswordPlain = $_lfgPassEnv
    }
}

function Get-LfgEphemeralTcpPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return [int]$listener.LocalEndpoint.Port
    } finally {
        try { $listener.Stop() } catch {}
    }
}

function Test-LfgMcpPortBindAvailable {
    param([int]$Port)
    try {
        $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
        try {
            $l.Start()
            return $true
        } finally {
            try { $l.Stop() } catch {}
        }
    } catch {
        return $false
    }
}

# Cursor / another agentdecompile-server often holds 8099; LFG must not fail startup — pick a free port.
# Do not rely on Get-NetTCPConnection (varies by OS permissions); bind-probe matches what the MCP server needs.
if (-not (Test-LfgMcpPortBindAvailable -Port $McpPort)) {
    $ephemeral = Get-LfgEphemeralTcpPort
    Write-Host "MCP port $McpPort is not bindable; LFG using ephemeral port $ephemeral (CLI --server-url updated)." -ForegroundColor Yellow
    $McpPort = $ephemeral
    $ServerUrl = "http://127.0.0.1:$McpPort"
}

# Launcher reads AGENT_DECOMPILE_PORT from the environment; inherited 8099 would override --port if unset.
$env:AGENT_DECOMPILE_PORT = "$McpPort"

$ghidraRoot = if ($GhidraHome -and $GhidraHome.Trim()) { $GhidraHome.Trim() } elseif ($env:GHIDRA_INSTALL_DIR) { $env:GHIDRA_INSTALL_DIR.Trim() } else { "" }
if (-not $ghidraRoot) { throw "Set GHIDRA_INSTALL_DIR or pass -GhidraHome to the Ghidra_*_PUBLIC root" }
$env:GHIDRA_INSTALL_DIR = $ghidraRoot

$py = Join-Path $RepoRoot ".venv/Scripts/python.exe"
if (-not (Test-Path $py)) { $py = "python" }

$script:McpInvocation = 0
$script:LfgStartedGhidra = $false
$script:LfgGhidraPatchedBat = $null
$script:LfgGhidraLauncherPs1 = $null
$script:LfgIsolatedGhidraRepos = $null
# When AutoStartGhidraServer: context to re-launch the same isolated server if the console window exited early.
$script:LfgGhidraRelaunchContext = $null

function Test-LfgTcpOpen {
    param([string]$HostName, [int]$Port, [int]$TimeoutMs = 2500)
    # TcpClient.Connect() can block indefinitely on some hosts; always bound wait time.
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $tcp.BeginConnect($HostName, $Port, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not $ok) {
            return $false
        }
        $tcp.EndConnect($iar)
        return $true
    } catch {
        return $false
    } finally {
        try { $tcp.Close() } catch {}
    }
}

function Find-LfgFreeGhidraBasePort {
    <#
    Picks the first TCP base port in [StartPort .. StartPort+MaxSpan-1] with nothing accepting connections.
    Ghidra uses the base port and typically the next ports for RMI/registry; LFG only probes the base.
    #>
    param(
        [int]$StartPort,
        [int]$MaxSpan = 80
    )
    for ($p = $StartPort; $p -lt ($StartPort + $MaxSpan); $p++) {
        if (-not (Test-LfgTcpOpen $GhidraHost $p)) {
            return $p
        }
    }
    throw "No free Ghidra base port found in range ${StartPort}-$(($StartPort + $MaxSpan - 1))"
}

function New-LfgPatchedGhidraSvrBat {
    <#
    Stock ghidraSvr.bat "console" uses `start "<title>" java ...` which opens a second OS window.
    Copy the bat and replace that line with `start /B "" java ... >> stdout 2>> stderr` so the JVM stays
    backgrounded with logs in the evidence dir (see .cursor/commands/lfg.md).
    #>
    param(
        [string]$SourceGhidraSvrBat,
        [string]$DestPatchBat,
        [string]$OutLog,
        [string]$ErrLog,
        [string]$WrapperConfPath = ""
    )
    $raw = [System.IO.File]::ReadAllText($SourceGhidraSvrBat)
    $pattern = '\s*start\s+"%APP_LONG_NAME%"\s+"%java%"\s+%VMARGS%\s+%DEBUG%\s+-jar\s+"%WRAPPER_HOME%/wrapper\.jar"\s+-c\s+"%WRAPPER_CONF%"'
    $replacement = 'start /B "" "%java%" %VMARGS% %DEBUG% -jar "%WRAPPER_HOME%/wrapper.jar" -c "%WRAPPER_CONF%" >> "' + $OutLog + '" 2>> "' + $ErrLog + '"'
    $raw2 = [System.Text.RegularExpressions.Regex]::Replace($raw, $pattern, $replacement, 1)
    if ($raw2 -eq $raw) {
        throw "Could not patch Ghidra ghidraSvr.bat console line (Ghidra version changed?). Edit lfg_cmd_sequence.ps1 pattern. Source: $SourceGhidraSvrBat"
    }
    if ($WrapperConfPath -and $WrapperConfPath.Trim()) {
        $wc = $WrapperConfPath.Trim()
        $wcBat = $wc -replace '/', '\\'
        $confPat = 'set "WRAPPER_CONF=%SERVER_DIR%\\server\.conf"'
        $confRep = 'set "WRAPPER_CONF=' + $wcBat + '"'
        $raw3 = [System.Text.RegularExpressions.Regex]::Replace($raw2, $confPat, $confRep, 1)
        if ($raw3 -eq $raw2) {
            throw "Could not patch WRAPPER_CONF in ghidraSvr.bat (expected line: set WRAPPER_CONF=%SERVER_DIR%\server.conf). Source: $SourceGhidraSvrBat"
        }
        $raw2 = $raw3
    }
    [System.IO.File]::WriteAllText($DestPatchBat, $raw2, [System.Text.UTF8Encoding]::new($false))
}

function Invoke-LfgGhidraConsoleSeparateTerminal {
    <#
    ghidraSvr.bat console prints "Use Ctrl-C ..." and blocks its host shell. Never attach that to the driver
    terminal (-NoNewWindow). Spawn a dedicated PowerShell window so the driver returns immediately and you
    can watch that window (JVM still uses start /B + evidence-dir logs from the patched bat).
    #>
    param(
        [string]$GhidraRoot,
        [string]$EvidenceDir,
        [int]$ListenPort,
        [string]$WrapperConfPath = ""
    )
    $serverDir = Join-Path $GhidraRoot "server"
    $srcBat = Join-Path $serverDir "ghidraSvr.bat"
    if (-not (Test-Path -LiteralPath $srcBat)) { throw "Missing $srcBat" }
    $outLog = Join-Path $EvidenceDir "ghidra_server.stdout.log"
    $errLog = Join-Path $EvidenceDir "ghidra_server.stderr.log"
    # Patched bat MUST live under server\ so ghidraSvr.bat's %%~dp0 SERVER_DIR resolves to the real install.
    $patched = Join-Path $serverDir "ghidraSvr_lfg_no_extra_window.agentdecompile.bat"
    New-LfgPatchedGhidraSvrBat -SourceGhidraSvrBat $srcBat -DestPatchBat $patched -OutLog $outLog -ErrLog $errLog -WrapperConfPath $WrapperConfPath
    $script:LfgGhidraPatchedBat = $patched
    $launcher = Join-Path $EvidenceDir "launch_ghidra_lfg_console.ps1"
    $script:LfgGhidraLauncherPs1 = $launcher
    @"
# LFG: dedicated Ghidra Server console (do not close until the driver finishes, or use Ctrl+C here).
Write-Host "LFG Ghidra Server — TCP base port $ListenPort — JVM logs: $outLog / $errLog" -ForegroundColor Cyan
Set-Location -LiteralPath '$($serverDir.Replace("'", "''"))'
& '$($patched.Replace("'", "''"))' console
"@ | Set-Content -LiteralPath $launcher -Encoding utf8

    # New window: parent script never blocks on "Use Ctrl-C to terminate".
    Start-Process -FilePath "powershell.exe" -WorkingDirectory $serverDir `
        -ArgumentList @(
        '-NoExit', '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', $launcher
    ) | Out-Null
}

function Invoke-LfgGhidraSvrAdmin {
    <#
    Runs Ghidra ServerAdmin against a specific server.conf (same file the running server uses).
    Typical: -add <sid> creates a user with default password changeme (see Ghidra svrREADME).
    Uses cmd /c call because PowerShell's & *.bat @args does not reliably forward argv to launch.bat.
    #>
    param(
        [string]$GhidraRoot,
        [string]$ServerConfPath,
        [string[]]$AdminArgs
    )
    $launchBat = Join-Path $GhidraRoot "support\launch.bat"
    if (-not (Test-Path -LiteralPath $launchBat)) { throw "Missing $launchBat" }
    $env:GHIDRA_HOME = $GhidraRoot
    $vmargs = '-DUserAdmin.invocation=svrAdmin'
    $tail = if ($AdminArgs -and $AdminArgs.Count -gt 0) { ' ' + ($AdminArgs -join ' ') } else { '' }
    $inner = "call `"$launchBat`" fg jre svrAdmin 128M `"$vmargs`" ghidra.server.ServerAdmin `"$ServerConfPath`"$tail"
    cmd.exe /c $inner
    return $LASTEXITCODE
}

function Stop-LfgGhidra {
    param([int]$Port)
    if (-not $script:LfgStartedGhidra) { return }
    try {
        $conns = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
        foreach ($x in $conns) {
            Stop-Process -Id $x.OwningProcess -Force -ErrorAction SilentlyContinue
        }
    } catch {}
    $script:LfgStartedGhidra = $false
    Start-Sleep -Seconds 2
}

function Ensure-LfgGhidraServerUp {
    <#
    The dedicated Ghidra window can be closed accidentally or the JVM may exit during long local-only phases.
    Before any shared-repo tool-seq, confirm the RMI port is listening; re-launch using the same server.conf/repos if not.
    #>
    param([string]$HostName, [int]$Port)
    if (Test-LfgTcpOpen $HostName $Port) { return }
    $ctx = $script:LfgGhidraRelaunchContext
    if (-not $ctx -or -not $script:LfgStartedGhidra) {
        throw "Ghidra Server not reachable at ${HostName}:${Port} (no LFG relaunch context; start the server or use -AutoStartGhidraServer:`$true)."
    }
    Write-Host "Ghidra not listening on ${HostName}:${Port}; re-launching isolated LFG server (same repos dir)..." -ForegroundColor Yellow
    Invoke-LfgGhidraConsoleSeparateTerminal -GhidraRoot $ctx.GhidraRoot -EvidenceDir $ctx.EvidenceDir -ListenPort $ctx.ListenPort -WrapperConfPath $ctx.WrapperConfPath
    $ghOk = $false
    for ($i = 0; $i -lt 120; $i++) {
        if (Test-LfgTcpOpen $HostName $Port) { $ghOk = $true; break }
        if ($i -gt 0 -and ($i % 15) -eq 0) {
            Write-Host "  still waiting for Ghidra relaunch on ${HostName}:${Port} (attempt $i/120)..." -ForegroundColor DarkYellow
        }
        Start-Sleep -Seconds 2
    }
    if (-not $ghOk) {
        throw "Ghidra relaunch did not listen on ${HostName}:${Port} in time. See ghidra_server.stderr.log under $($ctx.EvidenceDir)"
    }
    Write-Host "Ghidra relaunch ready on ${HostName}:${Port}" -ForegroundColor Green
    Start-Sleep -Seconds 5
}

function Stop-LfgMcp {
    Get-NetTCPConnection -LocalPort $McpPort -ErrorAction SilentlyContinue | ForEach-Object {
        Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
    }
    # Allow TIME_WAIT / JVM teardown so the next bind + PyGhidra init does not race the LFG health probe.
    Start-Sleep -Seconds 5
}

function Start-LfgMcp {
    param([string]$ProjectPath)
    Stop-LfgMcp
    $env:GHIDRA_INSTALL_DIR = $env:GHIDRA_INSTALL_DIR
    if (-not $env:GHIDRA_INSTALL_DIR) {
        throw "Set GHIDRA_INSTALL_DIR to your Ghidra install"
    }
    $script:McpInvocation++
    $n = $script:McpInvocation
    $mcpOut = Join-Path $Evidence "mcp_server_${n}.stdout.log"
    $mcpErr = Join-Path $Evidence "mcp_server_${n}.stderr.log"
    if ($StartMcpInNewWindow) {
        $mcpLauncher = Join-Path $Evidence "launch_mcp_lfg_${n}.ps1"
        @"
Write-Host "LFG MCP #$n — http://127.0.0.1:$McpPort/health — tee log: $($mcpOut.Replace("'", "''"))" -ForegroundColor Cyan
Set-Location -LiteralPath '$($RepoRoot.Replace("'", "''"))'
& '$($py.Replace("'", "''"))' -m agentdecompile_cli.server -t streamable-http --host 127.0.0.1 --port $McpPort --project-path '$($ProjectPath.Replace("'", "''"))' 2>&1 | Tee-Object -FilePath '$($mcpOut.Replace("'", "''"))' -Append
"@ | Set-Content -LiteralPath $mcpLauncher -Encoding utf8
        Start-Process -FilePath "powershell.exe" -WorkingDirectory $RepoRoot `
            -ArgumentList @('-NoExit', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $mcpLauncher) | Out-Null
    } else {
        # Detached from driver TTY: do not use -NoNewWindow (would attach MCP stdio to this console).
        Start-Process -FilePath $py -ArgumentList @(
            "-m", "agentdecompile_cli.server", "-t", "streamable-http",
            "--host", "127.0.0.1", "--port", "$McpPort", "--project-path", $ProjectPath
        ) -WorkingDirectory $RepoRoot `
            -RedirectStandardOutput $mcpOut -RedirectStandardError $mcpErr `
            -WindowStyle Hidden -PassThru | Out-Null
    }
    Write-Host "MCP logs: $mcpOut | $mcpErr" -ForegroundColor DarkGray
    $ok = $false
    for ($i = 0; $i -lt 90; $i++) {
        try {
            $r = Invoke-WebRequest -Uri "http://127.0.0.1:$McpPort/health" -UseBasicParsing -TimeoutSec 3
            if ($r.StatusCode -eq 200) { $ok = $true; break }
        } catch {}
        Start-Sleep -Seconds 1
    }
    if (-not $ok) { throw "MCP health check failed on port $McpPort (see $mcpOut / $mcpErr)" }
    # Uvicorn /health can succeed before streamable-http MCP is fully accepting tool-seq traffic.
    Start-Sleep -Seconds 5
}

function Clear-LfgCliState {
    # CLI uses Path.cwd()/.agentdecompile/cli_state.json (repo-relative), not USERPROFILE.
    $statePath = Join-Path $RepoRoot ".agentdecompile/cli_state.json"
    Remove-Item -LiteralPath $statePath -ErrorAction SilentlyContinue
}

function Invoke-LfgSeq {
    param([string]$Name, [string]$Json)
    $tmp = Join-Path $Evidence "$Name.steps.json"
    [System.IO.File]::WriteAllText($tmp, $Json.Trim(), [System.Text.UTF8Encoding]::new($false))
    $log = Join-Path $Evidence "$Name.stdout.log"
    $attempt = 0
    $maxAttempts = 10
    $ec = 1
    $combined = ""
    while ($attempt -lt $maxAttempts) {
        $attempt++
        # Capture $LASTEXITCODE before any pipeline (Tee-Object clears the real child exit code on some PS versions).
        $out = & $py -m agentdecompile_cli.cli --server-url $ServerUrl -f json tool-seq "@$tmp" 2>&1
        $ec = $LASTEXITCODE
        $combined = $out | Out-String
        if ($ec -eq 0) { break }
        $transient = $combined -match '(?i)connection attempts failed|connection refused|ConnectError|Could not connect|Cannot connect|agentdecompile backend|actively refused|ghidra server not reachable|notconnectedexception|connection to server failed|10061'
        if (-not $transient -or $attempt -ge $maxAttempts) { break }
        Write-Host "tool-seq $Name transient connection failure (attempt $attempt/$maxAttempts); retrying in 3s..." -ForegroundColor Yellow
        # Ghidra JVM/console may exit during long MCP-only phases; re-arm before retry on shared-server steps.
        if ($Name -match '(?i)_shared_|^(05_|07_|08_|09_)') {
            Ensure-LfgGhidraServerUp -HostName $GhidraHost -Port $GhidraPort
        }
        Start-Sleep -Seconds 3
    }
    Set-Content -LiteralPath $log -Value $combined -Encoding utf8
    if ($ec -ne 0) {
        throw "tool-seq $Name failed exit $ec (see $log)"
    }
}

function Invoke-LfgSeqUnchecked {
    param([string]$Name, [string]$Json)
    $tmp = Join-Path $Evidence "$Name.steps.json"
    [System.IO.File]::WriteAllText($tmp, $Json.Trim(), [System.Text.UTF8Encoding]::new($false))
    $log = Join-Path $Evidence "$Name.stdout.log"
    $out = & $py -m agentdecompile_cli.cli --server-url $ServerUrl -f json tool-seq "@$tmp" 2>&1
    $ec = $LASTEXITCODE
    Set-Content -LiteralPath $log -Value ($out | Out-String) -Encoding utf8
    return $ec
}

function Invoke-LfgCreateLabelWithOptionalResolve {
    param(
        [string]$LogBaseName,
        [string]$ProgramPath,
        [string]$Address,
        [string]$LabelName
    )
    $json = @"
[
  {"name":"create-label","arguments":{"programPath":"$ProgramPath","address":"$Address","labelName":"$LabelName"}}
]
"@
    $exitC = Invoke-LfgSeqUnchecked -Name $LogBaseName -Json $json
    if ($exitC -eq 0) { return }
    $logPath = Join-Path $Evidence "$LogBaseName.stdout.log"
    $raw = [System.IO.File]::ReadAllText($logPath)
    if ($raw -notmatch '## Modification conflict') {
        throw "create-label $LabelName failed exit $exitC (see $logPath)"
    }
    $cid = $null
    if ($raw -match '\*\*conflictId:\*\* `([0-9a-f-]{36})`') { $cid = $Matches[1] }
    elseif ($raw -match '"conflictId"\s*:\s*"([0-9a-f-]{36})"') { $cid = $Matches[1] }
    if (-not $cid) {
        throw "create-label ${LabelName}: modification conflict but no conflictId (see $logPath)"
    }
    $resJson = @"
[
  {"name":"resolve-modification-conflict","arguments":{"conflictId":"$cid","resolution":"overwrite"}}
]
"@
    Invoke-LfgSeq -Name "${LogBaseName}_resolve" -Json $resJson
}

function Invoke-LfgPushFifthVerifySequence {
    param(
        [string]$SharedPath,
        [string]$RunIdPart,
        [string]$AddrPushPart
    )
    Ensure-LfgGhidraServerUp -HostName $GhidraHost -Port $GhidraPort
    # Checkout alone: establishes exclusive server checkout before mutations.
    Invoke-LfgSeq "09_push_checkout" "[{`"name`":`"checkout-program`",`"arguments`":{`"programPath`":`"$SharedPath`",`"exclusive`":true}}]"
    # Label + checkin in one tool-seq (same MCP round-trip) avoids post-pull "not modified since checkout".
    $pushLabelCheckin = @"
[
  {"name":"create-label","arguments":{"programPath":"$SharedPath","address":"$AddrPushPart","labelName":"loc_${RunIdPart}_PUSH"}},
  {"name":"checkin-program","arguments":{"programPath":"$SharedPath","comment":"sh_${RunIdPart}_after_pull_local_edit"}}
]
"@
    $ec = Invoke-LfgSeqUnchecked -Name "09_push_label_checkin" -Json $pushLabelCheckin
    if ($ec -eq 0) {
        Invoke-LfgSeq "09_push_checkout_after_checkin" "[{`"name`":`"checkout-program`",`"arguments`":{`"programPath`":`"$SharedPath`",`"exclusive`":true}}]"
        $pushSyncVerify = @"
[
  {"name":"sync-project","arguments":{"mode":"push","path":"/","recursive":true,"dryRun":false}},
  {"name":"checkout-status","arguments":{"programPath":"$SharedPath","responseFormat":"json"}},
  {"name":"search-symbols","arguments":{"programPath":"$SharedPath","query":"loc_${RunIdPart}_PUSH"}}
]
"@
        Invoke-LfgSeq "09_push_sync_verify" $pushSyncVerify
        return
    }
    $logPath = Join-Path $Evidence "09_push_label_checkin.stdout.log"
    $raw = [System.IO.File]::ReadAllText($logPath)
    if ($raw -match '(?i)## Modification conflict') {
        $cid = $null
        if ($raw -match '\*\*conflictId:\*\* `([0-9a-f-]{36})`') { $cid = $Matches[1] }
        elseif ($raw -match '"conflictId"\s*:\s*"([0-9a-f-]{36})"') { $cid = $Matches[1] }
        if (-not $cid) {
            throw "09_push_label_checkin: modification conflict but no conflictId (see $logPath)"
        }
        Invoke-LfgSeq -Name "09_push_resolve" -Json @"
[
  {"name":"resolve-modification-conflict","arguments":{"conflictId":"$cid","resolution":"overwrite"}}
]
"@
        Invoke-LfgSeq -Name "09_push_retry_checkin" "[{`"name`":`"checkin-program`",`"arguments`":{`"programPath`":`"$SharedPath`",`"comment`":`"sh_${RunIdPart}_after_pull_local_edit`"}}]"
        Invoke-LfgSeq "09_push_checkout_after_resolve" "[{`"name`":`"checkout-program`",`"arguments`":{`"programPath`":`"$SharedPath`",`"exclusive`":true}}]"
        $pushAfterResolve = @"
[
  {"name":"sync-project","arguments":{"mode":"push","path":"/","recursive":true,"dryRun":false}},
  {"name":"checkout-status","arguments":{"programPath":"$SharedPath","responseFormat":"json"}},
  {"name":"search-symbols","arguments":{"programPath":"$SharedPath","query":"loc_${RunIdPart}_PUSH"}}
]
"@
        Invoke-LfgSeq -Name "09_push_retry_sync_verify" -Json $pushAfterResolve
        return
    }
    throw "09_push_label_checkin failed exit $ec (see $logPath)"
}

Write-Host "=== LFG CMD SEQUENCE RunId=$RunId Evidence=$Evidence (.cursor/commands/lfg.md) ===" -ForegroundColor Cyan

if (-not $AutoStartGhidraServer) {
    if (-not (Test-LfgTcpOpen $GhidraHost $GhidraPort)) {
        throw "Ghidra Server not reachable at ${GhidraHost}:${GhidraPort}. Start it manually or pass -AutoStartGhidraServer:`$true."
    }
    Write-Host "Using existing Ghidra Server at ${GhidraHost}:${GhidraPort} (AutoStart off)." -ForegroundColor DarkGreen
} else {
    $lfgListen = Find-LfgFreeGhidraBasePort -StartPort $GhidraPort
    if ($lfgListen -ne $GhidraPort) {
        Write-Host "LFG selected Ghidra base TCP port $lfgListen (requested $GhidraPort is already in use)." -ForegroundColor Yellow
    }
    $GhidraPort = $lfgListen
    $reposRoot = Join-Path $Evidence "ghidra_server_repositories"
    New-Item -ItemType Directory -Force -Path $reposRoot | Out-Null
    $script:LfgIsolatedGhidraRepos = $reposRoot
    $reposForward = ($reposRoot -replace '\\', '/')
    $srcConf = Join-Path $ghidraRoot "server\server.conf"
    $dstConf = Join-Path $Evidence "lfg_ghidra_server.conf"
    $dstConfFull = [System.IO.Path]::GetFullPath($dstConf)
    if (-not (Test-Path -LiteralPath $srcConf)) { throw "Missing Ghidra server.conf: $srcConf" }
    $confText = [System.IO.File]::ReadAllText($srcConf)
    $confText = [regex]::Replace($confText, '(?m)^wrapper\.app\.parameter\.3=-p\d+', "wrapper.app.parameter.3=-p$GhidraPort")
    $confText = [regex]::Replace($confText, '(?m)^ghidra\.repositories\.dir=.*', "ghidra.repositories.dir=$reposForward")
    [System.IO.File]::WriteAllText($dstConfFull, $confText, [System.Text.UTF8Encoding]::new($false))

    Write-Host "Starting dedicated LFG Ghidra Server (isolated repos, base port $GhidraPort). Logs:" -ForegroundColor Yellow
    Write-Host "  $Evidence\ghidra_server.stdout.log" -ForegroundColor DarkGray
    Write-Host "  $Evidence\ghidra_server.stderr.log" -ForegroundColor DarkGray
    $env:GHIDRA_HOME = $ghidraRoot
    Write-Host "  Ghidra may open a console window; JVM logs are tee'd as above." -ForegroundColor DarkGray
    Invoke-LfgGhidraConsoleSeparateTerminal -GhidraRoot $ghidraRoot -EvidenceDir $Evidence -ListenPort $GhidraPort -WrapperConfPath $dstConfFull
    $script:LfgStartedGhidra = $true
    $script:LfgGhidraRelaunchContext = @{
        GhidraRoot      = $ghidraRoot
        EvidenceDir     = $Evidence
        ListenPort      = $GhidraPort
        WrapperConfPath = $dstConfFull
    }
    $ghOk = $false
    for ($i = 0; $i -lt 120; $i++) {
        if (Test-LfgTcpOpen $GhidraHost $GhidraPort) { $ghOk = $true; break }
        if ($i -gt 0 -and ($i % 15) -eq 0) {
            Write-Host "  still waiting for Ghidra on ${GhidraHost}:${GhidraPort} (attempt $i/120)..." -ForegroundColor DarkYellow
        }
        Start-Sleep -Seconds 2
    }
    if (-not $ghOk) {
        throw "Ghidra did not listen on ${GhidraHost}:${GhidraPort} in time. See ghidra_server.stderr.log under $Evidence"
    }
    Write-Host "Ghidra ready on ${GhidraHost}:${GhidraPort}" -ForegroundColor Green
    Start-Sleep -Seconds 5
    $ecAd = Invoke-LfgGhidraSvrAdmin -GhidraRoot $ghidraRoot -ServerConfPath $dstConfFull -AdminArgs @('-add', $GhidraUser)
    if (($null -ne $ecAd) -and ($ecAd -ne 0)) {
        Write-Host "svrAdmin -add $GhidraUser exit $ecAd (OK if user already exists)." -ForegroundColor DarkYellow
    }
    $GhidraPassword = 'changeme'
    $GhidraPasswordPlain = 'changeme'
    Write-Host "LFG dedicated Ghidra credentials: $GhidraUser / changeme (Ghidra default for svrAdmin -add)." -ForegroundColor DarkCyan
}

$openShared = @"
[
  {"name":"open","arguments":{"shared":true,"path":"$Repo","serverHost":"$GhidraHost","serverPort":$GhidraPort,"serverUsername":"$GhidraUser","serverPassword":"$GhidraPasswordPlain"}}
]
"@

# Off-alignment VAs ~2KiB apart deep in .text so create-label avoids function entries, CRT/IAT, and PE helpers on sort.exe.
# RunId-scoped slide reduces collisions when re-running /lfg against the same shared EXE.
$addrKey = [Text.Encoding]::UTF8.GetBytes("${RunId}|lfg-addr-v6")
$sha = [System.Security.Cryptography.SHA256]::Create()
try {
    $addrHash = $sha.ComputeHash($addrKey)
} finally {
    $sha.Dispose()
}
$slide = [int]([BitConverter]::ToUInt32($addrHash, 0) % 2048)
$base = [int64]0x140002000 + [int64]$slide
$addr1 = "0x{0:X}" -f ($base + 0x80)
$addr2 = "0x{0:X}" -f ($base + 0x880)
$addr3 = "0x{0:X}" -f ($base + 0x1080)
$addr4 = "0x{0:X}" -f ($base + 0x1880)
$addrPush = "0x{0:X}" -f ($base + 0x2080)

$assertShared = @"
[
  {"name":"open","arguments":{"shared":true,"path":"$Repo","serverHost":"$GhidraHost","serverPort":$GhidraPort,"serverUsername":"$GhidraUser","serverPassword":"$GhidraPasswordPlain"}},
  {"name":"checkout-program","arguments":{"programPath":"$SharedProgramPath","exclusive":true}},
  {"name":"search-symbols","arguments":{"programPath":"$SharedProgramPath","query":"sh_${RunId}_"}}
]
"@

$openLocalImport = @"
[
  {"name":"open","arguments":{"path":"$LocalDirJson"}},
  {"name":"import-binary","arguments":{"filePath":"$ImportJson","programPath":"/sort.exe","enableVersionControl":false,"analyzeAfterImport":false}}
]
"@

$assertLocal = @"
[
  {"name":"open","arguments":{"path":"$LocalDirJson"}},
  {"name":"search-symbols","arguments":{"programPath":"/sort.exe","query":"loc_${RunId}_"}}
]
"@

# Step 11: pull shared → local mirror; prove L1–L4 and checkout-status shows 4 server revisions for this EXE.
$pullVerifyFour = @"
[
  {"name":"open","arguments":{"shared":true,"path":"$Repo","serverHost":"$GhidraHost","serverPort":$GhidraPort,"serverUsername":"$GhidraUser","serverPassword":"$GhidraPasswordPlain"}},
  {"name":"checkin-program","arguments":{"programPath":"$SharedProgramPath","comment":"lfg_release_checkout_before_pull"}},
  {"name":"sync-project","arguments":{"mode":"pull","path":"$SharedProgramPath","recursive":true,"force":true,"dryRun":false}},
  {"name":"checkout-program","arguments":{"programPath":"$SharedProgramPath","exclusive":true}},
  {"name":"search-symbols","arguments":{"programPath":"$SharedProgramPath","query":"sh_${RunId}_"}},
  {"name":"checkout-status","arguments":{"programPath":"$SharedProgramPath","responseFormat":"json"}}
]
"@

# Step 12: same MCP session as 11 (reuse cli_state.json — do not Clear-LfgCliState between these two).
# Push/fifth revision: Invoke-LfgPushFifthVerifySequence (handles create-label modification conflicts via resolve overwrite).

$assertLocalAgain = @"
[
  {"name":"open","arguments":{"path":"$LocalDirJson"}},
  {"name":"search-symbols","arguments":{"programPath":"/sort.exe","query":"loc_${RunId}_"}}
]
"@

try {

# Steps 1–2: shared three check-ins
Start-LfgMcp -ProjectPath $McpWsJson
Clear-LfgCliState
Ensure-LfgGhidraServerUp -HostName $GhidraHost -Port $GhidraPort
Invoke-LfgSeq "01_shared_open" $openShared
if ($script:LfgIsolatedGhidraRepos) {
    $importSharedFixture = @"
[
  {"name":"import-binary","arguments":{"filePath":"$ImportJson","programPath":"$SharedProgramPath","enableVersionControl":true,"analyzeAfterImport":false}}
]
"@
    Invoke-LfgSeq "01b_shared_import_fixture" $importSharedFixture
}
Invoke-LfgSeq "02_shared_ck1_checkout" "[{`"name`":`"checkout-program`",`"arguments`":{`"programPath`":`"$SharedProgramPath`",`"exclusive`":true}}]"
Invoke-LfgCreateLabelWithOptionalResolve "02_shared_ck1_label" $SharedProgramPath $addr1 "sh_${RunId}_L1"
Invoke-LfgSeq "02_shared_ck1_checkin" "[{`"name`":`"checkin-program`",`"arguments`":{`"programPath`":`"$SharedProgramPath`",`"comment`":`"sh_${RunId}_ck_1`"}}]"
Invoke-LfgSeq "02_shared_ck2_checkout" "[{`"name`":`"checkout-program`",`"arguments`":{`"programPath`":`"$SharedProgramPath`",`"exclusive`":true}}]"
Invoke-LfgCreateLabelWithOptionalResolve "02_shared_ck2_label" $SharedProgramPath $addr2 "sh_${RunId}_L2"
Invoke-LfgSeq "02_shared_ck2_checkin" "[{`"name`":`"checkin-program`",`"arguments`":{`"programPath`":`"$SharedProgramPath`",`"comment`":`"sh_${RunId}_ck_2`"}}]"
Invoke-LfgSeq "02_shared_ck3_checkout" "[{`"name`":`"checkout-program`",`"arguments`":{`"programPath`":`"$SharedProgramPath`",`"exclusive`":true}}]"
Invoke-LfgCreateLabelWithOptionalResolve "02_shared_ck3_label" $SharedProgramPath $addr3 "sh_${RunId}_L3"
Invoke-LfgSeq "02_shared_ck3_checkin" "[{`"name`":`"checkin-program`",`"arguments`":{`"programPath`":`"$SharedProgramPath`",`"comment`":`"sh_${RunId}_ck_3`"}}]"

# Steps 3–4: local three check-ins
Start-LfgMcp -ProjectPath $McpWsJson
Clear-LfgCliState
Invoke-LfgSeq "03_local_open_import" $openLocalImport
Invoke-LfgSeq "04_local_ck1_checkout" "[{`"name`":`"checkout-program`",`"arguments`":{`"programPath`":`"/sort.exe`",`"exclusive`":false}}]"
Invoke-LfgCreateLabelWithOptionalResolve "04_local_ck1_label" "/sort.exe" $addr1 "loc_${RunId}_L1"
Invoke-LfgSeq "04_local_ck1_checkin" "[{`"name`":`"checkin-program`",`"arguments`":{`"programPath`":`"/sort.exe`",`"comment`":`"loc_${RunId}_ck_1`"}}]"
Invoke-LfgSeq "04_local_ck2_checkout" "[{`"name`":`"checkout-program`",`"arguments`":{`"programPath`":`"/sort.exe`",`"exclusive`":false}}]"
Invoke-LfgCreateLabelWithOptionalResolve "04_local_ck2_label" "/sort.exe" $addr2 "loc_${RunId}_L2"
Invoke-LfgSeq "04_local_ck2_checkin" "[{`"name`":`"checkin-program`",`"arguments`":{`"programPath`":`"/sort.exe`",`"comment`":`"loc_${RunId}_ck_2`"}}]"
Invoke-LfgSeq "04_local_ck3_checkout" "[{`"name`":`"checkout-program`",`"arguments`":{`"programPath`":`"/sort.exe`",`"exclusive`":false}}]"
Invoke-LfgCreateLabelWithOptionalResolve "04_local_ck3_label" "/sort.exe" $addr3 "loc_${RunId}_L3"
Invoke-LfgSeq "04_local_ck3_checkin" "[{`"name`":`"checkin-program`",`"arguments`":{`"programPath`":`"/sort.exe`",`"comment`":`"loc_${RunId}_ck_3`"}}]"

# Steps 5–6: shared persistence after MCP restart
Start-LfgMcp -ProjectPath $McpWsJson
Clear-LfgCliState
# Local-only steps 3–4 do not touch the Ghidra server; the dedicated console/JVM may have exited — re-arm before shared open.
Ensure-LfgGhidraServerUp -HostName $GhidraHost -Port $GhidraPort
Invoke-LfgSeq "05_assert_shared_after_mcp" $assertShared

# Steps 7–8: local persistence after MCP restart
Start-LfgMcp -ProjectPath $McpWsJson
Clear-LfgCliState
Invoke-LfgSeq "06_assert_local_after_mcp" $assertLocal

# Steps 9–10: fourth shared check-in
Start-LfgMcp -ProjectPath $McpWsJson
Clear-LfgCliState
Ensure-LfgGhidraServerUp -HostName $GhidraHost -Port $GhidraPort
Invoke-LfgSeq "07_shared_open_checkout" @"
[
  {"name":"open","arguments":{"shared":true,"path":"$Repo","serverHost":"$GhidraHost","serverPort":$GhidraPort,"serverUsername":"$GhidraUser","serverPassword":"$GhidraPasswordPlain"}},
  {"name":"checkout-program","arguments":{"programPath":"$SharedProgramPath","exclusive":true}}
]
"@
Invoke-LfgCreateLabelWithOptionalResolve "07_shared_L4_label" $SharedProgramPath $addr4 "sh_${RunId}_L4"
Invoke-LfgSeq "07_shared_checkin_status" @"
[
  {"name":"checkin-program","arguments":{"programPath":"$SharedProgramPath","comment":"sh_${RunId}_ck_4"}},
  {"name":"checkout-status","arguments":{"programPath":"$SharedProgramPath","responseFormat":"json"}}
]
"@

# Steps 11–12: pull + verify 4 revisions, then fifth check-in + push (same session; no Clear between 08 and 09)
Start-LfgMcp -ProjectPath $McpWsJson
Clear-LfgCliState
Ensure-LfgGhidraServerUp -HostName $GhidraHost -Port $GhidraPort
Invoke-LfgSeq "08_pull_verify_four_ck" $pullVerifyFour
# sync-project pull replaces versioned files on disk; continuing in the same PyGhidra JVM can leave
# checkout/check-in metadata inconsistent (checkin-program: "not modified since checkout" after real edits).
# Re-start MCP and re-open the shared project so step 09 uses a fresh Ghidra session.
Start-LfgMcp -ProjectPath $McpWsJson
Clear-LfgCliState
Ensure-LfgGhidraServerUp -HostName $GhidraHost -Port $GhidraPort
Invoke-LfgSeq "09_open_shared_after_pull" $openShared
Invoke-LfgPushFifthVerifySequence -SharedPath $SharedProgramPath -RunIdPart $RunId -AddrPushPart $addrPush

# Steps 13–14: local .gpr Track B still has L1–L3
Start-LfgMcp -ProjectPath $McpWsJson
Clear-LfgCliState
Invoke-LfgSeq "10_assert_local_persistence" $assertLocalAgain

Write-Host "=== DONE. Evidence under $Evidence ===" -ForegroundColor Green

} finally {
    if ($script:LfgGhidraPatchedBat -and (Test-Path -LiteralPath $script:LfgGhidraPatchedBat)) {
        Remove-Item -LiteralPath $script:LfgGhidraPatchedBat -Force -ErrorAction SilentlyContinue
    }
    $script:LfgGhidraPatchedBat = $null
    Stop-LfgMcp
    if ($StopStartedGhidraOnExit -and $script:LfgStartedGhidra) {
        Write-Host "Stopping Ghidra Server started by this script (port $GhidraPort)..." -ForegroundColor DarkYellow
        Stop-LfgGhidra -Port $GhidraPort
    }
}
