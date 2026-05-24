# E2E runner for .cursor/plans/shared_local_checkout_sync_e2e_7c2a9f01.plan.md
# Prerequisites: Ghidra Server (e.g. ghidraSvr.bat), agentdecompile-server on $ServerUrl, GHIDRA_INSTALL_DIR
# Usage:
#   Shared + sync in ONE session (recommended):  -Phase shared_plus_sync
#   Shared only:  -Phase shared | -Phase all       then restart MCP, then -Phase restart_assert
#   Local:        -Phase local_full -LocalProjectDir C:\temp\e2e_local_gpr
#   Sync alone:   -Phase sync  ONLY works in the same CLI/MCP session as open+import (or use shared_plus_sync).
#   Function names: run list-functions with your binary; pass -FunCycle1/-FunCycle3/-LabelAddress if defaults fail.
#   -ContinueOnError: pass --continue-on-error to tool-seq (run all steps; CLI still exits non-zero if any step failed).
param(
    [ValidateSet("shared", "shared_plus_sync", "local", "local_full", "restart_assert", "restart_local_assert", "sync", "all", "all_local")]
    [string]$Phase = "all",
    [string]$ServerUrl = "http://127.0.0.1:8080",
    [string]$Repo = "agentrepo",
    [string]$GhidraHost = "127.0.0.1",
    [int]$GhidraPort = 13100,
    [string]$GhidraUser = "ghidra",
    [string]$GhidraPassword = "admin",
    [string]$ProgramPath = "/sort.exe",
    [string]$ImportSource = "C:\WINDOWS\system32\sort.exe",
    [string]$LocalProjectDir = "",
    # Windows system32\sort.exe (x64): FUN_140001010 exists; FUN_140001030 often does not — use 140001140 for cycle 3.
    [string]$FunCycle1 = "FUN_140001010",
    [string]$LabelAddress = "140001020",
    [string]$FunCycle3 = "FUN_140001140",
    [switch]$AnalyzeAfterImport,
    [switch]$ContinueOnError
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path $PSScriptRoot -Parent
Set-Location $RepoRoot
if (-not (Test-Path ".\pyproject.toml")) { throw "Run from agentdecompile repo root (pyproject.toml missing)" }

$analyzeFlag = if ($AnalyzeAfterImport) { "true" } else { "false" }
# JSON cannot contain unescaped Windows backslashes (breaks ConvertFrom-Json merge for shared_plus_sync)
$ImportSourceJson = ($ImportSource -replace "\\", "/")
# open(path) for local .gpr must use forward slashes in JSON on Windows
$LocalProjectDirJson = if ($LocalProjectDir) { ($LocalProjectDir -replace "\\", "/") } else { "" }


function Invoke-ToolSeq([string]$Json) {
    $tmp = [System.IO.Path]::GetTempFileName() + ".json"
    $extra = @()
    if ($ContinueOnError) { $extra = @("--continue-on-error") }
    try {
        [System.IO.File]::WriteAllText($tmp, $Json, [System.Text.UTF8Encoding]::new($false))
        $py = Join-Path $RepoRoot ".venv\Scripts\python.exe"
        if (Test-Path $py) {
            & $py -m agentdecompile_cli.cli --server-url $ServerUrl tool-seq "@$tmp" @extra
        } else {
            & uv run python -m agentdecompile_cli.cli --server-url $ServerUrl tool-seq "@$tmp" @extra
        }
        if ($LASTEXITCODE -ne 0) {
            throw "tool-seq failed (exit $LASTEXITCODE). Check Ghidra Server, agentdecompile-server, --server-url, and tool output above."
        }
    } finally {
        Remove-Item -Force -ErrorAction SilentlyContinue $tmp
    }
}

$openShared = @"
[
  {"name":"open","arguments":{"shared":true,"path":"$Repo","serverHost":"$GhidraHost","serverPort":$GhidraPort,"serverUsername":"$GhidraUser","serverPassword":"$GhidraPassword"}},
  {"name":"list-project-files","arguments":{}},
  {"name":"import-binary","arguments":{"filePath":"$ImportSourceJson","programPath":"sort.exe","enableVersionControl":true,"analyzeAfterImport":$analyzeFlag}},
  {"name":"list-project-files","arguments":{}}
]
"@

$threeCycles = @"
[
  {"name":"checkout-program","arguments":{"programPath":"$ProgramPath","exclusive":true}},
  {"name":"manage-function","arguments":{"mode":"rename","programPath":"$ProgramPath","functionIdentifier":"$FunCycle1","newName":"e2e_cycle1_fn"}},
  {"name":"checkin-program","arguments":{"programPath":"$ProgramPath","comment":"e2e-cycle-1"}},
  {"name":"checkout-program","arguments":{"programPath":"$ProgramPath","exclusive":true}},
  {"name":"create-label","arguments":{"programPath":"$ProgramPath","address":"$LabelAddress","labelName":"e2e_cycle2_lbl"}},
  {"name":"checkin-program","arguments":{"programPath":"$ProgramPath","comment":"e2e-cycle-2"}},
  {"name":"checkout-program","arguments":{"programPath":"$ProgramPath","exclusive":true}},
  {"name":"manage-function","arguments":{"mode":"rename","programPath":"$ProgramPath","functionIdentifier":"$FunCycle3","newName":"e2e_cycle3_fn"}},
  {"name":"checkin-program","arguments":{"programPath":"$ProgramPath","comment":"e2e-cycle-3"}},
  {"name":"list-project-files","arguments":{}}
]
"@

# Local .gpr: non-versioned save path; avoid exclusive checkout (not shared repo locks)
$openLocal = @"
[
  {"name":"open","arguments":{"path":"$LocalProjectDirJson"}},
  {"name":"list-project-files","arguments":{}},
  {"name":"import-binary","arguments":{"filePath":"$ImportSourceJson","programPath":"sort.exe","enableVersionControl":false,"analyzeAfterImport":$analyzeFlag}},
  {"name":"list-project-files","arguments":{}}
]
"@

$localThreeCycles = @"
[
  {"name":"checkout-program","arguments":{"programPath":"$ProgramPath","exclusive":false}},
  {"name":"manage-function","arguments":{"mode":"rename","programPath":"$ProgramPath","functionIdentifier":"$FunCycle1","newName":"e2e_local_cycle1_fn"}},
  {"name":"checkin-program","arguments":{"programPath":"$ProgramPath","comment":"e2e-local-cycle-1"}},
  {"name":"checkout-program","arguments":{"programPath":"$ProgramPath","exclusive":false}},
  {"name":"create-label","arguments":{"programPath":"$ProgramPath","address":"$LabelAddress","labelName":"e2e_local_cycle2_lbl"}},
  {"name":"checkin-program","arguments":{"programPath":"$ProgramPath","comment":"e2e-local-cycle-2"}},
  {"name":"checkout-program","arguments":{"programPath":"$ProgramPath","exclusive":false}},
  {"name":"manage-function","arguments":{"mode":"rename","programPath":"$ProgramPath","functionIdentifier":"$FunCycle3","newName":"e2e_local_cycle3_fn"}},
  {"name":"checkin-program","arguments":{"programPath":"$ProgramPath","comment":"e2e-local-cycle-3"}},
  {"name":"list-project-files","arguments":{}}
]
"@

$restartLocalAssert = @"
[
  {"name":"open","arguments":{"path":"$LocalProjectDirJson"}},
  {"name":"list-project-files","arguments":{}},
  {"name":"get-function","arguments":{"programPath":"$ProgramPath","functionIdentifier":"e2e_local_cycle1_fn"}},
  {"name":"search-symbols","arguments":{"programPath":"$ProgramPath","query":"e2e_local"}}
]
"@

$syncPullPush = @"
[
  {"name":"sync-project","arguments":{"mode":"pull","dryRun":true}},
  {"name":"sync-project","arguments":{"mode":"pull","dryRun":false}},
  {"name":"sync-project","arguments":{"mode":"push","dryRun":true}},
  {"name":"sync-project","arguments":{"mode":"push","dryRun":false}}
]
"@

$restartAssert = @"
[
  {"name":"open","arguments":{"shared":true,"path":"$Repo","serverHost":"$GhidraHost","serverPort":$GhidraPort,"serverUsername":"$GhidraUser","serverPassword":"$GhidraPassword"}},
  {"name":"list-project-files","arguments":{}},
  {"name":"checkout-program","arguments":{"programPath":"$ProgramPath","exclusive":true}},
  {"name":"get-function","arguments":{"programPath":"$ProgramPath","functionIdentifier":"e2e_cycle1_fn"}},
  {"name":"search-symbols","arguments":{"programPath":"$ProgramPath","query":"e2e_cycle"}}
]
"@

switch ($Phase) {
    "shared" {
        Write-Host "=== Phase A: shared import + 3 cycles (single MCP session) ===" -ForegroundColor Cyan
        $openArr = $openShared | ConvertFrom-Json
        $cycleArr = $threeCycles | ConvertFrom-Json
        Invoke-ToolSeq (@($openArr) + @($cycleArr) | ConvertTo-Json -Depth 20 -Compress)
    }
    "shared_plus_sync" {
        Write-Host "=== Shared: open + import + 3 checkout/edit/checkin cycles + sync pull/push (single MCP session) ===" -ForegroundColor Cyan
        $openArr = $openShared | ConvertFrom-Json
        $cycleArr = $threeCycles | ConvertFrom-Json
        $syncArr = $syncPullPush | ConvertFrom-Json
        $merged = @($openArr) + @($cycleArr) + @($syncArr)
        $mergedJson = $merged | ConvertTo-Json -Depth 20 -Compress
        Invoke-ToolSeq $mergedJson
        Write-Host "Next: restart agentdecompile-server, then: -Phase restart_assert" -ForegroundColor Yellow
    }
    "sync" {
        Write-Host "=== Phase D: sync pull/push ===" -ForegroundColor Cyan
        Invoke-ToolSeq $syncPullPush
    }
    "restart_assert" {
        Write-Host "=== After MCP restart: reopen + assert ===" -ForegroundColor Cyan
        Invoke-ToolSeq $restartAssert
    }
    "local" {
        if (-not $LocalProjectDir) {
            Write-Error "Set -LocalProjectDir to a directory for a local Ghidra project (a .gpr will be created under it if missing)."
        }
        Write-Host "=== Phase C (light): open local + list files only ===" -ForegroundColor Cyan
        $localOpenOnly = @"
[
  {"name":"open","arguments":{"path":"$LocalProjectDirJson"}},
  {"name":"list-project-files","arguments":{}}
]
"@
        Invoke-ToolSeq $localOpenOnly
    }
    "local_full" {
        if (-not $LocalProjectDir) {
            Write-Error "Set -LocalProjectDir for local_full (directory for .gpr project)."
        }
        Write-Host "=== Phase C: local open + import + 3 edit/save cycles (single MCP session) ===" -ForegroundColor Cyan
        $openArr = $openLocal | ConvertFrom-Json
        $cycleArr = $localThreeCycles | ConvertFrom-Json
        $mergedLocal = @($openArr) + @($cycleArr)
        $mergedLocalJson = $mergedLocal | ConvertTo-Json -Depth 20 -Compress
        Invoke-ToolSeq $mergedLocalJson
        Write-Host "Next: restart agentdecompile-server, then: -Phase restart_local_assert -LocalProjectDir <same>" -ForegroundColor Yellow
    }
    "restart_local_assert" {
        if (-not $LocalProjectDir) {
            Write-Error "Set -LocalProjectDir (same path as local_full)."
        }
        Write-Host "=== After MCP restart: local reopen + assert renames/labels ===" -ForegroundColor Cyan
        Invoke-ToolSeq $restartLocalAssert
    }
    "all" {
        Write-Host "=== Full shared path (import + 3 cycles, single MCP session). Run restart_assert after restarting MCP server. ===" -ForegroundColor Cyan
        $openArr = $openShared | ConvertFrom-Json
        $cycleArr = $threeCycles | ConvertFrom-Json
        $mergedShared = @($openArr) + @($cycleArr)
        Invoke-ToolSeq ($mergedShared | ConvertTo-Json -Depth 20 -Compress)
        Write-Host "Next: restart agentdecompile-server, then: -Phase restart_assert" -ForegroundColor Yellow
        Write-Host "sync-project (shared session + project_data): run -Phase sync in the same CLI session without restarting, or repeat open+import then sync." -ForegroundColor Yellow
    }
    "all_local" {
        if (-not $LocalProjectDir) {
            Write-Error "Set -LocalProjectDir for all_local."
        }
        Write-Host "=== Full local path (import + 3 cycles, single MCP session). Run restart_local_assert after MCP restart. ===" -ForegroundColor Cyan
        $openArr = $openLocal | ConvertFrom-Json
        $cycleArr = $localThreeCycles | ConvertFrom-Json
        $mergedLocal = @($openArr) + @($cycleArr)
        Invoke-ToolSeq ($mergedLocal | ConvertTo-Json -Depth 20 -Compress)
        Write-Host "Next: restart agentdecompile-server, then: -Phase restart_local_assert -LocalProjectDir <same>" -ForegroundColor Yellow
    }
}
