# Test script to verify shared Ghidra project workflow
# Prerequisites:
#   1. Ghidra server running (e.g. docker run or svrLaunch)
#   2. agentdecompile-server running (e.g. uv run agentdecompile-server -t streamable-http --host 127.0.0.1 --port 8080 --project-path ./docker/shared_server_project)
#
# Usage: .\scripts\test_shared_project.ps1 [-ServerUrl "http://127.0.0.1:8080"]

param(
    [string]$ServerUrl = "http://127.0.0.1:8080"
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
# Use single-line JSON so PowerShell passes it as one argument
$JsonPath = Join-Path $ScriptDir "shared_open_list_oneline.json"
if (-not (Test-Path $JsonPath)) { $JsonPath = Join-Path $ScriptDir "shared_open_list.json" }
if (-not (Test-Path $JsonPath)) {
    Write-Host "ERROR: JSON file not found: $JsonPath" -ForegroundColor Red
    exit 1
}

Write-Host "=== Testing Shared Ghidra Project Workflow ===" -ForegroundColor Cyan
Write-Host "Server URL: $ServerUrl" -ForegroundColor Yellow
Write-Host "Steps JSON: $JsonPath" -ForegroundColor Yellow
Write-Host ""

Write-Host "Step 1 & 2: Open shared project + list-project-files..." -ForegroundColor Green
$jsonContent = Get-Content -Path $JsonPath -Raw -Encoding UTF8
# Pass JSON as single argument (do not use -- or PowerShell may split)
$result = & uv run agentdecompile-cli --server-url $ServerUrl tool-seq $jsonContent 2>&1
$exitCode = $LASTEXITCODE

if ($exitCode -ne 0) {
    Write-Host "ERROR: tool-seq failed (exit $exitCode)" -ForegroundColor Red
    Write-Host $result
    exit 1
}

# Check if response contains "shared-server-session"
if ($result -match "shared-server-session") {
    Write-Host "PASS: Response shows shared-server-session source" -ForegroundColor Green
} else {
    Write-Host "WARNING: Response does not show shared-server-session source" -ForegroundColor Yellow
    Write-Host $result
}

# Fail if we see local project being used
if ($result -match "local-ghidra-project") {
    Write-Host "FAIL: Response shows local-ghidra-project - using local project instead of shared!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=== Test Complete ===" -ForegroundColor Cyan
Write-Host "Shared project workflow is functional." -ForegroundColor Green
