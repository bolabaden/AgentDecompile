# Poll an LFG driver started via Start-Process; tail driver.log and optionally wait for completion.
#
# Do not assign to $pid / $PID: in PowerShell $PID is the *current* process id (read-only).
# Capture the child with Start-Process -PassThru and pass -DriverProcessId $proc.Id (or any name except $pid).
param(
    [Parameter(Mandatory)]
    [int]$DriverProcessId,
    [Parameter(Mandatory)]
    [string]$RunId,
    [switch]$Wait,
    [int]$IntervalSeconds = 15,
    [int]$MaxWaitSeconds = 1200
)

$ErrorActionPreference = "Continue"
$repoRoot = Split-Path $PSScriptRoot -Parent
$logPath = Join-Path $repoRoot ".lfg_run\lfg_cmd_$RunId\driver.log"

function Show-Tail {
    if (-not (Test-Path -LiteralPath $logPath)) { return }
    Get-Content -LiteralPath $logPath -Tail 12 -ErrorAction SilentlyContinue
}

if (-not $Wait) {
    Show-Tail
    exit 0
}

$deadline = [datetime]::UtcNow.AddSeconds($MaxWaitSeconds)
while ([datetime]::UtcNow -lt $deadline) {
    Show-Tail
    $raw = if (Test-Path -LiteralPath $logPath) { Get-Content -LiteralPath $logPath -Raw -ErrorAction SilentlyContinue } else { "" }
    if ($raw -match "DONE\. Evidence") {
        Write-Host "=== LFG: completion line found in driver.log ===" -ForegroundColor Green
        exit 0
    }
    $drv = Get-Process -Id $DriverProcessId -ErrorAction SilentlyContinue
    if (-not $drv) {
        if ($raw -match "DONE\. Evidence") {
            exit 0
        }
        Write-Host "Driver process $DriverProcessId exited; driver.log has no DONE line. Check logs under .lfg_run\lfg_cmd_$RunId\" -ForegroundColor Yellow
        exit 1
    }
    Start-Sleep -Seconds $IntervalSeconds
}

Write-Host "Timed out after ${MaxWaitSeconds}s waiting for LFG DONE line." -ForegroundColor Yellow
exit 2
