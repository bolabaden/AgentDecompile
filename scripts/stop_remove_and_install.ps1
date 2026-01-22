# Stops Python processes referencing AgentDecompile, removes existing extension, and runs installer
$ProjectDir = 'D:\AgentDecompile'
$extDir = 'C:\Users\shawn\Downloads\ghidra_12.0_PUBLIC_20251205\ghidra_12.0_PUBLIC\Ghidra\Extensions\agentdecompile'
Write-Host "ProjectDir: $ProjectDir"
Write-Host "Extension dir: $extDir"

Write-Host 'Scanning python processes for references to AgentDecompile...'
$pyprocs = Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'python' }
$matches = $pyprocs | Where-Object { $_.CommandLine -and ($_.CommandLine -match 'agentdecompile' -or $_.CommandLine -match 'AgentDecompile' -or $_.CommandLine -match [regex]::Escape($extDir) -or $_.CommandLine -match 'agentdecompile_cli' -or $_.CommandLine -match 'AgentDecompile.jar') }

if ($matches -and $matches.Count -gt 0) {
    Write-Host 'Matching python processes to stop:'
    $matches | Select-Object ProcessId,CommandLine | Format-Table -AutoSize
    $ids = $matches | ForEach-Object { $_.ProcessId }
    Write-Host "Stopping PIDs: $($ids -join ',')"
    Stop-Process -Id $ids -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
} else {
    Write-Host 'No matching python processes found. Listing all python processes:'
    $pyprocs | Select-Object ProcessId,CommandLine | Format-Table -AutoSize
}

if (Test-Path -LiteralPath $extDir) {
    Write-Host "Removing existing extension directory: $extDir"
    Remove-Item -LiteralPath $extDir -Recurse -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    if (Test-Path -LiteralPath $extDir) {
        Write-Host 'Failed to remove extension directory; it may still be locked.' -ForegroundColor Yellow
    } else {
        Write-Host 'Existing extension directory removed.' -ForegroundColor Green
    }
} else {
    Write-Host 'No existing extension directory found.'
}

Write-Host 'Running build-and-install.ps1...'
Set-Location -LiteralPath $ProjectDir
.\build-and-install.ps1 -ProjectDir $ProjectDir -GhidraInstallDir 'C:\Users\shawn\Downloads\ghidra_12.0_PUBLIC_20251205\ghidra_12.0_PUBLIC' -GradlePath 'C:\Gradle\bin\gradle.bat' -ForceKillLocks
