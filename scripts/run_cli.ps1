# Run AgentDecompile Python CLI (keeps process in foreground)
param(
    [string]$GhidraPath = "",
    [string]$VenvPath = ".\.venv\Scripts\python.exe"
)

if (-not [string]::IsNullOrWhiteSpace($GhidraPath)) {
    Set-Item -Path Env:GHIDRA_INSTALL_DIR -Value $GhidraPath
}

Write-Host "Starting AgentDecompile CLI..."
& $VenvPath -m agentdecompile_cli --verbose
