$gh = Join-Path $env:GHIDRA_INSTALL_DIR 'Ghidra'
$ext = Join-Path $gh 'Extensions\agentdecompile\lib'
$j = @(Get-ChildItem -Path $gh -Filter *.jar -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
if (Test-Path $ext) {
    $j += @(Get-ChildItem -Path $ext -Filter *.jar -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
}
$cp = [string]::Join(';', $j)
Write-Host "Classpath length: $($cp.Length)"
Write-Host "Launching Java headless launcher..."
& java -cp $cp agentdecompile.headless.AgentDecompileHeadlessLauncher
