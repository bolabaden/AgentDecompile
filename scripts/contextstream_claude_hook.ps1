# ContextStream Claude Code hooks — PowerShell launcher (no bash).
# Resolves the global npm install (avoids stale npx cache paths).
# Uses redirected I/O so hook JSON is captured before Node can hit a Windows libuv teardown quirk after stdout.
#
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File this.ps1 <hook-subcommand>

param(
    [Parameter(Position = 0, Mandatory = $true)]
    [string]$HookName
)

$ErrorActionPreference = 'Stop'

function Resolve-ContextStreamIndexJs {
    if ($env:CONTEXTSTREAM_MCP_INDEX_JS) {
        $p = $env:CONTEXTSTREAM_MCP_INDEX_JS.Trim()
        if ($p -and (Test-Path -LiteralPath $p)) { return $p }
    }
    $candidates = @(
        (Join-Path $env:APPDATA 'npm\node_modules\@contextstream\mcp-server\dist\index.js')
    )
    $npmCmd = Get-Command npm -ErrorAction SilentlyContinue
    if ($npmCmd) {
        $npmDir = Split-Path -Parent $npmCmd.Source
        $candidates += (Join-Path $npmDir 'node_modules\@contextstream\mcp-server\dist\index.js')
    }
    foreach ($p in $candidates) {
        if ($p -and (Test-Path -LiteralPath $p)) { return $p }
    }
    try {
        $npmRoot = (& npm root -g 2>$null | Select-Object -First 1).ToString().Trim()
        if ($npmRoot) {
            $try = Join-Path $npmRoot '@contextstream\mcp-server\dist\index.js'
            if (Test-Path -LiteralPath $try) { return $try }
        }
    }
    catch {
    }
    return $null
}

$indexJs = Resolve-ContextStreamIndexJs
if (-not $indexJs) {
    [Console]::Error.WriteLine(
        'contextstream_claude_hook: @contextstream/mcp-server not found. Install: npm install -g @contextstream/mcp-server'
    )
    exit 0
}

$node = (Get-Command node -ErrorAction SilentlyContinue).Source
if (-not $node) {
    [Console]::Error.WriteLine('contextstream_claude_hook: node not on PATH.')
    exit 0
}

[Console]::InputEncoding = [System.Text.Encoding]::UTF8
$stdinText = [Console]::In.ReadToEnd()

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $node
$psi.Arguments = @(
    "`"$indexJs`"",
    'hook',
    $HookName
) -join ' '
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true

$p = New-Object System.Diagnostics.Process
$p.StartInfo = $psi
[void]$p.Start()
$p.StandardInput.Write($stdinText)
$p.StandardInput.Close()
$stdout = $p.StandardOutput.ReadToEnd()
$stderr = $p.StandardError.ReadToEnd()
$p.WaitForExit()

if ($stderr -and ($stderr -notmatch 'Assertion failed')) {
    [Console]::Error.Write($stderr)
}
[Console]::Out.Write($stdout)

# After emitting hook JSON, ContextStream's Node build can abort on Windows (libuv) with a negative exit code.
# Claude treats non-zero as hook failure — normalize to success when we got JSON on stdout.
$trimOut = $stdout.Trim()
if ($trimOut.StartsWith('{') -and $trimOut.EndsWith('}')) {
    exit 0
}

$code = $p.ExitCode
if ($null -eq $code) { exit 0 }
exit $code
