param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string[]]$IncludePatterns = @("*"),   # e.g. *.py, *.ps1
    [string[]]$ExcludeDirs = @(),          # e.g. __pycache__, .git
    [string]$OutputFile
)

function Show-Tree {
    param(
        [string]$CurrentPath,
        [string]$Prefix = ""
    )

    $items = Get-ChildItem -LiteralPath $CurrentPath -Force -ErrorAction SilentlyContinue |
    Where-Object {
        # Keep directory unless excluded
        ($_.PSIsContainer -and ($ExcludeDirs -notcontains $_.Name)) -or
        # Keep file if it matches any include pattern
        (-not $_.PSIsContainer -and (
            $IncludePatterns | Where-Object { $_.Name -like $_ }
        ))
    } |
    Sort-Object -Property @{Expression="PSIsContainer";Descending=$true}, Name

    for ($i = 0; $i -lt $items.Count; $i++) {
        $item = $items[$i]
        $isLast = $i -eq ($items.Count - 1)

        $connector = if ($isLast) { "`-- " } else { "|-- " }
        Write-Output "$Prefix$connector$($item.Name)"

        if ($item.PSIsContainer) {
            $newPrefix = if ($isLast) { "$Prefix    " } else { "$Prefix|   " }
            Show-Tree -CurrentPath $item.FullName -Prefix $newPrefix
        }
    }
}

$resolvedPath = (Resolve-Path $Path).Path

if ($OutputFile) {
    Show-Tree -CurrentPath $resolvedPath | Out-File $OutputFile -Encoding ascii
}
else {
    Show-Tree -CurrentPath $resolvedPath
}