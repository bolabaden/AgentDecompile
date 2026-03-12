<#
.SYNOPSIS
    Download YouTube video as MKV (best quality, no re-encode), captions as VTT, generate transcripts, and optionally extract PNG frames (default 1080p).
    Standalone script: no dependency on this repo. Requires yt-dlp on PATH.

.DESCRIPTION
    Run interactively (default) or with parameters. Supports:
    - Download video (MKV; native resolution/bitrate, no re-encoding for best frame quality)
    - Download captions (VTT)
    - Plain transcript (VTT -> .txt, no timestamps)
    - Timestamped transcript (VTT -> .txt with [HH:MM:SS] every N seconds)
    - Frame extraction (video -> PNG frames at every interval; default native resolution for best readability, or -FrameSize 1080p/720p/4k)
    Frame extraction needs a video source: use -Video to download, or -FrameVideoPath with path to video file (or directory containing it).
    Use -FramesOutDir to choose where frame PNGs are written (default: frames subfolder beside the VTT).

.EXAMPLE
    .\YouTube-Transcript.ps1
    # Interactive mode: prompts for source and actions

.EXAMPLE
    .\YouTube-Transcript.ps1 -Url "https://www.youtube.com/watch?v=..." -OutDir .\out -Video -Subs -SubsLang en -Transcript both -Interval 3
    # Non-interactive: download video, subs, and both transcript types

.EXAMPLE
    .\YouTube-Transcript.ps1 -Vtt "C:\path\to\file.en.vtt" -OutDir .\out -Transcript both -Interval 3
    # Transcript-only from existing VTT file

.EXAMPLE
    .\YouTube-Transcript.ps1 -Url "https://www.youtube.com/watch?v=..." -OutDir .\out -Video -Subs -ExtractFrames -Interval 5
    # Download video/subs and extract PNG frames every 5s at native resolution (default, best readability)

.EXAMPLE
    .\YouTube-Transcript.ps1 -Url "https://www.youtube.com/watch?v=..." -OutDir .\out -Subs -ExtractFrames -Interval 5 -FrameVideoPath "C:\videos\my.mkv" -FramesOutDir "C:\output\frames"
    # Subs + frames from existing video file; frames written to custom folder

.EXAMPLE
    .\YouTube-Transcript.ps1 -Url "https://www.youtube.com/watch?v=..." -OutDir .\out -Video -Subs -ExtractFrames -Interval 5 -FrameSize 720p
    # Video + subs + frames at 720p to save space

.NOTES
    Preferred: run with PowerShell 7 (pwsh.exe) for best performance and logging.
    Example: pwsh -NoProfile -File .\YouTube-Transcript.ps1 -Url "..." -Video -Subs -ExtractFrames -Interval 3
    Auto-installs yt-dlp and ffmpeg from GitHub releases if not on PATH (Windows, Linux, macOS).
    This script is standalone and does not use any code from this repository.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$Url,

    [Parameter()]
    [string]$OutDir = (Get-Location).Path,

    [Parameter()]
    [switch]$Video,

    [Parameter()]
    [switch]$Subs,

    [Parameter()]
    [string]$SubsLang = 'en',

    [Parameter()]
    [ValidateSet('plain', 'timestamped', 'both')]
    [string]$Transcript = '',

    [Parameter()]
    [ValidateRange(1, 3600)]
    [int]$Interval = 3,

    [Parameter()]
    [switch]$ExtractFrames,

    [Parameter(HelpMessage = 'Path to the video file (or directory containing the video) used for frame extraction. Not the folder where frame PNGs are written; use -FramesOutDir for that.')]
    [string]$FrameVideoPath = '',

    [Parameter(HelpMessage = 'Directory where frame PNGs are written. Default: frames subfolder beside the VTT file.')]
    [string]$FramesOutDir = '',

    [Parameter(HelpMessage = 'Output resolution for extracted frames: source (native, best readability), 720p, 1080p, or 4k. Default: source.')]
    [ValidateSet('720p', '1080p', '4k', 'source')]
    [string]$FrameSize = 'source',

    [Parameter(HelpMessage = 'Explicit frame width (overrides -FrameSize when set with -FrameHeight).')]
    [int]$FrameWidth = 0,

    [Parameter(HelpMessage = 'Explicit frame height (overrides -FrameSize when set with -FrameWidth).')]
    [int]$FrameHeight = 0,

    [Parameter(HelpMessage = 'Path to existing VTT file for transcript-only or frame extraction with existing video.')]
    [string]$Vtt = '',

    [Parameter()]
    [switch]$Interactive
)

$ErrorActionPreference = 'Stop'

$Script:RunStart = Get-Date

function Write-Log {
    param(
        [ValidateSet('DEBUG', 'INFO', 'STEP', 'SUCCESS', 'WARN', 'ERROR')]
        [string]$Level,
        [string]$Message
    )
    $ts = (Get-Date).ToString('HH:mm:ss.fff')
    $elapsed = [int]((Get-Date) - $Script:RunStart).TotalSeconds
    $prefix = "[{0} +{1}s] [{2}] " -f $ts, $elapsed, $Level
    $color = 'Gray'
    switch ($Level) {
        'DEBUG' { $color = 'DarkGray' }
        'INFO' { $color = 'Gray' }
        'STEP' { $color = 'Cyan' }
        'SUCCESS' { $color = 'Green' }
        'WARN' { $color = 'Yellow' }
        'ERROR' { $color = 'Red' }
    }
    Write-Host ($prefix + $Message) -ForegroundColor $color
}

function Fail {
    param([string]$Message)
    Write-Log -Level 'ERROR' -Message $Message
    throw $Message
}

# Prefer PowerShell 7; log version at start (PS 5.1 safe: PSEdition may not exist)
$psVer = $PSVersionTable.PSVersion
$edition = if ($PSVersionTable.PSEdition) { $PSVersionTable.PSEdition } else { 'Desktop' }
Write-Log -Level 'INFO' -Message ("PowerShell {0}.{1} ({2})" -f $psVer.Major, $psVer.Minor, $edition)
if ($psVer.Major -lt 7) {
    Write-Log -Level 'WARN' -Message 'For best performance and logging, run with PowerShell 7: pwsh -NoProfile -File .\YouTube-Transcript.ps1 ...'
}

# --- Run yt-dlp --dump-json; capture stdout only so stderr warnings do not break PS 5.1 ---
function Invoke-YtDlpJson {
    param([string]$YtDlp, [string[]]$ArgList)
    Write-Log -Level 'DEBUG' -Message ('Invoke-YtDlpJson: {0} args' -f $ArgList.Count)
    $tempFile = [System.IO.Path]::GetTempFileName()
    try {
        Start-Process -FilePath $YtDlp -ArgumentList $ArgList -RedirectStandardOutput $tempFile -RedirectStandardError ([System.IO.Path]::GetTempFileName()) -Wait -NoNewWindow -PassThru | Out-Null
        if (-not (Test-Path $tempFile)) { Write-Log -Level 'DEBUG' -Message 'Invoke-YtDlpJson: no stdout file'; return $null }
        $stdout = Get-Content -LiteralPath $tempFile -Raw -ErrorAction SilentlyContinue
        if (-not $stdout -or -not $stdout.Trim()) { Write-Log -Level 'DEBUG' -Message 'Invoke-YtDlpJson: empty stdout'; return $null }
        $stdout.Trim() | ConvertFrom-Json
    } finally {
        if (Test-Path $tempFile) { Remove-Item $tempFile -Force -ErrorAction SilentlyContinue }
    }
}

# --- Detect Windows (PowerShell 5 and Core) ---
$IsWindowsOs = if ($null -ne $IsWindows) { $IsWindows } else { $env:OS -eq 'Windows_NT' }

# --- Dir for auto-installed yt-dlp (cross-platform) ---
$YtDlpBinDir = if ($IsWindowsOs) {
    Join-Path $env:LOCALAPPDATA 'YouTube-Transcript\bin'
} else {
    Join-Path $HOME '.local/share/YouTube-Transcript/bin'
}
$YtDlpExeName = if ($IsWindowsOs) { 'yt-dlp.exe' } else { 'yt-dlp' }
$YtDlpLocalPath = Join-Path $YtDlpBinDir $YtDlpExeName

$FfmpegExeName = if ($IsWindowsOs) { 'ffmpeg.exe' } else { 'ffmpeg' }
$FfprobeExeName = if ($IsWindowsOs) { 'ffprobe.exe' } else { 'ffprobe' }
$FfmpegLocalDir = Join-Path $YtDlpBinDir 'ffmpeg'
$FfmpegLocalPath = Join-Path $FfmpegLocalDir $FfmpegExeName
$FfprobeLocalPath = Join-Path $FfmpegLocalDir $FfprobeExeName

# --- Find or install yt-dlp ---
function Find-YtDlp {
    Write-Log -Level 'DEBUG' -Message 'Find-YtDlp: resolving yt-dlp (PATH, then local bin, then auto-install).'
    # 1) On PATH
    $ytdlp = Get-Command yt-dlp -ErrorAction SilentlyContinue
    if ($ytdlp) {
        Write-Log -Level 'DEBUG' -Message ("Find-YtDlp: using yt-dlp on PATH: {0}" -f $ytdlp.Source)
        return $ytdlp.Source
    }
    $env:PATH -split [System.IO.Path]::PathSeparator | ForEach-Object {
        $exe = Join-Path $_ $YtDlpExeName
        if (Test-Path -LiteralPath $exe) {
            Write-Log -Level 'DEBUG' -Message ("Find-YtDlp: using yt-dlp on PATH: {0}" -f $exe)
            return $exe
        }
    }
    # 2) Our local bin
    if (Test-Path -LiteralPath $YtDlpLocalPath) {
        Write-Log -Level 'DEBUG' -Message ("Find-YtDlp: using local yt-dlp: {0}" -f $YtDlpLocalPath)
        return $YtDlpLocalPath
    }
    # 3) Auto-install from GitHub
    Write-Log -Level 'STEP' -Message 'yt-dlp not found on PATH; attempting auto-install.'
    return Install-YtDlp
}

function Install-YtDlp {
    $api = 'https://api.github.com/repos/yt-dlp/yt-dlp/releases/latest'
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $release = Invoke-RestMethod -Uri $api -UseBasicParsing
    } catch {
        Fail "Could not fetch yt-dlp release: $_"
    }
    $asset = $release.assets | Where-Object { $_.name -eq $YtDlpExeName } | Select-Object -First 1
    if (-not $asset) {
        Fail "No asset named '$YtDlpExeName' in latest yt-dlp release."
    }
    if (-not (Test-Path $YtDlpBinDir)) {
        New-Item -ItemType Directory -Path $YtDlpBinDir -Force | Out-Null
    }
    Write-Log -Level 'STEP' -Message ("Installing yt-dlp to {0}" -f $YtDlpLocalPath)
    try {
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $YtDlpLocalPath -UseBasicParsing
    } catch {
        Fail "yt-dlp download failed: $_"
    }
    if (-not $IsWindowsOs) {
        try { & chmod u+x $YtDlpLocalPath 2>$null } catch { }
    }
    $YtDlpLocalPath
}

# --- Find or install ffmpeg ---
function Find-Ffmpeg {
    Write-Log -Level 'DEBUG' -Message 'Find-Ffmpeg: resolving ffmpeg (PATH, then local bin, then auto-install).'
    # 1) On PATH
    $ffmpeg = Get-Command ffmpeg -ErrorAction SilentlyContinue
    if ($ffmpeg) {
        Write-Log -Level 'DEBUG' -Message ("Find-Ffmpeg: using ffmpeg on PATH: {0}" -f $ffmpeg.Source)
        return $ffmpeg.Source
    }
    $env:PATH -split [System.IO.Path]::PathSeparator | ForEach-Object {
        $exe = Join-Path $_ $FfmpegExeName
        if (Test-Path -LiteralPath $exe) {
            Write-Log -Level 'DEBUG' -Message ("Find-Ffmpeg: using ffmpeg on PATH: {0}" -f $exe)
            return $exe
        }
    }
    # 2) Our local bin
    if (Test-Path -LiteralPath $FfmpegLocalPath) {
        Write-Log -Level 'DEBUG' -Message ("Find-Ffmpeg: using local ffmpeg: {0}" -f $FfmpegLocalPath)
        return $FfmpegLocalPath
    }
    # 3) Auto-install from GitHub
    Write-Log -Level 'STEP' -Message 'ffmpeg not found on PATH; attempting auto-install.'
    return Install-Ffmpeg
}

function Find-Ffprobe {
    $ffprobe = Get-Command ffprobe -ErrorAction SilentlyContinue
    if ($ffprobe) { return $ffprobe.Source }
    $env:PATH -split [System.IO.Path]::PathSeparator | ForEach-Object {
        $exe = Join-Path $_ $FfprobeExeName
        if (Test-Path -LiteralPath $exe) { return $exe }
    }
    if (Test-Path -LiteralPath $FfprobeLocalPath) { return $FfprobeLocalPath }
    return $null
}

function Install-Ffmpeg {
    $api = 'https://api.github.com/repos/BtbN/FFmpeg-Builds/releases/latest'
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $release = Invoke-RestMethod -Uri $api -UseBasicParsing
    } catch {
        Fail "Could not fetch ffmpeg release: $_"
    }

    if ($IsWindowsOs) {
        $assetName = 'ffmpeg-master-latest-win64-gpl.zip'
    } elseif ($PSVersionTable.Platform -eq 'Unix' -and (uname) -match 'Darwin') {
        $assetName = 'ffmpeg-master-latest-macos64-gpl.zip'
    } else {
        $assetName = 'ffmpeg-master-latest-linux64-gpl.tar.xz'
    }

    $asset = $release.assets | Where-Object { $_.name -eq $assetName } | Select-Object -First 1
    if (-not $asset) {
        Fail "No asset named '$assetName' in latest FFmpeg build release."
    }

    if (-not (Test-Path $FfmpegLocalDir)) {
        New-Item -ItemType Directory -Path $FfmpegLocalDir -Force | Out-Null
    }

    $downloadPath = Join-Path ([System.IO.Path]::GetTempPath()) $asset.name
    $extractDir = Join-Path ([System.IO.Path]::GetTempPath()) ("ffmpeg-extract-" + [Guid]::NewGuid().ToString('N'))
    Write-Log -Level 'STEP' -Message ("Installing ffmpeg to {0}" -f $FfmpegLocalDir)
    try {
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $downloadPath -UseBasicParsing
        if ($downloadPath -like '*.zip') {
            Expand-Archive -LiteralPath $downloadPath -DestinationPath $extractDir -Force
        } else {
            Fail "Unsupported ffmpeg archive format for auto-install: $downloadPath"
        }
        $ffmpegExe = Get-ChildItem -Path $extractDir -Recurse -Filter $FfmpegExeName | Select-Object -First 1
        $ffprobeExe = Get-ChildItem -Path $extractDir -Recurse -Filter $FfprobeExeName | Select-Object -First 1
        if (-not $ffmpegExe) { Fail 'Could not locate ffmpeg executable in downloaded archive.' }
        Copy-Item -LiteralPath $ffmpegExe.FullName -Destination $FfmpegLocalPath -Force
        if ($ffprobeExe) { Copy-Item -LiteralPath $ffprobeExe.FullName -Destination $FfprobeLocalPath -Force }
    } catch {
        Fail "FFmpeg install failed: $_"
    } finally {
        if (Test-Path -LiteralPath $downloadPath) { Remove-Item -LiteralPath $downloadPath -Force -ErrorAction SilentlyContinue }
        if (Test-Path -LiteralPath $extractDir) { Remove-Item -LiteralPath $extractDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
    if (-not $IsWindowsOs) {
        try { & chmod u+x $FfmpegLocalPath 2>$null } catch { }
        if (Test-Path -LiteralPath $FfprobeLocalPath) { try { & chmod u+x $FfprobeLocalPath 2>$null } catch { } }
    }
    $FfmpegLocalPath
}

# --- Sanitize filename ---
function Get-SafeBaseName {
    param([string]$Name)
    $bad = [System.IO.Path]::GetInvalidFileNameChars()
    foreach ($c in $bad) { $Name = $Name.Replace($c, '_') }
    $Name = $Name -replace '\s+', ' '
    $Name.Trim().TrimEnd('.')
}

# --- Download video: native resolution, best bitrate, NO re-encode ---
# yt-dlp without --format-sort-force can pick 360p/144p (extractor preference overrides -S).
# We require height>=720 so we never get 144p/360p when higher exists; --format-sort-force
# makes -S res,br actually define "best". Merge to MKV with -c copy (no re-encode).
# Refs: https://github.com/yt-dlp/yt-dlp/issues/10859, https://github.com/yt-dlp/yt-dlp/issues/2259
function Invoke-DownloadVideo {
    param([string]$YtDlp, [string]$Url, [string]$OutDir)
    Write-Log -Level 'STEP' -Message 'Fetching video metadata (dump-json)...'
    $info = $null
    $maxAttempts = 3
    $argList = @('--dump-json', '--no-download', $Url)
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        $info = Invoke-YtDlpJson -YtDlp $YtDlp -ArgList $argList
        if ($info -and $info.title) { break }
        if ($attempt -lt $maxAttempts) {
            Write-Log -Level 'WARN' -Message ("Retrying metadata fetch (attempt {0}/{1})..." -f ($attempt + 1), $maxAttempts)
            Start-Sleep -Seconds 2
        }
    }
    if (-not $info -or -not $info.title) { Fail 'Could not get video title from URL after retries. Check URL and network, then try again.' }
    $title = Get-SafeBaseName $info.title
    $outPath = Join-Path $OutDir "$title.mkv"
    if (Test-Path -LiteralPath $outPath) {
        Write-Log -Level 'INFO' -Message ("Output file already exists; will overwrite (default): {0}" -f $outPath)
    }
    Write-Log -Level 'INFO' -Message ("Downloading video (720p+ required, best by res then br, no re-encode) -> {0}" -f $outPath)
    $tmpl = Join-Path $OutDir '%(title)s.%(ext)s'
    # Require height>=720 so we never get 360p/144p; fallback to bestvideo+bestaudio only if no 720p+ exists.
    $format = 'bestvideo[height>=720]+bestaudio/bestvideo+bestaudio'
    $sortArgs = @('--format-sort-force', '-S', 'res,br')
    $mergeArgs = @('--merge-output-format', 'mkv')
    $ppaArgs = @('--postprocessor-args', 'ffmpeg:-c copy')
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $YtDlp -f $format @sortArgs @mergeArgs @ppaArgs -o $tmpl $Url 2>&1 | Out-Null
    } finally {
        $ErrorActionPreference = $prev
    }
    Write-Log -Level 'SUCCESS' -Message ("Video saved: {0}" -f $outPath)
    $outPath
}

# --- Download captions (VTT) ---
function Invoke-DownloadSubs {
    param([string]$YtDlp, [string]$Url, [string]$OutDir, [string]$Lang = 'en')
    Write-Log -Level 'STEP' -Message ("Downloading captions (lang={0})..." -f $Lang)
    $tmpl = Join-Path $OutDir '%(title)s'
    Write-Log -Level 'DEBUG' -Message ("Invoke-DownloadSubs: output template {0}; existing VTT in dir will be overwritten by default." -f $tmpl)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $YtDlp --write-subs --write-auto-subs --sub-langs $Lang --skip-download -o $tmpl $Url 2>&1 | Out-Null } finally { $ErrorActionPreference = $prev }
    Write-Log -Level 'DEBUG' -Message 'Resolving caption file path from metadata...'
    $info = $null
    foreach ($attempt in 1..3) {
        $info = Invoke-YtDlpJson -YtDlp $YtDlp -ArgList @('--dump-json', '--no-download', $Url)
        if ($info -and $info.title) { break }
        if ($attempt -lt 3) { Start-Sleep -Seconds 2 }
    }
    if (-not $info -or -not $info.title) { Fail 'Could not get video title from URL after retries. Check URL and network, then try again.' }
    $title = Get-SafeBaseName $info.title
    $vttPath = Join-Path $OutDir "$title.$Lang.vtt"
    if (-not (Test-Path $vttPath)) {
        $fallbackVtt = Get-ChildItem -Path $OutDir -Filter "*.vtt" | Where-Object { $_.Name -like "*$Lang*" } | Select-Object -First 1
        if ($fallbackVtt) {
            $vttPath = $fallbackVtt.FullName
            Write-Log -Level 'DEBUG' -Message ("Invoke-DownloadSubs: using fallback VTT path: {0}" -f $vttPath)
        }
    }
    Write-Log -Level 'SUCCESS' -Message ("Captions saved: {0}" -f $vttPath)
    $vttPath
}

# --- Parse VTT: return list of { StartSec, EndSec, Text } (EndSec from --> end time) ---
function Get-VttCues {
    param([string]$VttPath)
    $lines = Get-Content -LiteralPath $VttPath -Encoding UTF8
    $cues = @()
    $i = 0
    while ($i -lt $lines.Count) {
        $line = $lines[$i]
        if ($line -match '^(\d{2}):(\d{2}):(\d{2})\.(\d{3})\s*-->') {
            $startSec = [int]$Matches[1] * 3600 + [int]$Matches[2] * 60 + [int]$Matches[3] + [int]$Matches[4] / 1000.0
            $endSec = $startSec
            $parts = $line -split '\s*-->\s*', 2
            if ($parts.Count -ge 2) {
                $endPart = $parts[1].Trim()
                if ($endPart -match '^(\d{2}):(\d{2}):(\d{2})\.(\d{3})') {
                    $endSec = [int]$Matches[1] * 3600 + [int]$Matches[2] * 60 + [int]$Matches[3] + [int]$Matches[4] / 1000.0
                }
            }
            $i++
            $texts = @()
            while ($i -lt $lines.Count -and $lines[$i] -notmatch '^\d{2}:\d{2}:\d{2}\.\d{3}\s*-->') {
                $part = $lines[$i].Trim()
                if ($part -and $part -notmatch '^align:' -and $part -notmatch '%') {
                    $clean = $part -replace '<\d{2}:\d{2}:\d{2}\.\d{3}><c>', '' -replace '</c>', '' -replace '<[^>]+>', ''
                    $clean = $clean.Trim()
                    if ($clean) { $texts += $clean }
                }
                $i++
            }
            if ($texts.Count -gt 0) {
                $text = ($texts | Sort-Object -Property Length -Descending | Select-Object -First 1)
                $cues += [pscustomobject]@{ StartSec = $startSec; EndSec = $endSec; Text = $text }
            }
        } else { $i++ }
    }
    Write-Log -Level 'DEBUG' -Message ("Parsed VTT: {0} cues" -f $cues.Count)
    $cues
}

# --- Plain transcript: VTT -> single .txt, deduped ---
function Export-PlainTranscript {
    param([string]$VttPath, [string]$OutPath)
    Write-Log -Level 'STEP' -Message ("Generating plain transcript from {0}" -f $VttPath)
    if (Test-Path -LiteralPath $OutPath) {
        Write-Log -Level 'INFO' -Message ("Export-PlainTranscript: output already exists; overwriting (default): {0}" -f $OutPath)
    }
    $cues = Get-VttCues -VttPath $VttPath
    $prev = ''
    $lines = @()
    foreach ($c in $cues) {
        if ($c.Text -ne $prev) { $lines += $c.Text; $prev = $c.Text }
    }
    $lines | Set-Content -LiteralPath $OutPath -Encoding UTF8
    Write-Log -Level 'SUCCESS' -Message ("Plain transcript saved: {0} ({1} lines)" -f $OutPath, $lines.Count)
    $OutPath
}

# --- Timestamped transcript: VTT -> .txt with [HH:MM:SS] every N seconds (every interval emitted) ---
function Export-TimestampedTranscript {
    param([string]$VttPath, [string]$OutPath, [int]$IntervalSec = 3)
    Write-Log -Level 'STEP' -Message ("Generating timestamped transcript every {0}s from {1}" -f $IntervalSec, $VttPath)
    if (Test-Path -LiteralPath $OutPath) {
        Write-Log -Level 'INFO' -Message ("Export-TimestampedTranscript: output already exists; overwriting (default): {0}" -f $OutPath)
    }
    $cues = Get-VttCues -VttPath $VttPath
    $buckets = @{}
    $maxSec = 0
    $lastEndSec = 0
    $maxStartSec = 0
    foreach ($c in $cues) {
        $bucket = [int][Math]::Floor($c.StartSec / $IntervalSec) * $IntervalSec
        if ($bucket -gt $maxSec) { $maxSec = $bucket }
        if ($c.StartSec -gt $maxStartSec) { $maxStartSec = $c.StartSec }
        if ($null -ne $c.EndSec -and $c.EndSec -gt $lastEndSec) { $lastEndSec = $c.EndSec }
        if (-not $buckets.ContainsKey($bucket)) { $buckets[$bucket] = @() }
        $buckets[$bucket] += $c.Text
    }
    # Ensure we emit timestamps through the end: use last cue end time, or at least through last cue start
    $endBucket = [int][Math]::Ceiling($lastEndSec / $IntervalSec) * $IntervalSec
    $startEndBucket = [int][Math]::Ceiling($maxStartSec / $IntervalSec) * $IntervalSec
    if ($startEndBucket -gt $maxSec) { $maxSec = $startEndBucket }
    if ($endBucket -gt $maxSec) { $maxSec = $endBucket }
    $out = @()
    $maxSec = [int]$maxSec
    $n = [int]([Math]::Floor($maxSec / $IntervalSec)) + 1
    for ($idx = 0; $idx -lt $n; $idx++) {
        $sec = $idx * [int]$IntervalSec
        $hours = [int][Math]::Floor($sec / 3600)
        $mins = [int][Math]::Floor(($sec % 3600) / 60)
        $secs = [int]($sec % 60)
        $ts = '{0:D2}:{1:D2}:{2:D2}' -f $hours, $mins, $secs
        $out += "[$ts]"
        if ($buckets.ContainsKey($sec)) {
            $prev = ''
            $merged = @()
            foreach ($t in $buckets[$sec]) {
                if ($t -ne $prev) { $merged += $t; $prev = $t }
            }
            $out += ($merged -join ' ')
        }
        $out += ''
    }
    $out | Set-Content -LiteralPath $OutPath -Encoding UTF8
    Write-Log -Level 'SUCCESS' -Message ("Timestamped transcript saved: {0} ({1} blocks)" -f $OutPath, ($out.Count / 3))
    $OutPath
}

function Get-IntervalTimestamps {
    param([string]$VttPath, [int]$IntervalSec = 3)
    $cues = Get-VttCues -VttPath $VttPath
    if (-not $cues -or $cues.Count -eq 0) { return @(0) }
    $lastEndSec = 0
    $maxStartSec = 0
    foreach ($c in $cues) {
        if ($c.StartSec -gt $maxStartSec) { $maxStartSec = $c.StartSec }
        if ($null -ne $c.EndSec -and $c.EndSec -gt $lastEndSec) { $lastEndSec = $c.EndSec }
    }
    $maxSec = [int][Math]::Ceiling(([Math]::Max($lastEndSec, $maxStartSec)) / $IntervalSec) * $IntervalSec
    $n = [int][Math]::Floor($maxSec / $IntervalSec)
    $arr = @()
    for ($i = 0; $i -le $n; $i++) { $arr += ($i * $IntervalSec) }
    $arr
}

$VideoExtensions = @('.mp4', '.mkv', '.webm', '.mov', '.avi', '.m4v')

function Resolve-FrameVideoPath {
    param(
        [string]$PreferredPath,
        [string]$DownloadedVideoPath,
        [string]$VttPath,
        [string]$OutDir,
        [string]$BaseName
    )
    Write-Log -Level 'DEBUG' -Message 'Resolve-FrameVideoPath: resolving source video for frame extraction.'

    if ($PreferredPath) {
        $candidate = $PreferredPath.Trim().Trim('"')
        Write-Log -Level 'DEBUG' -Message ("Resolve-FrameVideoPath: -FrameVideoPath supplied: {0}" -f $candidate)
        if (-not (Test-Path -LiteralPath $candidate)) {
            Write-Log -Level 'DEBUG' -Message ("Resolve-FrameVideoPath: path does not exist; failing." -f $candidate)
            Fail ("Frame video not found: {0}. Use -Video to download the video, or -FrameVideoPath with the path to your video file (e.g. -FrameVideoPath 'C:\path\to\video.mp4')." -f $candidate)
        }
        $resolved = (Resolve-Path -LiteralPath $candidate).Path
        $item = Get-Item -LiteralPath $resolved
        if ($item -is [System.IO.DirectoryInfo]) {
            Write-Log -Level 'INFO' -Message ("Resolve-FrameVideoPath: path is a directory; looking for video file inside (base name or first video)." -f $resolved)
            $exts = @('mp4', 'mkv', 'webm', 'mov', 'avi', 'm4v')
            if ($BaseName) {
                foreach ($ext in $exts) {
                    $p = Join-Path $resolved "$BaseName.$ext"
                    if (Test-Path -LiteralPath $p) {
                        Write-Log -Level 'INFO' -Message ("Resolve-FrameVideoPath: using video by base name (existing file): {0}" -f $p)
                        return (Resolve-Path -LiteralPath $p).Path
                    }
                }
                Write-Log -Level 'DEBUG' -Message ("Resolve-FrameVideoPath: no file matching base name '{0}' in directory; trying first video." -f $BaseName)
            }
            $firstVideo = Get-ChildItem -Path $resolved -File -ErrorAction SilentlyContinue |
                Where-Object { $VideoExtensions -contains $_.Extension.ToLowerInvariant() } |
                Select-Object -First 1
            if ($firstVideo) {
                Write-Log -Level 'INFO' -Message ("Resolve-FrameVideoPath: using first video in directory (existing file): {0}" -f $firstVideo.FullName)
                return $firstVideo.FullName
            }
            Write-Log -Level 'DEBUG' -Message ("Resolve-FrameVideoPath: no video file in directory; failing." -f $resolved)
            Fail ("No video file found in directory: {0}. Use -FrameVideoPath with a path to a .mp4/.mkv file, or use -Video to download the video." -f $resolved)
        }
        Write-Log -Level 'INFO' -Message ("Resolve-FrameVideoPath: using -FrameVideoPath as file (existing): {0}" -f $resolved)
        return $resolved
    }

    if ($DownloadedVideoPath -and (Test-Path -LiteralPath $DownloadedVideoPath)) {
        Write-Log -Level 'INFO' -Message ("Resolve-FrameVideoPath: using downloaded video from this run (no -FrameVideoPath): {0}" -f $DownloadedVideoPath)
        return (Resolve-Path -LiteralPath $DownloadedVideoPath).Path
    }

    $dirs = @()
    if ($VttPath) { $dirs += (Split-Path -Parent $VttPath) }
    if ($OutDir) { $dirs += $OutDir }
    $dirs += (Get-Location).Path
    $dirs = $dirs | Where-Object { $_ } | Select-Object -Unique
    Write-Log -Level 'DEBUG' -Message ("Resolve-FrameVideoPath: auto-detect: searching {0} dir(s) for video by base name or first video." -f $dirs.Count)

    $exts = @('mp4', 'mkv', 'webm', 'mov', 'avi', 'm4v')
    foreach ($d in $dirs) {
        foreach ($ext in $exts) {
            if ($BaseName) {
                $p = Join-Path $d "$BaseName.$ext"
                if (Test-Path -LiteralPath $p) {
                    Write-Log -Level 'INFO' -Message ("Resolve-FrameVideoPath: auto-detected video by base name (existing file): {0}" -f $p)
                    return (Resolve-Path -LiteralPath $p).Path
                }
            }
        }
    }

    foreach ($d in $dirs) {
        $firstVideo = Get-ChildItem -Path $d -File -ErrorAction SilentlyContinue |
            Where-Object { $VideoExtensions -contains $_.Extension.ToLowerInvariant() } |
            Select-Object -First 1
        if ($firstVideo) {
            Write-Log -Level 'INFO' -Message ("Resolve-FrameVideoPath: auto-detected first video in dir (existing file): {0}" -f $firstVideo.FullName)
            return $firstVideo.FullName
        }
    }

    Write-Log -Level 'DEBUG' -Message 'Resolve-FrameVideoPath: no video source found; caller must require -Video or -FrameVideoPath.'
    return $null
}

function Get-VideoDurationSec {
    param(
        [string]$FfmpegPath,
        [string]$VideoPath
    )
    Write-Log -Level 'DEBUG' -Message ("Get-VideoDurationSec: probing duration for: {0}" -f $VideoPath)
    $ffprobePath = Find-Ffprobe
    if ($ffprobePath) {
        $durRaw = & $ffprobePath -v error -show_entries format=duration -of default=noprint_wrappers=1:nokey=1 $VideoPath
        if ($durRaw -and "$durRaw".Trim()) {
            $sec = [double]("$durRaw".Trim())
            Write-Log -Level 'DEBUG' -Message ("Video duration (ffprobe): {0:N2}s" -f $sec)
            return $sec
        }
    }

    # Fallback: parse ffmpeg stderr Duration line.
    $tmp = [System.IO.Path]::GetTempFileName()
    try {
        Start-Process -FilePath $FfmpegPath -ArgumentList @('-i', $VideoPath) -RedirectStandardError $tmp -Wait -NoNewWindow | Out-Null
        $stderr = Get-Content -LiteralPath $tmp -Raw -ErrorAction SilentlyContinue
        if ($stderr -match 'Duration:\s*(\d{2}):(\d{2}):(\d{2})\.(\d{2})') {
            return ([int]$Matches[1] * 3600) + ([int]$Matches[2] * 60) + [int]$Matches[3] + ([int]$Matches[4] / 100.0)
        }
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
    return 0
}

$ScaleFilterLanczosSuffix = ':flags=lanczos'

function Get-FrameScaleFilter {
    param(
        [string]$FrameSizePreset = 'source',
        [int]$Width = 0,
        [int]$Height = 0
    )
    $base = $null
    if ($Width -gt 0 -or $Height -gt 0) {
        $w = if ($Width -gt 0) { $Width } else { -1 }
        $h = if ($Height -gt 0) { $Height } else { -1 }
        $base = 'scale={0}:{1}:force_original_aspect_ratio=decrease' -f $w, $h
        Write-Log -Level 'DEBUG' -Message ("Get-FrameScaleFilter: using explicit size (width={0}, height={1}); scale then lanczos." -f $w, $h)
    } else {
        switch ($FrameSizePreset) {
            '720p'  { $base = 'scale=1280:720:force_original_aspect_ratio=decrease'; break }
            '1080p' { $base = 'scale=1920:1080:force_original_aspect_ratio=decrease'; break }
            '4k'    { $base = 'scale=3840:2160:force_original_aspect_ratio=decrease'; break }
            'source'{ Write-Log -Level 'DEBUG' -Message 'Get-FrameScaleFilter: FrameSize=source; no scaling (native resolution).'; return '' }
            default { $base = 'scale=1920:1080:force_original_aspect_ratio=decrease'; break }
        }
        Write-Log -Level 'DEBUG' -Message ("Get-FrameScaleFilter: using preset '{0}'; scale then lanczos." -f $FrameSizePreset)
    }
    return $base + $ScaleFilterLanczosSuffix
}

function Export-FramesAtInterval {
    param(
        [string]$FfmpegPath,
        [string]$VideoPath,
        [string]$VttPath,
        [int]$IntervalSec = 3,
        [string]$FramesOutDirOverride = '',
        [string]$ScaleFilter = ''
    )
    if (-not (Test-Path -LiteralPath $VideoPath)) {
        Fail ("Video file not found for frame extraction: {0}. Use -Video to download it, or -FrameVideoPath with the path to your video file." -f $VideoPath)
    }
    if (-not (Test-Path -LiteralPath $VttPath)) {
        Fail ("VTT file not found for frame extraction: {0}. Provide -Vtt with path to your .vtt file, or use -Url with -Subs to download captions." -f $VttPath)
    }

    $framesDir = if ($FramesOutDirOverride -and $FramesOutDirOverride.Trim()) {
        $override = $FramesOutDirOverride.Trim().Trim('"')
        if (-not [System.IO.Path]::IsPathRooted($override)) { $override = Join-Path (Get-Location) $override }
        Write-Log -Level 'DEBUG' -Message ("Export-FramesAtInterval: using -FramesOutDir override: {0}" -f $override)
        $override
    } else {
        $defaultDir = Join-Path (Split-Path -Parent $VttPath) 'frames'
        Write-Log -Level 'DEBUG' -Message ("Export-FramesAtInterval: using default frames dir (beside VTT): {0}" -f $defaultDir)
        $defaultDir
    }
    if (-not (Test-Path -LiteralPath $framesDir)) {
        Write-Log -Level 'DEBUG' -Message ("Export-FramesAtInterval: creating frames directory: {0}" -f $framesDir)
        New-Item -ItemType Directory -Path $framesDir -Force | Out-Null
    }
    $existingFrames = @(Get-ChildItem -Path $framesDir -Filter 'frame_*.png' -File -ErrorAction SilentlyContinue)
    $existingTmp = @(Get-ChildItem -Path $framesDir -Filter 'frame_tmp_*.png' -File -ErrorAction SilentlyContinue)
    if ($existingFrames.Count -gt 0 -or $existingTmp.Count -gt 0) {
        Write-Log -Level 'INFO' -Message ("Export-FramesAtInterval: removing {0} existing frame(s) and {1} tmp frame(s); will overwrite with fresh extraction (default)." -f $existingFrames.Count, $existingTmp.Count)
    }
    $existingFrames | Remove-Item -Force -ErrorAction SilentlyContinue
    $existingTmp | Remove-Item -Force -ErrorAction SilentlyContinue

    $durationSec = Get-VideoDurationSec -FfmpegPath $FfmpegPath -VideoPath $VideoPath
    if ($durationSec -le 0) {
        Fail ("Could not determine video duration for: {0}. Ensure the path is a video file (e.g. .mp4), not a directory. Use -FrameVideoPath with a path to the video file." -f $VideoPath)
    }
    $maxSec = [int][Math]::Floor($durationSec)
    $expected = [int][Math]::Floor($maxSec / $IntervalSec) + 1

    Write-Log -Level 'INFO' -Message ("Frame extraction input: {0}" -f $VideoPath)
    Write-Log -Level 'INFO' -Message ("Frame extraction output dir: {0}" -f $framesDir)
    $durStr = $durationSec.ToString('0.00', [System.Globalization.CultureInfo]::InvariantCulture)
    Write-Log -Level 'INFO' -Message ("Interval: {0}s | Duration: {1}s | Expected frames: {2} (seek-per-frame for speed)" -f $IntervalSec, $durStr, $expected)
    if (-not $ScaleFilter) {
        Write-Log -Level 'INFO' -Message 'Resolution: native (no scaling) for best readability.'
    } else {
        Write-Log -Level 'INFO' -Message ("Resolution: scaled (filter: {0})" -f $ScaleFilter)
    }
    Write-Log -Level 'STEP' -Message 'Extracting frames (one per timestamp; -ss before -i for fast seek)...'

    $createdCount = 0
    $progressInterval = [Math]::Max(1, [int][Math]::Floor($expected / 20))
    for ($i = 0; $i -lt $expected; $i++) {
        $sec = $i * [int]$IntervalSec
        if ($sec -gt $maxSec) { break }
        $h = [int][Math]::Floor($sec / 3600)
        $m = [int][Math]::Floor(($sec % 3600) / 60)
        $s = [int]($sec % 60)
        $label = '{0:D2}-{1:D2}-{2:D2}' -f $h, $m, $s
        $outPath = Join-Path $framesDir ("frame_{0}.png" -f $label)
        if ($ScaleFilter) {
            & $FfmpegPath -hide_banner -loglevel error -ss $sec -i $VideoPath -vf $ScaleFilter -frames:v 1 -c:v png -y $outPath 2>$null | Out-Null
        } else {
            & $FfmpegPath -hide_banner -loglevel error -ss $sec -i $VideoPath -frames:v 1 -c:v png -y $outPath 2>$null | Out-Null
        }
        if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $outPath)) {
            $createdCount++
        }
        if (($i + 1) % $progressInterval -eq 0 -or ($i + 1) -eq $expected) {
            Write-Log -Level 'INFO' -Message ("Frames: {0}/{1}" -f ($i + 1), $expected)
        }
    }

    if ($createdCount -eq 0) {
        Fail 'ffmpeg did not produce any frames. Ensure the video file is valid and ffmpeg can decode it.'
    }
    if ($createdCount -lt $expected) {
        Write-Log -Level 'WARN' -Message ("Expected {0} frames but created {1}. Video end may not align exactly to interval boundaries." -f $expected, $createdCount)
    }
    Write-Log -Level 'SUCCESS' -Message ("Frame extraction complete: {0} files" -f $createdCount)
    $framesDir
}

# --- Interactive menu (colorful TUI, PS 5.1 safe) ---
function Show-Interactive {
    $ytdlp = Find-YtDlp
    if (-not $ytdlp) {
        Write-Host ''
        Write-Host '  ERROR: yt-dlp not found.' -ForegroundColor Red
        Write-Host '  Install it or let this script auto-install it (run again).' -ForegroundColor Gray
        Write-Host ''
        return
    }

    Write-Host ''
    Write-Host '  ============================================' -ForegroundColor DarkCyan
    Write-Host '    YouTube Video & Transcript' -ForegroundColor Cyan
    Write-Host '    Download MP4, VTT, plain or timestamped .txt' -ForegroundColor Gray
    Write-Host '  ============================================' -ForegroundColor DarkCyan
    Write-Host ''

    Write-Host '  [1] Source' -ForegroundColor Yellow
    Write-Host '      1) YouTube URL'
    Write-Host '      2) Existing VTT file path'
    $srcChoice = Read-Host '      Choice (1 or 2)'
    $url = ''
    $vttPath = ''

    if ($srcChoice -eq '2') {
        $vttPath = (Read-Host '      VTT file path').Trim().Trim('"')
        if (-not (Test-Path -LiteralPath $vttPath)) {
            Write-Host '      File not found.' -ForegroundColor Red
            return
        }
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($vttPath) -replace '\.(en|[\w-]+)$', ''
    } else {
        $url = (Read-Host '      YouTube URL').Trim().Trim('"')
        if (-not $url) {
            Write-Host '      URL required.' -ForegroundColor Red
            return
        }
        $info = $null
        foreach ($attempt in 1..3) {
            $info = Invoke-YtDlpJson -YtDlp $ytdlp -ArgList @('--dump-json', '--no-download', $url)
            if ($info -and $info.title) { break }
            if ($attempt -lt 3) { Start-Sleep -Seconds 2 }
        }
        if (-not $info -or -not $info.title) {
            Write-Host '      Could not read video info after retries. Check URL and network.' -ForegroundColor Red
            return
        }
        $baseName = Get-SafeBaseName $info.title
    }

    Write-Host ''
    Write-Host '  [2] Output directory' -ForegroundColor Yellow
    $outDir = Read-Host "      (default: $(Get-Location))"
    if (-not $outDir) { $outDir = (Get-Location).Path }
    $outDir = $outDir.Trim().Trim('"')
    if (-not [System.IO.Path]::IsPathRooted($outDir)) { $outDir = Join-Path (Get-Location) $outDir }
    if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
    Write-Host "      Using: $outDir" -ForegroundColor Gray

    $doVideo = $false
    $doSubs = $false
    $doPlain = $false
    $doTimestamped = $false
    $doFrames = $false
    $subsLang = 'en'
    $intervalSec = 3
    $frameVideoPath = ''
    $downloadedVideoPath = ''

    Write-Host ''
    Write-Host '  [3] Actions (modular: pick any combination)' -ForegroundColor Yellow
    if ($url) {
        Write-Host '      1) Download video (MP4)'
        Write-Host '      2) Download captions (VTT)'
        Write-Host '      3) Generate plain transcript (.txt)'
        Write-Host '      4) Generate timestamped transcript (.txt, every N sec)'
        Write-Host '      5) Extract PNG frames (every N sec, requires video + VTT)'
        Write-Host '      0) All of the above'
        $actions = (Read-Host '      Choices (e.g. 1,2,3,4 or 0)').Trim()
        if ($actions -eq '0') { $doVideo = $doSubs = $doPlain = $doTimestamped = $doFrames = $true }
        else {
            foreach ($a in ($actions -split ',')) {
                switch ($a.Trim()) {
                    '1' { $doVideo = $true }
                    '2' { $doSubs = $true }
                    '3' { $doPlain = $true }
                    '4' { $doTimestamped = $true }
                    '5' { $doFrames = $true }
                }
            }
        }
        if ($doSubs) { $subsLang = Read-Host '      Subtitle language (default: en)'; if (-not $subsLang) { $subsLang = 'en' } }
        if ($doTimestamped -or $doFrames) { $raw = Read-Host '      Interval in seconds (default: 3)'; $intervalSec = if ($raw -match '^\d+$') { [int]$raw } else { 3 } }
        if ($doFrames -and -not $doVideo) {
            $frameVideoPath = (Read-Host '      Existing local video path for frames (optional if auto-detect)').Trim().Trim('"')
        }
    } else {
        Write-Host '      1) Plain transcript'
        Write-Host '      2) Timestamped transcript'
        Write-Host '      3) Both'
        Write-Host '      4) Extract PNG frames'
        $tChoice = Read-Host '      Choice (1, 2, 3, or 4)'
        switch ($tChoice) {
            '1' { $doPlain = $true }
            '2' { $doTimestamped = $true }
            '3' { $doPlain = $true; $doTimestamped = $true }
            '4' { $doFrames = $true }
        }
        if ($doTimestamped -or $doFrames) { $raw = Read-Host '      Interval in seconds (default: 3)'; $intervalSec = if ($raw -match '^\d+$') { [int]$raw } else { 3 } }
        if ($doFrames) {
            $frameVideoPath = (Read-Host '      Existing local video path for frames (optional if auto-detect)').Trim().Trim('"')
        }
    }

    $results = @()
    Write-Host ''
    Write-Host '  [4] Run' -ForegroundColor Yellow

    if ($url -and $doVideo) {
        Write-Host '      Downloading video...' -ForegroundColor Cyan
        $downloadedVideoPath = Invoke-DownloadVideo -YtDlp $ytdlp -Url $url -OutDir $outDir
        $results += $downloadedVideoPath
        Write-Host '      Video done.' -ForegroundColor Green
    }

    if ($url -and $doSubs) {
        Write-Host '      Downloading captions...' -ForegroundColor Cyan
        $vttPath = Invoke-DownloadSubs -YtDlp $ytdlp -Url $url -OutDir $outDir -Lang $subsLang
        $results += $vttPath
        Write-Host '      Captions done.' -ForegroundColor Green
    }

    if (-not $vttPath -and ($doPlain -or $doTimestamped)) {
        Write-Host '      No VTT file available for transcript.' -ForegroundColor Red
    } elseif ($vttPath) {
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($vttPath) -replace '\.(en|[\w-]+)$', ''
        if ($doPlain) {
            Write-Host '      Writing plain transcript...' -ForegroundColor Cyan
            $plainPath = Join-Path $outDir "${baseName}_transcript.txt"
            $results += Export-PlainTranscript -VttPath $vttPath -OutPath $plainPath
            Write-Host '      Plain transcript done.' -ForegroundColor Green
        }
        if ($doTimestamped) {
            Write-Host '      Writing timestamped transcript...' -ForegroundColor Cyan
            $tsPath = Join-Path $outDir "${baseName}_transcript_${intervalSec}s.txt"
            $results += Export-TimestampedTranscript -VttPath $vttPath -OutPath $tsPath -IntervalSec $intervalSec
            Write-Host '      Timestamped transcript done.' -ForegroundColor Green
        }
        if ($doFrames) {
            $ffmpegPath = Find-Ffmpeg
            if (-not $ffmpegPath) { Fail 'Could not find or install ffmpeg for frame extraction. Install ffmpeg and ensure it is on PATH, or let the script attempt auto-install.' }
            $resolvedVideoPath = Resolve-FrameVideoPath -PreferredPath $frameVideoPath -DownloadedVideoPath $downloadedVideoPath -VttPath $vttPath -OutDir $outDir -BaseName $baseName
            if (-not $resolvedVideoPath) {
                Fail "Frame extraction needs a video. Use action 1 (download video) or provide a local video path for frames (e.g. -FrameVideoPath 'C:\path\to\video.mp4')."
            }
            Write-Host '      Extracting frames...' -ForegroundColor Cyan
            $scaleFilter = Get-FrameScaleFilter -FrameSizePreset $FrameSize -Width $FrameWidth -Height $FrameHeight
            $framesDir = Export-FramesAtInterval -FfmpegPath $ffmpegPath -VideoPath $resolvedVideoPath -VttPath $vttPath -IntervalSec $intervalSec -FramesOutDirOverride $FramesOutDir -ScaleFilter $scaleFilter
            $results += $framesDir
            Write-Host '      Frame extraction done.' -ForegroundColor Green
        }
    }

    Write-Host ''
    Write-Host '  ============================================' -ForegroundColor DarkCyan
    Write-Host '    Done. Created:' -ForegroundColor Green
    $results | ForEach-Object { Write-Host "      $_" -ForegroundColor White }
    Write-Host '  ============================================' -ForegroundColor DarkCyan
    Write-Host ''
}

# --- Non-interactive run ---
function Invoke-NonInteractive {
    $ytdlp = Find-YtDlp
    if (-not $ytdlp) {
        Fail 'yt-dlp not found. Install it and ensure it is on PATH.'
    }

    $needUrl = $Video -or $Subs
    $needVtt = $Transcript -eq 'plain' -or $Transcript -eq 'timestamped' -or $Transcript -eq 'both'
    if ($needUrl -and -not $Url -and -not $Vtt) {
        Fail 'Provide -Url (for video/subs) or -Vtt (for transcript-only). Example: -Url "https://www.youtube.com/watch?v=..." -Video -Subs'
    }
    if ($needVtt -and -not $Vtt -and -not $Url) {
        Fail 'Provide -Url or -Vtt to generate transcript(s). Example: -Url "..." -Subs -Transcript both'
    }
    if ($ExtractFrames -and -not $Vtt -and -not $Subs -and -not $Url) {
        Fail 'Frame extraction needs subtitle timing. Provide -Vtt (path to .vtt file), or use -Url with -Subs.'
    }
    Write-Log -Level 'INFO' -Message ("Run options: Video={0}, Subs={1}, Transcript={2}, ExtractFrames={3}, Interval={4}" -f $Video, $Subs, $Transcript, $ExtractFrames, $Interval)

    $outDir = $OutDir.Trim().Trim('"')
    if (-not [System.IO.Path]::IsPathRooted($outDir)) { $outDir = Join-Path (Get-Location) $outDir }
    if (-not (Test-Path $outDir)) {
        Write-Log -Level 'STEP' -Message ("Creating output directory: {0}" -f $outDir)
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    } else {
        Write-Log -Level 'DEBUG' -Message ("Output directory already exists; will use it (overwrite by default): {0}" -f $outDir)
    }
    Write-Log -Level 'INFO' -Message ("Output directory: {0}" -f $outDir)

    $vttPath = $Vtt
    $baseName = ''
    $results = @()
    $downloadedVideoPath = ''

    if ($Url) {
        Write-Log -Level 'STEP' -Message ("Resolving URL metadata: {0}" -f $Url)
        $info = $null
        $maxAttempts = 3
        $argList = @('--dump-json', '--no-download', $Url)
        for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
            $info = Invoke-YtDlpJson -YtDlp $ytdlp -ArgList $argList
            if ($info -and $info.title) { break }
            if ($attempt -lt $maxAttempts) {
                Write-Log -Level 'WARN' -Message ("Retrying metadata fetch (attempt {0}/{1})..." -f ($attempt + 1), $maxAttempts)
                Start-Sleep -Seconds 2
            }
        }
        if (-not $info -or -not $info.title) {
            Fail 'Could not get video title from URL after retries. Check URL and network, then try again.'
        }
        $baseName = Get-SafeBaseName $info.title
        if ($Video) {
            Write-Log -Level 'STEP' -Message 'Downloading video...'
            $downloadedVideoPath = Invoke-DownloadVideo -YtDlp $ytdlp -Url $Url -OutDir $outDir
            $results += $downloadedVideoPath
        }
        if ($Subs) {
            $lang = $SubsLang
            Write-Log -Level 'STEP' -Message ("Downloading captions (lang={0})..." -f $lang)
            $vttPath = Invoke-DownloadSubs -YtDlp $ytdlp -Url $Url -OutDir $outDir -Lang $lang
            $results += $vttPath
        }
    }

    if ($Vtt) {
        if (-not (Test-Path -LiteralPath $Vtt)) { Fail ("VTT file not found: {0}. Use a valid path to a .vtt file." -f $Vtt) }
        $vttPath = $Vtt
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($Vtt) -replace '\.(en|[\w-]+)$', ''
        Write-Log -Level 'INFO' -Message ("Using input VTT (existing file): {0}" -f $vttPath)
    } elseif ($vttPath) {
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($vttPath) -replace '\.(en|[\w-]+)$', ''
        Write-Log -Level 'DEBUG' -Message ("Base name for outputs: {0}" -f $baseName)
    }

    if ($Transcript -and $vttPath) {
        Write-Log -Level 'DEBUG' -Message ("Transcript requested: {0}; generating from VTT." -f $Transcript)
        if ($Transcript -eq 'plain' -or $Transcript -eq 'both') {
            Write-Log -Level 'STEP' -Message 'Writing plain transcript...'
            $plainPath = Join-Path $outDir "${baseName}_transcript.txt"
            $results += Export-PlainTranscript -VttPath $vttPath -OutPath $plainPath
        }
        if ($Transcript -eq 'timestamped' -or $Transcript -eq 'both') {
            Write-Log -Level 'STEP' -Message ("Writing timestamped transcript ({0}s)..." -f $Interval)
            $tsPath = Join-Path $outDir "${baseName}_transcript_${Interval}s.txt"
            $results += Export-TimestampedTranscript -VttPath $vttPath -OutPath $tsPath -IntervalSec $Interval
        }
    }

    if ($ExtractFrames) {
        Write-Log -Level 'DEBUG' -Message 'ExtractFrames requested; resolving video source and output dir.'
        if (-not $vttPath -or -not (Test-Path -LiteralPath $vttPath)) {
            Fail 'No VTT timing source available for frame extraction. Provide -Vtt (path to .vtt file), or use -Url with -Subs to download captions.'
        }
        $ffmpegPath = Find-Ffmpeg
        if (-not $ffmpegPath) { Fail 'Could not find or install ffmpeg for frame extraction. Install ffmpeg and ensure it is on PATH, or let the script attempt auto-install.' }
        $resolvedVideoPath = Resolve-FrameVideoPath -PreferredPath $FrameVideoPath -DownloadedVideoPath $downloadedVideoPath -VttPath $vttPath -OutDir $outDir -BaseName $baseName
        if (-not $resolvedVideoPath) {
            Fail "Frame extraction needs a video. Use -Video to download it, or -FrameVideoPath with the path to your video file (e.g. -FrameVideoPath 'C:\path\to\video.mp4')."
        }
        Write-Log -Level 'STEP' -Message 'Extracting frames...'
        $scaleFilter = Get-FrameScaleFilter -FrameSizePreset $FrameSize -Width $FrameWidth -Height $FrameHeight
        $framesDir = Export-FramesAtInterval -FfmpegPath $ffmpegPath -VideoPath $resolvedVideoPath -VttPath $vttPath -IntervalSec $Interval -FramesOutDirOverride $FramesOutDir -ScaleFilter $scaleFilter
        $results += $framesDir
    }

    Write-Log -Level 'SUCCESS' -Message 'Done. Created:'
    $results | ForEach-Object { Write-Log -Level 'SUCCESS' -Message ("  {0}" -f $_) }
}

# --- Entry ---
# If any non-interactive option is set, run CLI (except -Interactive alone)
$hasNonInteractive = $Url -or $Vtt -or $Video -or $Subs -or $Transcript -or $ExtractFrames -or $FrameVideoPath
if ($Interactive -and -not $hasNonInteractive) {
    Show-Interactive
} elseif ($hasNonInteractive) {
    Invoke-NonInteractive
} else {
    Show-Interactive
}
