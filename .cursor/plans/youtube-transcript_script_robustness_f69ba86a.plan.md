---
name: YouTube-Transcript script robustness
overview: Harden the YouTube-Transcript.ps1 script so frame-extraction parameters are intuitive, directory-vs-file confusion is eliminated, transient yt-dlp/network failures are handled gracefully, and extracted frame PNGs are high quality (default 1080p, configurable).
todos:
  - id: param-clarity
    content: Clarify -FrameVideoPath vs frame output dir; add -FramesOutDir; accept dir or file for FrameVideoPath
    status: completed
  - id: frame-quality
    content: Add 1080p default scale and -FrameWidth/-FrameHeight or -FrameSize for frame extraction
    status: completed
  - id: retry-ytdlp
    content: Retry Invoke-YtDlpJson on empty stdout (transient failures) with backoff
    status: completed
  - id: errors-actionable
    content: Make all frame/video errors actionable (what to pass, example commands)
    status: completed
  - id: doc-examples
    content: Update .SYNOPSIS/.EXAMPLE and help for new params and common workflows
    status: completed
isProject: false
---

# YouTube-Transcript.ps1 robustness and usability

## Root causes of your errors


| What you ran                                     | What went wrong                                                         | Root cause                                                                                                                                                                                                                      |
| ------------------------------------------------ | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-Subs -ExtractFrames -Interval 5` (no `-Video`) | "Could not locate source video for frame extraction"                    | ExtractFrames needs a video source; script didn’t make it obvious that you must use `-Video` or `-FrameVideoPath <file>`.                                                                                                       |
| `-FrameVideoPath ..\docs\from_video\frames\`     | "Could not determine video duration for: ...\frames                     | You passed the **frames output folder**; script treats `-FrameVideoPath` as the **video file** (or path to it). It then ran ffprobe on a directory path. Naming/semantics are confusing; no separate “frames output dir” param. |
| `-FrameVideoPath -Subs ...` (no value)           | "Missing an argument for parameter 'FrameVideoPath'"                    | PowerShell requires a string after `-FrameVideoPath`; there’s no way to “use auto-detect only” without omitting the switch.                                                                                                     |
| Same URL, one run                                | "Could not get video title from URL" / "Invoke-YtDlpJson: empty stdout" | Transient yt-dlp or network failure; script doesn’t retry.                                                                                                                                                                      |
| Frames extracted                                 | PNGs "horrible quality, unusable"                                       | No scale filter in ffmpeg; output is whatever the decoder gives (can be low res). No resolution/quality options.                                                                                                                |


---

## Design goals

1. **Intuitive** – Users can guess: “video file goes here, frame folder goes there,” and “frames will be 1080p unless I say otherwise.”
2. **Flexible** – Subs-only, video+subs, frames from existing video file or from just-downloaded video; optional frame output dir and resolution.
3. **Robust** – Transient yt-dlp/network failures retried; errors tell you exactly what to pass (e.g. `-Video` or `-FrameVideoPath C:\path\to\video.mp4`).
4. **Frame quality** – Default 1080p; configurable resolution/size so PNGs are usable.

---

## 1. Parameter clarity (frame video vs frame output)

### 1.1 `-FrameVideoPath` semantics

- **Meaning**: Path to the **source video** used for frame extraction (file path, or directory that contains the video).
- **Behavior**:
  - If it’s a **file** (e.g. `video.mp4`): use it.
  - If it’s a **directory**: resolve to a single video file in that directory (same logic as “video beside VTT”: by base name first, then first video by extension). If none found, error with an actionable message.
- **Help text**: State explicitly: “Path to the video **file** (or a directory containing the video). Not the folder where frame PNGs are written.”
- **Optional**: Rename to `-VideoPath` or keep `-FrameVideoPath` but document clearly and add `-FramesOutDir` so “frames folder” is never confused with “video path.”

### 1.2 New: `-FramesOutDir`

- **Purpose**: Where to write frame PNGs (e.g. `frame_00-00-00.png`).
- **Default**: `Join-Path (directory of VTT) 'frames'` (current behavior).
- **When set**: Create it if missing; extract frames there. Removes the temptation to misuse `-FrameVideoPath` as “frames folder.”

### 1.3 Error messages

- When no video source is found for frame extraction, say exactly what to do, e.g.  
“Frame extraction needs a video. Use -Video to download it, or -FrameVideoPath with the path to your video file (e.g. -FrameVideoPath 'C:\path\to\video.mp4').”
- When `-FrameVideoPath` points to a directory and no video is found there:  
“No video file found in directory: . Use -FrameVideoPath with a path to a .mp4/.mkv file, or use -Video to download the video.”

---

## 2. Frame PNG quality (default 1080p, configurable)

### 2.1 Current behavior

- ffmpeg: `-vf fps=1/<Interval>` and `-c:v png -compression_level 1`.
- No scaling; resolution = decode resolution (can be low or inconsistent).

### 2.2 Desired behavior

- **Default**: Scale to 1080p (max width 1920, max height 1080, preserve aspect ratio).  
  - ffmpeg: e.g. `scale=1920:1080:force_original_aspect_ratio=decrease` (then pad if you want fixed 1920x1080) or `scale='min(1920,iw)':'min(1080,ih)':force_original_aspect_ratio=decrease` so output is at most 1080p.
- **Configurable**:
  - Option A: `-FrameWidth` and `-FrameHeight` (e.g. 1920, 1080). If only one set, derive the other from aspect (or allow “max width” / “max height” only).
  - Option B: `-FrameSize` with presets: `720p`, `1080p`, `4k`, `source`. Map to scale filter; `source` = no scale.
- **Recommendation**: Default 1080p; add `-FrameSize` (720p | 1080p | 4k | source) and optionally `-FrameWidth` / `-FrameHeight` for explicit dimensions. If explicit dimensions are set, they override `-FrameSize`.

### 2.3 ffmpeg changes

- Build scale filter from `-FrameSize` or `-FrameWidth`/`-FrameHeight`.
- Combine with existing fps filter: e.g. `scale=...,fps=1/<Interval>`.
- Keep PNG; `compression_level` can stay or be made configurable later (quality is mainly resolution).

---

## 3. Resilience (transient failures)

### 3.1 yt-dlp / metadata

- When `Invoke-YtDlpJson` returns empty/null or no `title`:
  - Retry up to 2 times (e.g. 2–3 s delay) before failing.
  - Final error: “Could not get video title from URL after retries. Check URL and network, then try again.”
- Optionally log “Retrying metadata fetch (attempt N/3)…” on retries.

### 3.2 Other calls

- Keep current behavior for download/caption steps unless we see repeated transient failures; then add retries similarly.

---

## 4. Implementation checklist (todos)

- **param-clarity**: Implement `-FramesOutDir`; treat `-FrameVideoPath` as file or directory (resolve to one video); update all “no video found” and “path is a dir” errors to be actionable; document in comment-based help.
- **frame-quality**: Add default 1080p scale in `Export-FramesAtInterval`; add `-FrameSize` (and optionally `-FrameWidth`/`-FrameHeight`); thread through from params to `Export-FramesAtInterval`; document.
- **retry-ytdlp**: In URL metadata path, retry `Invoke-YtDlpJson` up to 2 times with short delay on empty/null or missing title; improve final error message.
- **errors-actionable**: Audit all `Fail` messages for frame/video/sub flows; add one-line “do this” (e.g. “Use -Video or -FrameVideoPath ”) where needed.
- **doc-examples**: Update .SYNOPSIS, .DESCRIPTION, .EXAMPLE, and parameter help for `-FrameVideoPath`, `-FramesOutDir`, `-FrameSize` (and any new params); add examples for “subs + frames from existing video” and “video + subs + frames at 1080p.”

---

## 5. Example invocations (target behavior)

After implementation, these should work as intended:

```powershell
# Subs + frames: must provide video source (download or path)
.\YouTube-Transcript.ps1 -Url "..." -OutDir .\out -Subs -ExtractFrames -Interval 5 -Video

# Frames from existing video; frames go to custom folder
.\YouTube-Transcript.ps1 -Url "..." -OutDir .\out -Subs -ExtractFrames -Interval 5 -FrameVideoPath "C:\videos\my.mp4" -FramesOutDir "C:\output\frames"

# Frames at 1080p (default)
.\YouTube-Transcript.ps1 -Url "..." -OutDir .\out -Video -Subs -ExtractFrames -Interval 5

# Frames at 720p to save space
.\YouTube-Transcript.ps1 -Url "..." -OutDir .\out -Video -Subs -ExtractFrames -Interval 5 -FrameSize 720p
```

No other changes beyond writing and filling out this plan file.