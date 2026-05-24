# Brainstorm: Fix Atrocious Quality of Extracted Frames (YouTube-Transcript.ps1)

**Date:** 2026-03-11  
**Context:** User has reported repeatedly that extracted PNG frames from the YouTube-Transcript.ps1 script are blurry, pixelated, and unusable—even at 1920p scaling. Screenshots show a Ghidra UI with poor visual fidelity across the entire frame.

---

## What We're Building

A **single, definitive fix** for frame quality so that:

1. Downloaded video is **native resolution and bitrate** with **no unnecessary re-encoding**.
2. Extracted PNGs are **sharp and usable** (screenshots, documentation, thumbnails).

---

## Root Cause (Why Quality Stayed Bad)

Previous changes improved things but missed the main cause:

| Layer | What we did | What was still wrong |
|-------|-------------|----------------------|
| **Download** | `bestvideo+bestaudio`, sort by `res,br`, merge to MP4, re-encode with CRF 18 when codec isn’t H264 | **Re-encoding is the problem.** YouTube often serves **VP9** (or AV1) at 1080p+. Forcing **MP4** forces a **transcode** (VP9→H264). Even at CRF 18, that’s a **generation loss** and can soften text/UI. |
| **Extraction** | Lanczos scaling, seek-per-frame | Scaling and extraction are fine; **input video was already degraded** by the download re-encode. |

So the **source file** written by the script was already lower quality than the stream. No amount of better scaling or extraction can recover that.

---

## Why This Approach

**Avoid re-encoding on download.**

- Use **MKV** as the merge container when the best stream is VP9/AV1. MKV supports VP9 natively, so we can **remux with `-c copy`** and keep the stream bit-for-bit.
- Only merge to MP4 when the chosen streams are already H264+AAC (then remux with `-c copy` to MP4). If we always prefer “best” by resolution/bitrate, we often get VP9, so the practical default is **merge to MKV with `-c copy`** and **no re-encode**.
- Frame extraction (ffmpeg) reads MKV as well as MP4; the rest of the script (path resolution, etc.) already supports `.mkv`.

**References:**

- [Use `.mkv` for VP9, and use `.mp4` for AVC](https://github.com/ytdl-org/youtube-dl/issues/31294) — MKV for VP9 avoids re-encode.
- [yt-dlp best quality](https://github.com/yt-dlp/yt-dlp/issues/10226) — Format selection and codec order.
- FFmpeg: PNG frame extraction is lossless; quality limit is the **decoded video** we feed it.

---

## Key Decisions

1. **Default: merge to MKV with `-c copy`**  
   No re-encoding. Output file is `%(title)s.mkv`. Preserves VP9/AV1 at full quality.

2. **No postprocessor re-encode**  
   Remove `--postprocessor-args "ffmpeg:-c:v libx264 -crf 18 ..."`. Use `--postprocessor-args "ffmpeg:-c copy"` so merge is remux-only.

3. **Script output path**  
   Expect `$title.mkv` (not `$title.mp4`) when using MKV. Path resolution and frame extraction already accept `.mkv`.

4. **Optional later: “Prefer MP4”**  
   If we need MP4 for compatibility, add a switch (e.g. `-PreferMp4`) that merges to MP4 and re-encodes when necessary (current behavior). Default stays “best quality = MKV + copy.”

---

## Open Questions

- **None.** Root cause and fix are clear: stop re-encoding; use MKV + copy.

---

## Resolved Questions

- *Why was quality still bad after CRF 18 and lanczos?* → Re-encoding (VP9→H264) was the bottleneck; CRF 18 still loses clarity on text/UI.
- *Will users mind .mkv instead of .mp4?* → For frame extraction and local use, MKV is fine. We can add a “prefer MP4” option later if needed.
