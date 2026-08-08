---
title: PotPlayer video renderer/filter-graph recovery (personal research)
date: 2026-07-30
type: feat
depth: lightweight
---

# PotPlayer Video Renderer/Filter-Graph Recovery

## Summary

Use the existing AgentDecompile pipeline (Ghidra ground truth → candidate C → compile + objdiff verification) against `PotPlayerMini64.exe` to understand how its Direct3D 11 video renderer and DirectShow filter-graph negotiation work. This is personal research/understanding, not a clone-and-ship effort (see Scope Boundaries). Motivation: earlier in this session we hit a real integration gap — PotPlayer's renderer/filter negotiation interacting with Wine/DXVK's stubbed D3D11 Video Processor API — and understanding PotPlayer's actual negotiation logic would make any future frame-generation integration (`lsfg-vk`, or a future from-scratch renderer) more robust than guessing from black-box behavior alone.

## Problem Frame

PotPlayer is closed-source. We don't know:
- How it enumerates/selects video renderers (Direct3D 11 "internal" renderer vs EVR vs madVR vs overlay mixer) at runtime
- How it negotiates DirectShow filter chains — specifically how/when it queries `ID3D11VideoDevice`/`ID3D11VideoContext` and what it does when those interfaces report degraded or stubbed capabilities (the exact situation we hit with DXVK)
- What triggers its "Zero-Copy mode" path (referenced in BlueskyFRC's own docs as requiring PotPlayer's "internal Direct3D 11 video renderer")

This plan recovers enough of that logic — verified via AgentDecompile's compile+objdiff gate where possible, advisory (Ghidra decompilation) where a full verified match isn't achievable — to document it, without redistributing any decompiled code.

## Scope Boundaries

**In scope:**
- Static/dynamic analysis of `PotPlayerMini64.exe` for renderer selection and filter-graph negotiation logic
- Producing human-readable notes/documentation of *behavior* (what it does, when, why) for personal use
- Using AgentDecompile's existing recovery pipeline as-is; no changes to AgentDecompile itself unless a real bug blocks analysis

**Explicitly out of scope:**
- Redistributing decompiled/recovered source, in whole or part
- A literal port of recovered logic into the eventual Rust reimplementation — any future Rust code must be written from the *behavioral spec* this analysis produces, not from recovered C, to stay clean-room
- Full-application recovery (codecs, UI, playlist, subtitle engine, etc.) — explicitly deferred

### Deferred to Follow-Up Work
- Subtitle rendering, playlist/UI, and codec-adjacent DLLs (`ffcodec64.dll` etc.) if later research needs them
- The actual Rust reimplementation (separate plan, once the behavior spec exists)

## Key Technical Decisions

- **Target binary:** `PotPlayerMini64.exe` only for this pass (2.5MB; renderer/filter logic lives here, not in the codec DLLs, confirmed by inspecting the installed binaries — `d3dcompiler_47.dll` is Microsoft's own shader compiler, not PotPlayer logic).
- **Tool:** AgentDecompile's existing `agentdecompile-reconstruct` front door (enrich-before-decompile: names/types/RTTI/module-map via PyGhidra, then candidate generation, then compile+objdiff gate). No new tooling needed.
- **Output form:** A behavior-spec document (`docs/potplayer-renderer-notes.md` in agentdecompile, or wherever the project's existing advisory/verified export convention puts it — follow whatever `verified/`/`advisory/` split the repo already uses), not raw recovered source kept as a deliverable.
- **Legal posture:** Personal understanding only (see Scope Boundaries). If this ever turns into a shipped Rust player, the renderer/filter behavior must be re-derived as a written spec and handed to that clean-room effort — the recovered C itself never gets copied into the new codebase.

## Implementation Units

### U1. Set up an AgentDecompile project targeting PotPlayerMini64.exe

**Goal:** Get a working Ghidra-backed AgentDecompile project pointed at the binary, with initial auto-analysis complete.

**Files:** New project under `agentdecompile_projects/` (e.g. `potplayer_renderer.gpr` + `.rep`), following the existing per-target project pattern already used by other entries in that directory.

**Approach:** Use `agentdecompile-server --project-path agentdecompile_projects/potplayer_renderer --project-name potplayer_renderer` (or the CLI-client equivalent against a running shared server, per the README's "Project creation and opening" section) against a copy of `/home/brunner56/.wine/drive_c/Program Files/DAUM/PotPlayer/PotPlayerMini64.exe`.

**Verification:** Project opens cleanly in Ghidra/PyGhidra MCP; initial auto-analysis finishes without errors; binary inventory (function count, imports) is available.

**Test expectation:** none — infrastructure setup, no behavioral change.

### U2. Locate renderer-selection and D3D11 Video API entry points

**Goal:** Find where the binary calls into `ID3D11VideoDevice`/`ID3D11VideoContext`/`ID3D11VideoProcessorEnumerator` (or decides between D3D11/EVR/madVR/overlay renderers), using imports and string references as anchors.

**Files:** Advisory notes only at this stage (no source promotion yet).

**Approach:** Use AgentDecompile's inventory + Ghidra decompilation (advisory tier) to search imports from `d3d11.dll`/`dxva2.dll`/`strmiids` and cross-reference against renderer-related strings (PotPlayer exposes renderer names in its own preferences UI, which gives good string anchors to pivot from).

**Verification:** A short list of candidate function addresses/names identified as renderer-selection and video-API-negotiation entry points, with enough confidence to prioritize for U3.

**Test expectation:** none — analysis/discovery unit.

### U3. Promote and verify the core negotiation path

**Goal:** Run the compile+objdiff recovery loop on the highest-value functions found in U2 to get verified (not just advisory) understanding of the actual negotiation logic.

**Files:** Whatever `verified/`/`advisory/` export paths AgentDecompile's existing pipeline already writes to for this project.

**Approach:** `agentdecompile-reconstruct` against the candidate functions from U2; accept AgentDecompile's own promotion gate (objdiff zero) as the bar for "verified" vs falling back to advisory-only notes for functions that don't cleanly match.

**Verification:** At least the renderer-selection function and the D3D11 Video API negotiation call site reach either verified or a well-documented advisory state (not silence/unknown).

**Test expectation:** none — recovery/verification unit; correctness is defined by AgentDecompile's own objdiff gate, not new test code.

### U4. Write the behavior-spec document

**Goal:** Turn U2/U3's findings into a plain-language behavior spec: how PotPlayer picks a renderer, when/how it queries D3D11 Video API capabilities, and what it does differently when those capabilities report degraded/stubbed (the DXVK situation).

**Files:** `docs/potplayer-renderer-notes.md` (new)

**Approach:** Prose + short pseudocode sketches of control flow (state machine or flowchart if the branching is non-trivial). No recovered C pasted in verbatim — paraphrase behavior only, consistent with the clean-room posture in Scope Boundaries.

**Verification:** Document answers, in plain language: (1) how renderer selection works, (2) exactly what triggers "Zero-Copy mode" / internal D3D11 renderer path, (3) what happens when D3D11 Video API capability queries come back empty.

**Test expectation:** none — documentation unit.

## Open Questions

- Whether `PotPlayerMini64.exe` statically contains all relevant logic or delegates to a helper DLL not yet identified (`DesktopHook64.dll`, `ATextOut64.dll` are candidates worth a quick grep in U2 if the exe alone doesn't turn up the negotiation path).
