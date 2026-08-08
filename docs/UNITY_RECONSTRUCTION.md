# Unity game → editable Unity project

Point the front door at a shipped Unity game and get a project that opens in the
Unity Editor:

```bash
uv run agentdecompile-reconstruct "/path/to/TheVillainSimulator" \
  --unity-project-out /path/to/output-project
```

Every Unity-specific decision is derived from the shipped player. You do not
tell it the Unity version, the scene list, the build order, which packages the
project needs, or how to avoid running out of memory on a large title.

## Stages

Seven stages run between `snapshot-existing-recovery` and `report`. They are
inert for non-Unity targets: each writes a `skipped` receipt and returns, so
adding them changed nothing for PE/ELF runs.

| Stage | Receipt | Does |
|---|---|---|
| `unity-probe` | `unity/probe.json` | Facts only: `*_Data` layout, Unity version, scripting backend, scene inventory, managed assemblies, XR markers, container sizes |
| `unity-plan` | `unity/plan.json` | Decisions only: memory-budgeted export mode, editor selection, implied package set |
| `unity-export-assets` | `unity/assetripper.json` | AssetRipper headless export → `ExportedProject/` |
| `unity-decompile-managed` | `unity/managed.json` | `ilspycmd` on the game assemblies + scaffolding strip |
| `unity-compose-project` | `unity/compose.json` | Compose the openable project at `--unity-project-out` |
| `unity-editor-validate` | `unity/validate.json` | Headless batchmode open; parse compile/scene/package errors |
| `unity-repair` | `unity/repair.json` | Diagnostic-driven repair loop, re-validating each attempt |

Facts and decisions are deliberately split across the first two receipts: a plan
can be re-derived under a different budget without re-probing, and a surprising
plan is always traceable to the fact that produced it.

## What is derived, and from where

| Decision | Derived from |
|---|---|
| Unity version | ASCII version run in the `globalgamemanagers` header — available *before* any export tool runs, which is what makes editor selection possible up front |
| Scripting backend | `Managed/*.dll` → Mono; `GameAssembly` + `il2cpp_data` → IL2CPP |
| Scene list **and build order** | `levelN` filenames — `N` *is* the build index |
| Package dependencies | Shipped assembly names mapped to UPM ids (AssetRipper emits only `com.unity.modules.*` built-ins, so third-party packages must come from assembly evidence) |
| Export memory mode | Container sizes vs. host available RAM |
| Editor to use | Unity Hub scan, exact version preferred |

## The memory decision

Whole-graph exporters load the asset graph before writing anything, so a title
larger than RAM dies partway through — which is exactly how an earlier run of
this pipeline lost its scenes to an `OutOfMemoryException`.

When the budget is short, `resources.assets` is dropped first: it is the largest
container and the only large one scene export does not need. The remaining
containers are exposed to the exporter through a **symlink** tree, so staging a
2 GiB subset of a 15 GiB install costs kilobytes.

On a real 15.1 GiB title with ~4.5 GiB available, the planner independently
reproduced a staging set that had previously been hand-tuned: 2.42 GiB, dropping
exactly `resources.assets` and `resources.assets.resS`.

The cost is recorded, not hidden — `claimBoundary` states that assets loaded at
runtime from excluded containers become unresolved references.

## Compose what the tools emit

The composition stage copies rather than synthesizes. AssetRipper's
`ExportedProject/` already contains `ProjectSettings/EditorBuildSettings.asset`
with the correct scene build order **and** GUIDs, `ProjectVersion.txt`, a
`Packages/manifest.json`, per-scene lighting folders, and a `.meta` for every
plugin DLL. Hand-writing any of that is duplicated work and a source of drift.

Only two things are genuinely synthesized: package entries implied by shipped
assemblies (merged into AssetRipper's manifest as the base, never clobbering an
existing pin), and `validateReferences: 0` on shipped-plugin `.meta` files.

## Verification, not the MCP bridge

Validation uses `Unity -batchmode -quit -nographics -projectPath … -executeMethod`.
A cold batchmode open performs a full asset import, so nothing depends on an
Editor window having OS focus — an interactive Editor's background asset scanner
is unreliable when unfocused and can take minutes to notice externally-written
files.

An injected `ADRecoveryValidate.Run` opens every build-settings scene and writes
a JSON report: per-scene root object count and missing-script count, plus
compile state. `validatorRan: false` is a normal first-pass outcome rather than a
bug — Unity refuses `-executeMethod` when compilation fails, so the log becomes
the sole evidence.

## Repair loop

Errors are classified into recipes rather than fixed by hardcoded special cases:

| Signature | Recipe | Status |
|---|---|---|
| `CS0579` duplicate assembly attribute | `delete-file` (path comes from the error) | implemented |
| `CS0101` / `CS0111` duplicate type | `dedupe-type` | not implemented |
| `CS0246` / `CS0234` type not found | `resolve-missing-type` | not implemented |
| missing script / GUID | `remap-guid` (via `AuxiliaryFiles/path_id_map.json`) | not implemented |
| package resolution failure | `relax-package` | not implemented |

Unimplemented recipes return `{"status": "not-implemented"}` — they are counted
and reported, never faked. `delete-file` generically catches ILSpy's
`Properties/AssemblyInfo.cs` without hardcoding that filename, and refuses any
path resolving outside `<project>/Assets`.

The loop stops when the project is clean, when no recipe matches, when the error
count fails to decrease (non-convergence), or at `--unity-repair-attempts`.

## Prerequisites

| Tool | Resolution | Env override |
|---|---|---|
| AssetRipper | `target/assetripper/`, then PATH | `AGENTDECOMPILE_ASSETRIPPER_CLI` |
| `ilspycmd` | PATH, then `~/.dotnet/tools/` (`dotnet tool install -g ilspycmd`) | `AGENTDECOMPILE_ILSPYCMD` |
| Unity Editor | Unity Hub layouts (Linux/macOS/Windows) | `AGENTDECOMPILE_UNITY_EDITOR`, `AGENTDECOMPILE_UNITY_HUB_ROOT` |

All three land in `capabilities.json` under `tools.*`. A missing tool raises
`ToolchainError` → `blocked:toolchain` (exit 2) rather than silently degrading.

## Claim boundary

A successful run proves: the Editor opened the composed project in batchmode
with N compile errors, resolved packages, and opened M/T build scenes with K
missing script references.

It does **not** prove byte-identity with the shipped build, correct gameplay
behavior, or that content excluded by a staged export left no dangling
references. Decompiled C# is behavioral reconstruction, not original source.

## Known gaps

- **IL2CPP is detected and blocked, not supported.** Managed code is compiled to
  native, so no decompilable assembly exists; real support needs
  Cpp2IL/Il2CppDumper.
- Four of five repair recipes are stubs.
- Editor **version drift** is reported (`editor.match`, `editor.versionDrift`)
  but not prevented: opening a 2022.3 project in Unity 6 silently upgrades
  assets. Pin with `--unity-editor-version` when that matters.
- The AssetRipper invocation is ported from a working PowerShell implementation
  and exercised against a stub server; it has not yet been run end-to-end
  against a real title from inside this pipeline.
