---
date: 2026-07-25
topic: readable-recovery-quality
---

# Readable Recovery Quality

## Summary

Make AgentDecompile's recovered source read like real C/C++ instead of a Ghidra
dump, by enriching the Ghidra database with names, types, structs, and
RTTI/vtable class shapes *before* bulk decompile — on the default
`agentdecompile-reconstruct` path and for PE targets, not only the ELF one-shot
path where enrichment exists today. Noise stripping and evidence-based module
mapping become standard dump behavior, and a readability gate governs what
reaches `Port/CODE`. Readability stays advisory; `verified/` still requires
objdiff 0.

## Problem Frame

The product already has the honest scaffolding of a serious
matching-decompilation tool: `verified/` vs `advisory/` layers, a proof ladder,
byte-emitter rejection, and objdiff gating. But the source a user actually opens
still reads like raw Ghidra: `FUN_0040xxxx` names, `param_1`/`undefined4`
locals, `void*` where a class pointer belongs, and WARNING/library-match banners
inline in the body.

The cause is structural, not cosmetic. The richer enrichment machinery
(`src/agentdecompile_recovery/pyghidra_enrich.py`, `rtti_recover.py`,
`module_resolver.py`, `reference_corpus.py`) runs on the ELF one-shot path in
`source_parity_one_shot.py`, but the default product entrypoint
(`agentdecompile-reconstruct` → `frontdoor.py` → `pipeline.py` `RecoveryRunner`)
does not call it. That path inventories, generates bounded synthesis tasks, and
dumps — with decompiler facts only if acquisition already supplied them. So the
default experience is the thin one, which is why the output feels simplistic.

External practice is unanimous on the fix: Hex-Rays, Binary Ninja, and Ghidra's
own RTTI class recovery all treat missing type information as the primary cause
of unreadable decompilation, and apply types/names *before or during* decompile
rather than cleaning text afterward. 2025-26 research (SK²Decompile, DeGPT,
DecLLM) converges on the same two-phase shape — recover structure first, then
naming — with compile/semantic gates on any LLM-assisted naming.

## Key Decisions

**Enrich the database before decompile, rather than post-processing text.**
Applying signatures, structs, and class types into the program collapses casts
and reveals fields in every function that touches them, and the improvement
compounds across callers. Text cleanup alone cannot recover a type that was
never applied, so it hits a cosmetic ceiling. Post-decompile cleanup
(noise-strip, module clustering) is still included, but as a finishing step on
top of enrichment, not the primary mechanism.

**Readability is advisory and never implies parity.** Names, types, and module
paths are recovered evidence, not proof. A function only enters `verified/` at
objdiff 0. Readable-but-unverified functions live in the advisory / `Port/CODE`
layers with honest banners. This preserves the existing claim taxonomy
(`objdiff-verified-semantic`, `byte-authoritative`, `advisory-decompiler`,
`context-hint`).

**Frame recovery as skeleton-then-skin.** Structure (types, structs, RTTI/vtable
classes, control-flow shaping) is phase one; identifiers and module layout are
phase two. This makes readability measurable via a gate and keeps the
verified/advisory separation clean.

**A readability score gates `Port/CODE` inclusion.** A function reaches the
readable module tree only when it clears an evidence bar (non-default name plus
a non-fallback module). Everything else stays in the advisory layer. This exists
today (`passes_readability_gate`) and becomes the standard governor rather than
an ELF-only detail. A numeric score with a tunable cutoff is optional later;
v1 ships the existing boolean gate.

**Enrichment is default-on for `agentdecompile-reconstruct`.** Cold-run wall
time rises because a live PyGhidra enrich session is required. A skip/fast flag
may exist for operators who only need inventory or match receipts, but the
default product path produces enriched, readable decompiles.

## Requirements

### Enrichment before decompile

- R1. The default `agentdecompile-reconstruct` path applies recovered names,
  signatures, and types into the Ghidra database before bulk decompile, so
  emitted C is typed and named at the source rather than patched afterward.
- R2. Enrichment ordering is load-bearing and deterministic: boundaries →
  types/structs → names → decompile. Naming precedes decompilation so the
  decompiler emits the recovered identifiers.
- R3. Names applied before decompile come from ranked evidence — non-default
  Ghidra symbols (imports, FLIRT/library matches, user labels) first, then
  RTTI/corpus-derived class-qualified names — and each carries a provenance tag.
- R4. Type and struct recovery applies recovered aggregate shapes (fields,
  sizes) so member access renders as `obj->field` rather than raw offset
  arithmetic, when evidence for the shape exists.

### C++ class recovery (PE parity with ELF)

- R5. PE targets recover MSVC-style RTTI, class hierarchies, and vtables and
  apply class data types before decompile, reaching parity with the existing
  ELF Itanium-ABI path.
- R6. Recovered vtable slots map to method names where evidence (corpus,
  demangled symbols) supports it; unmapped slots render as stable placeholder
  slot names rather than being dropped.

### Module layout

- R7. Functions are grouped into readable modules from ranked evidence —
  embedded source-path / `__FILE__` strings and their xrefs, RTTI class →
  module association, and call-graph affinity — instead of a single flat file or
  one `recovered/unmapped` bucket.
- R8. Module mapping runs for both PE and ELF and produces a module-map receipt
  the dump consumes; functions without evidence fall back to a clearly labeled
  unmapped module.

### Dump readability

- R9. The dump strips Ghidra decompiler noise (WARNING banners, library-match
  comment blocks) from `Port/CODE` and advisory bodies while preserving a single
  honest authority banner per unit.
- R10. A readability gate governs `Port/CODE` inclusion: a function enters the
  readable tree only with a non-default name and a non-fallback module;
  everything else remains in the advisory layer.
- R11. Recovered source follows a consistent, readable house style (brace
  style, formatting) applied uniformly across verified, advisory, and Port
  layers.

### Honesty invariants (unchanged, restated as guardrails)

- R12. Readability signals (named count, module-resolved count, readability
  score) are advisory metadata and never inflate the proof ladder numerator.
- R13. Byte emitters, inline asm, `.incbin`, and copied target bytes are never
  promoted into `verified/` regardless of readability.

## Acceptance Examples

- AE1. Covers R1, R2, R3. **Given** a function the decompiler would name
  `FUN_00401000` with an import call to a known API, **when** the default path
  enriches then decompiles, **then** the emitted C uses the evidence-derived
  name and the fact records its provenance — not the raw `FUN_` stem.
- AE2. Covers R4. **Given** a function that accesses a recovered struct's field
  at a known offset, **when** the struct type is applied before decompile,
  **then** the body renders `obj->field_name` rather than
  `*(int *)(param_1 + 8)`.
- AE3. Covers R5, R6. **Given** a PE with MSVC RTTI, **when** class recovery
  runs, **then** the recovered class type is applied and its methods render as
  class-qualified functions with vtable slots named where evidence exists.
- AE4. Covers R7, R10. **Given** a function whose body xrefs an embedded
  `.../CODE/foo/bar.cpp` string, **when** module mapping runs, **then** the
  function is placed under the corresponding readable module and — if also named
  — clears the readability gate into `Port/CODE`.
- AE5. Covers R9. **Given** decompiler output containing `/* WARNING: ... */`
  and `/* Library Function ... */` banners, **when** the dump styles it, **then**
  those banners are removed from the body and a single authority banner remains.
- AE6. Covers R12, R13. **Given** a readable-but-unverified function, **when**
  the proof ladder is computed, **then** the function does not count toward the
  verified numerator and is not written under `verified/`.

## Success Criteria

- A sampled function in `Port/CODE` reads as typed, named C: a human reviewer
  can tell what it does without cross-referencing the disassembly.
- Named-function share and module-resolved share on a default run rise
  materially versus the current baseline (measured from the dump manifest, which
  already reports `namedCount` / `moduleResolvedCount`).
- No Ghidra WARNING / library-match banners remain in `Port/CODE` bodies.
- The proof ladder and `verified/` contents are unchanged by readability work —
  readability adds no verified claims.
- PE targets produce class-shaped output where RTTI exists, not `void*` soup.

## Scope Boundaries

### Deferred for later

- LLM-assisted naming / "skin" as a default mechanism. Allowed only later as an
  opt-in, compile-and-semantic-gated advisory pass; it is not how readability is
  achieved in this scope.
- Advanced control-flow structuring (SAILR-style goto reduction). Desirable and
  noted by research, but a separate track from type/name enrichment.
- DWARF/PDB ingestion as a first-class naming source. Valuable when symbols
  exist; treated as an additional evidence feed after the core enrichment path
  lands.
- Cross-binary name/type reuse (propagating recovered names between related
  targets).
- Numeric readability score with a tunable cutoff (v1 uses the existing
  name+module boolean gate).
- Adjacent improvement tracks outside this readability slice (still valuable,
  planned separately): unifying one-shot enrichment into reconstruct so the
  default path is not a thinner shell; raising proof-ladder coverage beyond
  bounded synth; a stronger autonomous vacuum/repair loop for agents.

### Outside this product's identity

- Presenting readable-but-unverified output as recovered/matched source. The
  verified/advisory split is the product's core honesty promise.
- Near-term whole-binary semantic parity claims. The ladder stays 1% → 5% → 20%.
- Any second product brand or recovery from the archived Mizuchi tree.

## Dependencies / Assumptions

- A live PyGhidra enrich session on the default path is accepted; cold-run time
  may rise. An optional skip/fast flag is allowed for operators who do not need
  readable decompiles, but enrichment remains the default.
- The existing ELF enrichment machinery
  (`pyghidra_enrich.py`, `rtti_recover.py`, `module_resolver.py`,
  `reference_corpus.py`) is the reuse base; PE MSVC RTTI/class recovery is the
  primary net-new component.
- Dump-manifest metrics (`namedCount`, `moduleResolvedCount`,
  `readabilityExcludedFromPort`) are the measurement surface.
- The reference corpus is optional; binary-only evidence (symbols, RTTI,
  strings, call graph) must still produce readable output.

## Outstanding Questions

### Deferred to planning

- Where PE MSVC RTTI recovery sources its class data (Ghidra's built-in RTTI
  analysis vs a dedicated recover pass).
- How module mapping reconciles conflicting evidence beyond the current ranked
  resolver (assert-string vs RTTI vs call-graph vote).
- Exact shape of an optional skip-enrichment / fast flag for reconstruct.

## Sources / Research

- Repo pipeline split — default `RecoveryRunner`
  (`src/agentdecompile_recovery/pipeline.py`, `frontdoor.py`) vs the richer
  `source_parity_one_shot.py` enrichment path; enrichment modules
  `pyghidra_enrich.py`, `rtti_recover.py`, `module_resolver.py`,
  `reference_corpus.py`; dump + gate in `source_dump.py`
  (`passes_readability_gate`). Vocabulary and honesty invariants in
  `STRATEGY.md`, `docs/CRITICAL_PATH.md`, `AGENTS.md`.
- Type-first decompilation: Hex-Rays decompiler docs and rename/retype tips;
  Binary Ninja type guide ("missing type information is the biggest culprit of
  bad decompilation"); Ghidra `RecoverClassesFromRTTIScript` for class/vtable
  recovery.
- Control-flow readability: SAILR (USENIX Security 2024) — structural fidelity
  over goto-count.
- Matching / proof loop: `objdiff`, `decomp.me`, splat/dtk workflows; Mizuchi
  agent matching writeup — compile + objdiff as the accept gate.
- Two-phase and LLM-refine research: SK²Decompile (skeleton then skin), DeGPT
  (NDSS 2024, semantic-guarded rename/simplify), DecLLM (ISSTA 2025, compile +
  runtime feedback).
