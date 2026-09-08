---
name: AgentDecompile
last_updated: 2026-09-08
charter: VISION.md
---

# AgentDecompile Methodology

Charter: [VISION.md](VISION.md). Near-term investment map: [STRATEGY.md](STRATEGY.md). This file is the durable how — principles that should survive pipeline rewrites, plus the mechanisms we use today.

## Part I — Core principles

These stay valid if the recovery pipeline, UI, tool surface, compiler targets, or module layout change.

### 1. Treat binaries as structured context

The point is legibility for humans and agents — executable layout, packages, resources, functions, symbols, types, relationships, debug info, recovered source, and verification evidence. Perfect reconstruction is not required for a useful result. Partial structure already pays.

### 2. Ground everything in evidence

Bytes and observable program state are authoritative. Decompiler text, names, types, comments, symbols, debug info, source candidates, and model output are witnesses on that reality. They must not silently replace it.

### 3. Preserve provenance

Every important fact keeps where it came from, which artifact or address it refers to, which tool or witness produced it, its claim boundary, and competing evidence when it exists. Unknown or conflicting information stays visible — not papered over by invention.

### 4. Never blur claim levels

Useful information and proven information are different.

| Layer | Meaning |
|---|---|
| **Verified** | Survived the required hard proof. |
| **Readable / compiling** | Useful reconstructed source — not necessarily identical to the original. |
| **Advisory** | Inferred, decompiled, generated, or otherwise unproven. |
| **Context hint** | Symbols, notes, names, debug info, and related witnesses. |
| **Byte-authoritative** | Exact target bytes — not recovered authored source. |

Readability does not imply parity. Compilation does not imply parity. Job completion does not imply parity. Model confidence does not imply parity.

### 5. Compose capabilities; do not funnel

Dismantling, triage, analysis, decompilation, matching, type recovery, synthesis, compilation, verification, and export stay independently useful. Recovery is one recipe over the substrate, not the product identity.

### 6. Partial work must pay

A failed or incomplete stage narrows evidence and lowers the claim tier. It does not erase prior useful output. Legitimate partials include package trees, section layout, function inventory, call graphs, typed decompilation, advisory source, partial logical matching, or a named blocker.

### 7. Escalate analysis only when necessary

Use the cheapest method that answers the question. Do not pay for deep Ghidra analysis when static inspection suffices. Do not re-run `analyze-program` on a program that already has analysis; open that project and use the functions already there. Do not mutate analysis state when read-only evidence suffices. Do not invoke semantic recovery when structure already answers the task.

### 8. Recover knowledge once, then propagate

When several binaries share logical code, recovery targets the shared logical entity — not every address in isolation. Names, types, annotations, source, and verified knowledge propagate through stable identity when the evidence allows.

### 9. Solve global uncertainty before local uncertainty

Compiler identity, optimization, ABI, calling conventions, and structure layouts affect thousands of functions. Expression shape, temporaries, inlining, and control-flow idioms are local. Local search cannot converge while global assumptions are wrong — fix globals first.

### 10. Turn failures into information

A failed comparison is not a scalar “wrong.” Diff shape should drive the next move: compiler mismatch, type layout, calling convention, inlining, local source shape, boundary error, or a poor target for more spend. Failure should reduce uncertainty.

### 11. Spend compute where convergence is plausible

Not every unresolved function deserves equal effort. Near-complete candidates get focused work before wholesale divergences. Prioritize by expected value, not inventory order alone.

### 12. Deterministic methods before creative search

Before an agent or model rewrites source, exhaust cheaper explainable paths: compiler/profile variation, mechanical transforms, known idioms, propagated sibling knowledge, structural correction. Creative rewriting is a challenger lane, not the opening move.

### 13. Models propose; tools prove

Models may generate names, source, hypotheses, transforms, and repair ideas. Correctness comes from external mechanical proof — not from the model.

### 14. Keep autonomous work bounded and auditable

Autonomous recovery needs explicit budgets, queues, iteration history, stop conditions, and named terminals. Infinite retry and silent exit are both failures.

### 15. A named failure beats fake success

`near-miss`, `budget-stop`, `readability-blocked`, `bridge-failed`, and other precise terminals tell the next operator or agent what is actually wrong.

### 16. Validate theory against the real toolchain

A plausible heuristic is untrusted until it survives the actual compiler, linker, object format, and comparison pipeline. When empirical A/B contradicts the plan, the implementation follows the evidence.

### 17. Engineer context for agents

Agents get structured evidence — hypothesis, trusted and untrusted witnesses, prior attempts, prior diffs, dependencies, structures, sibling functions, and the acceptance gate — not a wall of pseudocode. Prompt shape must preserve trust boundaries.

### 18. One system for humans and agents

Workbench, CLI, HTTP API, MCP tools, and autonomous loops converge on the same capabilities and state. No hidden agent-only workflow.

### 19. Interface design preserves epistemic honesty

The UI must not dress weak evidence as strong. A finished job is not a verified match. Green progress is not proof. Readable C is not byte identity. A successful import is not successful recovery. Visual language matches backend claim tiers.

### 20. Design for stable operator cognition

RE work depends on spatial and contextual memory. Favor stable layout, dense information, predictable navigation, persistent selection, restrained hierarchy, and clear separation between data, action, notification, and proof.

### 21. Build for accretion

Perfect arbitrary round-tripping is a long horizon. Every improvement in extraction, analysis, typing, identity, source generation, verification, and context engineering should pay off immediately without waiting for the whole machine.

---

## Part II — Current mechanisms

These realize Part I today. They may change without rewriting the principles.

### Tiered analysis routing

Four practical tiers:

| Tier | Implementation |
|---|---|
| **0** | File triage, strings, metadata, external scans |
| **1** | Batch/offline decompilation, BSim, SAST, snapshots |
| **2** | Ghidra read-only MCP operations |
| **3** | Deep Ghidra analysis and mutation |

Typical path: cold binary → Tier 0 → Tier 1 if useful → analyzed Ghidra session → Tier 2 → Tier 3 only when needed. Multi-agent workflow maps to Planner → Worker → Critic → Aggregator.

### Context acquisition and fusion

Reconstruction accepts mixed evidence: binaries, Ghidra projects, source dumps, notes, JSON/JSONL, debug info, archived context. Evidence lands procedurally by address or path; unplaced material stays unplaced; conflicts keep all witnesses. Source dumps may seed advisory source — they do not become verified output.

### Enrich-before-decompile

Readability flow applies analysis improvements before bulk decompilation: boundaries → types/structures → names → decompile. Evidence may come from curated Ghidra state, symbols, RTTI, debug info, module evidence, or cross-binary context. Structure improves decompiler output instead of polishing bad pseudocode after the fact.

### Readability scoring and repair

Functions carry advisory readability scores. A boolean gate controls entry to the readable output tree; functions below it enter a ranked repair queue (rename, module refresh, re-enrich/decompile). After repair, enrichment reruns and the queue rebuilds. Readability repair does not change proof coverage by itself.

### Cross-build logical identity

Related corpora bind concrete functions to shared `logical_id`s via strong names, STABS/debug info, strings/constants/imports, decompiled shape, BSim, and only then a unique byte window. A virtual address is an instance, not the identity. Knowledge moves through the logical entity instead of copying nearby instruction blobs from one exe into another.

### Corpus recovery ladder (current order)

1. Logical identity (skip `analyze-program` when the program already has analysis)
2. Global calibration (compiler, flags, ABI, layouts)
3. Assembly floor (donor link; not byte identity)
4. Compiling Ghidra C
5. Cross-place successful C
6. Expensive semantic recovery for leftovers only
7. Byte-accuracy audit

Skip a rung when its receipt or Ghidra state already exists. Stages stay conceptually separate; promotion across tiers requires the matching proof bar.

### Compiling substrate

A donor workspace may use `_emit` or equivalent assembly as a temporary compilation floor so the project links before every function has readable C. Real C replaces substrate on success; assembly fallback remains on failure. Scaffolding — not source-recovery credit.

### Compiler calibration

Prefer calibration over guessing. Known-source functions (e.g. runtime-library code when available) compile under candidate compiler and flag combinations; generated objects compare to shipped functions. The best corpus-wide match identifies the likely build configuration.

### Structure recovery

Layouts are testable hypotheses from curated structures, observed offsets, access widths, RTTI, and cross-build agreement. Candidate layouts are checked against observed accesses — not accepted because they look plausible.

### Dependency-ordered recovery

Attack call-graph leaves before callers. A known callee constrains callers. Investigate inlining before burning large candidate budgets on structurally blocked callers.

### Compile-and-diff loop

Every source candidate: candidate → compiler → object → objdiff → classified result. Only the accepted comparison path promotes verified source; everything else stays advisory.

### Mismatch classification

Routing uses instruction-level objdiff evidence, not total difference counts alone. Classes feed permuter, shape search, boundary repair, prototype repair, compiler-profile correction, or deferral. Diff shape drives the repair action.

### Proof-target queue

Unverified functions rank by semantic source availability, size, synthesis eligibility, and prior near-miss evidence. A recent small near miss can outrank a cold function with similar size.

### Proof ladder

Progress rungs (e.g. 1% → 5% → 20%) expose how many additional verified functions reach the next rung. The numerator is receipt-backed hard verification only.

### Autonomous proof campaigns

Bounded loop: queue seed → candidate generation → compile → objdiff → receipt → ladder check. Limits include functions per campaign, campaign count, attempts, and wall time. Terminals include accepted, near-miss, budget-stop, empty-queue, readability-blocked, bridge-failed.

### Autonomous advisory repair

Around proof campaigns, the agent loop may apply contextual labels, PDB/DWARF symbol ingest, readability repair, re-enrichment, and near-miss repair. Mutations go through existing MCP/Ghidra conflict handling.

### Challenger mechanisms

Difficult near misses use staged challengers: (1) compiler flags/profiles/pragmas, (2) mechanical source transforms, (3) agent rewrite after cheaper paths fail. The agent receives candidate, target evidence, and mismatch detail — not raw bytes alone.

### Agent rewrite queue

Creative rewriting sits outside the Python recovery runtime. Python emits a typed rewrite request; a live agent session returns a candidate; the next campaign verifies through the ordinary compile/objdiff path. No alternate proof path for agent-generated source.

### Real-toolchain A/B testing

Recovery-rule changes that depend on compiler output validate with real compilers and real objdiff. Relocation-evidence work established one lesson: symbolic relocation metadata helps only when the candidate representation produces a corresponding relocation — literal pointer casts may not. Test results overrule design assumptions.

### Caching and parallelism

Repeated deterministic compilation caches on source + compiler configuration → object/result. Parallel toolchain work isolates mutable execution state (e.g. Wine environments) so parallelism cannot create false mismatches.

### Shared action catalog

Workbench, MCP, API, CLI, and automation converge on the same action definitions: current selection/context → catalog action → job → persistent evidence/state update. No independently maintained browser-only workflow.

### Workbench interaction model

Dense RE instrument, not a dashboard: explorer/project hierarchy, functions with stable address/name columns, compact chrome, document-style editor, contextual actions, peripheral jobs, command palette, explicit dialogs. Sidebar follows Ghidra/IDA conventions. Editor keeps real surfaces visible; tabs navigate rather than hide content.

### CSS ownership model

Cascade split: layout → tokens → controls → specialized widget styles. Specialized files own chrome, sidebar, editor, dialogs, overlays. Legacy `workbench.css` retains structure; conflicting visual rules are neutralized elsewhere.

### Design tokens

Shared tokens own surfaces, foreground levels, accent, focus, hover/press, danger, selection, address coloring, kind coloring, and z-index layers. Components consume tokens instead of inventing local colors.

### UI honesty rules

Completed jobs avoid success-green. Toast completion is not match confirmation. Status/pulse stays restrained. Byte verification looks distinct from generic progress. The jobs dock keeps: **“A finished job is not a match.”**

### Spatial consistency

Avoid responsive transforms that destroy operator memory: fixed function address/name columns, column project trees, compact single-row toolbar, stable editor/tab regions, predictable jobs location. Repeated navigation should become automatic.

### UI verification

Structural checks cover expected selectors, token-only styling, forbidden rounded-card patterns, stable grid columns, and surfaces staying visible. Live browser verification is required before claiming visual or interaction correctness — CSS-only checks are not browser proof.

---

## Compact summary

**Principles:** Binary reality is authoritative. Preserve provenance. Keep claim tiers separate. Make partial work useful. Compose capabilities. Escalate analysis only when necessary, and never re-analyze a program that already has it. Recover shared logical knowledge once. Solve global uncertainty before local search. Turn failures into diagnostic feedback. Spend compute where convergence is plausible. Models propose, tools prove. Bound autonomy. Name every stop. Let real toolchains overrule theory. One coherent system for humans and agents. The interface reflects the same honesty model.

**Mechanisms (today):** Tiered RE → context fusion → enrich-before-decompile → readability repair → logical identity → compiling substrate → Ghidra-C replacement → cross-place → proof-target ranking → compile/objdiff → mismatch routing → bounded proof campaigns → deterministic challengers → queued agent rewrites → hard verification. Workbench implements the human side as a dense, stable RE surface on the same action/state model, with componentized CSS and explicit separation between selection, progress, completion, and proof.
