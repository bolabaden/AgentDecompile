---
name: AgentDecompile
last_updated: 2026-07-13
---

# AgentDecompile Strategy

## Target problem

Reverse engineers sit on a pile of partial truth—binaries, Ghidra projects, dumps, notes, and half-recovered source—that never composes into one representation they can trust enough to rebuild and change. Format hops lose fidelity, and nothing closes the loop between “looks right” and “matches the original object.”

_Worth revisiting:_ problem statement was inferred after a deferred interview; confirm the primary pain is still *unverifiable multi-artifact recovery* vs *missing pretty decompiler output*.

## Our approach

Treat recovery as **context-first multi-representation transpilation with proof gates**: ingest supported context, keep Ghidra (and binary inventory) as ground truth, generate candidates across natural formats (asm, C/C++, and higher-level views), and accept only what survives compiler-in-the-loop / objdiff (or an equally strong claim boundary)—so “transpiled” never means unverified paraphrase.

## Who it's for

**Primary:** Matching-decomp reverse engineers and RE agents recovering Windows/game EXEs (and ELF/Mach-O peers) — they're hiring AgentDecompile to turn a binary plus optional context into verified, rebuildable high-level source they can compile and work with.

**Secondary:** Agent builders wiring MCP into RE workflows — they need session-stable Ghidra tools and an autonomous recovery loop that self-corrects instead of dumping pseudocode.

## Key metrics

- **Verified function parity** — share of inventoried functions accepted at objdiff 0 (or equivalent strong object gate); measured in target coverage receipts
- **Context merge yield** — fraction of acquired artifacts (notes, dumps, partial source, Ghidra exports) that update labels/data/functions without manual glue; measured in acquisition registry receipts
- **One-shot slice success** — rate at which a bounded recovery run produces lint-clean, compilable source for the requested slice with honest claim boundaries; measured in one-shot run reports
- **False-claim rate** — accepted artifacts that later fail a stronger gate (must trend down); measured in proof-ladder audits
- **Agent loop completion** — autonomous vacuum/repair cycles that terminate with either a verified match or an explicit failure class (not silent mush); measured in orchestrator state

## Tracks

### Acquisition and context fusion

One path to feed partial decomp, notes, Ghidra dumps, and project files into the current recovery target—updating symbols, data, and function candidates without ad-hoc guesswork.

_Why it serves the approach:_ Context is the input side of accurate multi-format transpilation; without fusion, every run starts from a cold binary.

### Ghidra MCP integrity

Session-stable PyGhidra MCP/CLI with honest analysis gates so agents mutate and read the same program state a human trusts in the UI.

_Why it serves the approach:_ Ground truth for labels and structure must be reliable before any “natural language” view is credible.

### Matching recovery and autonomy

Compiler-profile corpus, relocation-aware objects, candidate generation, and a self-correcting vacuum/repair loop that only promotes on proof.

_Why it serves the approach:_ This is how accuracy becomes tractable at scale instead of hoping a single LLM dump is right.

### Multi-format export with claim boundaries

Export and round-trip views (asm, C/C++, higher-level sketches, hex/authority packages, Ghidra-backed serialization) labeled by what is proven vs advisory.

_Why it serves the approach:_ Users want format fluidity; claim boundaries keep “anything” from becoming marketing for unverified mush.

## Not working on

- Claiming semantic source recovery from byte emitters, `.incbin`, or copied target bytes
- Treating decompiler pseudocode or LLM output as proof without a compile/objdiff (or stronger) gate
- Pretending ≥90% whole-binary semantic parity for targets like `swkotor.exe` is a near-term one-shot deliverable
- Shipping dual permanent product brands (mizuchi/reconkit) beside AgentDecompile—capabilities fold in; names do not
- Implementing this product inside unrelated repos (e.g. clifwrap)

## Marketing

**One-liner:** AgentDecompile turns binaries and messy RE context into verified, multi-format source you can actually rebuild—not pretty pseudocode.

**Key message:** Context in, proof out. Ghidra-backed ground truth, autonomous matching recovery, and honest claim boundaries across the formats reverse engineers already live in.
