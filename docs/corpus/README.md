# docs/corpus

This folder is the written form of the corpus pipeline. The code lives in
`src/agentdecompile_recovery/corpus/`. Operator commands and rules live in
the parent document: [CORPUS_PIPELINE.md](../CORPUS_PIPELINE.md).

How we build it: [../../docs/plans/2026-09-08-0156-feat-recovery-pipeline-ladder-plan.md](../plans/2026-09-08-0156-feat-recovery-pipeline-ladder-plan.md). Strategy: [../../STRATEGY.md](../../STRATEGY.md).

Skip a row when its receipt or Ghidra state already exists.

| Stage | What it does | What it does not do |
|---|---|---|
| extract | Read functions already pulled from each binary | Re-analyze a program that already has Ghidra analysis |
| identify | Bind the same function across builds to one `logical_id` (debug, content channels, BSim; byte-window last) | Copy C, or treat a VA as the identity |
| calibrate-global | Solve compiler, flags, ABI, and global layouts once | Tune matcher score/margin (`corpus calibrate`) |
| assembly-floor | One file per function; exact inline asm if no C; must link | Prove bytes |
| recover-source | Write Ghidra C; keep asm on compile fail | Copy C or claim `byte_exact` |
| apply-cross-build | Place compiling assembly-free C onto bound siblings | Place failing C or wrappers |
| leftover-recover | Targeted AI / genproject on stamped leftovers only | Decompile a `logical_id` that already has `real_c` |
| verify-byte-accuracy | Isolated objdiff vs the shipped binary | Confuse compile with match |

Old `--stop-after` names (`compile`, `generate-projects`, `merge-knowledge`, `preparse`, `llm-cleanup`) stay aliases for one release. `compile` means recover-source (C compiled), not the assembly-floor link.

A VA is an instance of a `logical_id`. `corpus.export-hookpack` writes `agentdecompile.hookpack/v1` from the identity store so a host (KotorPhasor, or a clone for another corpus) can resolve by signature when the recorded address is missing or stale.
