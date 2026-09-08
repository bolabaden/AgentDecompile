---
name: source-recovery
description: "Use this skill when the user wants recovered C, objdiff, --dump-source, rematch, or reconstruct. Do not treat leftover target/ receipts as this run's source."
license: AGPL-3.0-or-later
metadata:
  author: AgentDecompile
  version: "1.0"
---

# Source recovery

This repo is the only active recovery cwd. Package: `src/agentdecompile_recovery/`.

## Rule

A run that is supposed to produce source must write inventory, facts, and match receipts **in that execution**. `--resume`, match cache, and `--dump-source-only` are for operators doing incremental work — not for agents skipping the pipeline.

## Defaults

- Entry: `agentdecompile-reconstruct` / `scripts/decomp-cli.sh`; corpus: `agentdecompile-corpus`.
- Fast dump: reconstruct with `--resume --dump-source DIR`. Default reconstruct runs PyGhidra enrich-decompile (`--skip-enrichment` to opt out).
- Never claim match without objdiff 0. Never promote byte-emitters into `verified/`.
- Profiles are format/stem-derived (PE vs ELF). Do not hardcode product binaries.
- Rematch intended → `--force-rematch`.

See `docs/CRITICAL_PATH.md` and `docs/CORPUS_PIPELINE.md`.
