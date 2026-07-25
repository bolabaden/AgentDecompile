# Verifier honesty vs CRITICAL_PATH claims

**Date:** 2026-07-24 
**Reviewed:** `docs/CRITICAL_PATH.md`

## Problem

The runbook says `verified/` means objdiff zero and that parallel workers cannot create false proofs. The code does not fully enforce that today.

| Code path | What happens | Risk |
|-----------|--------------|------|
| `parse_objdiff_report` | Empty stdout with exit 0 → `differences = 0` | Empty output counted as match |
| `run_objdiff` | On error, falls back to `compare_objdump_code_bytes` | Fallback rows get `matched`, `differences: 0` |
| `is_proven_zero` | Only checks `differences == 0` and status | Ignores `fallback` — fallback can land in `verified/` |

Relevant files: `source_parity_synthesize.py` (`parse_objdiff_report`, `run_objdiff`), `match_cache.py` (`is_proven_zero`).

**Action:** Fix the gate in code (reject empty objdiff; exclude fallback from `is_proven_zero`). Do not change operator docs to bless the fallback as intended behavior. Re-audit dumps after the fix.

## Other risks flagged in review

1. Compile marked ok when an object file already exists (stale artifact after resume)
2. Match cache key `(entry, sourceSha256)` omits analysis-image digest
3. Byte-emitter filter misses `_asm`, MASM `db`/`dw`/`dd`, some const-blob patterns
4. Proof ladder denominator can shrink via inventory fallbacks

## Doc updates from this review

Runbook fixes applied: pipeline diagram, `--source-synthesis msvc`, receipt wiring, post-dump checklist, `verified/` path notes. Hard-rule wording stays accurate to intent; code fixes tracked in the living perf plan.
