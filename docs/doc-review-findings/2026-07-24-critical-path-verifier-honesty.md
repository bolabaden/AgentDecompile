# Doc review finding: CRITICAL_PATH honesty vs verifier code

**Date:** 2026-07-24  
**Document reviewed:** `docs/CRITICAL_PATH.md`  
**Reviewers:** coherence, feasibility, adversarial (ce-doc-review)

## Finding report (code contradicts published claim)

The runbook and README state that `verified/` is **objdiff 0 only** and that parallel workers can produce a false mismatch but **never a false proof**. The verifier does not enforce that.

| Path | Behavior | Effect on `verified/` |
|------|----------|------------------------|
| `parse_objdiff_report` | `elif not output.strip(): differences = 0` when exit code is 0 | Empty stdout scored as a match |
| `run_objdiff` | On `status == "error"`, substitutes `compare_objdump_code_bytes` | Fallback rows carry `"fallback": "objdump-disassembly-byte-compare"` with `status: matched`, `differences: 0` |
| `is_proven_zero` | Checks only `differences == 0` and status ∈ {matched, code-slice-*, source-shape-*} | **Ignores** `fallback` — fallback rows promote to `verified/` |

Evidence anchors:

- `src/agentdecompile_recovery/source_parity_synthesize.py` — `parse_objdiff_report`, `run_objdiff`, `compare_objdump_code_bytes`
- `src/agentdecompile_recovery/match_cache.py` — `is_proven_zero`

**Do not** rewrite operator docs to treat the fallback as the intended product. Fix the gate (fail-closed empty output; never promote fallback into `verified/` / `is_proven_zero`) then re-audit existing dumps.

## Secondary code risks (from adversarial review)

1. Compile `ok` when `object_path.exists()` without unlinking first — resume + Wine flake can gate against a prior artifact.
2. Match cache key is `(entry, sourceSha256)` with no analysis-image / inventory digest — proofs can survive a changed unpack at the same entry.
3. Byte-emitter denylist misses `_asm`, MASM `db`/`dw`/`dd`, const-blob+memcpy shapes.
4. Ladder denominator falls back through inventory symbol counts and can shrink silently.

## Doc-side status

Mechanical runbook fixes from this review were applied to `docs/CRITICAL_PATH.md` (diagram, `--source-synthesis msvc`, receipt wiring, dump verify checklist, `verified/` path disambiguation). Hard-rule overclaims are queued as gated/manual decisions for the operator — not silent-rewritten to match the bug.
