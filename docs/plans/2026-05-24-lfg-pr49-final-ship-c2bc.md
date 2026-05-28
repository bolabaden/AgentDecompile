---
title: LFG — PR #49 final ship (CI fix + doc closeout)
type: fix
status: completed
date: 2026-05-24
branch: impl/agent-native-audit-c2bc
pr: https://github.com/bolabaden/AgentDecompile/pull/49
origin: docs/residual-review-findings/impl-agent-native-audit-c2bc.md
---

# LFG — PR #49 final ship (CI fix + doc closeout)

## Summary

All P1–P3 audit slices are implemented. CI headless jobs fail on a **stale advertised-tool count (55 vs 56)** after `manage-enums`. Fix the test/docs drift and refresh audit/residual closeout rows so PR #49 is merge-ready.

---

## Requirements

- R1. Fix `test_default_surface_advertises_all_non_gui_canonical_tools` — remove hardcoded `55`; assert dynamic count.
- R2. Update README/USAGE advertised-tool count (55 → 56).
- R3. Refresh audit doc top-10 and scorecard rows for completed P1–P3 work.
- R4. Unit + headless parity test pass locally.
- R5. Residual doc ship gate notes CI fix.

---

## Implementation Units

- U1. Fix `tests/test_canonical_tool_parity.py` assertion.
- U2. Update `README.md`, `USAGE.md` tool counts.
- U3. Update `docs/audits/2026-05-24-agent-native-audit.md` completed rows.
- U4. Residual doc ship gate note.

## Verification

```bash
uv run pytest tests/test_canonical_tool_parity.py tests/test_tool_surface_curated.py -m unit -q --timeout=60
uv run pytest -m unit -q --timeout=120
```
