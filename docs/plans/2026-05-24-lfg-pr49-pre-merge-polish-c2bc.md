---
title: LFG — PR #49 pre-merge doc polish
type: fix
status: completed
date: 2026-05-24
branch: impl/agent-native-audit-c2bc
pr: https://github.com/bolabaden/AgentDecompile/pull/49
origin: docs/residual-review-findings/impl-agent-native-audit-c2bc.md
commit: df6b0cc
---

# LFG — PR #49 pre-merge doc polish

## Summary

PR #49 is merge-ready; all P1–P3 + P2-4 items are Done. Fix remaining **canonical tool count drift (59→60)** in README, archive superseded architecture review doc, and add a **PR summary fallback** in the residual tracker (gh pr edit blocked).

## Flow

```mermaid
flowchart TD
    R1[README 59→60 canonical count] --> V[uv run pytest -m unit]
    R2[Superseded banner on prior review] --> V
    R3[Residual PR #49 merge summary] --> V
    V --> H[Human squash-merge PR #49]
```

---

## Requirements

- R1. README: update canonical tool count 59 → 60 (mermaid + prose); keep 56 advertised.
- R2. Add superseded banner to `docs/agent-native-architecture-review-2026-05-24.md` pointing to the May 24 audit.
- R3. Residual doc: add PR #49 summary section for merge reviewers.
- R4. Unit tests pass locally; PR #49 CI green on required checks.

---

## Scope Boundaries

- **In scope:** Doc drift fixes, merge reviewer summary.
- **Out of scope:** Merge to `master` (human); new features; MCP resource work.

---

## Implementation Units

- U1. Fix README tool counts (`README.md` lines ~16, ~753).
- U2. Superseded banner on prior review doc.
- U3. Residual doc PR summary for reviewers.

## Verification

```bash
uv run pytest -m unit -q --timeout=120
gh pr checks 49
```
