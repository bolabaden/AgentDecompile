---
title: LFG — PR #49 merge-ready (P2-4 capabilities + verification)
type: feat
status: completed
date: 2026-05-24
branch: impl/agent-native-audit-c2bc
pr: https://github.com/bolabaden/AgentDecompile/pull/49
origin: docs/residual-review-findings/impl-agent-native-audit-c2bc.md
---

# LFG — PR #49 merge-ready (P2-4 capabilities + verification)

## Summary

PR #49 has all P1–P3 implementation and CI green. Close the optional **P2-4 `/capabilities`** discovery gap, verify merge readiness, and update residual/plan docs so the branch is ready for human merge.

---

## Problem Frame

The agent-native audit residual tracker marks every P1–P3 item **Done**; only **merge to master** (human) and optional **P2-4 `/capabilities`** remain. CI previously failed on advertised-tool count drift — fixed in prior slice.

---

## Requirements

- R1. Add `.cursor/commands/capabilities.md` slash command listing MCP tools, prompts, and discovery surfaces (P2-4).
- R2. Cross-link `/capabilities` from `help.md` and audit discovery rows.
- R3. Residual doc marks P2-4 done and ship gate **merge-ready** with CI confirmation.
- R4. Mark stale active plan `docs/plans/2026-05-24-lfg-pr49-ship-c2bc.md` completed.
- R5. Unit + parity tests pass locally; PR #49 required CI checks green.

---

## Scope Boundaries

- **In scope:** Discovery command doc, residual/plan closeout, CI verification.
- **Out of scope:** Merge to `master` (human gate); `agentdecompile://capabilities` MCP resource; variable rename on `manage-function`.

---

## Implementation Units

- U1. **Create `/capabilities` command** — `.cursor/commands/capabilities.md` with tool categories, 56 advertised tools note, prompts list, env flags.
- U2. **Cross-links** — `help.md` Related docs; audit P2-4 row; residual P2-4 Done.
- U3. **Ship gate closeout** — residual doc merge-ready note; mark `lfg-pr49-ship-c2bc.md` completed.

## Verification

```bash
uv run pytest -m unit -q --timeout=120
gh pr checks 49
```
