---
title: LFG PR #44 — dispatch fast-path and ship docs
status: completed
note: superseded by ship-fastpath plan for final commit
created: 2026-05-24
pr: https://github.com/bolabaden/AgentDecompile/pull/44
---

# LFG PR #44 — dispatch fast-path and ship docs

## Objective

Reduce redundant Ghidra polling on the hot MCP dispatch path when a program is already analyzed, and document how to verify/merge [#44](https://github.com/bolabaden/AgentDecompile/pull/44).

## Flow

```mermaid
flowchart TD
    P[Plan] --> F[wait_for_ready idle skip when session analyzed]
    F --> T[Unit test + tests/README]
    T --> S[PR #44 ship checklist in residual doc]
    S --> V[pytest gate]
    V --> PUSH[commit push]
```

## Requirements traceability

| ID | Requirement | Verification |
|----|-------------|--------------|
| R1 | `wait_for_program_analysis_ready` skips idle wait when session marked analyzed and Ghidra agrees | Code + unit test |
| R2 | `tests/README.md` documents gate tests and CI unit workflow | Doc section |
| R3 | Residual doc includes PR #44 merge verification commands | `impl-blocking-analysis-gate-c2bc.md` |
| R4 | No regressions | `pytest -m unit -q` |

## Verification

```bash
uv run pytest tests/test_program_analysis_gate.py tests/test_tool_providers_analysis_gate.py -m unit -q
```
