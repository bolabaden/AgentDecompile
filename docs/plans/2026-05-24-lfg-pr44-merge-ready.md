---
title: LFG PR #44 — merge-ready hardening
status: completed
created: 2026-05-24
pr: https://github.com/bolabaden/AgentDecompile/pull/44
---

# LFG PR #44 — merge-ready hardening

## Objective

Finalize [#44](https://github.com/bolabaden/AgentDecompile/pull/44) for merge: exception-safe lock cleanup, maintainability in `program_analysis.py`, clarify shared-import `analyzeAfterImport=false` responses, close stale doc-review items.

## Flow

```mermaid
flowchart TD
    P[Plan] --> L[try/finally lock release]
    L --> R[Consolidate Ghidra utilities checks]
    R --> I[Shared import response hint]
    I --> D[Close doc-review open items]
    D --> V[pytest gate unit]
    V --> PUSH[commit push]
```

## Requirements traceability

| ID | Requirement | Verification |
|----|-------------|--------------|
| R1 | Locks released on analysis exceptions | `try`/`finally` around locked sections |
| R2 | Single Ghidra utilities helper | `_ghidra_utilities_pending()` used by needs/running |
| R3 | Shared import documents deferred in-session ensure | `inSessionAnalysisPending` in success payload when `analyzeAfterImport=false` |
| R4 | Doc-review findings reflect merged fixes | Update `docs/doc-review-findings/2026-05-24-blocking-program-analysis-gate.md` |
| R5 | Tests pass | Gate unit pytest |

## Out of scope

- Full LFG e2e (Ghidra Server in CI)
- Changing workflow branch filters (`main` vs `master`)

## Verification

```bash
uv run pytest tests/test_program_analysis_gate.py tests/test_tool_providers_analysis_gate.py -m unit -q
```
