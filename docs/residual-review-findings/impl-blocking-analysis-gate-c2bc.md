# Residual review findings — `impl/blocking-analysis-gate-c2bc`

**Plan:** [docs/plans/2026-05-24-blocking-program-analysis-gate.md](../plans/2026-05-24-blocking-program-analysis-gate.md)  
**Code review plan:** [docs/plans/2026-05-24-blocking-analysis-code-review.md](../plans/2026-05-24-blocking-analysis-code-review.md)  
**PR:** [#39](https://github.com/bolabaden/AgentDecompile/pull/39) — **merged** into `master`  
**LFG pass:** [docs/plans/2026-05-24-lfg-strategy-doc-code-review.md](../plans/2026-05-24-lfg-strategy-doc-code-review.md)  
**Follow-up:** `STRATEGY.md` and doc-only commits land via `impl/post-merge-strategy-docs-c2bc`

## Residual Review Findings

**Residual actionable work: none.** (P3 post-merge / docs-only items below.)

### Closed in branch (2026-05-24 review pass)

- **P2** | `project.py` | `_blocking_ensure_program_analyzed` no longer swallows failures
- **P2** | `program_analysis.py` | Idle wait raises `ProgramAnalysisTimeout` (fail-closed)
- **P1** | `import_export.py` | `analyzeAfterImport=false` skips import-time analyze by design; in-session ensure on open/checkout/import
- **P1** | `tool_providers.py` | `ProgramAnalysisTimeout` → structured MCP `analysis-timeout` error
- **P2** | `tool_providers.py` | Requested `programPath` no longer falls back to session active program for gate/wait
- **P0/P1** | `tests/test_tool_providers_analysis_gate.py` | Gate invoke/skip, autoprereq bypass, timeout error, programPath resolution

### Still open (downstream)

- **P3** | e2e | Canonical `/lfg` post-merge (`scripts/lfg_validation.py` or driver)
- **P3** | docs | Align `docs/IMPORT_EXPORT_GUIDE.md` with in-session ensure semantics
- **P3** | `program_analysis.py` | Optional lock map pruning for long-lived servers
- **P3** | `program_analysis.py` | Consider exempting VC tools (`checkout-program`, `checkin-program`) from redundant gate waits

### Filed (prior)

- [#40](https://github.com/bolabaden/AgentDecompile/issues/40) openAllPrograms — fixed in branch
- [#41](https://github.com/bolabaden/AgentDecompile/issues/41) fallback import — fixed in branch
