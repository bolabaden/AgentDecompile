# Residual review findings — `impl/blocking-analysis-gate-c2bc`

**Plan:** [docs/plans/2026-05-24-blocking-program-analysis-gate.md](../plans/2026-05-24-blocking-program-analysis-gate.md)  
**Doc review:** [docs/doc-review-findings/2026-05-24-blocking-program-analysis-gate.md](../doc-review-findings/2026-05-24-blocking-program-analysis-gate.md)  
**PR:** [#39](https://github.com/bolabaden/AgentDecompile/pull/39)

## Residual Review Findings

### Code (ce-code-review)

- **P1** | `import_export.py:1004` | Shared PyGhidra import still honors `analyzeAfterImport=false` for in-process analyze
- **P1** | `import_export.py:1156` | Shared analyzeHeadless `-noanalysis` when flag false (in-session ensure must cover before mutating tools)
- **P2** | `project.py:3691` | `_blocking_ensure_program_analyzed` swallows analysis failures
- **P2** | `tool_providers.py` | Pre-dispatch gate may wait on active program vs requested `programPath` during `checkout-program`
- **P0** | `tests/` | `ToolProviderManager` integration test for analysis gate before dispatch
- **P1** | `tests/` | Test `autoprereqinvocation` bypass of gate
- **P2** | `program_analysis.py` | Analysis idle wait should fail closed on timeout
- **P3** | e2e | Canonical `/lfg` post-merge (plan verification section)

### Document (ce-doc-review — addressed in plan text)

- **P1** | plan | `analyzeAfterImport` scoped semantics — **updated in plan**
- **P2** | plan | Exempt tool enumeration — **updated in plan**
- **P2** | plan | openAllPrograms secondaries — **noted in unit 2** (implemented in branch)

### Filed (prior)

- [#40](https://github.com/bolabaden/AgentDecompile/issues/40) openAllPrograms — fixed in branch
- [#41](https://github.com/bolabaden/AgentDecompile/issues/41) fallback import — fixed in branch

## No sink

- Post-merge `/lfg` harness proof and `IMPORT_EXPORT_GUIDE.md` alignment with in-session ensure semantics
