# Residual review findings — `impl/blocking-analysis-gate-c2bc`

**Source:** ce-code-review `mode:autofix` (2026-05-24)  
**Plan:** [docs/plans/2026-05-24-blocking-program-analysis-gate.md](../plans/2026-05-24-blocking-program-analysis-gate.md)  
**Artifact:** `/tmp/compound-engineering/ce-code-review/20260524-blocking-gate-c2bc/summary.md`  
**PR:** [#39](https://github.com/bolabaden/AgentDecompile/pull/39)

## Filed (prior round)

- **Important** | openAllPrograms secondaries — [#40](https://github.com/bolabaden/AgentDecompile/issues/40) *(addressed in branch: secondary ensure at open)*
- **Important** | fallback import path — [#41](https://github.com/bolabaden/AgentDecompile/issues/41) *(addressed in branch: blocking_ensure on fallback import)*

## Residual Review Findings (current)

- **P1** | `import_export.py` | Shared PyGhidra import still honors `analyzeAfterImport=false` for in-process analyze — align with always-try plan or document LFG deferral
- **P1** | `import_export.py` | Shared analyzeHeadless `-noanalysis` when flag false — same as above
- **P2** | `tool_providers.py` | checkout-program may wait on active program vs requested programPath — consider exempting checkout/checkin from pre-dispatch gate
- **P2** | `project.py` | `_blocking_ensure_program_analyzed` swallows exceptions — surface analysis failure on open/import response
- **P0** | `tests/` | Add ToolProviderManager gate integration test (`wait_for_program_analysis_ready` before handler)
- **P3** | e2e | Run canonical `/lfg` (`scripts/lfg_validation.py` or `scripts/lfg_cmd_sequence.ps1`) after merge

## No sink

- Post-merge `/lfg` label/search persistence validation (process step; see plan LFG note)
