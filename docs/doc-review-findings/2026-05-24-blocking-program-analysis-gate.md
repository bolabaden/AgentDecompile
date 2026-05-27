# Document review — blocking program analysis gate plan

**Document:** [docs/plans/2026-05-24-blocking-program-analysis-gate.md](plans/2026-05-24-blocking-program-analysis-gate.md)  
**Reviewers:** coherence, feasibility, scope-guardian, adversarial (ce-doc-review, headless synthesis)  
**Branch:** `impl/blocking-analysis-gate-c2bc`

## Applied to plan (safe_auto + clarifications)

- Renamed flowchart node to `blocking_ensure_analyzed`
- Added `analyzeAfterImport semantics` table (scoped always-try vs headless skip)
- Normalized implementation unit paths under `src/agentdecompile_cli/`
- Enumerated gate-exempt tools (matches `_ANALYSIS_GATE_EXEMPT_TOOLS`)
- Clarified LFG acceptance: ensure before `02d` search-symbols
- Added fail-closed rule; fixed stale “default False” problem bullet

## Open questions (manual / downstream)

| Sev | Topic |
|-----|--------|
| ~~P1~~ | ~~Align `import_export.py` shared paths with plan semantics (`analyzeAfterImport=false`)~~ — headless `-noanalysis` + `inSessionAnalysisPending` on success ([#44](https://github.com/bolabaden/AgentDecompile/pull/44)) |
| ~~P1~~ | ~~`checkout-program` pre-dispatch gate vs VC latency~~ — closed [#43](https://github.com/bolabaden/AgentDecompile/pull/43) (VC tools gate-exempt) |
| ~~P0~~ | ~~`ToolProviderManager` gate integration test~~ — `tests/test_tool_providers_analysis_gate.py` |
| ~~P2~~ | ~~Analysis idle timeout should raise, not return silently~~ — `ProgramAnalysisTimeout` |
| ~~P2~~ | ~~`_blocking_ensure_program_analyzed` should not swallow failures~~ — fixed in branch |

## Coverage

All four personas completed. Plan updated in-repo; code residuals tracked in [residual-review-findings/impl-blocking-analysis-gate-c2bc.md](residual-review-findings/impl-blocking-analysis-gate-c2bc.md).
