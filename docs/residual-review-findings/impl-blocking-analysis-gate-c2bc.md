# Residual review findings — `impl/blocking-analysis-gate-c2bc`

**Source:** ce-code-review `mode:autofix` (2026-05-24, rounds 2–3)  
**Plan:** [docs/plans/2026-05-24-blocking-program-analysis-gate.md](../plans/2026-05-24-blocking-program-analysis-gate.md)  
**Agent-native audit:** [docs/agent-native-architecture-review-2026-05-24.md](../agent-native-architecture-review-2026-05-24.md)  
**PR:** [#39](https://github.com/bolabaden/AgentDecompile/pull/39)

## Filed (prior round)

- **Important** | openAllPrograms secondaries — [#40](https://github.com/bolabaden/AgentDecompile/issues/40) *(fixed in branch: secondary ensure at open)*
- **Important** | fallback import path — [#41](https://github.com/bolabaden/AgentDecompile/issues/41) *(fixed in branch: blocking_ensure on fallback import)*

## Residual Review Findings (downstream-resolver)

- **P1** | `import_export.py` | Shared PyGhidra import still honors `analyzeAfterImport=false` for in-process analyze
- **P1** | `import_export.py` | Shared analyzeHeadless `-noanalysis` when flag false
- **P2** | `tool_providers.py` | Pre-dispatch gate may wait on active program vs requested `programPath` during `checkout-program`
- **P2** | `project.py` | `_blocking_ensure_program_analyzed` swallows analysis failures (warning only)
- **P0** | `tests/` | `ToolProviderManager` integration test for analysis gate before dispatch
- **P1** | `tests/` | Test `autoprereqinvocation` bypass of analysis gate
- **P3** | e2e | Run canonical `/lfg` post-merge

## No sink

- Post-merge `/lfg` label/search persistence validation
- Agent-native follow-ups (see audit doc): `prompts/get`, expand `projectContext`, primitive-first curated surface
