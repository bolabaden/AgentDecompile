---
title: MCP tools ran before Ghidra auto-analysis finished
date: 2026-05-24
category: integration-issues
module: agentdecompile_cli.mcp_server
problem_type: integration_issue
component: tooling
symptoms:
  - search-symbols or create-label returned empty results on freshly opened programs
  - ghidra_analysis_complete was true while analyzers had not run
root_cause: logic_error
resolution_type: code_fix
severity: high
tags:
  - program-analysis
  - mcp-gate
  - pyghidra
---

# MCP tools ran before Ghidra auto-analysis finished

## Problem

Program-scoped MCP tools could run while Ghidra auto-analysis had not completed, so the program database looked empty or stale even though the session reported the program as analyzed.

## Symptoms

- Symbol search and labeling tools returned no matches right after open or import.
- `GhidraProgramUtilities.setAnalyzedFlag(True)` or `ghidra_analysis_complete=True` was set without running analyzers.

## What Didn't Work

- Skipping analysis at import time (`analyzeAfterImport=false` / headless `-noanalysis`) without a later in-session ensure left programs unanalyzed indefinitely.
- A duplicate idle-wait loop only in `import_export.py` diverged from the shared coordinator.

## Solution

Centralize coordination in `src/agentdecompile_cli/mcp_utils/program_analysis.py`:

- `blocking_ensure_analyzed()` after open, import, and checkout paths.
- `wait_for_program_analysis_ready()` before non-exempt `ToolProviderManager.call_tool` dispatch.
- Exempt tools that manage analysis themselves (`open`, `import-binary`, `analyze-program`, VC lifecycle tools, etc.).
- Adaptive idle polling (50ms–1s backoff) and per-program lock pruning after ensure/wait.
- Shared import with `analyzeAfterImport=false` uses headless `-noanalysis` and sets `inSessionAnalysisPending` on success; in-session ensure runs on open/checkout.

Map `ProgramAnalysisTimeout` to a structured MCP error (`state: analysis-timeout`) in `tool_providers.py`.

## Why This Works

Ghidra exposes real analysis state via `Program.getAnalysisState()` and `shouldAskToAnalyze`. The gate blocks mutating tools until analysis is idle and incremental ensure has run under a per-program lock.

## Prevention

- Never set analyzed flags without running analyzers.
- Add unit tests in `tests/test_program_analysis_gate.py` and `tests/test_tool_providers_analysis_gate.py` when changing gate behavior.
- Re-run `/lfg` after merge when import uses `analyzeAfterImport: false`.

## Related Issues

- Plan: `docs/plans/2026-05-24-blocking-program-analysis-gate.md`
- PR: https://github.com/bolabaden/AgentDecompile/pull/39 (merged); follow-up https://github.com/bolabaden/AgentDecompile/pull/44 (**merged** `7359c6a` on `master`, 2026-05-27)
