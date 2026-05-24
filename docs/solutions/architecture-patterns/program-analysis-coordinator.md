---
title: Single coordinator for Ghidra program analysis waits
date: 2026-05-24
category: architecture-patterns
module: agentdecompile_cli.mcp_utils
problem_type: architecture_pattern
component: tooling
severity: medium
applies_when:
  - Multiple providers need to wait for Ghidra auto-analysis
  - Per-program locking is required for concurrent MCP tools
tags:
  - program-analysis
  - dhh-style
  - locking
---

# Single coordinator for Ghidra program analysis waits

## Context

Analysis idle polling and ensure logic had been duplicated (for example in `ImportExportToolProvider._wait_for_program_analysis_idle`). Divergent timeouts and silent returns made failures hard to diagnose.

## Guidance

Use one module as the source of truth:

- `wait_for_program_analysis_idle()` — poll until idle or raise `ProgramAnalysisTimeout`.
- `blocking_ensure_analyzed()` — per-program lock, incremental `run_analysis(force_analysis=False)` when needed.
- `analysis_gate_exempt_tool()` — normalized tool names that must not pre-wait.

Providers call these functions; they do not reimplement poll loops.

## Why This Matters

One obvious place for behavior beats parallel service-style helpers. Fail-closed timeouts surface stuck analysis instead of letting tools proceed on incomplete databases.

## When to Apply

- Any new code path that opens a `Program` in the MCP JVM session.
- Before adding another `_wait_for_*` helper on a provider class.

## Examples

```python
from agentdecompile_cli.mcp_utils.program_analysis import (
    blocking_ensure_analyzed,
    wait_for_program_analysis_idle,
)

blocking_ensure_analyzed(program, program_info, program_path=path, force=False)
wait_for_program_analysis_idle(program, max_wait_sec=90.0)
```

## Related

- `docs/solutions/integration-issues/mcp-program-analysis-gate.md`
- `docs/plans/2026-05-24-dhh-style-python-simplification.md`
