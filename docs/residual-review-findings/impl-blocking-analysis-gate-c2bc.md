# Residual review findings — `impl/blocking-analysis-gate-c2bc`

**Plan:** [docs/plans/2026-05-24-blocking-program-analysis-gate.md](../plans/2026-05-24-blocking-program-analysis-gate.md)  
**Code review plan:** [docs/plans/2026-05-24-blocking-analysis-code-review.md](../plans/2026-05-24-blocking-analysis-code-review.md)  
**PR:** [#39](https://github.com/bolabaden/AgentDecompile/pull/39) — **merged** into `master`  
**PR #43:** [#43](https://github.com/bolabaden/AgentDecompile/pull/43) — **superseded on `master`** at `fa73c1f` (2026-05-28 LFG rebase); VC exempt tools, import docs, and LFG step 0 landed via #44/#45 and agent-native arc doc merges. Closeout: [plan](../plans/2026-05-24-lfg-pr43-ship-c2bc.md).

**PR #44:** [#44](https://github.com/bolabaden/AgentDecompile/pull/44) — **merged** to `master` as `7359c6a` (2026-05-27, squash)  
**PR #45:** [#45](https://github.com/bolabaden/AgentDecompile/pull/45) — **merged** to `master` as `00cfca2` (post-merge `program_analysis.__all__` + docs)  
**PR #53:** [#53](https://github.com/bolabaden/AgentDecompile/pull/53) — **open** (`lfg-nightly.yml`; merge SHA pending squash merge)  
**LFG pass:** [docs/plans/2026-05-24-lfg-strategy-doc-code-review.md](../plans/2026-05-24-lfg-strategy-doc-code-review.md)  
**Follow-up:** `STRATEGY.md` and doc-only commits land via `impl/post-merge-strategy-docs-c2bc`

## Residual Review Findings

**Residual actionable work: none.** (P3 e2e `/lfg` CI closed via `lfg-nightly.yml`; see below.)

### Closed in branch (2026-05-24 review pass)

- **P2** | `project.py` | `_blocking_ensure_program_analyzed` no longer swallows failures
- **P2** | `program_analysis.py` | Idle wait raises `ProgramAnalysisTimeout` (fail-closed)
- **P1** | `import_export.py` | `analyzeAfterImport=false` skips import-time analyze by design; in-session ensure on open/checkout/import
- **P1** | `tool_providers.py` | `ProgramAnalysisTimeout` → structured MCP `analysis-timeout` error
- **P2** | `tool_providers.py` | Requested `programPath` no longer falls back to session active program for gate/wait
- **P0/P1** | `tests/test_tool_providers_analysis_gate.py` | Gate invoke/skip, autoprereq bypass, timeout error, programPath resolution

### PR #44 — merged

Squash merge: **`7359c6a`** on `master` (2026-05-27). **68+** unit tests on `master` after PR #45 (`program_analysis.__all__` export test). Feature branch `impl/blocking-analysis-gate-c2bc` superseded.

```bash
uv run pytest tests/test_program_analysis_gate.py tests/test_tool_providers_analysis_gate.py -m unit -q
uv run pytest -m unit -q --timeout=120
uv run ruff check --no-fix src/agentdecompile_cli/mcp_utils/program_analysis.py src/agentdecompile_cli/mcp_server/tool_providers.py
```

After merge: `tests/test_lfg_e2e.py` provides fast smoke (no `lfg` marker) and opt-in full stack when `LFG_RUN=1` (see `tests/README.md` and `.cursor/commands/lfg.md`).

### Still open (downstream)

_(none — P3 e2e `/lfg` CI covered by `lfg-nightly.yml`)_

### Closed (2026-05-28 LFG)

- **P3** | e2e | Canonical `/lfg` in CI/nightly — PR [#53](https://github.com/bolabaden/AgentDecompile/pull/53); [`.github/workflows/lfg-nightly.yml`](../../.github/workflows/lfg-nightly.yml) (weekly + `workflow_dispatch`; `LFG_RUN=1 pytest -m lfg`; merge SHA after squash)

### Closed (2026-05-24 LFG)

- **P3** | `tool_providers.py` | Provider-raised `ProgramAnalysisTimeout` (e.g. open/import ensure) returns structured `analysis-timeout` like gate path

### Closed post-merge (2026-05-24, PR after #42)

- **P3** | docs | `IMPORT_EXPORT_GUIDE.md` aligned with in-session ensure semantics — [plan](../plans/2026-05-24-post-merge-p3-hygiene.md)
- **P3** | `program_analysis.py` | VC tools (`checkout-program`, `checkin-program`, `checkout-status`) exempt from redundant gate waits
- **P3** | `program_analysis.py` | Idle per-program lock map pruning (`_release_program_lock`, cap 512)

### Filed (prior)

- [#40](https://github.com/bolabaden/AgentDecompile/issues/40) openAllPrograms — fixed in branch
- [#41](https://github.com/bolabaden/AgentDecompile/issues/41) fallback import — fixed in branch
