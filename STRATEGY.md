---
name: AgentDecompile
last_updated: 2026-05-24
---

# AgentDecompile Strategy

## Target problem

Reverse engineers and security researchers spend most of their time on repetitive Ghidra work—waiting for analysis, hunting symbols, and verifying that automation did not run on half-analyzed programs—while AI assistants need reliable, session-stable MCP access to the same program state a human would trust in the UI.

## Our approach

Ship a **Python-first MCP server** on PyGhidra that exposes Ghidra’s real program database to agents with honest analysis state, fail-closed timeouts, and CLI ergonomics built for headless automation—one coordinator for analysis waits, one obvious tool dispatch gate, and documented institutional learnings in `docs/solutions/`.

## Who it's for

**Primary:** Reverse engineers and agent builders — they hire AgentDecompile to drive Ghidra projects (local or shared server) through MCP tools and `agentdecompile-cli` without silent “analyzed but empty” program state.

**Secondary:** Maintainers of AgentDecompile — they need canonical tool specs (`TOOLS_LIST.md`), unit-tested gate behavior, and `/lfg`-style proof paths after risky MCP changes.

## Key metrics

- **Analysis correctness** — mutating MCP tools never run on programs that still need Ghidra auto-analysis (gate + unit tests green)
- **Agent success rate** — CLI/MCP invocations complete without session loss, auth mismatch, or `analysis-timeout` on healthy workloads
- **Tool reliability** — canonical tool count advertised matches implemented handlers; regression tests cover dispatch and argument normalization
- **Knowledge compound** — `docs/solutions/` learnings stay aligned with `src/agentdecompile_cli/` after each major feature branch

## Tracks

### MCP analysis integrity

Per-program locks, `blocking_ensure_analyzed`, and pre-dispatch `wait_for_program_analysis_ready` so open/import and downstream tools share one truth about analysis state.

_Why it serves the approach:_ Agents only trust results when the underlying Ghidra DB matches what “analyzed” means in the UI.

### Agent-native CLI and docs

JSON tool lists, stdin `tool-seq`, actionable `--help`, and discoverable `docs/solutions/` for repeat automation.

_Why it serves the approach:_ Reduces failed agent loops and encodes verified fixes for the next session.

### Shared Ghidra server and session fidelity

Shared-project open/checkout, proxy session headers, and LFG-style proof sequences for versioned binaries (e.g. KOTOR cross-binary workflows).

_Why it serves the approach:_ Production RE often uses team servers; MCP must preserve the same logical session end-to-end.

## Not working on

- Reintroducing a Java-first tool implementation path for new features
- Browser-based Ghidra UI automation as a substitute for MCP tool coverage
- Expanding scope into unrelated app stacks (Rails, generic web perf) on this repo

## Marketing

**One-liner:** AgentDecompile is the MCP bridge that lets AI agents reverse engineer in Ghidra with real analysis state—not fake flags and empty databases.

**Key message:** Built on the Model Context Protocol and PyGhidra, it packages dozens of RE tools, session-aware project management, and agent-friendly CLI workflows so you can chat with binaries instead of clicking through every analyzer by hand.
