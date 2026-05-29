# Residual review findings — impl/max-analysis-tier-filter-c2bc

Source: ce-correctness-reviewer on commit `6b4d58b` (plan `docs/plans/2026-05-24-lfg-max-analysis-tier-filter-c2bc.md`).

## Residual Review Findings

**Actionable work: none** (ship-ready; remaining items are optional polish).

Addressed in follow-up commit on this branch:

- Proxy forward test for `x-agentdecompile-max-analysis-tier`
- Capabilities test env isolation (`monkeypatch.delenv`)
- Legacy env alias test + invalid header fallback test
- `list_tools()` docstring update

Optional (not blocking merge):

- Document `AGENTDECOMPILE_MAX_ANALYSIS_TIER` / header in `AGENTS.md` alongside auto-match env vars
- Integration test: HTTP `tools/list` with tier header through middleware
- Stronger T4 test invoking `ToolProviderManager.call_tool()` under tier-2 filter (requires Ghidra mocks)
