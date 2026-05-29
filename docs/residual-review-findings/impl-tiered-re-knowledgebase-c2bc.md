---
branch: impl/tiered-re-knowledgebase-c2bc
plan: docs/plans/2026-05-24-tiered-re-knowledgebase-c2bc.md
---

# Residual findings — tiered RE knowledge base arc

**PR:** [#62](https://github.com/bolabaden/AgentDecompile/pull/62) — **merged** to `master` as `7471598` (2026-05-29, squash)

## Delivered

| Area | Item |
|------|------|
| Docs | Tier 0–3 knowledge base, tiered-re-analysis skill |
| Agents | RE Planner/Worker/Critic tier routing; artifact protocol |
| Code | `ToolMetadata.analysis_tier`, tool-reference payload |
| Tests | `tests/test_tool_analysis_tier.py` (14 tests) |
| Discovery | `/help`, `/capabilities`, `AGENTS.md`, `docs/INDEX.md` |

## Residual actionable work

**None.**

### Future (not blocking) — all Done

- ~~MCP wrappers for capa/yara/binwalk (Tier 0)~~ — **Done** (`run-file-triage`, `run-external-re-scan`, PRs #82–#85)
- ~~`agentdecompile://capabilities` resource with tier summary~~ — **Done** (PR #64; tier 0–1 verify PR #88)
- ~~Runtime `tools/list` filter by max tier~~ — **Done** (PR #66)
- ~~Discovery doc sync (66/62 counts, MCP Tier 0–1)~~ — **Done** (PR #86)

## Verification

```bash
uv run pytest tests/test_tool_analysis_tier.py tests/test_capabilities_resource.py -m unit -q
uv run pytest -m unit -q --timeout=120
```
