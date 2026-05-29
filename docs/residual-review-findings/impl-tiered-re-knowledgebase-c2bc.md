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

### Future (not blocking)

- MCP wrappers for capa/yara/binwalk (Tier 0)
- `agentdecompile://capabilities` resource with tier summary
- Runtime `tools/list` filter by max tier

## Verification

```bash
uv run pytest tests/test_tool_analysis_tier.py -m unit -q
uv run pytest -m unit -q --timeout=120
```
