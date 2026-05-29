---
branch: impl/capabilities-resource-c2bc
plan: docs/plans/2026-05-24-lfg-capabilities-resource-c2bc.md
---

# Residual findings — capabilities MCP resource arc

**PR:** [#64](https://github.com/bolabaden/AgentDecompile/pull/64) — **merged** to `master` as `cd4b069` (2026-05-24, squash)

## Delivered

| Area | Item |
|------|------|
| MCP | `agentdecompile://capabilities` resource |
| Code | `CapabilitiesResource`, `mcp_utils/tool_reference.py` |
| Registry | `ResourceUri.CAPABILITIES` |
| Tests | `tests/test_capabilities_resource.py` (7 tests) |
| Docs | `/capabilities` command, KB future-extensions marked done |

## Residual actionable work

**None.**

### Future (not blocking) — all Done

- ~~Runtime `tools/list` filter by max tier~~ — **Done** (PR #66)
- ~~Tier 0 MCP wrappers (capa/yara/binwalk)~~ — **Done** (`run-file-triage`, `run-external-re-scan`, PRs #82–#85)
- ~~Tier 1 ghidrecomp MCP facade~~ — **Done** (`run-batch-*`, PRs #80–#83)
- ~~Discovery doc sync (66/62 counts)~~ — **Done** (PR #86)

## Verification

```bash
uv run pytest tests/test_capabilities_resource.py -m unit -q
uv run pytest -m unit -q --timeout=120
```
