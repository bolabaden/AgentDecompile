---
title: "Agent-native MCP patterns from PR #49 audit follow-up"
date: 2026-05-24
category: architecture-patterns
module: agentdecompile_cli.mcp_server
problem_type: architecture_pattern
component: tooling
symptoms:
  - Agents lacked session context on errors
  - Mutating tools did not guide GUI reload workflow
  - Advertised tool count drift broke CI after manage-enums
root_cause: missing_agent_native_surface
resolution_type: code_and_docs
severity: medium
tags:
  - agent-native
  - mcp
  - project-context
  - ui-hints
  - capability-discovery
---

# Agent-native MCP patterns from PR #49 audit follow-up

## Problem

The 2026-05-24 agent-native audit scored AgentDecompile ~74% on eight principles. Gaps included passive context injection, GUI reload guidance, enum CRUD, discovery commands, and brittle tool-count tests.

## Patterns implemented (PR #49)

### 1. Passive `projectContext` on success and errors

`program_metadata.collect_project_context()` enriches responses with `analysisComplete`, `analysisByProgram`, and `checkoutSummary` (shared mode). Injected on structured errors when programs are loaded — omitted when the session is empty.

**Files:** `src/agentdecompile_cli/mcp_server/program_metadata.py`, `tests/test_project_context.py`

### 2. UI hints scoped to mutating actions

`uiVisibility` / `guiHint` footers attach only when `payload_has_mutating_action()` is true for the tool payload (e.g. enum `list` skipped; `create` included). Auto-checkin uses the same scoping.

**Files:** `program_metadata.py`, `tool_providers.py`, `tests/test_ui_hints.py`

### 3. MCP `prompts/get` with session substitution

Nine RE workflow prompts in `prompt_providers.py` are fetchable via `prompts/get`; active program path substitutes when `program_path` is omitted.

**Files:** `mcp_server/prompt_providers.py`, `tests/test_prompt_providers.py`

### 4. Dynamic advertised-tool count in tests

Do not hardcode tool counts. Assert:

```python
len(advertised) == len(Tool) - len(DISABLED_GUI_ONLY_TOOLS)
```

Registry: **60 canonical**, **4 GUI-only hidden**, **56 advertised** by default.

**Files:** `tests/test_canonical_tool_parity.py`, `registry.py`

### 5. Discovery slash commands

`.cursor/commands/help.md` (workflow) and `.cursor/commands/capabilities.md` (full inventory) for agent capability discovery without MCP initialize preamble.

## Prevention

- When adding tools to `Tool` enum, update dynamic parity test — not hardcoded counts.
- Scope UI hints and auto-checkin via `payload_has_mutating_action()`, not tool name alone.
- Run `uv run pytest -m unit` before merge; headless parity includes tool surface tests.

## Related

- Audit: `docs/audits/2026-05-24-agent-native-audit.md`
- Residual tracker: `docs/residual-review-findings/impl-agent-native-audit-c2bc.md`
- PR: https://github.com/bolabaden/AgentDecompile/pull/49 (merged squash `13200d6`, 2026-05-28)
