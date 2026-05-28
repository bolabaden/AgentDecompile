---
title: LFG — P1-3 uiVisibility and guiHint on mutating tools
type: feat
status: completed
date: 2026-05-24
branch: impl/agent-native-audit-c2bc
pr: https://github.com/bolabaden/AgentDecompile/pull/49
origin: docs/residual-review-findings/impl-agent-native-audit-c2bc.md
---

# LFG — P1-3 `uiVisibility` / `guiHint` on mutating tool responses

## Summary

Inject **`uiVisibility`** and **`guiHint`** into successful mutating tool JSON responses (central middleware, like `projectContext`). Tell agents that MCP runs headless and GUI updates require reload/check-in/sync.

---

## Problem Frame

The agent-native audit scores UI integration at 0/23 live CodeBrowser sync. Mutations persist via the headless MCP JVM, but responses do not explain GUI visibility. Agents cannot infer when to call `checkin-program` or tell users to reload CodeBrowser.

---

## Requirements

- R1. Successful mutating tool responses include **`uiVisibility`** (structured) and **`guiHint`** (string).
- R2. Injection is centralized in tool dispatch (reuse `_AUTO_CHECKIN_TRIGGER_TOOLS` success gate).
- R3. **`uiVisibility`** reflects session mode (local vs shared-server), persistence path, and whether auto-checkin env is enabled.
- R4. Skip injection for read-only tools, conflicts, errors, and meta tools (`debuginfo`, `listtools`).
- R5. Markdown formatter renders a **UI Visibility** footer when fields present.
- R6. Unit tests + residual doc update (mark P1-3 done).

---

## Scope Boundaries

- **In scope:** `program_metadata.py`, `tool_providers.py`, `response_formatter.py`, tests, docs.
- **Out of scope:** Live GUI event bus, P1-4 proxy header, README dual-JVM doc (P3-1).

---

## Key Technical Decisions

- Reuse **`_AUTO_CHECKIN_TRIGGER_TOOLS`** + same success parsing as auto-checkin middleware (consistent mutating scope).
- Place builders next to `projectContext` in **`program_metadata.py`**.
- Chain injection after `inject_project_context` in `ToolProvider.call_tool`.

---

## Implementation Units

- U1. **`build_ui_visibility()` + inject helpers** in `program_metadata.py`
- U2. **Wire injection** in `tool_providers.py` after projectContext
- U3. **Markdown footer** in `response_formatter.py`
- U4. **Tests** in `tests/test_ui_hints.py` + doc updates

## Verification

```bash
uv run pytest tests/test_ui_hints.py -m unit -q --timeout=60
uv run pytest -m unit -q --timeout=120
```
