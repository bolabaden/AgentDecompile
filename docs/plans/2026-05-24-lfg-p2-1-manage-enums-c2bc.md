---
title: LFG — P2-1 manage-enums CRUD tool
type: feat
status: completed
date: 2026-05-24
branch: impl/agent-native-audit-c2bc
pr: https://github.com/bolabaden/AgentDecompile/pull/49
origin: docs/residual-review-findings/impl-agent-native-audit-c2bc.md
---

# LFG — P2-1 `manage-enums` CRUD tool

## Summary

Add **`manage-enums`** MCP tool with list/info/create/add_member/edit_member/remove_member/delete modes so agents get full enum CRUD parity (audit gap: 0/4 → full).

---

## Problem Frame

Agent-native audit scores enum CRUD at 0/4. Structures have `manage-structures`; enums have no dedicated tool despite AGENTS.md naming conventions for enum members.

---

## Requirements

- R1. New tool **`manage-enums`** registered in `registry.py` with aliases `create-enum`, `edit-enum`, `list-enums`, `delete-enum`.
- R2. Modes: **list**, **info**, **create**, **add_member**, **edit_member**, **remove_member**, **delete**.
- R3. Enum member names follow **COBRA_CASE** convention in docs/schema; values are integers.
- R4. Conflict flow on create when enum exists (reuse two-step pattern).
- R5. Auto-checkin + ui hints on mutating modes (same as `manage-structures`).
- R6. Unit tests for member parsing + schema; mark P2-1 done in residual doc.

---

## Scope Boundaries

- **In scope:** `enums.py` provider, `_collectors.collect_enums`, registry, formatter, tests.
- **Out of scope:** P2-3 curated surface, CLI group, TOOLS_LIST.md full spec.

---

## Implementation Units

- U1. **`collect_enums()`** in `_collectors.py`
- U2. **`EnumToolProvider`** in `providers/enums.py`
- U3. **Registry + registration** (`Tool.MANAGE_ENUMS`, aliases, auto-checkin)
- U4. **Formatter + tests + residual doc**

## Verification

```bash
uv run pytest tests/test_manage_enums.py -m unit -q --timeout=60
uv run pytest -m unit -q --timeout=120
```
