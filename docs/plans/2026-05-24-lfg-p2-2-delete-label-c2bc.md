---
title: LFG — P2-2 delete_label on manage-symbols
type: feat
status: completed
date: 2026-05-24
branch: impl/agent-native-audit-c2bc
pr: https://github.com/bolabaden/AgentDecompile/pull/49
origin: docs/residual-review-findings/impl-agent-native-audit-c2bc.md
---

# LFG — P2-2 `delete_label` on `manage-symbols`

## Summary

Add **`delete_label`** mode to `manage-symbols` so agents can remove user-defined labels at an address, completing CRUD parity with `create_label`.

---

## Problem Frame

The agent-native audit scores CRUD completeness at 58%. Agents can create labels via `create_label` but cannot delete them headlessly. Ghidra GUI supports label removal; MCP must expose the same capability.

---

## Requirements

- R1. `manage-symbols` accepts **`mode=delete_label`** (and normalized `deletelabel`).
- R2. Requires **`addressOrSymbol`**; optional **`labelName`** to target a specific secondary label at the address.
- R3. Deletes only **user-defined LABEL** symbols; refuses functions, imports, and Ghidra auto-names.
- R4. Uses program transaction + shared check-in touch (same as `create_label`).
- R5. Markdown formatter renders delete response; unit tests cover schema + selection helper.
- R6. Mark P2-2 done in residual doc.

---

## Scope Boundaries

- **In scope:** `symbols.py`, `response_formatter.py`, tests, residual doc.
- **Out of scope:** P2-1 enum CRUD, new standalone tool, conflict two-step for delete.

---

## Key Technical Decisions

- Mirror **`create_label`** patterns: transaction, versioned notify, optional batch later deferred.
- Use **`SymbolTable.removeSymbolSpecial(symbol)`** for deletion.
- Optional **`labelName`**: when omitted, delete primary deletable label at address.

---

## Implementation Units

- U1. **`delete_label` handler** in `symbols.py` + schema/dispatch
- U2. **Markdown render** for `delete_label` mode
- U3. **Tests** in `tests/test_manage_symbols_delete_label.py`
- U4. **Residual doc** update

## Verification

```bash
uv run pytest tests/test_manage_symbols_delete_label.py -m unit -q --timeout=60
uv run pytest -m unit -q --timeout=120
```
