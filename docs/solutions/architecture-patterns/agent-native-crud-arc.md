---
title: Agent-native CRUD arc — compound learning
date: 2026-05-24
category: architecture-patterns
module: agentdecompile_cli.mcp_server.providers
problem_type: architecture_pattern
component: crud-completeness
symptoms:
  - Strings scored 1/4 CRUD (read-only manage-strings)
  - Data-type catalog lacked create/delete/update in manage-data-types
  - Function tags lacked real set (replace-all) mode
  - Overall CRUD completeness stuck at 75% (9/12)
root_cause: missing_mutating_modes_on_multi_mode_tools
resolution_type: code_and_docs
severity: medium
tags:
  - agent-native
  - mcp
  - crud
  - manage-strings
  - manage-data-types
  - manage-function-tags
---

# Agent-native CRUD arc

## Problem

The 2026-05-24 audit listed **strings CRUD**, **data-type catalog create**, **catalog update**, and **function-tag set** as remaining gaps across `manage-strings`, `manage-data-types`, and `manage-function-tags`.

## Solution (mega-stack PR #111)

**Merged** squash `b72a932` (PR [#111](https://github.com/bolabaden/AgentDecompile/pull/111), 2026-05-29) on `master`. Supersedes #105–#110.

```mermaid
flowchart LR
  subgraph strings [Strings 4/4]
    A[create update delete]
  end
  subgraph dtypes [Catalog 4/4]
    B[create update delete info]
  end
  subgraph tags [Function tags 4/4]
    C[add remove set]
  end
  strings --> M[mega-stack PR]
  dtypes --> M
  tags --> M
```

| Slice | Deliverable |
|-------|-------------|
| Strings | `manage-strings` create/update/delete |
| Catalog | `manage-data-types` create/update/delete/info |
| Tags | `manage-function-tags` set replaces all tags |
| **Merge** | One PR → **12/12 CRUD (100%)** |

## Audit impact

| Entity | Before | After |
|--------|--------|-------|
| Strings | 1/4 | **4/4** |
| Data types (catalog) | 2/4 | **4/4** |
| Function tags | 3/4 | **4/4** |
| CRUD completeness | 9/12 (75%) | **12/12 (100%)** |

## Patterns

- Mutating multi-mode tools: return `action` in JSON; gate UI hints via `_MUTATING_TOOL_ACTIONS` in `program_metadata.py`.
- Catalog CRUD: `TypedefDataType` + `dtm.addDataType()` / `dtm.remove()` with conflict flow on create/rename.
- Function-tags set: clear `func.getTags()` then `addTag` each name in one transaction.

## Verification

```bash
uv run pytest tests/test_manage_strings.py tests/test_manage_data_types.py tests/test_manage_function_tags.py -m unit -q --timeout=60
uv run pytest -m unit -q --timeout=120
```
