---
title: Workbench AIO - Plan
date: 2026-08-31
type: feat
topic: workbench-aio
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
product_contract_source: ce-brainstorm
execution: code
---

# Workbench AIO - Plan

## Goal Capsule

Objective: One AgentDecompile workbench on the MCP HTTP server (default 8080) that an operator can use as the only surface for corpus binaries, recovery work, advertised MCP tools, and public CLIs — including drag/drop and manage of binaries — without visiting leftover ports or inventing argv.

Product authority: STRATEGY.md primary actors (operators and agents who need binary fluency). This plan owns the 8080 operator surface. Donor compile farms, k2 start, and leftover :5173 restyle are not active scope.

Open blockers: none. Binary ingest is both path-register and copy-in. Public scripts that only wrap cataloged CLIs stay out.

```mermaid
flowchart TD
  drop[Drop or pick a binary]
  path[Register an existing path]
  store[Store lists every binary]
  page[One workbench page]
  swagger["/docs typed actions"]
  jobs[Shared job runner]
  drop --> store
  path --> store
  store --> page
  page --> jobs
  swagger --> jobs
  page --> tools[Graph map prompt MCP panels]
```

## Product Contract

### Summary

Ship one professional AgentDecompile page on 8080 that keeps every current UI capability, exposes every public CLI and advertised MCP verb in Swagger and in the page, lets the operator add and remove binaries by drop/upload/path, and shows live job reactions. The conversation workbench is the accepted prototype, not a throwaway to rebuild from zero.

### Problem Frame

Today’s surfaces are split: leftover Atlas on 5173, classic dashboard panels, a generic jobs POST, and CLIs that never appear as Try-it operations. An operator cannot treat 8080 as the whole product. A green label is still not a match, and a 40 KB linked stub is still not a complete executable.

### Key Decisions

- One page, tool strip, no tab bar. (session-settled: user-directed — chosen over separate sites or a tab strip: the operator stays on one professional surface.) Governs R2, R3.
- Public CLI and advertised MCP only in Swagger. (session-settled: user-directed — chosen over advertising GUI-only hidden tools: headless 8080 is not the Ghidra GUI.) Governs R6.
- Dual overlapping bars are decomp and validate, not byte-accuracy. (session-settled: user-directed — chosen over a third accuracy bar: compiling C and a linked image stay separate from objdiff 0.) Governs R5.
- Leftover 5173 is not restyled. (session-settled: user-directed — chosen over restyling Mizuchi Atlas: 8080 is the Atlas.) Governs R10.
- Ingest is copy-in and path-register. (session-settled: user-approved — chosen over path-only or copy-only: comprehensive management without losing binaries that already live on disk.) Governs R7, R8.
- The prior 8080 workbench is the prototype. (session-settled: user-directed — chosen over a new ce-prototype: previous prompts already showed the chrome.) Governs R1.

### Actors

- Operator — adds binaries, runs jobs, reads bars and inspector, never invents argv.
- Agent client — same catalog via `/docs` and `/mcp`.
- Job runner — executes cataloged commands without blocking a sibling job.

### Requirements

**Surface**

- R1. 8080 serves one workbench as the default `/dashboard` (and `/app`) with AgentDecompile chrome and no Mizuchi branding.
- R2. The page keeps every capability of the current UIs (overview panels, functions/logical/review/graph/builds, atlas prompt, report, artifacts, action dock), reachable without a tab strip.
- R3. Center content switches by a tool strip or command palette. Deep links use `tool`, `slug`, `addr`, `logical_id`. Old URLs redirect here or keep a no-JS fallback.

**Live work**

- R4. All registered binaries appear together. Selecting one loads a windowed function list. Selecting a function updates graph, inspector, and tool prefills.
- R5. Binary and function rows show overlapping decomp (none / asm / real C) and validate (none / obj / linked) tracks. Validate jobs must not block leftover C-replace or other cataloged jobs.
- R6. Every public `agentdecompile-corpus`, `agentdecompile-recover`, `agentdecompile-reconstruct`, `agentdecompile-cli`, and advertised MCP verb is a typed `/docs` operation and a workbench action. The browser never sends freeform argv. GUI-only hidden MCP tools stay out.

**Binaries**

- R7. The operator can register an existing filesystem path as a corpus binary (slug, role, label) without hardcoding product stems.
- R8. The operator can drag/drop or file-pick a binary; the server copies it into the workspace and registers it. A dropped path that is already readable may register in place instead of copying.
- R9. The operator can remove a registered binary only with confirm, and can change role or label on an existing row.

**Honesty**

- R10. Completeness is receipts and a real linked image, not a dashboard label. Incremental link must not keep a stub after link flags change.
- R11. Empty env is honest: no binaries, no kotorxid/sqlite defaults, no invented match.

### Key Flows

```mermaid
flowchart TD
  open[Open 8080 workbench]
  empty{Store empty?}
  drop[Drop or path-add a binary]
  list[Binary dock updates]
  pick[Pick a function]
  run[Run MCP or CLI action]
  live[Inspector and bars refresh]
  open --> empty
  empty -->|yes| drop
  empty -->|no| list
  drop --> list
  list --> pick
  pick --> run
  run --> live
```

- F1. Empty store → drop or path-add → binary appears with dual bars → functions load.
- F2. Select function → inspector shows C/siblings → run decompile or rename → live log and refresh.
- F3. Start C-replace and compile-link together → both visible in the job pulse; neither waits on the other.
- F4. Swagger Try-it on the same action id → same job runner as the page.
- F5. Remove binary with confirm → row gone; without confirm → refused.

### Acceptance Examples

- AE1. Covers R1, R2, R3. `/dashboard` shows AgentDecompile, a tool strip, and no `role=tablist`. `/docs` is one click away.
- AE2. Covers R7, R8, R9. Drop a small PE, see it listed; register a second path; remove the first only after confirm.
- AE3. Covers R6, F4. `/openapi.json` contains an operationId for every public corpus/recover/reconstruct/cli/MCP verb, with named properties not a freeform argv blob.
- AE4. Covers R5, F3. Two long jobs start and both show running.
- AE5. Covers R11. Unset corpus env yields an empty binary dock and no product-path strings in the HTML.

### Scope Boundaries

In scope: 8080 workbench, Swagger catalog, binary add/remove/edit, live jobs, existing panel/atlas/report mounts, `/OPT:NOREF` + link stamp honesty.

Out of scope: restyling leftover :5173; byte-accuracy as a third bar; GUI-only MCP tools; freeform remote shell; starting k2 compile; raising leftover C-replace workers; wrapping every `scripts/*.sh` that already has a cataloged CLI.

### Success Criteria

An operator can add binaries, run any public tool, and watch decomp/validate and job output on one 8080 page. Swagger can invoke the same tools. A green bar is never treated as a byte match. The 5173 leftover can stay unused.

### Outstanding Questions

None blocking. Deferred: reconstruct legacy aliases do not need duplicate operationIds if `recover.*` already covers them.

## Planning Contract

### Approach

Extend the existing 8080 workbench and generated action catalog. Do not rebuild the prototype and do not restyle leftover Atlas.

Catalog stays generated from live parsers plus advertised MCP plus public Click commands that are not already MCP names. Jobs stay the only execution path. Binary manage is a first-class workbench API that writes the identity store and optional import copies, then the same list/dock refresh as other jobs.

Execution direction: test-first for new binary manage and catalog completeness; browser dogfood after the page is launchable on 8080.

### Key Technical Decisions

- KTD1. Uploads land under the live work dir `imports/` using the original basename (collision suffix). Path-register does not copy. Governs R8.
- KTD2. Click public commands become `cli.<name>` with backend `mcp-cli` or the click entry; skip names already in `ADVERTISED_TOOLS`. Governs R6.
- KTD3. Binary add/remove/edit are HTTP APIs on the dashboard router and also catalog actions (`corpus.add-binary`, `corpus.remove-binary`) so Swagger and the dropzone share behavior. Governs R7, R9.
- KTD4. Windowed function list stays keyset/limit (80 default), not a 24k DOM dump. Governs R4.
- KTD5. `/OPT:NOREF` plus `.link-stamp` remains the skip-link honesty rule. Governs R10.

### Assumptions

- `AGENT_DECOMPILE_CORPUS_DB` and `AGENT_DECOMPILE_CORPUS_WORK_DIR` are the only path sources.
- Advertised MCP count follows `ADVERTISED_TOOLS` (68 today); GUI-only stay hidden.
- Classic `/dashboard/overview` and `/dashboard/functions` remain as no-JS/test fallbacks.

### Sequencing

U1 catalog click surface → U2 binary manage APIs (TDD) → U3 dropzone/manage chrome → U4 live reactions + MCP groups → U5 launch/dogfood gates. U5 is verification, not a product feature.

## Implementation Units

### U1. Complete public catalog in Swagger

Covers R6, AE3.

Files: `src/agentdecompile_recovery/corpus/dashboard/actions/introspect.py`, `src/agentdecompile_recovery/corpus/dashboard/actions/catalog.py`, `src/agentdecompile_recovery/corpus/dashboard/actions/openapi.py`, `tests/test_dashboard_openapi_catalog.py`, `tests/test_workbench_binaries.py`.

Tests: every public corpus/recover/reconstruct/cli/MCP id is present; OpenAPI bodies have named properties; `cli.tool` or `cli.alias` or `cli.ghidrecomp` exists; no GUI-only tools.

### U2. Binary register, copy-in, remove, edit

Covers R7, R8, R9, F1, F5, AE2.

Files: `src/agentdecompile_recovery/corpus/dashboard/workbench.py`, `src/agentdecompile_recovery/corpus/dashboard/router.py`, `src/agentdecompile_recovery/corpus/store.py` (reuse `remove_binary`), `tests/test_workbench_binaries.py`.

Tests (already red-shaped): path add lists the slug; upload copies bytes and lists; delete without confirm is 400; delete with confirm removes the row; work dir has no product-path defaults.

### U3. Dropzone and manage chrome

Covers R1, R2, R3, R4, AE1.

Files: `src/agentdecompile_recovery/corpus/dashboard/workbench.py`, `src/agentdecompile_recovery/corpus/dashboard/static/workbench.js`, `src/agentdecompile_recovery/corpus/dashboard/static/workbench.css`, `tests/test_workbench_binaries.py`.

Tests: HTML contains `wb-drop`, path field, remove control; no `role=tablist`; no Mizuchi string.

### U4. Live jobs and MCP integration

Covers R5, F2, F3, F4, AE4.

Files: `src/agentdecompile_recovery/corpus/dashboard/static/workbench.js`, `src/agentdecompile_recovery/corpus/dashboard/actions/jobs.py`, `tests/test_dashboard_openapi_catalog.py`.

Tests: two jobs start without waiting; workbench poll refreshes binaries/functions after a finishing job (unit on the runner is enough if JS stays thin).

### U5. Honesty and launch

Covers R10, R11, AE5.

Files: `src/agentdecompile_recovery/corpus/compile_link.py`, `tests/test_corpus_workspace_skeleton.py`, living plan mermaid in `docs/plans/2026-08-30-corpus-semantic-pipeline-living-plan.md`.

Tests: missing `.link-stamp` forces relink; empty env HTML has no kotorxid defaults.

## Verification Contract

- `uv run pytest tests/test_workbench_binaries.py tests/test_dashboard_openapi_catalog.py tests/test_dashboard_actions.py tests/test_unified_pages.py tests/test_corpus_workspace_skeleton.py`
- After launch: `GET /dashboard`, `GET /docs`, `GET /openapi.json` on 8080.
- Browser dogfood (`agent-browser`) on the workbench: drop/path, strip tools, Swagger Try-it dry-run, empty and populated docks.
- Do not restart `kotorxid-recovery.service`. Do not start k2 compile.

## Definition of Done

- Product Contract R1–R11 have a unit or browser check.
- Catalog completeness test green.
- Binary add (path and upload) and confirm-remove green.
- Workbench on 8080 has dropzone, tool strip, Swagger link, live job pulse.
- Link stamp honesty tests green.
- No product-path defaults. No 5173 restyle.
