---
name: Shared/local checkout-checkin + sync E2E (deepened)
overview: Same as base plan, plus research-backed Ghidra 12 / PyGhidra / official Java VC API contract and references. Deepened 2026-03-25 via repo-research-analyst, framework-docs-researcher, firecrawl-search.
parent_plan: shared_local_checkout_sync_e2e_7c2a9f01.plan.md
isProject: false
---

## Enhancement Summary

**Deepened on:** 2026-03-25  
**Research sources:** NSA Ghidra Javadoc (ghidra.re, ghidradocs 12.x), in-repo Help (`project_repository.htm`), HeadlessAnalyzer course docs, PyGhidra README, byte.how collaborative Ghidra Server article, parallel `repo-research-analyst` + `framework-docs-researcher` passes on this repository.

### Key improvements captured below

1. **Stated explicitly:** PyGhidra does not expose a second VC API — the **proper** implementation path is **Ghidra’s Java framework** (`DomainFile`, `ProjectData`, `RepositoryAdapter`, `GhidraProject`, `DefaultCheckinHandler`, etc.) **via JPype** after JVM init. That is what “PyGhidra can do VC” means in production.
2. **Documented hard requirements** from official Javadoc: `checkin(CheckinHandler, TaskMonitor)` needs **checked out** + **modified since checkout**; `addToVersionControl(comment, keepCheckedOut, monitor)` semantics; deprecated `checkin(..., okToUpgrade, ...)` must not be used.
3. **Two legitimate server layers:** `RepositoryAdapter.checkout(...)` (server handle) vs `DomainFile.checkout(...)` (project tree) — agentdecompile uses both; correctness is **matching DomainFile identity** for the open shared project and **ending Program transactions** before `DomainFile.save` / checkin.
4. **Headless `ghidra://` + `-commit`** is an **official** batch path, not a hack; restrictions (e.g. `-process` / `-readOnly` on shared) come from Ghidra docs.

### New considerations for implementation / E2E

- **Listing vs reality:** `RepositoryAdapter.getItemList` can lag or differ from `ProjectData` until a **successful versioned check-in** publishes a revision; relying only on listing without satisfying `canCheckin` / `modifiedSinceCheckout` is invalid per API contract.
- **Hijacked / private file:** Official `DomainFile.isHijacked()` and user-help text match failures like **“Cannot checkout, private file exists”** — naming/collision between private copy and repo file.
- **Dedicated shared checkout project:** Repo already binds `GhidraProject` to a temp tree on shared connect to avoid stale non-versioned DomainFile handles (see `project.py` research).

---

# Plan: Shared + local checkout/checkin, persistence, sync-project

*(Original plan body preserved below.)*

## Goals

1. **Shared** and **local** projects both work with `checkout-program` / `checkin-program` / `checkout-status` where applicable.
2. **Three successive cycles** per mode: checkout → **rename function** or **set label** → checkin (shared) or checkin/save (local).
3. **Restart** the **MCP server** (agentdecompile-server), reopen project, **assert** edits still visible (persistence on Ghidra side, not in-memory session).
4. `**sync-project`**: **pull** (shared → local) and **push** (local changes into shared-backed workflow / save), including `**dryRun: true`** first.

### Research Insights (Goals alignment)

**Best practices (Ghidra docs + help):**

- Treat **shared** workflow like the GUI: **connect to repository** → **checkout** → **edit** → **save** → **check in** with comment. Help: [project_repository.htm (NSA Ghidra repo)](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/src/main/help/help/topics/VersionControl/project_repository.htm).
- **PyGhidra README** ([NSA PyGhidra README](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/PyGhidra/src/main/py/README.md)) documents **local** `open_project` / `consume_program` / `transaction` — **not** a parallel VC API. VC = call **Java** classes listed in “Official API surface” below.

**Edge cases:**

- **`canCheckin()` false** with **`isCheckedOut()` true** often means **not modified since checkout** (Javadoc). Must mutate domain / flush Program / end transactions so `modifiedSinceCheckout()` becomes true before checkin.
- **`DomainFile.checkout`**: if file is **already private**, method may **do nothing** (per Javadoc) — logic must not assume a fresh server checkout occurred.

**References:**

- [DomainFile](https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html)
- [GhidraFile](https://ghidra.re/ghidra_docs/api/ghidra/framework/data/GhidraFile.html)
- [DefaultCheckinHandler](https://ghidra.re/ghidra_docs/api/ghidra/framework/data/DefaultCheckinHandler.html)
- [ProjectData](https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ProjectData.html)
- [GhidraProject](https://ghidra.re/ghidra_docs/api/ghidra/base/project/GhidraProject.html) (`getServerRepository`, `createProject`, etc.)
- [RepositoryAdapter](https://ghidra.re/ghidra_docs/api/ghidra/framework/client/RepositoryAdapter.html)
- [ClientUtil](https://ghidra.re/ghidra_docs/api/ghidra/framework/client/ClientUtil.html)
- [AnalyzeHeadless Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/app/util/headless/AnalyzeHeadless.html)
- [HeadlessAnalyzer 12.0 class notes](https://ghidradocs.com/12.0_PUBLIC/docs/GhidraClass/Intermediate/HeadlessAnalyzer.html)
- Bundled: `<GHIDRA_INSTALL>/support/analyzeHeadlessREADME.html`

## Official API surface: version control (exhaustive checklist for implementers)

Use **only** the non-deprecated overloads for your Ghidra minor version.

| Area | Type / method | Notes |
|------|----------------|-------|
| Publish private file to repo | `DomainFile.addToVersionControl(String comment, boolean keepCheckedOut, TaskMonitor)` | `keepCheckedOut` matches GUI “keep checked out” |
| Preconditions | `canAddToRepository()` | Does not cover all “in use” failures |
| Checkout (project file) | `DomainFile.checkout(boolean exclusive, TaskMonitor)` | No-op if already private |
| Checkin | `DomainFile.checkin(CheckinHandler, TaskMonitor)` | **Requires** checked out + modified since checkout; use `DefaultCheckinHandler(comment, keepCheckedOut, createKeepFile)` |
| Deprecated | `checkin(CheckinHandler, boolean okToUpgrade, TaskMonitor)` | **Deprecated since 11.1** — do not use |
| State | `isVersioned`, `isCheckedOut`, `isCheckedOutExclusive`, `modifiedSinceCheckout`, `canCheckin`, `canCheckout` | Drive branching |
| Merge / undo | `canMerge`, `merge`, `undoCheckout`, `terminateCheckout` | Shared collaboration |
| Hijack | `isHijacked` | Private vs repo collision |
| Project | `ProjectData.getRepository()` → `RepositoryAdapter`; `refresh`; `findCheckedOutFiles`; `convertProjectToShared` | Migration / reconnect |
| Server checkout | `RepositoryAdapter.checkout(folderPath, itemName, checkoutType, projectPath)` | Used with `CheckoutType` NORMAL / EXCLUSIVE |
| Batch import+commit | `analyzeHeadless` + `ghidra://host:port/repo` + `-import` + `-connect` + `-p` + `-commit` | See README + 12.0 HeadlessAnalyzer doc for `-readOnly` / `-process` limits on shared |

## Repository research (agentdecompile code map)

Condensed from `repo-research-analyst`:

- **import_export.py:** `_handle_checkin` / `_handle_checkout`, path-resolved `checkin_domain_file` vs `Program.getDomainFile()`, transaction drain helpers, `DefaultCheckinHandler`.
- **project.py:** `ClientUtil` / `RepositoryAdapter`, `_checkout_shared_program`, dedicated temp `GhidraProject` for shared checkouts, sync pull/push.
- **repository_adapter_listing.py:** Root `"/"`, `""`, `"."` for `getItemList` / `getSubfolderList`.
- **symbols.py:** Intentionally skip `ghidra_project.save(program)` on some shared paths so VC dirty state is not cleared before checkin.

## Preconditions

- **Ghidra Server** running (e.g. `ghidraSvr.bat` on Windows per project docs); repository exists (e.g. `agentrepo`).
- `**GHIDRA_INSTALL_DIR`** set; `**uv run agentdecompile-server**` (or equivalent) for MCP.
- **Same `--server-url`** for all steps in a run so CLI persists `**mcp-session-id**` ([AGENTS.md](AGENTS.md)); if using **proxy**, it must **forward** session id to backend ([fix_shared_project_cli_persistence_b811ed58.plan.md](fix_shared_project_cli_persistence_b811ed58.plan.md)).
- Use `**programPath`** values from `**list-project-files**` after import/open (canonical casing; code also **canonicalizes** via [session_context.py](src/agentdecompile_cli/mcp_server/session_context.py) `canonicalize_program_path`).

## Implementation map (reference)


| Concern                           | Primary code                                                                                                                                                                                  |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Checkout / checkin / status       | [import_export.py](src/agentdecompile_cli/mcp_server/providers/import_export.py) `_handle_checkout`, `_handle_checkin`, `_handle_checkout_status`, `_resolve_domain_file_for_checkout_status` |
| Path canonicalization             | [session_context.py](src/agentdecompile_cli/mcp_server/session_context.py) `canonicalize_program_path`                                                                                        |
| Shared repo checkout              | [project.py](src/agentdecompile_cli/mcp_server/providers/project.py) `_checkout_shared_program`                                                                                               |
| Checkout reclaim (foreign holder) | [import_export.py](src/agentdecompile_cli/mcp_server/providers/import_export.py) `_ensure_versioned_file_ready_for_checkin`                                                                   |
| Sync pull/push                    | [project.py](src/agentdecompile_cli/mcp_server/providers/project.py) `_sync_shared_repository`, `_pull_shared_repository_to_local`, `_push_local_project_to_shared`                           |


## Phase A — Shared project: three cycles + edits

Run as **one `tool-seq`** (or one HTTP session with stable session id).

1. `**open**` — `shared: true`, `path` / repository, `serverHost`, `serverPort`, `serverUsername`, `serverPassword`.
2. `**list-project-files**` — pick `programPath` `P` (e.g. import `sort.exe` first if repo empty).
3. **Cycle 1:** `checkout-program` `programPath: P` → `**manage-function`** `mode=rename` (valid address) → `**checkin-program**` `programPath: P`, `comment: cycle-1`.
4. **Cycle 2:** `checkout-program` `programPath: P` → `**create-label`** or `**manage-symbols**` → `**checkin-program**` `comment: cycle-2`.
5. **Cycle 3:** `checkout-program` → another edit → `**checkin-program`** `comment: cycle-3`.
6. `**list-project-files**` — confirm program still listed.

**Assertions:** Each step returns `success` where expected; `checkout-status` after checkout shows checked out; after checkin, state matches expectations (not checked in vs kept checked out per flags).

### Research Insights (Phase A)

- After edits, ensure **no open Ghidra transaction** on the `Program` consumer before checkin (matches GUI “save and close” guidance; see [byte.how — check in](https://byte.how/posts/collaborative-reverse-engineering/#how-do-i-check-in-a-file)).
- If checkin fails with “not modified”, official contract is consistent: **must** establish `modifiedSinceCheckout` via real domain changes + flush, not retries alone.

## Phase B — Persistence after MCP restart (shared)

1. Stop **agentdecompile-server** (not necessarily Ghidra Server).
2. Start server again; **same** `--server-url` so CLI reuses session if configured.
3. `**open`** (same shared args).
4. `**checkout-program**` `P` (or path from `list-project-files`).
5. `**get-function**` / `**search-symbols**` / `**decompile-function**` — **assert** renamed symbols / labels from phases A1–A3.

## Phase C — Local project: three cycles + edits

1. `**open`** with **local** project path (`.gpr` or directory per launcher).
2. `**list-project-files`** → pick `L`.
3. Three cycles: edits + `**checkin-program**` with `programPath: L` (non-versioned projects may **save** locally; versioned local mirrors shared flow).
4. Restart MCP server; `**open`** same path; assert edits.

### Research Insights (Phase C)

- **Local non-versioned:** `checkin` may degrade to **save** (agentdecompile documents this branch).
- **Local → shared migration:** Official API `ProjectData.convertProjectToShared(RepositoryAdapter, TaskMonitor)` then **close and reopen** project (Javadoc on [ProjectData](https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ProjectData.html)).

## Phase D — sync-project

**Requires** active **shared** session **and** resolvable **local** `project_data` (open local project or same session setup as `_sync_shared_repository` expects — see [project.py](src/agentdecompile_cli/mcp_server/providers/project.py) prerequisite checks).

1. `**sync-project`** `mode: pull` (or `download`), `**dryRun: true**` — inspect planned items / errors.
2. `**sync-project**` `mode: pull`, `**dryRun: false**` — expect `direction: shared-to-local` (or equivalent in payload).
3. `**sync-project**` `mode: push` (or `upload`), `**dryRun: true**` then `**false**` — expect `direction: local-to-shared` or documented save-only behavior.

### Research Insights (Phase D)

- Push uses `DomainFile.save`; Ghidra throws **“Unable to lock due to active transaction”** if Program consumers hold transactions — drain via `DomainFile.getConsumers()` / nested `endTransaction` (agentdecompile delegates to `ImportExportToolProvider._end_open_transactions_on_domain_file_consumers` from push path).

## Phase E — Optional code hardening (code-reviewer)


| Item                                       | Action                                                                                                                    |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------- |
| `exclusive` ignored on shared checkout     | Pass `exclusive` into `_checkout_shared_program`; use Ghidra exclusive checkout type if API allows.                       |
| Check-in all + versioned + `!canCheckin()` | Avoid reporting `save_local` + success as server check-in; return failure or explicit warning with checkout holder hints. |
| Sync push `endTransaction(..., true)`      | Document that push may commit open transactions, or match policy to import_export transaction helpers.                    |


## CLI template (PowerShell)

Replace `P`, server args, and tool payloads (addresses) with real values from your binary.

```powershell
$seq = @'
[
  {"name":"open","arguments":{"shared":true,"path":"REPO","serverHost":"127.0.0.1","serverPort":13100,"serverUsername":"ghidra","serverPassword":"admin"}},
  {"name":"list-project-files","arguments":{}},
  {"name":"checkout-program","arguments":{"programPath":"/P"}},
  {"name":"manage-function","arguments":{"mode":"rename","programPath":"/P","functionIdentifier":"FUN_...","newName":"e2e_cycle1"}},
  {"name":"checkin-program","arguments":{"programPath":"/P","comment":"cycle-1"}},
  {"name":"checkout-program","arguments":{"programPath":"/P"}},
  {"name":"create-label","arguments":{"programPath":"/P","address":"...","labelName":"e2e_l2"}},
  {"name":"checkin-program","arguments":{"programPath":"/P","comment":"cycle-2"}},
  {"name":"checkout-program","arguments":{"programPath":"/P"}},
  {"name":"manage-function","arguments":{"mode":"rename","programPath":"/P","functionIdentifier":"FUN_...","newName":"e2e_cycle3"}},
  {"name":"checkin-program","arguments":{"programPath":"/P","comment":"cycle-3"}},
  {"name":"list-project-files","arguments":{}}
]
'@
uv run python -m agentdecompile_cli.cli --server-url http://127.0.0.1:8080 tool-seq $seq
```

After restart, run a shorter seq: `open` → `checkout-program` → `get-function` / `search-symbols` with identifiers from the renames.

## `/lfg` note

Steps 1–9 in `/lfg` are **Cursor slash workflows** (ralph-loop, workflows:plan, compound-engineering, feature-video, etc.). They must be run **inside Cursor**; this file is the **technical plan** for the shared/local/sync/persistence work those workflows may orchestrate.

## Done criteria

- Shared: 3 edit cycles + checkin succeed in one session.
- Shared: After MCP restart, edits visible.
- Local: 3 cycles + persistence after restart.
- `sync-project` pull and push validated (at least dryRun + one real run each direction).
- Optional: code-reviewer items triaged (implement or document).
