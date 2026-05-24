# `/lfg` — end-to-end proof sequence (canonical spec)

**Single source of truth for execution order:** [`scripts/lfg_cmd_sequence.ps1`](../../scripts/lfg_cmd_sequence.ps1). This file describes everything that driver runs: shared Ghidra Server track, local `.gpr` track, **`sync-project` pull/push**, MCP restarts, extended MCP tool sweeps, and CLI `--local` headless phases. Agents implementing `/lfg` should follow this document and the script together.

**This is not** `pytest` and not the small unit tests under `tests/` — it is a **live** Ghidra + MCP + CLI harness. Do not substitute “run the test suite” for this sequence.

---

## Prerequisites

- **`GHIDRA_INSTALL_DIR`** (or `-GhidraHome`) pointing at a Ghidra install.
- **`agentdecompile-server`** / CLI available via `uv run` or repo `.venv` (the script uses `.venv/Scripts/python.exe` when present).
- For the **shared** phases: Ghidra Server reachable at the **TCP base port** used in `open` (default **25100** in the script; may auto-shift if the port triplet is busy — see script `Find-LfgFreeGhidraBasePort`).
- **`MCP restart`** means: stop the MCP Python process, start a new one, delete persisted CLI session (`$RepoRoot/.agentdecompile/cli_state.json` — the driver calls **`Clear-LfgCliState`**), then call **`open`** again in the new process.

---

## Run identity, artifacts, and project directories

- Pick **`RUN_ID`** (script param **`-RunId`**). **Shared** labels: **`sh_<RUN_ID>_…`**; **local Track B**: **`loc_<RUN_ID>_…`**; **CLI headless** label: **`cli_<RUN_ID>_…`**.
- **Shared program path** (default **`/sort_lfgpytest_b4bea676fd4f.exe`**) — fixture imported under version control on the server.
- **Import source** (default **`C:/Windows/System32/sort.exe`**) — copied/imported as the binary under test.
- **Evidence root:** `.lfg_run/lfg_cmd_<RunId>/`
  - **`mcp_workspace/`** — PyGhidra project used for **shared-server** MCP sessions (must align with versioned server state).
  - **`local_gpr_dir/`** — **separate** local-only `.gpr` root for Track B (script starts MCP with **`-LocalTrack`** on this path so it never shares the same project tree as `mcp_workspace`).
  - **`local_cli_gpr_dir/`** — fresh project dir for **CLI `--local`** phases (15–17); cleaned before phase E.
  - Logs: **`driver.log`**, **`mcp_server_<n>.*.log`**, **`<step>.stdout.log`**, **`*.steps.json`**, **`ghidra_server.*.log`**.

**Driver command:**

```powershell
.\scripts\lfg_cmd_sequence.ps1 -RunId "<id>" [-GhidraPort 25100] [-SkipLocalHeadless:$false] ...
```

---

## Process hygiene (agents)

- **Never** run stock **`ghidraSvr.bat console`** unmodified for automation: it uses `start "<title>"` and opens a **separate JVM window**; logs are not in your terminal.
- **Never** attach `ghidraSvr.bat console` to the **driver** terminal (`cmd /c … -NoNewWindow`): it blocks the shell. The driver uses a **headless** `cmd.exe` (`CreateNoWindow`); JVM logs go to **`ghidra_server.*.log`** under the evidence folder.
- **MCP** uses `Start-Process` **without** `-NoNewWindow` (detached, **`-WindowStyle Hidden`** by default). **`StartMcpInNewWindow`** tees MCP logs to a visible window.
- **Tail logs:** e.g. `Get-Content .lfg_run\lfg_cmd_<RunId>\ghidra_server.stdout.log -Tail 40 -Wait`
- The driver **frees the MCP port** (stops stale listeners / prior `agentdecompile-server`), clears inherited **`AGENT_DECOMPILE_PORT`**, sets it for this run, and in **`finally`** stops MCP + Ghidra started by the script.
- **Long runs (~10+ minutes):** do **not** block the agent’s main shell on the script. Spawn a **separate** `powershell.exe` that `Set-Location`s the repo, sets **`GHIDRA_INSTALL_DIR`**, runs the script, and tees to **`driver.log`**. Use **`Start-Process -PassThru`** for the child PID (never assign **`$pid`**). Optionally **`.\scripts\lfg_watch_driver.ps1`**.

---

## Ordered sequence (matches the script)

### Ghidra Server bootstrap (when `-AutoStartGhidraServer` is true)

- Isolated repos under evidence, patched **`ghidraSvr`** + **`lfg_ghidra_server.conf`**.
- Wait for **`ghidra_server_repositories/users`** (not merely TCP on the base port — see script).
- **`svrAdmin -add`** for the Ghidra user; poll **`-users`** (not **`-list`**, which is repo-centric and may omit SIDs when no repos exist); if still missing, **restart Ghidra once** to flush the `~admin` queue, **`-add`** again, then poll; if the user never appears, the script **throws** (no bogus **`changeme`**). MCP **`open`** uses **`changeme`** once the user exists.

### Session A — Shared server: fixture + three versioned check-ins (one MCP process)

1. **`Start-LfgMcp`** with **`mcp_workspace`** (not local track).
2. **`Clear-LfgCliState`**
3. **`Ensure-LfgGhidraServerUp`**
4. **`open`** — `shared: true`, repository path, server host/port, user/password.
5. **If** auto-started isolated repos (**`LfgIsolatedGhidraRepos`**): **`import-binary`** with **`enableVersionControl: true`**, **`filePath`** = import source, **`programPath`** = shared EXE path, **`analyzeAfterImport: false`** (step **`01b_shared_import_fixture`**).
6. **×3 cycles** on the **shared** program (same MCP session):
   - **`checkout-program`** — **`exclusive: true`**
   - **`create-label`** — **`sh_<RUN_ID>_L1` … `L3`** at distinct VAs (script derives addresses from **`RUN_ID`**)
   - **`checkin-program`** — comments **`sh_<RUN_ID>_ck_1` … `3`**
   - Script inserts sleeps between cycles 2 and 3 to avoid HTTP/JVM flake after versioned reopen.
7. **02d (same MCP session, before any restart):** **`checkout-program`** (exclusive) → **`search-symbols`** query **`sh_<RUN_ID>_`**. **Hard assert:** log must contain **`L1`, `L2`, `L3`** (`Assert-LfgLogContainsAll` on **`02d_shared_search_same_mcp.stdout.log`**).

### MCP restart → Session B — Local `.gpr` Track B: import + three saves

8. **`Start-LfgMcp`** with **`local_gpr_dir`** and **local track** flag (see script **`-LocalTrack`**).
9. **`Clear-LfgCliState`**
10. **`open`** (local project dir) → **`import-binary`** **`enableVersionControl: false`** → program **`/sort.exe`**
11. **×3 cycles** on **`/sort.exe`**:
    - **`checkout-program`** — **`exclusive: false`**
    - **`create-label`** — **`loc_<RUN_ID>_L1` … `L3`**
    - **`checkin-program`** — **`loc_<RUN_ID>_ck_1` … `3`**

### MCP restart → Session C — Shared persistence (post-restart)

12. **`Start-LfgMcp`** **`mcp_workspace`**, **`Clear-LfgCliState`**, **`Ensure-LfgGhidraServerUp`**
13. **`open`** shared → **`checkout-program`** exclusive → **`search-symbols`** **`sh_<RUN_ID>_`**. **Hard assert:** **`L1–L3`** in **`05_assert_shared_after_mcp.stdout.log`**.

### MCP restart → Session D — Local persistence (post-restart)

14. **`Start-LfgMcp`** **`local_gpr_dir`** local track, **`Clear-LfgCliState`**
15. **`open`** local dir → **`search-symbols`** **`loc_<RUN_ID>_`**. **Hard assert:** **`L1–L3`** in **`06_assert_local_after_mcp.stdout.log`**.

### MCP restart → Session E — Fourth shared check-in

16. **`Start-LfgMcp`** **`mcp_workspace`**, **`Clear-LfgCliState`**, **`Ensure-LfgGhidraServerUp`**
17. **`open`** shared → **`checkout-program`** exclusive
18. **`create-label`** **`sh_<RUN_ID>_L4`**
19. **`checkin-program`** + **`checkout-status`** (JSON) — step **`07_*`**.

### MCP restart → Session F — `sync-project` **pull** + prove **four** server revisions

20. **`Start-LfgMcp`** **`mcp_workspace`**, **`Clear-LfgCliState`**, **`Ensure-LfgGhidraServerUp`**
21. Tool-seq **`08_pull_verify_four_ck`** (exact order matters):
    - **`open`** shared
    - **`checkin-program`** — comment **`lfg_release_checkout_before_pull`** (releases checkout so pull can proceed cleanly)
    - **`sync-project`** — **`mode: pull`**, path = shared EXE, **`recursive: true`**, **`force: true`**, **`dryRun: false`**
    - **`checkout-program`** exclusive
    - **`search-symbols`** **`sh_<RUN_ID>_`** — **hard assert** **`L1–L4`**
    - **`checkout-status`** JSON — **hard assert** **`latest_version`** is **4** (regex in script)

### MCP restart → Session G — Fifth revision: mutate, **`sync-project` push**, verify **five** revisions

22. **Required extra restart:** After pull, the script **restarts MCP** again (`Start-LfgMcp` + **`Clear-LfgCliState`**) so the next session is a **fresh PyGhidra JVM** (avoids checkout metadata corruption after pull).
23. **`open`** shared (**`09_open_shared_after_pull`**)
24. **`Invoke-LfgPushFifthVerifySequence`**:
    - **`checkout-program`** exclusive
    - **`create-label`** **`loc_<RUN_ID>_PUSH`** + **`checkin-program`** in one tool-seq (or **`resolve-modification-conflict`** **`overwrite`** + retry checkin if Ghidra reports a modification conflict)
    - **`sync-project`** **`mode: push`**, **`path: /`**, **`recursive: true`**, **`dryRun: false`**
    - **`checkout-program`** exclusive
    - **`checkout-status`** JSON — **assert** **`latest_version`** **5**
    - **`search-symbols`** query **`loc_<RUN_ID>_PUSH`** — **assert** hit
    - Success logs: **`09_push_sync_verify.stdout.log`** or **`09_push_retry_sync_verify.stdout.log`**

### MCP restart → Session H — Local Track B still isolated after server pull + push

After **`sync-project` pull** and the **fifth-revision push** on the shared program, the driver proves the **separate** local `.gpr` tree was not overwritten: labels **`loc_*_L1–L3`** must still resolve.

25. **`Start-LfgMcp`** **`local_gpr_dir`** local track, **`Clear-LfgCliState`**
26. **`open`** local dir → **`search-symbols`** **`loc_<RUN_ID>_`**. **Hard assert:** **`L1–L3`** still present (**`10_assert_local_persistence.stdout.log`**).

---

## Extended MCP tool coverage (Phases A–D, same driver run)

After step **H**, the script runs **additional `tool-seq` groups** against **`/sort.exe`** (local track) and the **shared** program. These use **`Invoke-LfgSeqUnchecked`** for many groups: **non-zero exit increments a counter and prints a WARN** but **does not abort** the run unless a later hard assert fails. Treat this as **broad e2e surface area**, not a guarantee that every possible tool/argument combination is covered.

**Boundary:** **`Start-LfgMcp`** **`local_gpr_dir`** + **`Clear-LfgCliState`** immediately before extended coverage.

**Phase A — local project (read-heavy; `open` is a hard gate)**

| Log prefix (example) | Tools invoked (in order) |
|----------------------|---------------------------|
| `11_ext_open_analyze` | **`open`** local project dir only (**`Invoke-LfgSeq`** — must succeed; name is historical) |
| `11_ext_discovery_surface` | `search-everything`, `manage-symbols` (imports/exports), `list-project-files`, `get-current-program` |
| `11_ext_memory_bytes` | `inspect-memory` (read + data_at) |
| `11_ext_function_context` | `get-function`, `get-call-graph` |
| `11_ext_search_tools` | `search-everything`, `search-constants` |
| `11_ext_refs_xrefs` | `get-function` |
| `11_ext_data_types_structures` | `manage-data-types` (list), `manage-structures` (list), `list-project-files`, `manage-files` (list), `manage-symbols` (symbols) |
| `11_ext_manage_readonly` | `manage-bookmarks` (list), `manage-comments` (search), `manage-function-tags` (list), `get-function` |
| `11_ext_export_suggest` | `export` (SARIF to evidence path), `suggest` |
| `11_ext_processors` | `list-processors` |

**Phase B — local mutations + checkin**

- **`12_ext_checkout_mutate`:** `checkout-program` → `manage-bookmarks` set → `manage-comments` set → `manage-function-tags` add  
- **`12_ext_verify_mutations`:** list/get modes for bookmarks, comments, function-tags  
- **`12_ext_checkin`:** `checkin-program` (throws on failure — **`Invoke-LfgSeq`**)

**Phase C — shared program (analyze + read + checkin)**

- **`13_ext_shared_open_analyze`:** `open` shared → `checkout-program` exclusive → **`analyze-program`** → `search-everything`, `get-function` → **`checkin-program`**

**Phase D — `svr-admin`**

- **`14_ext_svr_admin`:** `svr-admin` with **`-list`** against the **install** `server.conf` — often **no default server** in LFG; **non-zero is acceptable** (tool still exercised).

---

## CLI local headless (Phase E) — no MCP HTTP server

**Skipped** if **`-SkipLocalHeadless:$true`**.

1. **`Stop-LfgMcp`** and cooldown; **wipe `local_cli_gpr_dir/*`** to avoid stale locks.
2. **Step 15 (`15_cli_local_import_label`):** `agentdecompile-cli --local --local-project-path <local_cli_gpr_dir> tool-seq`:
   - **`import-binary`** (no VC) → **`checkout-program`** → **`create-label`** **`cli_<RUN_ID>_L1`** → **`checkin-program`**
   - **Hard assert:** exit **0**.
3. **Step 16 (`16_cli_local_persist`):** **new OS process**, same project dir:
   - **`open`** **`/sort.exe`** → **`search-symbols`** **`cli_<RUN_ID>_`**
   - **Hard assert:** **`cli_<RUN_ID>_L1`** in log.
4. **Step 17 (`17_cli_local_readonly`):** third **`--local`** invocation (unchecked exit — warns on failure):
   - **`open`** **`/sort.exe`** → **`get-function`**, **`inspect-memory`**, **`search-everything`**

---

## Pass / fail semantics

- **Hard failures (script throws, `finally` still tears down Ghidra/MCP):** any missing assert log, wrong substring, **`Invoke-LfgSeq`** non-zero where used, CLI steps **15–16** non-zero.
- **Soft failures:** extended phases **11_ext_***–**14_ext_*** and CLI step **17** may log **WARN** and still reach **`=== DONE`** if counters are non-zero — inspect the named **`*.stdout.log`** files.
- **Completion line:** **`=== DONE. Evidence under <path> ===`**

---

## What LFG is not

- **Not** a replacement for `list-tools` / full registry enumeration: some tools are GUI-only, experimental, or require credentials or binaries not present on the host.
- **Not** pytest: do not conflate this harness with `uv run pytest`.

For **every tool name and argument** the driver uses, prefer reading the **`*.steps.json`** files under the evidence directory for the exact JSON the CLI sent.
