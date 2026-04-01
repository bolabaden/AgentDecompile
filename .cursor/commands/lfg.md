# `/lfg` — strict proof sequence (run exactly in this order)

**Prereqs:** Ghidra Server listening on the TCP base port used by `open` (see `server/server.conf`, e.g. `-p23100`); `GHIDRA_INSTALL_DIR`; `agentdecompile-server` reachable. **MCP restart** = stop the MCP Python process, start a new one, delete persisted CLI session (CLI uses `Path.cwd()/.agentdecompile/cli_state.json` — driver clears `$RepoRoot/.agentdecompile/cli_state.json`), then call **`open`** again.

### Process hygiene (agents — do not spawn throwaway GUI consoles)

- **Never** run **stock** `ghidraSvr.bat console` unmodified for automation: it uses `start "<title>"` and opens a **separate JVM window**; logs are not in your terminal.
- **Never** attach `ghidraSvr.bat console` to the **driver** terminal (`cmd /c … -NoNewWindow`): it prints “Use Ctrl-C…” and **blocks** that shell. The driver opens a **separate PowerShell window** for Ghidra only; your driver terminal keeps running tool-seqs.
- **MCP** in the driver uses `Start-Process` **without** `-NoNewWindow` (detached child, **`-WindowStyle Hidden`**, logs under `mcp_server_<n>.*.log`). For live MCP output in another window, pass **`-StartMcpInNewWindow`** (tees to the same log files).
- **Do** tail evidence logs from any terminal: `Get-Content .lfg_run\lfg_cmd_<RunId>\ghidra_server.stdout.log -Tail 40 -Wait` (stop with Ctrl+C).
- The **driver** `lfg_cmd_sequence.ps1` auto-starts Ghidra via a **patched** `ghidraSvr.bat` under **`GHIDRA_INSTALL_DIR\server\`** (temp name, removed in `finally`) with **`start /B "" java … >> …\ghidra_server.stdout.log`**. Flags: **`-AutoStartGhidraServer:$false`** if the port is already up; **`-StopStartedGhidraOnExit:$false`** to leave an auto-started Ghidra running after a green run (default is to stop only the server **this** script started).
- **Agents (automation):** The driver can run **10+ minutes**. Do **not** block the agent’s shell on `.\scripts\lfg_cmd_sequence.ps1` — you cannot tail logs or run other checks while it holds the terminal. Spawn a **separate** `powershell.exe` (`Start-Process`) that `Set-Location`s the repo, sets `GHIDRA_INSTALL_DIR`, runs the script, and pipes output to **`.lfg_run/lfg_cmd_<RunId>/driver.log`** (e.g. `*>&1 | Tee-Object`). Then tail `driver.log`, `mcp_server_*.log`, and `*.stdout.log` under the same evidence folder while the run continues. **PowerShell:** `$PID` / `$pid` is the *current* process id (read-only) — never assign `$pid = <child id>`; use `Start-Process -PassThru` and e.g. `$lfgDriver = Start-Process ...; $lfgDriver.Id`, or run **`.\scripts\lfg_watch_driver.ps1 -DriverProcessId $lfgDriver.Id -RunId "<id>" -Wait`** to poll safely. Monitor that child PID and stop it when restarting; do not start multiple drivers without closing the old one.

Pick **`RUN_ID`**. Shared labels/symbols: **`sh_<RUN_ID>_…`**; local Track B: **`loc_<RUN_ID>_…`**. Use one fixed **shared** program path (e.g. `/sort_lfgpytest_b4bea676fd4f.exe`) and a **dedicated empty directory** for the local `.gpr` (driver creates it under `.lfg_run/lfg_cmd_<RunId>/local_gpr_dir`).

**Driver:** `.\scripts\lfg_cmd_sequence.ps1 -RunId "<id>" -GhidraPort <server.conf> …` — artifacts: `.lfg_run/lfg_cmd_<RunId>/` (`*.steps.json`, `*.stdout.log`, `ghidra_server.*.log`, `mcp_server_*.log`).

---

1. **Shared — three check-ins** (same MCP session): `open` (shared repo) → **×3:** `checkout-program` (`exclusive: true`) → mutating tool (e.g. `create-label` `sh_<RUN_ID>_L1` … `L3`, distinct addresses) → `checkin-program` (distinct comments `sh_<RUN_ID>_ck_1` … `3`).

2. **MCP restart.**

3. **Local — three check-ins/saves** (same MCP session): `open` (local dir) → `import-binary` (`enableVersionControl: false`) → **×3:** `checkout-program` → `create-label` `loc_<RUN_ID>_L1` … `L3` → `checkin-program` `loc_<RUN_ID>_ck_1` … `3`.

4. **MCP restart.**

5. **Shared persistence:** `open` (shared) → `checkout-program` → `search-symbols` query `sh_<RUN_ID>_` — **all three** shared labels must appear.

6. **MCP restart.**

7. **Local persistence:** `open` (same local dir) → `search-symbols` query `loc_<RUN_ID>_` — **all three** local labels must appear.

8. **MCP restart.**

9. **Shared — fourth check-in:** `open` (shared) → `checkout-program` → `create-label` `sh_<RUN_ID>_L4` → `checkin-program` → `checkout-status` (note version).

10. **MCP restart.**

11. **Pull shared → local mirror + prove four revisions** (same MCP session): `open` (shared) → `sync-project` **`pull`** for that EXE path (`force: true` if the mirror already exists) → `checkout-program` → `search-symbols` `sh_<RUN_ID>_` — **L1–L4** present → `checkout-status` — **`latest_version` / `current_version` must reflect four check-ins** for that EXE on the server.

12. **Fifth revision — edit mirror, push** (same session as step 11): `checkout-program` if needed → mutating tool on the **post-pull** working copy (e.g. `create-label` `loc_<RUN_ID>_PUSH`) → `checkin-program` → `sync-project` **`push`** (`dryRun: false`) → `checkout-status` — **five** check-ins for that EXE → `search-symbols` finds `loc_<RUN_ID>_PUSH`.

13. **MCP restart.**

14. **Local `.gpr` Track B intact:** `open` (same local dir as step 3) → `search-symbols` `loc_<RUN_ID>_` — **L1–L3** still present (proves pre-pull local project unchanged).

---

**Pass:** every `tool-seq` exits **0** and logs satisfy steps 5, 7, 11–12 (symbol counts + version numbers), and step 14.
