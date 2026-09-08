---
name: workbench-operator
description: "Use this skill when working in /dashboard, dogfooding the workbench, or making the UI feel like IDA, Ghidra, or x64dbg. Apply even if they only say the dashboard is empty, boilerplate, or unusable."
license: AGPL-3.0-or-later
metadata:
  author: AgentDecompile
  version: "1.0"
---

# Workbench operator

The 8080/8767 workbench is the human loop for the same catalog agents call. It is not a settings page or a Swagger wrapper.

## Default loop

1. File → Open a Ghidra repository (shared-fs / `.gpr` / `ghidra://`).
2. Pick a **program** in Explorer (not an Import slug unless you want corpus-SQLite).
3. Functions + Listing should show that program. Empty list → Analyze → Ingest repository into BSim (skill `bsim-corpus`), then Refresh.
4. Select a function → Listing tools (decompile, comment, label, xrefs) via the action strip. **Run**, do not only open the strip.
5. Jobs stay in the dock. Finished ≠ match.

## Implementation rules

- Authoritative UI: `src/agentdecompile_recovery/corpus/dashboard/static/workbench-app.js`.
- After UI changes: restart the dogfood server (do **not** click Restart/Shutdown in the page). Playwright-verify. Do not use curl as the proof.
- If the port is wedged (listen but no HTTP, or D-state): kill −9 or switch port. Never idle-wait.
- Do not claim Functions work from leftover `target/` or backfilled JSONL.

## Anti-patterns

- Treating the Functions window as corpus-only when a Ghidra program is selected.
- Burying BSim ingest in a 193-command list with no Analyze menu.
- Declaring the dashboard done from a screenshot.
