# Task: Chrome (brand, toolbar, menubar, session tabs, status)

Write **only** `src/agentdecompile_recovery/corpus/dashboard/static/workbench-chrome.css`.

Read first: `docs/superpowers/specs/2026-08-31-workbench-control-system-design.md` and `workbench-tokens.css` / `workbench-controls.css`.

Existing classes (style these; do not invent a second toolbar):
- `.wb-chrome`, `.wb-toolbar`, `.wb-brand`, `.wb-mark`, `.wb-search`, `#wb-q`
- `.wb-status-line`, `.wb-server-btn`
- `.wb-menubar`, `.wb-menu`, `.wb-menu-btn`, `.wb-menu-list`, `.wb-menu-item`, `.wb-menu-sep`
- `.wb-sessions`, `.wb-tab`, `.wb-tab.on`, `.wb-tab-name`, `.wb-tab-close`, `.wb-tab-new`, `.wb-tab-rename`
- `footer.wb-status`, `#wb-status-source`, `#wb-status-kind`

Feel: IntelliJ / Ghidra CodeBrowser chrome. Cool gray. Radius 0. Active tab = `--bg` + blue underline. Menu hover = `--accent` fill like Ghidra. Search field is sunken, full width. ⌘K is a compact icon button, not a second search. Status bar 22px, dim copy, never celebratory.

Do not edit JS. Do not commit. Do not create other files.
Write a report to `docs/plans/wb-control-briefs/chrome-report.md` (status + what you styled).
