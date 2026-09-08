# Task: Sidebar (Explorer + Functions)

Write **only** `src/agentdecompile_recovery/corpus/dashboard/static/workbench-sidebar.css`.

Read first: `docs/superpowers/specs/2026-08-31-workbench-control-system-design.md` and tokens/controls CSS.

Classes:
- `.wb-sidebar`, `.wb-sidebar-section`, `.wb-sidebar-head`
- `#wb-binary-list`, `.wb-source-tree`, `.wb-source-project`, `.wb-bin`
- `.wb-programs`, `.wb-import-head`, `.wb-import`, `.wb-remove`
- `#wb-functions`, `#wb-func-window`, `.wb-func-row`, `.wb-func-row.on`, `.wb-func-check`
- `.wb-empty`, function empty hint

Feel: Ghidra Program Trees + IDA Functions. Tree is a **column**, not a wrapping card grid. Imports first, kicker label. Kind-colored rail on project root. Selected row `--sel`. Function rows: checkbox, tabular `code` address in `--addr`, name in `--fg-max`. Dense 22px rows. Hover/select/focus distinct.

Do not edit JS. Do not commit.
Report: `docs/plans/wb-control-briefs/sidebar-report.md`.
