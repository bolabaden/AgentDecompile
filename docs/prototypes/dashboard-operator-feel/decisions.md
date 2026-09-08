# Dashboard operator feel — prototype decisions

Run: 2026-08-31 (Ghidra / IDA / Cheat Engine shell)  
Feel doc: [feel.md](./feel.md) (~10k words)  
Plans: [flow evolution](../../plans/2026-08-31-1029-feat-dashboard-flow-evolution-plan.md), [Phase B spatial](../../plans/2026-08-31-0625-feat-workbench-phase-b-spatial-plan.md), [Phase C batch](../../plans/2026-08-31-0721-feat-dashboard-phase-c-batch-plan.md)

```mermaid
flowchart TD
  chrome[Menubar + project tabs] --> shell[Explorer + Functions]
  shell --> editor[One editor window]
  editor --> listing[Listing]
  editor --> graph[Graph]
  editor --> corpus[Atlas / Pipeline / STABS]
  chrome --> status[Status + jobs output]
```

## Viewport reshape (shipped)

Phases A–C added verbs on a scrolling card stack. That felt like an admin dashboard, not a reverse-engineering tool.

| Steal | From |
|-------|------|
| Menubar + thin toolbar, Program Trees / Functions left | Ghidra CodeBrowser |
| Listing / Graph as window tabs; blue current line; cyan addresses | IDA |
| Splitters, dense rows, no pills or slogans | Cheat Engine |

Corpus panels are **editor tabs**, not a chip strip over a grid of cards. Empty listing is a drop target. Restart / health pills stay out of the header.

## Phase A (shipped)

- Cmd+K primary; File/View backup
- Strip before POST from palette
- Bottom dock; ConfirmDialog
- Session slug ≠ import slug; save without re-open
- Palette ↑↓ Enter; j/k function nav; welcome/project drop

## Phase B (shipped)

| Question | Choice |
|----------|--------|
| Corpus panel discoverability | Always-visible **corpus nav strip** (chips), wb-more default open |
| Laptop cramping | **Compact density** toggle (View menu, localStorage) |
| Dock vs function list | **Optional side rail** on ≥1280px (View menu, localStorage) |
| Repeat verbs | **Recent actions** in palette (localStorage, max 8) |

## Phase C (shipped)

| Question | Choice |
|----------|--------|
| Batch without nesting | **Checked set** on the function list (checkbox, `x`/Space, Ctrl/⌘-click, Shift range). Not a Batch menu. |
| Primary vs checked | Click inspects; checks persist until Esc, chip ×, or program/slug change |
| Batch execute | One strip Run; one confirm; sequential POSTs; “Run N” + count chip |
| Job status for AT | Hidden `#wb-job-live` `aria-live="polite"` on **transitions only**, honest finished copy |

## Rejected

- Accordion-only corpus access
- Third accuracy bar
- Auto-run on function select (Enter opens strip only)
- Custom themes beyond density
- Nested “batch mode” or a second toolbar for multi-select
- `aria-live` on the visible pulse (would re-announce every poll)

## Prototypes

- Phase A: [../dashboard-flow-evolution/mock.html](../dashboard-flow-evolution/mock.html)
- Phase B: [phase-b-mock.html](./phase-b-mock.html)
- Phase C: [phase-c-mock.html](./phase-c-mock.html)

## Dogfood 2026-08-31 — shipped after second drive

Confirmed live on `http://127.0.0.1:8767` with work dir `/tmp/wb-dogfood-fixes`: path-paste open of `/home/brunner56/biodecompwarehouse/repos` (24 programs), Save As `.gpr`, existing `agentdecompile.gpr`, shared-fs export, HTTP `ghidra://127.0.0.1:13100/odyssey`, 8 NWN path imports with distinct slugs, File → Save, reload.

| Shipped | How |
|---------|-----|
| `File → Open from URL…` | `openProjectDialog(tab)` keeps Remote URL |
| Cross-match body | Editor no longer `display:none`s `.wb-surface`; Run Cross-place + island HTML |
| Function list | `list_functions` uses `func.name` when `logical_name` is absent |
| Duplicate filenames | Platform-dir slugs (`nwmain-linux-x86` vs `nwmain-linux-arm64`) + unique dest |
| Open path field | `#wb-open-paste` + Open path |
| Sparse editor tabs | Listing / Graph / Overview / Atlas / Cross-match + More |
| One ⌘K | Button only; filter placeholder is `Filter functions…` |
| Imports first | Explorer **Imports** block above the 24 program names |
| Full project path | `.wb-project-path` wraps; no ellipsis |

| Still deferred | Why |
|----------------|-----|
| Save As `.gpr` from shared-fs/HTTP is a skeleton | Names in origin; Ghidra program DBs are not copied |
| `/report` and `/atlas` 404 on a dashboard-only process | Those routes live on the full MCP HTTP app |
| More menu closes after a pick | `CorpusNavBar` remounts with the tab |
| View → Jobs hits two buttons | Menu item and another Jobs control |
| Cross-match density file missing | Honest error when `reports/_gen_matches.md` is absent |
| Functions stay empty without inventory | Ghidra program names are not corpus slugs; no `func` rows yet |
| Explorer shows ~5 imports without scroll | Eight slugs exist; sidebar is short |
