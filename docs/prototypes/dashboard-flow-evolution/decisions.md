# Dashboard flow evolution — prototype decisions

Run: 2026-08-31  
Parent plan: `docs/plans/2026-08-31-1029-feat-dashboard-flow-evolution-plan.md`

## Question 1: Cmd+K vs menubar + scroll?

**Chosen:** Cmd+K command palette as primary power entry; menubar stays for file/project ops only.

**Rejected:** Removing menubar entirely (operators still expect File → Save).

**Reason:** Palette merges “run action” and “go to surface” without nested View hunting.

## Question 2: Run with defaults vs edit fields?

**Chosen:** Two-step on the context action strip — **Run** (context + env defaults, optional edited params) and **Fields** toggle for inline `ToolField` overrides.

**Rejected:** Always opening Swagger for params; always blocking on a full modal form.

**Reason:** Quick toolbar buttons keep one-click run; palette picks land on the strip first for inspection.

## Question 3: Bottom jobs dock vs stealing focus?

**Chosen:** Collapsible bottom **jobs dock** pinned open while jobs run; log fetched on row select; cancel inline.

**Rejected:** `window.alert` log tail; raw JSON as default inspector content.

**Reason:** Peripheral vision for running work without modal interruption.

## Question 4: Surface index enough without layout reshape?

**Chosen:** Yes for Phase A — palette “Go to” + View menu entries + auto-open `<details id="wb-more">` when navigating to buried panels.

**Rejected (Phase B deferred):** Right-rail jobs panel; always-visible corpus grid row.

**Sign-off:** Phase A interactions sufficient; **U4 layout reshape not required** unless dogfood proves otherwise.

## Feel anchors (short)

- Context is the command line — selection prefills, params visible on demand.
- Honest calm — “A finished job is not a match” in dock footer.
- In-app confirms for destructive ops — no `window.confirm`.
