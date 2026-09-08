---
title: "feat: Secondary documentation surfaces"
type: feat
status: ready
date: 2026-09-01
origin: docs/plans/2026-09-01-feat-user-facing-docs-consolidation-plan.md
product_contract_source: none
---

# Secondary documentation surfaces

**Goal:** The six surfaces left out of the landing rewrite get their own tidy pass, without rewriting historical plan bodies or generated tool entries.

```mermaid
flowchart TD
  tools[TOOLS_LIST preamble] --> strategy[STRATEGY and VISION]
  strategy --> skills[Skills catalog]
  skills --> plans[Plans hub]
  plans --> solutions[Solutions hub]
  solutions --> webui[Web UI hero]
  webui --> verify[Secondary docs tests]
```

This plan does **not** mutate the landing-page plan. Historical `docs/plans/**` bodies stay frozen except this file and a new hub.

## Slices

| Slice | Address | Must not |
|---|---|---|
| 1 TOOLS_LIST | Hand-edit preamble only: hops, 75/71/4, generator note | Rewrite Canonical Tool Docs |
| 2 STRATEGY / VISION | Hops, date, fix script-damaged words | Turn VISION into a README |
| 3 Skills | Catalog in `skills/README.md`; identical repo-root path text in both skill trees | Rewrite evals or stub loaders |
| 4 Plans | New `docs/plans/README.md` — living vs frozen | Rewrite dated execution plans |
| 5 Solutions | Hub + stale advertised-count note | Delete dated workflow-learnings |
| 6 Web UI hero | Headline and lede from `docs/HERO.md` | Redesign the tool runner |

## Verification

`tests/test_secondary_docs_surfaces.py` checks hubs, preamble counts, VISION corruption, and Web UI hero strings. Do not parse TOOLS_LIST tool bodies.
