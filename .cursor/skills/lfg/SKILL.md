---
name: lfg
description: Full autonomous engineering workflow with initiative when the next task is unclear
argument-hint: "[feature description]"
---

# LFG (project override)

This workspace extends the compound-engineering **lfg** skill. When both exist, follow **this file** for step 0; then execute the plugin skill steps in order (renumbered: plugin step 1 → step 1 here after step 0).

CRITICAL: Execute every step below **IN ORDER**. Do not skip the plan gate. Do not jump to implementation before a plan exists in `docs/plans/`.

## Step 0 — Infer intent and choose work (REQUIRED when task is vague)

Run this **before** `ce-plan` when the user says “continue”, “merged”, “/lfg”, or gives no concrete feature description.

1. **Sync and orient**
   - `git fetch origin` and checkout the default integration branch (`master` unless the repo says otherwise).
   - Read `STRATEGY.md`, the latest plan under `docs/plans/`, and `docs/residual-review-findings/*.md` if present.
   - Check open/merged PRs: `gh pr list --state open` and recent merges.

2. **Decide what this cycle will do** (write 3–5 bullets in the plan’s Objective; do not ask the user unless blocked)
   - Prefer **closed loops**: merged PR follow-ups, residual P3/P2 from review docs, explicit plan “Out of scope → now in scope”.
   - Prefer **verifiable software** over doc-only when both are available and similarly sized.
   - Do **one coherent slice** per cycle (docs + small code fix is OK if one plan ties them).
   - If nothing remains, state that in the plan and pick the next active plan file (e.g. CLI ergonomics, DHH simplification follow-ups).

3. **Take initiative**
   - Do not stop after “PR merged” — implement the next highest-value item and open the next PR.
   - Do not return only instructions; run tests, commit, push, and open/update PR yourself.

4. **Gate**
   - Pass the chosen scope into step 1 as `$ARGUMENTS` (one sentence + pointers to residual/plan paths).

## Steps 1–8 — Standard LFG pipeline

1. Invoke **ce-plan** with `$ARGUMENTS`. **GATE:** plan file must exist under `docs/plans/`. Record `plan:<path>` for code review.

2. Invoke **ce-work**. **GATE:** files changed beyond the plan.

3. Invoke **ce-code-review** with `mode:autofix plan:<plan-path>`.

4. **Persist review autofixes** — commit `fix(review): apply autofix feedback` if needed; push before step 5.

5. **Autonomous residual handoff** — only if residual `downstream-resolver` findings exist; else skip.

6. **ce-test-browser** `mode:pipeline` — skip when diff is doc-only or no web UI.

7. **ce-commit-push-pr** — commit, push, open/update PR.

8. Output `<promise>DONE</promise>` when complete.

Bundled skills when requested: **ce-strategy**, **ce-doc-review**, **ce-code-review** — run in logical order (strategy/doc review can inform step 0; code review is step 3).
