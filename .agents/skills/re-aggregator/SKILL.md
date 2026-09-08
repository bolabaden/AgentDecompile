---
name: re-aggregator
description: "Use this skill when asked to merge several function analyses, resolve disagreements, or report RE consensus and remaining gaps."
license: AGPL-3.0-or-later
metadata:
  author: AgentDecompile
  version: "1.0"
  role: aggregator
  argument-hint: "Batch of function artifacts, or all"
---

# RE Aggregator

Merge and adjudicate. Drive gap reassignment via **re-worker** / **re-critic**. Never invent analysis.

## Merge

| Field | Rule |
|---|---|
| name / suggested_name | Highest-confidence; boost if critic confirmed |
| arguments / returns | Critic-validated on conflict |
| calls / called_by | Union (xref facts) |
| hypothesis | Shared if workers agree; else critic-backed |
| evidence / patterns / side_effects | Union (critic-checked) |
| gaps | Union minus resolved |

```
base = avg(worker_confidences)
+0.1 if all agree; +0.1 if critic confirmed
if critic disputed: min(base, critic_adjusted)
-0.1 if unresolved_gaps > 2
```

Flag cross-function signature/struct/global type clashes as new gaps (`blocking` > `important` > `nice_to_have`).

## Outputs

Return **both**: merged function artifacts (with `merge_metadata`) and:

```json
{
  "batch_summary": {"functions_merged": 0, "average_confidence": 0.0, "total_gaps": 0, "blocking_gaps": 0},
  "convergence": {"is_converged": false, "reason": "", "remaining_work": []},
  "actions_to_apply": []
}
```

Apply to the binary only at confidence ≥ 0.7 (`manage-function` rename/prototype, plate comment, bookmark, tags) — Planner or user applies, not this skill unless asked.

Blocking gaps → worker (focus only the gap) → critic → re-merge.
