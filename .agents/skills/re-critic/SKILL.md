---
name: re-critic
description: "Use this skill when asked to review, challenge, or verify someone else's function analysis against the binary. Do not invent a new hypothesis."
license: AGPL-3.0-or-later
metadata:
  author: AgentDecompile
  version: "1.0"
  role: critic
---

# RE Critic

Validate Worker artifacts. Independent tool calls. No new hypothesis.

**REQUIRED SUB-SKILL:** `tiered-re-analysis`

Use the lowest sufficient tier: strings/imports → Tier 0 or `list-strings`/`list-imports`; xrefs → Tier 2; types/semantics → fresh Tier 3 decompile.

## Procedure

1. Fresh `get-functions` decompile, `get-references`, `get-call-graph`, `search-constants`, `search-strings`.
2. Check `calls`, `called_by`, `arguments`, `returns`, `side_effects`, `hypothesis`, `constants_used`, `strings_referenced`.
3. If multiple workers: compare hypotheses and types; lower unjustified confidence.
4. Type propagation: return/args must match **all** callers; same offsets must agree.

Unverifiable claims → `unverified`, not assumed correct.

## Review record (return only this JSON)

```json
{
  "function_address": "0x",
  "worker_artifact_reviewed": "",
  "verdict": "confirmed | disputed | insufficient_evidence",
  "overall_confidence_adjustment": 0.0,
  "checks": [{"field": "", "claim": "", "verified": true, "method": "", "note": ""}],
  "issues": [{"severity": "critical | major | minor", "description": "", "evidence": "", "recommendation": ""}],
  "type_inconsistencies": [],
  "unverified_claims": [],
  "confidence_assessment": {"original": 0.0, "adjusted": 0.0, "reason": ""}
}
```

Adjustments: all verified +0.1; key unverified −0.1–0.2; contradiction −0.2–0.4; unsupported hypothesis −0.3–0.5; worker disagreement → min − 0.1. Hallucinated evidence is `critical`.
