---
name: re-worker
description: "Use this skill when asked to analyze, decompile, or type a single function and return a JSON artifact. Not for coordinating other agents."
license: AGPL-3.0-or-later
metadata:
  author: AgentDecompile
  version: "1.0"
  role: worker
---

# RE Worker

Analyze the assigned function. Output **is** the JSON artifact. No coordination.

**REQUIRED SUB-SKILL:** `tiered-re-analysis`

## Rules

1. Every claim needs evidence (decomp, xrefs, constants). No hallucinated types or names — use `UNKNOWN`.
2. Confidence 0.0–1.0. List gaps. Do not overwrite stronger prior findings.
3. Compare decompile vs disassembly. Do not trust the decompiler blindly.
4. Discovery-only (exists? callers?): Tier 2. Semantics/types: Tier 3. Never `execute-script` when an advertised tool exists.

## Procedure

1. `get-function` then `get-functions` decompile **and** disassemble. Flag mismatches.
2. Extract args, return, constants, memory, control flow.
3. `get-references` to/from, `get-call-graph`, `list-cross-references`. Check caller/callee type fit.
4. Patterns: parse, crypto, alloc, errors, vtables, buffer walks.
5. Return only this artifact:

```json
{
  "address": "0x",
  "name": "",
  "suggested_name": null,
  "signature": "",
  "calls": [],
  "called_by": [],
  "arguments": [{"index": 0, "name": "", "type": "", "confidence": 0.0, "evidence": ""}],
  "returns": {"type": "", "confidence": 0.0, "evidence": ""},
  "local_variables": [{"name": "", "type": "", "purpose": ""}],
  "constants_used": [],
  "strings_referenced": [],
  "side_effects": [],
  "hypothesis": "",
  "evidence": [],
  "patterns_detected": [],
  "confidence": 0.0,
  "gaps": [],
  "decompiler_warnings": []
}
```

Names: locals/params `camelCase`, fields `snake_case`, types `PascalCase`, enums `SCREAMING_SNAKE`.

| Score | Meaning |
|---|---|
| 0.9–1.0 | String/API-clear |
| 0.7–0.8 | Strong circumstantial |
| 0.5–0.6 | Plausible, gaps remain |
| 0.3–0.4 | Guess |
| 0.0–0.2 | Structural only |
