# PE critical path (Phase 5b)

Hard packed PE targets (swkotor-class) follow a **bounded checkpoint loop** inside `reconstruct` — no peer `acquire` or `vacuum` product verbs.

## Checkpoint sequence

```mermaid
flowchart LR
  A[prepare-analysis-image] --> B[inventory-binary]
  B --> C[discover-functions]
  C --> D[generate-source-candidates]
  D --> E[synthesize-source-tasks]
  E --> F[vacuum --autonomous]
```

| Stop-after stage | Receipt | Purpose |
|------------------|---------|---------|
| `prepare-analysis-image` | `analysis-target.json` | Steamless unpack or typed soft-fail |
| `inventory-binary` | `binary-inventory.json` | Sections, imports, symbols |
| `discover-functions` | `function-candidates.json` | Function-boundary candidates (proof ladder denominator) |
| `generate-source-candidates` | `source-generation/summary.json` | Decompiler-fact tasks |
| `synthesize-source-tasks` | `source-synthesis/summary.json` | Compile + objdiff bounded verify |

## Example operator flow

```bash
# Unpack + inventory only
agentdecompile-reconstruct swkotor.exe --stop-after discover-functions

# Inspect readiness (CLI legacy status or MCP reconstruct status)
# work dir contains critical-path.json with readiness + nextActions
```

Resume the same work dir with `--resume` (default) to continue through later stages.

## Soft-fail (Steamless / mono)

When a packed PE cannot be unpacked, `analysis-target.json` records `status: blocked` and `terminalStatus: blocked:toolchain`. `critical-path.json` surfaces `readiness: blocked:toolchain` with checkpoint `softFail` details — the run refuses to invent an analysis image.

## Next actions (glue, not auto-run)

`critical-path.json` → `nextActions` lists budget-gated follow-ups:

| Action | When ready |
|--------|------------|
| `synthesize-source-tasks` | Candidates + objdiff/clang (or wine) available |
| `vacuum-seed` | `source-generation/tasks.jsonl` exists; use `--autonomous` |
| `profile-corpus` | Objdiff-verified examples under `verified/` |
| `reloc-slice` | PE inventory + per-function target object helpers |

Listing an action as **ready** does not count toward the proof ladder — only receipt-backed objdiff accepts do.

## Claim boundary

Critical path readiness is orchestration metadata. Allowed public phrasing stays on measured ladder rungs (1% / 5% / 20% of inventoried functions at objdiff 0). Banned: “90% recovered” without claim class.
