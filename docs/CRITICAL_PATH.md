# PE critical path (Phase 5b)

Hard packed PE targets (swkotor-class) follow a **bounded checkpoint loop** inside `reconstruct` — no peer `acquire` or `vacuum` product verbs.

**Workspace freeze:** run recovery only from AgentDecompile. Mizuchi is a read-only donor ([MIZUCHI_ARCHIVE.md](MIZUCHI_ARCHIVE.md)).

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

## Operator fast path (swkotor dump)

From **AgentDecompile only** (`~/Workspaces/agentdecompile`):

```bash
# 1) Unpack + inventory once
uv run agentdecompile-reconstruct /path/to/swkotor.exe \
  --stop-after discover-functions

# 2) Incremental resume + Borealis-shaped dump (export-only when proofs exist)
uv run agentdecompile-reconstruct /path/to/swkotor.exe \
  --resume \
  --dump-source target/swkotor-source-dump \
  --vc-root <msvc8> \
  --source-synthesis-wineprefix <prefix>

# Export-only (skip stages; use existing receipts + optional Ghidra facts)
uv run agentdecompile-reconstruct /path/to/swkotor.exe \
  --dump-source-only \
  --dump-source target/swkotor-source-dump \
  --ghidra-facts target/swkotor-ghidra-merged-decomp.jsonl \
  --work-dir target/agentdecompile-reconstruct/<id>
```

Dump layout:

```text
target/swkotor-source-dump/
  README.md
  MANIFEST.json
  CLAIMS.md
  Port/CODE/...
  verified/            # objdiff 0 only
  advisory/ghidra/     # pretty, NOT proof
```

Open `target/swkotor-source-dump/README.md` — verified first, advisory for readability.

**Hard rules**

- Never rematch proven objdiff-0 functions unless `--force-rematch`. The cache only
  skips on an exact `(entry, sourceSha256)` hit — a changed candidate at the same
  entry is always re-verified (no entry-only skip), so the cache can never launder a
  stale proof.
- Match cache + `--workers` parallelize compile/objdiff; `stage-timings.json` records wall time.
  Workers share one `WINEPREFIX`; concurrent Wine/`cl.exe` can occasionally produce a
  **false mismatch** (never a false proof — the objdiff-0 gate is unchanged). If matches
  look flaky, re-run the affected functions with `--workers 1`.
- Never promote byte-emitters into `verified/`. Any inline-asm / `_emit` / `.incbin` /
  byte-emission source is rejected from `verified/` and only appears (if at all) as advisory.

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
| `slice-verify` | ELF/Mach-O candidates + clang/objcopy; runs at `discover-functions` |
| `apply-propose-labels` | `acquisition/propose-labels.json` has ready rows; apply via MCP + conflict protocol |

Listing an action as **ready** does not count toward the proof ladder — only receipt-backed objdiff accepts do.

## Claim boundary

Critical path readiness is orchestration metadata. Allowed public phrasing stays on measured ladder rungs (1% / 5% / 20% of inventoried functions at objdiff 0). Banned: “90% recovered” without claim class.
