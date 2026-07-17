# Context puzzle-piece fusion

AgentDecompile treats extra inputs as **puzzle pieces** for a target binary: sniff type, extract address-keyed facts when possible, register the bundle by target fingerprint, and keep everything advisory until objdiff.

## One mental model

```bash
agentdecompile-reconstruct game.exe ./ugly-decomp/ notes.md symbols.jsonl archive.gzf
```

Equivalent forms:

| Surface | How to pass pieces |
|---------|-------------------|
| CLI positional | paths after the binary |
| CLI flags | repeatable `--context PATH` |
| MCP | `reconstruct` with `contextPaths: [...]` |

Pieces are merged and deduped. Later `reconstruct` on the same target can reuse the registered acquisition bundle without re-passing paths.

## What gets integrated (procedural)

| Kind | Sniff | Placement rule |
|------|-------|----------------|
| C/C++ dump | `source-dump` | Function bodies with a recoverable address → facts + `advisory/context-seeds/` |
| Notes (md/txt/…) | `notes` | Kept as context items; become facts only if name/address present |
| JSON / JSONL | structured | Imported as facts when rows have addresses |
| Ghidra `.gzf` / project snapshot | `ghidra` | Headless acquisition export (unlocked snapshot required for live projects) |
| Directory | recursive text scan | Same as mixed files inside |

**No address guesswork:** pieces without a canonical address stay **unplaced** evidence. Conflicting names at the same address are retained as conflicts—nothing is auto-picked.

## What you see

After acquire, look at:

- `acquisition/placement.json` — placed / unplaced / conflicts / skipped
- `advisory/context-seeds/` — ugly-dump cleanup seeds (not verified)
- `status` MCP / recovery status → `contextFusion` summary

Context never increments the proof ladder. Seeds are `advisory-decompiler` / context-hint until compile+objdiff accepts them into `verified/`.

## Mid-run add another piece

```bash
agentdecompile-reconstruct game.exe --work-dir <same> --resume ./more-notes.md
```

Creates a new acquisition snapshot and merges into the target fingerprint without deleting `verified/`.

## Not in v1

- Silent bulk rename into an open Ghidra program (use `manage-function` + conflict resolution)
- Inventing VAs for unplaced notes via embeddings
