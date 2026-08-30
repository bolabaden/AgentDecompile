# Living plan: corpus-wide semantic decompilation

**Status:** active  
**Created:** 2026-08-30  
**Last updated:** 2026-08-30 (dead-code reduction)  
**Code:** `src/agentdecompile_recovery/corpus/`  
**CLI:** `agentdecompile-corpus`

## Objective

AgentDecompile’s main recovery pipeline is corpus-wide semantic decompilation: every registered binary becomes a readable, buildable C/C++ project. Compiled output is later proven byte-accurate. Adding another binary is a registry entry plus `--donor`, not a new product.

```mermaid
flowchart TD
  extract[extract] --> identify[identify]
  identify --> merge[merge knowledge]
  merge --> generate[STABS folders]
  generate --> recover[Ghidra into files]
  recover --> preparse[preparse]
  preparse --> compile[compile]
  compile --> apply[apply compiling C]
  apply --> llm[llm only if still failing]
  llm --> verify[byte accuracy]
```

## Priorities (do not reorder)

1. One STABS/DWARF donor project compiles and **links to a complete executable**.
2. Cross-match compiling C onto other registered binaries.
3. Independent byte-accuracy compare (real-C and byte-accuracy stay separate).
4. Call graphs, live UI (8791 / 5173), ELI16 docs, more binaries.

## Rules

- Naming: human, STABS, symbols, Ghidra, placeholder last. Placeholder never overwrites a stronger name.
- `__asm`, `naked`, `_emit`, `.byte` bodies are not source recovery.
- Cross-match **source** only after compile succeeds. Identity matching is earlier and separate.
- Never claim completion from a dashboard label or a stale artifact.
- Do not hardcode commercial binary names into defaults.

## Progress

### Delta Update

- Landed: removed unused recovery modules (`ghidra_advisory`, `prompt_context`, `capped_output`, `corpus/features`, `corpus_archive` shim) and leftover CLI duplicates (`stdio_bridge`, unused launcher server tail, unused ToolRegistry CLI helpers). Archive inventory is `corpus/archive.py`.
- Partial: no kotorxid SQLite/`cl.exe` driver in-tree; Wine/MSVC compile remains the operator toolchain. Dashboard 8791 is still the kotorxid process. Byte-accuracy still a receipt.
- Next: extract a real STABS donor with `extract-stabs`, register it `--donor`, `--stop-after compile`.
