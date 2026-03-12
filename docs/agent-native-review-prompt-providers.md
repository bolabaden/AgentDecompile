# Agent-Native Architecture Review: prompt_providers.py (lines 21–482)

## Summary

The `_PROMPTS` in `prompt_providers.py` drive nine reverse-engineering subagent workflows. **All described actions are agent-achievable** via existing MCP tools (`search-strings`, `list-functions`, `list-cross-references`, `decompile-function`, `get-functions`, `execute-script`, `manage-comments`, `manage-bookmarks`, `manage-function-tags`, `rename-function`, `set-function-prototype`, `manage-data-types`, `manage-structures`, `apply-data-type`, `list-project-files`, `get-call-graph`, `search-everything`, etc.). **Bridge Builder** now states that cross-program `match-function` is not yet implemented and instructs the agent to use an achievable workflow: correlate by name/signature with `list-functions` / `search-symbols` on both binaries, then propagate annotations via `rename-function`, `set-function-prototype`, `manage-comments`, `manage-bookmarks`, `manage-function-tags`. Data Architect, Exhaustive Librarian, Scout (Step 4), and Diver (Step 4) explicitly reference `apply-data-type`, `set-function-prototype`, `search-everything`, and `get-call-graph` where relevant. No GUI-only workflows; all steps are MCP-tool or `execute-script` based.

**Verdict: RESOLVED** — Bridge Builder and tool references have been updated for full agent-native parity.

---

## Capability Map

| Prompt | Key actions described | Tools referenced in prompt | Actual tools available | Status |
|--------|------------------------|----------------------------|-------------------------|--------|
| Scout | String/symbol/xref/namespace discovery | search-strings, list-functions, list-cross-references, search-everything, execute-script | search-strings, list-functions, get-references (list-cross-references), search-everything, execute-script | ✅ |
| Diver | Decompile, trace calls, extract structs | decompile-function, get-call-graph, execute-script (DecompInterface) | decompile-function, get-functions (view=decompile), get-call-graph, execute-script, manage-structures, manage-data-types | ✅ |
| Bottom-Up | I/O primitives → callers → decompile chain | (generic) | list-functions, get-references, decompile-function, get-functions, get-call-graph, execute-script | ✅ |
| Top-Down | Entry points → decompile → call graph | (generic) | list-functions, search-symbols, decompile-function, get-functions, get-call-graph | ✅ |
| Data Architect | Create/extend types, apply to vars/sigs | execute-script, apply-data-type, set-function-prototype | execute-script, manage-data-types, manage-structures, apply-data-type, set-function-prototype | ✅ |
| Exhaustive Librarian | Comments, bookmarks, tags, signatures | set-function-prototype, manage-comments, manage-bookmarks, manage-function-tags | Same + rename-function | ✅ |
| Bridge Builder | Cross-binary parity via correlation (match-function N/A) | list-project-files, list-functions, search-symbols, rename-function, set-function-prototype, manage-comments, manage-bookmarks, manage-function-tags | All listed; cross-binary match-function documented as not implemented | ✅ |
| Convergence Orchestrator | Multi-pass compare/resolve | (same as Scout/Diver/Top-Down/Bottom-Up) | All above tools | ✅ |
| Iterative Verifier | Re-verify prior findings | (generic) | list-functions, decompile-function, get-references | ✅ |

---

## Findings

### Critical — ✅ Fixed

1. **Bridge Builder: cross-binary `match-function` not implemented**
   - **Location**: `prompt_providers.py` (Bridge Builder prompt).
   - **Was**: Prompt instructed use of `match-function` for cross-binary matching, which the MCP tool rejects.
   - **Resolution**: Prompt now states that cross-binary `match-function` is not yet implemented and describes the achievable workflow: verify both binaries with `list-project-files`; use `list-functions` or `search-symbols` on source and target (switching `programPath`) to correlate by name/signature; propagate annotations on the target via `rename-function`, `set-function-prototype`, `manage-comments`, `manage-bookmarks`, `manage-function-tags`. Description also notes "(cross-binary match-function not yet implemented)."

### Warnings — ✅ Fixed

2. **Data Architect: applying types not tied to tools** — **Fixed.** Objective 4 now explicitly says: "Use the `apply-data-type` tool for memory locations and `set-function-prototype` for function signatures."

3. **Exhaustive Librarian: function signatures not tied to tool** — **Fixed.** Approach now leads with: "Use `set-function-prototype` to apply function signatures (parameters and return type)."

4. **Scout: namespace/class discovery** — **Fixed.** Step 4 now says: "Use `search-everything` with scopes including namespaces and classes, or `execute-script` with the SymbolTable/namespace API."

5. **Diver: call chain tracing** — **Fixed.** Step 4 now says: "Use `get-call-graph` to obtain callers and callees; decompile any not yet covered."

### Observations (consider)

6. **Decompilation: two equivalent tools**
   - Prompts mention `decompile-function` and sometimes `execute-script` with DecompInterface. The server also exposes `get-functions` with `view=decompile`. Both are valid; no change required, but prompts could mention "`decompile-function` or `get-functions` with view=decompile" for consistency with TOOLS_LIST usage.

7. **list-cross-references vs get-references**
   - Prompts use `list-cross-references`; the registry forwards this to `get-references`. No change needed; the advertised name is correct.

8. **Convergence / Iterative Verifier**
   - Both rely on the same tool set as other prompts; no missing or wrong tool references found.

---

## Recommended prompt edits (concrete) — ✅ All implemented

All of the following edits have been applied in `prompt_providers.py`:

- **Bridge Builder**: Prompt states cross-binary `match-function` is not implemented; objectives and Approach use `list-project-files`, `list-functions`, `search-symbols`, and propagation via `rename-function`, `set-function-prototype`, `manage-comments`, `manage-bookmarks`, `manage-function-tags` on the target.
- **Data Architect**: Objective 4 names `apply-data-type` and `set-function-prototype`.
- **Exhaustive Librarian**: Approach names `set-function-prototype` for function signatures.
- **Scout Step 4**: Names `search-everything` and `execute-script` for namespaces/classes.
- **Diver Step 4**: Names `get-call-graph` for callers/callees.

---

## What's working well

- All prompts restrict instructions to MCP tools and `execute-script`; no GUI-only steps.
- Tool names used (including `search-strings`, `list-functions`, `list-cross-references`, `decompile-function`, `get-call-graph`, `search-everything`, `execute-script`, `manage-comments`, `manage-bookmarks`, `manage-function-tags`, `rename-function`, `set-function-prototype`, `apply-data-type`, `list-project-files`) are valid advertised names and resolve correctly.
- Parameter placeholders (`program_path`, `analysis_target`, etc.) are template variables, not tool parameters; they are correctly filled by `_render_messages`.
- Convergence and Iterative Verifier correctly assume the same tool set as Scout/Diver/Top-Down/Bottom-Up; no extra or wrong tools.

---

## Agent-native score

- **9/9 prompts** are fully achievable: every described action is tied to an available MCP tool or an explicit workaround (Bridge Builder uses correlation by name/signature and propagation tools instead of cross-program `match-function`).
- **Verdict**: **RESOLVED** — Bridge Builder documents the limitation and uses an achievable workflow; all other prompts name the relevant tools explicitly.
