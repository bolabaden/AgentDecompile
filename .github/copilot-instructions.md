# AgentDecompile – Copilot/Claude Instructions

## Writing and Tone Policy (Anti-Fluff)
- **No Preambles or Postambles**: Never start with "Here is...", "Certainly!", or "Sure, I can help...". Do not end with summaries like "In conclusion..." or "Let me know if you need anything else."
- **No Sycophantic Echoing**: Do not repeat or embed the user's prompt back to them in your response. 
- **No AI Filler Words**: Avoid words like *delve, tapestry, crucial, testament, robust, flawlessly, seamless, embark*.
- **Direct & Clinical**: Adopt a strictly technical, objective, and factual tone. Just output the code, docs, or direct answer.

## Default Behavior Change Policy

- When a default behavior is intentionally changed by product direction, update tests to the new expected behavior.
- Do not preserve legacy regression expectations for intentionally changed defaults unless explicitly requested.
- Prefer updating central test fixtures/helpers over repetitive per-test edits when adapting large suites to new defaults.

## Planning and Documentation Diagram Policy

- Every new or updated planning/design document must include at least one Mermaid diagram.
- The diagram should appear near the top (after objective/scope) and provide a high-level flow.
- Keep diagrams synchronized with the written steps when plans evolve.
- Prefer simple `flowchart TD` diagrams for execution plans and phase sequencing.
- If a document has multiple phases/modules, include one top-level diagram plus optional focused diagrams.

## What is AgentDecompile?

AgentDecompile provides a comprehensive Model Context Protocol (MCP) server that allows AI clients to interact with Ghidra/PyGhidra for reverse engineering.

Full specification: [TOOLS_LIST.md](../TOOLS_LIST.md)

## Python Implementation

**Location:** `src/agentdecompile_cli/`

- `mcp_server/tool_providers.py` – `ToolProvider` base class + `ToolProviderManager` (centralized normalization, dispatch, error handling)
- `mcp_server/providers/*.py` – Tool implementations (19 files, one per domain)
- `mcp_server/server.py` – MCP server (FastAPI + MCP SDK wiring)
- `mcp_utils/*.py` – Shared utilities (address resolution, symbol lookup, etc.)
- `tools/wrappers.py` – `GhidraTools` wrapper class (comprehensive Ghidra API access)
- `registry.py` – Tool registry, `normalize_identifier()`, canonical tool list
- `models.py` – Response data structures
