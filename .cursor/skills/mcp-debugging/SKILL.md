---
name: mcp-debugging
description: Use when debugging MCP servers, self-healing, or when the user mentions MCP Inspector, mcptools, mcp-debug, mcp-trace, FastMCP CLI, or MCP tool/schema problems (timeouts, schema, GUI/coords, sandbox).
---

# MCP server debugging & self-healing

Reference for investigating and fixing MCP server issues: timeouts, schema mismatches, GUI/coords, sandbox, tool discovery failures. To apply: follow the meta-debug loop and use the five CLIs (MCP Inspector, mcptools, mcp-debug, mcp-trace, FastMCP CLI) as appropriate.

## When to use

- User or agent is debugging an MCP server (this repo’s or any other).
- Timeouts, missing tools, schema mismatches, or “tool not found” errors.
- Questions about MCP self-healing, workflows, or Claude-specific tool patterns.

## Quick start

1. Identify the need: schema check, workflow, or Claude prompts/tool patterns.
2. Open the matching reference below (detail in `references/`; read on demand).
3. Follow the meta-debug loop and CLI steps in the reference.

## Reference docs (progressive disclosure)

| Doc | Purpose |
|-----|--------|
| [references/CLIS_AND_META_DEBUG.md](references/CLIS_AND_META_DEBUG.md) | Five CLIs and the meta-debug loop checklist. |
| [references/WORKFLOWS.md](references/WORKFLOWS.md) | Agent behavior, workflows, and checklists. |
| [references/CLAUDE_MCP_DEBUG.md](references/CLAUDE_MCP_DEBUG.md) | Claude-oriented prompts, tool patterns, and edge cases. |

Use this SKILL.md as the entry point; open references only when procedures or patterns are needed.
