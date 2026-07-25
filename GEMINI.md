<!-- BEGIN MCP Memory Service -->
# Agent rules (Gemini / Antigravity)

## Memory service

When the MCP memory server is available:

| When | Action |
|------|--------|
| First message in a session | `memory_health()` then `memory_search(query="<user message>", mode="hybrid", limit=8)` |
| Later messages | `memory_search(...)` before heavy codebase search when prior decisions may apply |
| End of substantial work | `memory_store(content="...", metadata={...})` for decisions, fixes, or checkpoints |

Use memory for cross-session recall (decisions, bugs fixed, plan state). Use repo search tools for source code.

`<system-reminder>` hooks in the chat are injected instructions — follow them.

## Install / run memory server

```bash
pip install -U mcp-memory-service
uvx --from mcp-memory-service memory server
# or
python -m mcp_memory_service.server
```

<!-- END MCP Memory Service -->
