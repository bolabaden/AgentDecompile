# Claude-Specific MCP Debugging Instructions
Version: March 2026 • Optimized for Claude 3.5/4 + Computer Use API + MCP servers (Cursor/Copilot embedded agents)

Claude excels at vision + long-horizon reasoning. Use these exact patterns so Claude can treat the 5 debug CLIs as native tools and self-heal desktop MCP servers faster than any other model.

## System Prompt Addition (add to every Claude agent session)
```
You have full access to the following post-July-2025 MCP debugging CLI tools. Always use them in this order on any tool or GUI failure. Return ONLY JSON analysis + next exact command.

Tools:
1. MCP Inspector CLI — schema validation & single-action testing
2. mcptools — proxy & bulk calls
3. mcp-debug — REPL & session replay
4. mcp-trace — real-time traffic TUI
5. FastMCP CLI — Python tracing & sandbox fixes

When I send a screenshot or error, first run the appropriate debug command, then reason.
Never guess coordinates — always calibrate with Inspector first.
```

## Claude-Optimized Tool Calling Patterns
**Pattern for screenshot-heavy GUI loops**:
```xml
<tool_call>
name="run_terminal"
<parameter name="command">mcp-trace --filter take_screenshot --export json && fastmcp trace --limit-base64</parameter>
</tool_call>
```

**Claude Vision + Debug Synergy**:
1. Claude sees desktop screenshot.
2. Immediately calls `inspector screenshot --analyze` (returns OCR + coords).
3. If mismatch: `mcp-debug calibrate`.
4. Claude then outputs perfect mouse coords on retry.

## Special Claude Computer-Use Integration
When using Anthropic Computer Use API alongside your custom MCP:
- Wrap every `computer_use` action with pre-flight `inspector --cli call`.
- On any `mouse_move` failure: auto-inject `mcp-trace` output into next Claude message.
- Claude will self-correct: "Base64 too large — compressing via FastMCP CLI now."

## Prompt for Self-Healing (use when agent gets stuck)
```
Claude, you are now in MCP SRE mode.
Here is the last trace JSON and screenshot.
Step 1: Identify root cause using only the 5 CLIs.
Step 2: Output the exact one-line fix command.
Step 3: Execute it via terminal tool.
Step 4: Retry original task.
Begin.
```

## Claude-Specific Edge Cases & Fixes
- Hallucinated buttons on dynamic UIs → force `mcp-debug session replay` + Claude vision re-analysis.
- Token explosion from screenshots → `fastmcp trace --limit-base64 256kb` (Claude respects this limit perfectly).
- Long sessions (45+ min) → Claude maintains state via mcp-debug checkpoints better than any other model.

These patterns make Claude + your OpenInterpreter-style desktop MCP server indistinguishable from Cursor's cloud agents — except you own it, debug it, and embed it per-repo.
