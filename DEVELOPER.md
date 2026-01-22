# Developer Notes

Internals and architecture of AgentDecompile.

## Architecture

AgentDecompile runs as a generic Ghidra extension that starts a local HTTP server. This server implements the Model Context Protocol (MCP).

### Key Components

1.  **AgentDecompilePlugin**: The Ghidra plugin that manages the server lifecycle.
2.  **McpServerManager**: Handles MCP requests (list_tools, call_tool, etc.).
3.  **ToolProvider**: Abstract base class for all tools (Decompiler, Listing, etc.).

### Adding a New Tool

1.  Extend `AbstractToolProvider` in `agentdecompile.tools`.
2.  Implement `getToolDef()` to return the JSON schema.
3.  Implement `call()` to handle the request.
4.  Register it in `McpServerManager`.
