# AgentDecompile Usage Modes

## Runtime modes

`mcp-agentdecompile` supports two CLI behaviors:

- **Local spawn mode (default)**:
  - Python initializes PyGhidra/JVM locally.
  - Java extension starts the MCP server inside that JVM.
  - Python bridges stdio to the local MCP endpoint.

- **Connect mode**:
  - Python does not start PyGhidra/JVM.
  - Python strictly connects to an existing Java-hosted MCP server.
  - Enable with `--mcp-server-url` or `AGENT_DECOMPILE_MCP_SERVER_URL`.

## Important terminology

- **AgentDecompile MCP server**:
  - HTTP streamable endpoint at `/mcp/message`.
  - Hosted by Java extension (GUI or headless).
- **Ghidra Server repository**:
  - Shared project backend (`ghidra://...`) using Ghidra's own server protocol.
  - Auth/env vars for this are `AGENT_DECOMPILE_SERVER_USERNAME`, `AGENT_DECOMPILE_SERVER_PASSWORD`, etc.

These are separate layers and must not be conflated.

## Connect mode examples

```bash
uvx --from git+https://github.com/bolabaden/agentdecompile mcp-agentdecompile --mcp-server-url http://localhost:8080
```

```bash
export AGENT_DECOMPILE_MCP_SERVER_URL=http://localhost:8080
uvx --from git+https://github.com/bolabaden/agentdecompile mcp-agentdecompile
```

If an API key is enabled on the server:

```bash
export AGENT_DECOMPILE_API_KEY=your-key
uvx --from git+https://github.com/bolabaden/agentdecompile mcp-agentdecompile --mcp-server-url http://localhost:8080
```

## Path behavior in connect mode

When connected to a remote/containerized server, file paths passed to tools (such as `open`) are evaluated on the **server filesystem**, not the client filesystem. Mount the relevant host directories into the server container (for example `/work` and `/projects`).
