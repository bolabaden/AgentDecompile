# AgentDecompile - Your AI Companion for Ghidra

> AI-powered code analysis and reverse engineering, directly inside Ghidra.

**AgentDecompile** bridges the gap between Ghidra and modern Artificial Intelligence. It allows you to chat with your binaries, automating the tedious parts of reverse engineering so you can focus on the logic that matters.

Built on the open standard [Model Context Protocol (MCP)](https://modelcontextprotocol.io), AgentDecompile turns Ghidra into an intelligent agent that can read, understand, and explain code for you.

## Why AgentDecompile?

Reverse engineering is hard. There are thousands of functions, cryptic variable names, and complex logic flows. AgentDecompile helps you make sense of it all by letting you ask plain English questions about your target code.

- **Ask Questions**: "Where is the main loop?", "Find all encryption functions", "What does this variable do?"
- **Automate Analysis**: Let the AI rename variables, comment functions, and map out code structures for you.
- **Smart Context**: Unlike generic chat bots, AgentDecompile actually sees your code. It reads the decompiled output, checks cross-references, and understands the program structure just like a human analyst would.

It's designed to be your pair programmer for assembly and decompiled code.

## What Can It Do?

You can ask AgentDecompile to perform complex tasks:

- **"Analyze this entire binary and summarize what it does."**
- **"Find where the user password is checked."**
- **"Rename all these variables to something meaningful."**
- **"Draw a diagram of this class structure."**
- **"Write a Python script to solve this CTF challenge."**

It works by giving the AI specific "tools" to interact with Ghidra—reading memory, listing functions, checking references—so it gets real, ground-truth data from your project.

## Installation

> **Note**: AgentDecompile requires Ghidra 12.0 or higher.

### Option 1: Release Installation (Recommended)
1. Download the latest release from the [Releases page](../../releases).
2. Open Ghidra.
3. Go to **File > Install Extensions**.
4. Click the **+** (Plus) sign and select the downloaded zip file.
5. Restart Ghidra.

### Option 2: Build from Source
If you want the absolute latest features:
```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
gradle install
```

### Enabling the Extension
Once installed, you need to turn it on:
1. Open a binary in the **Code Browser**.
2. Go to **File > Configure**.
3. Click the **plug icon** (Configure All Plugins) in the top right.
4. Find **AgentDecompile** or **AgentDecompile Plugin** in the list and check the box.
5. Click **OK**.

## Usage

AgentDecompile runs as an MCP server so you can connect an AI client (Claude Desktop, IDE extensions, etc.) to Ghidra.

### Connection options

| Mode | How to connect | Endpoint / transport |
|------|-----------------|----------------------|
| **GUI** | MCP client → HTTP to host:port | `http://localhost:8080/mcp/message` (POST; port/host configurable in File → Edit Tool Options → AgentDecompile) |
| **CLI** | MCP client → stdio → `mcp-agentdecompile` | stdio JSON-RPC; bridge proxies to Java MCP server over HTTP |

**GUI (plugin):** Start Ghidra, open a project, enable AgentDecompile (File → Configure → Plugins). Point your MCP client at the URL above (default port 8080, host 127.0.0.1).

**CLI (stdio):** Configure your MCP client to use `mcp-agentdecompile` (e.g. `claude mcp add AgentDecompile -- mcp-agentdecompile`).

- **Default behavior (local spawn):** starts local PyGhidra/JVM, launches Java MCP server, then bridges stdio to it.
- **Connect mode (no local Java/Ghidra required):** pass `--mcp-server-url http://host:port` (or set `AGENT_DECOMPILE_MCP_SERVER_URL`) to connect directly to an already-running Java MCP server (headless Docker or GUI-hosted).

### Remote access

AgentDecompile does not include SSH or WebSocket transport. To allow remote MCP access: (1) run a Java-hosted MCP server bound to `0.0.0.0` (GUI options or standalone headless env `AGENT_DECOMPILE_HOST=0.0.0.0`); (2) enable API key authentication and set a key (clients send `X-API-Key`); (3) open the chosen port on the firewall; (4) point clients at `http://{remote_ip}:{port}/mcp/message` or use `--mcp-server-url http://{remote_ip}:{port}` in CLI connect mode.

**Note:** `AGENT_DECOMPILE_SERVER_USERNAME` and `AGENT_DECOMPILE_SERVER_PASSWORD` are for **Ghidra Server** (shared project repositories), not for authenticating to the MCP server itself.

### Docker

The project Dockerfile fetches **Ghidra from the official [NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra) GitHub repository** at build time. By default it uses the latest release; to pin a version set the build arg or env var `GHIDRA_VERSION` (e.g. `12.0.3`) when building.

### Environment variables

| Variable | Purpose |
|----------|---------|
| `GHIDRA_INSTALL_DIR` | Path to Ghidra installation (required for CLI/build). |
| `AGENT_DECOMPILE_MCP_SERVER_URL` | CLI connect mode target (`http(s)://host:port[/mcp/message]`). Skips local PyGhidra/JVM startup. |
| `AGENT_DECOMPILE_API_KEY` | Optional API key sent as `X-API-Key` by CLI connect mode. |
| `AGENT_DECOMPILE_API_KEY_ENABLED` | Enable API key authentication for MCP server access (default: `true` when `AGENT_DECOMPILE_API_KEY` is set, `false` otherwise). |
| `AGENT_DECOMPILE_PROJECT_PATH` | Path to a `.gpr` project file or directory for persistent project (CLI). |
| `AGENT_DECOMPILE_HOST` | Standalone headless MCP server bind host (default `127.0.0.1`; Docker commonly `0.0.0.0`). |
| `AGENT_DECOMPILE_PORT` | Standalone headless MCP server bind port (default `8080`). |
| `AGENT_DECOMPILE_SERVER_USERNAME` | Ghidra Server username (shared projects). |
| `AGENT_DECOMPILE_SERVER_PASSWORD` | Ghidra Server password (shared projects). |
| `AGENT_DECOMPILE_SERVER_HOST` | Ghidra Server host (reference). |
| `AGENT_DECOMPILE_SERVER_PORT` | Ghidra Server port (default 13100). |
| `AGENT_DECOMPILE_AUTO_LABEL` | Enable auto-labeling for names/comments (default: true). |
| `AGENT_DECOMPILE_AUTO_TAG` | Enable auto-tagging for functions (default: true). |
| `AGENT_DECOMPILE_AUTO_BOOKMARK_PERCENTILE` | Auto-bookmark top N% by reference count (default: 97.0; range 95–99). |
| `AGENT_DECOMPILE_FORCE_IGNORE_LOCK` | If `true`, delete project lock files before opening (risky; see Project locking below). |

### Intelligent features

AgentDecompile can automatically **bookmark** frequently referenced addresses, **tag** functions (e.g. crypto, network), **label** functions and variables, and **comment** at addresses. These are controlled only by environment variables (no tool parameters): `AGENT_DECOMPILE_AUTO_LABEL`, `AGENT_DECOMPILE_AUTO_TAG`, `AGENT_DECOMPILE_AUTO_BOOKMARK_PERCENTILE`. They are on by default; explicit values in tool calls always take precedence.

### Shared project authentication

When opening a `.gpr` file connected to a Ghidra Server, authentication may be required. Provide credentials via the `open` tool parameters (`serverUsername`, `serverPassword`) or the environment variables above; tool parameters override env. Local projects do not need credentials. If you see "Shared project requires authentication but no credentials provided", set the env vars or pass parameters. For troubleshooting, see [CONTRIBUTING.md](CONTRIBUTING.md) (Ghidra Project Authentication Implementation).

### Project locking

Ghidra allows only one process to open a project at a time (file-based locks). If you see "Project 'X' is locked", close the project in the other process or use a different project. For shared access, use Ghidra Server. **Workaround:** `AGENT_DECOMPILE_FORCE_IGNORE_LOCK=true` (or `forceIgnoreLock: true` on `open`) deletes lock files before opening—**risky**; can cause data corruption if multiple processes write. Use only when you are sure only one process will write and you have backups.

### Structure size (manage-structures)

When adding fields with `add_field`, `useReplace` defaults to `true` so the structure size is preserved (fields replace bytes at the given offset). Use `preserveSize: true` to fail if the structure would grow. For byte-perfect layouts, use the `parse_header` action with a full C definition. See [CONTRIBUTING.md](CONTRIBUTING.md) (Structure Size Preservation) for technical details.

## License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. See [LICENSE](LICENSE) for details. AGPL-3.0 is a strong copyleft license that also requires offering source to users who interact with the software over a network (e.g. SaaS). 

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for how to get involved.
