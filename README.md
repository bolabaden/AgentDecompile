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
1. Download the latest release from the [Releases page](https://github.com/bolabaden/AgentDecompile/releases).
2. Open Ghidra.
3. Go to **File > Install Extensions**.
4. Click the **+** (Plus) sign and select the downloaded zip file.
5. Restart Ghidra.

### Option 2: Install from Source
If you want the absolute latest features:
```bash
# Clone the repository
git clone https://github.com/bolabaden/AgentDecompile.git
cd AgentDecompile

# Install in development mode
pip install -e .
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

### Getting started

**Run with default (stdio, local project):**

```bash
uv run mcp-agentdecompile
# or: uvx agentdecompile  # if installed via pip/uv
```

With no arguments, the CLI starts a local MCP server over stdio and uses a default project directory. Your MCP client (e.g. Claude Desktop) talks to it via stdio.

**Docker (one-liner):**

```bash
docker run -i --rm <your-agentdecompile-image> -t stdio
```

Replace `<your-agentdecompile-image>` with your built image (see Dockerfile in the repo). Use `-t stdable-http` or `-t sse` and `-p 8080:8080` for HTTP-based clients.

### Project creation and opening

- **Basic:** Run `mcp-agentdecompile` or `agentdecompile-server` with no project options; a default project directory is used (see env `AGENT_DECOMPILE_PROJECT_PATH`).
- **Custom path/name:** Use `--project-path` and `--project-name` with the server (e.g. `agentdecompile-server --project-path ~/analysis/my_study --project-name my_study`).
- **Multiple projects:** Use different `--project-path` / `--project-name` per run.
- **Existing Ghidra project:** Pass a `.gpr` file: `--project-path /path/to/existing.gpr`. The server uses that project; name is derived from the file.

### Transports

| Transport | How to use | Typical use |
|-----------|------------|-------------|
| **stdio** | Default for `mcp-agentdecompile`; no `-t` needed. | Claude Desktop, IDE MCP clients that spawn a process. |
| **streamable-http** | `agentdecompile-server -t streamable-http` (and optional `-p` / `-o` for port/host). | Browser-based or HTTP clients; CLI client in another terminal. |
| **sse** | `agentdecompile-server -t sse`. | SSE-capable MCP clients. |

The Python MCP server speaks HTTP at `http://<host>:<port>/mcp/message`. The Python CLI either runs the MCP server directly (default) or connects to an existing server via `--server-url` (connect mode).

Local proxy mode (no local Ghidra/JVM startup):

```bash
agentdecompile-server -t streamable-http -o 127.0.0.1 -p 8081 --backend-url http://170.9.241.140:8080
```

This exposes a local MCP endpoint at `http://127.0.0.1:8081/mcp/message` and forwards all tools/resources/prompts to the remote backend 1:1.

### CLI client

For a command-line interface to a **running** server (no new Ghidra process per command):

1. **Start the server** (one terminal), e.g. HTTP so the CLI can connect:

   ```bash
  agentdecompile-server -t streamable-http --project-path ./projects
   ```

2. **Use the CLI** (another terminal):

   ```bash
  # Discover available commands
  agentdecompile-cli --help

  # List available MCP tools
  agentdecompile-cli tool --list-tools

  # Call a tool directly by name
  agentdecompile-cli tool open '{"path":"/path/to/binary"}'
   ```

Install the CLI with the same package (`uv sync` or `pip install -e .`); entry points: `agentdecompile-cli`, `agentdecompile`. Use `--host`, `--port`, or `--server-url` if the server is not on `127.0.0.1:8080`. To call a tool by name: `agentdecompile-cli tool <name> '<json-args>'`; list valid names: `agentdecompile-cli tool --list-tools`. See [TOOLS_LIST.md](TOOLS_LIST.md) for the full tool reference.

#### Shared server quick usage (concise)

The examples below use the published Git source install form and redact sensitive values.

```powershell
# 1) Open a program from a Ghidra shared repository
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080 open --server_host 170.9.241.140 --server_port 13100 --server_username OpenKotOR --server_password *** /K1/k1_win_gog_swkotor.exe

# concise output
mode: shared-server
serverConnected: True
repository: Odyssey
programCount: 26
checkedOutProgram: /K1/k1_win_gog_swkotor.exe

# 2) List files in the shared repository
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080 list project-files

# concise output
folder: /
count: 26
source: shared-server-session

# 3) List a small function sample
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080 get-functions --program_path /K1/k1_win_gog_swkotor.exe --limit 5

# concise output
count: 5
totalMatched: 24242
hasMore: True

# 4) Search symbols by name
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080 search-symbols-by-name --program_path /K1/k1_win_gog_swkotor.exe --query main --max_results 5

# concise output
query: main
count: 5
totalMatched: 58
hasMore: True

# 5) Find references to a symbol
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080 references to --binary /K1/k1_win_gog_swkotor.exe --target WinMain --limit 5

# concise output
mode: to
target: 004041f0
count: 1

# 6) Raw tool mode examples
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080 tool list-imports '{"programPath":"/K1/k1_win_gog_swkotor.exe","limit":5}'
uvx --from git+https://github.com/bolabaden/agentdecompile agentdecompile-cli --server-url http://***:8080 tool list-exports '{"programPath":"/K1/k1_win_gog_swkotor.exe","limit":5}'

# concise output
mode: imports
count: 5
mode: exports
count: 1
```

Tip: use `agentdecompile-cli tool --list-tools` to see server-advertised tool names. Use `agentdecompile-cli --help` and `agentdecompile-cli tool -h` to discover command/options.

For shared Ghidra server workflows (`open --server-host ... --server-port ...`), you can set defaults once with environment variables:

```bash
export AGENT_DECOMPILE_GHIDRA_SERVER_HOST=170.9.241.140
export AGENT_DECOMPILE_GHIDRA_SERVER_PORT=13100
export AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME=OpenKotOR
export AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD='***'
```

Then `agentdecompile-cli open /K1/k1_win_gog_swkotor.exe` will automatically use those values.

### Docker and volume mapping

Map a directory of binaries into the container so the server can import and analyze them:

```bash
mkdir -p ./binaries
cp /path/to/your/binaries/* ./binaries/

docker run -i --rm -v "$(pwd)/binaries:/binaries" -p 8080:8080 <your-agentdecompile-image> -t streamable-http /binaries/*
```

Adjust the image name and port to match your build and client.

### Claude Desktop

Add AgentDecompile to `claude_desktop_config.json` so Claude uses the MCP server:

**Using stdio (spawns server on each chat):**

```json
{
  "mcpServers": {
    "AgentDecompile": {
      "command": "mcp-agentdecompile",
      "args": [],
      "env": {
        "GHIDRA_INSTALL_DIR": "/path/to/ghidra",
        "AGENT_DECOMPILE_PROJECT_PATH": "/path/to/writable/project/dir"
      }
    }
  }
}
```

**Using an already-running server (connect mode):**

```json
{
  "mcpServers": {
    "AgentDecompile": {
      "command": "mcp-agentdecompile",
      "args": ["--server-url", "http://127.0.0.1:8080"],
      "env": {
        "GHIDRA_INSTALL_DIR": "/path/to/ghidra"
      }
    }
  }
}
```

On Windows use forward slashes or escaped backslashes in paths.

### API and tools (overview)

AgentDecompile exposes 49 canonical MCP tools (see `src/agentdecompile_cli/registry.py`) and 3 resources:

- Resources: `ghidra://programs`, `ghidra://static-analysis-results`, `ghidra://agentdecompile-debug-info`
- Representative tools: `open`, `import-binary`, `list-functions`, `decompile-function`, `get-references`, `inspect-memory`, `manage-symbols`, `manage-comments`, `get-call-graph`

Use `agentdecompile-cli tool --list-tools` to view tool names available from your running server, and use [TOOLS_LIST.md](TOOLS_LIST.md) for the reference.

### Connection options

| Mode | How to connect | Endpoint / transport |
|------|-----------------|----------------------|
| **GUI** | MCP client → HTTP to host:port | `http://localhost:8080/mcp/message` (POST; port/host configurable in File → Edit Tool Options → AgentDecompile) |
| **CLI** | MCP client → stdio → `mcp-agentdecompile` | stdio JSON-RPC; bridge proxies to Python MCP server over HTTP |

**GUI (plugin):** Start Ghidra, open a project, enable AgentDecompile (File → Configure → Plugins). Point your MCP client at the URL above (default port 8080, host 127.0.0.1).

**CLI (stdio):** Configure your MCP client to use `mcp-agentdecompile` (e.g. `claude mcp add AgentDecompile -- mcp-agentdecompile`).

- **Default behavior (local spawn):** starts local PyGhidra/JVM, launches Python MCP server, then bridges stdio to it.
- **Connect mode (no local runtime startup):** pass `--server-url http://host:port` (or set `AGENT_DECOMPILE_MCP_SERVER_URL`) to connect directly to an already-running Python MCP server (headless Docker or standalone).
- **Local proxy server mode:** run `agentdecompile-server --backend-url http://host:port` to host local MCP transports (`stdio`, `streamable-http`, `sse`) that forward to a remote MCP backend without starting local PyGhidra/JVM.

### Remote access

AgentDecompile does not include SSH or WebSocket transport. To allow remote MCP access: (1) run a Python-hosted MCP server bound to `0.0.0.0` (env `AGENT_DECOMPILE_HOST=0.0.0.0`); (2) open the chosen port on the firewall; (3) point clients at `http://{remote_ip}:{port}/mcp/message` or use `--server-url http://{remote_ip}:{port}` in CLI connect mode.

**Note:** `AGENT_DECOMPILE_SERVER_USERNAME` and `AGENT_DECOMPILE_SERVER_PASSWORD` are for **Ghidra Server** (shared project repositories), not for authenticating to the MCP server itself.

### Docker

The project Dockerfile fetches **Ghidra from the official [NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra) GitHub repository** at build time. By default it uses the latest release; to pin a version set the build arg or env var `GHIDRA_VERSION` (e.g. `12.0.3`) when building.

### Environment variables

| Variable | Purpose |
|----------|---------|
| `GHIDRA_INSTALL_DIR` | Path to Ghidra installation (required for CLI/build). |
| `AGENT_DECOMPILE_MCP_SERVER_URL` | CLI connect mode target (`http(s)://host:port[/mcp/message]`). Skips local PyGhidra/JVM startup. |
| `AGENT_DECOMPILE_PROJECT_PATH` | Path to a `.gpr` project file or directory for persistent project (CLI). |
| `AGENT_DECOMPILE_HOST` | Standalone headless MCP server bind host (default `127.0.0.1`; Docker commonly `0.0.0.0`). |
| `AGENT_DECOMPILE_PORT` | Standalone headless MCP server bind port (default `8080`). |
| `AGENT_DECOMPILE_SERVER_USERNAME` | Ghidra Server username (shared projects). |
| `AGENT_DECOMPILE_SERVER_PASSWORD` | Ghidra Server password (shared projects). |
| `AGENT_DECOMPILE_SERVER_HOST` | Ghidra Server host (reference). |
| `AGENT_DECOMPILE_SERVER_PORT` | Ghidra Server port (default 13100). |
| `AGENT_DECOMPILE_FORCE_IGNORE_LOCK` | If `true`, delete project lock files before opening (risky; see Project locking below). |

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
