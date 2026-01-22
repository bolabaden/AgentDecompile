# AgentDecompile Architecture

This document describes the high-level architecture of the AgentDecompile project, including how components interact and where different types of code live.

## Table of Contents

- [System Overview](#system-overview)
- [Component Breakdown](#component-breakdown)
- [Data Flow](#data-flow)
- [Deployment Models](#deployment-models)
- [Execution Environments](#execution-environments)

## System Overview

AgentDecompile is a **Model Context Protocol (MCP) server** that bridges AI language models to Ghidra's reverse engineering capabilities. It operates in two distinct modes:

### GUI Mode (Ghidra Plugin)
- Runs as a plugin within a Ghidra GUI instance
- One shared MCP server persists across multiple tools and projects
- Allows direct integration with Ghidra's UI
- Supports file dialogs, progress indicators, and interactive workflows

### Headless Mode (CLI + Python)
- Runs as a standalone Ghidra headless application
- Spawned by Python CLI (`agentdecompile_cli`) via PyGhidra
- Each invocation creates a new Java process and MCP server
- Suitable for scripting, automation, and non-interactive analysis

## Component Breakdown

```
┌─────────────────────────────────────────────────────────────┐
│                   Client Layer (AI Model)                   │
│                    (Claude, etc. via MCP)                   │
└──────────────────────┬──────────────────────────────────────┘
                       │ MCP (JSON-RPC over HTTP/Stdio)
┌──────────────────────┴──────────────────────────────────────┐
│                   Stdio Bridge (Python)                      │
│              src/agentdecompile_cli/stdio_bridge.py                   │
│  - Converts stdio JSON-RPC to HTTP requests                 │
│  - Wraps errors and logs as JSON-RPC notifications          │
│  - Handles reconnection and session management              │
└──────────────────────┬──────────────────────────────────────┘
                       │ HTTP (StreamableHTTP)
                       │ GET /mcp/message
┌──────────────────────┴──────────────────────────────────────┐
│               MCP Server (Java/Jetty)                        │
│          src/main/java/agentdecompile/server/McpServerManager          │
│  - Jetty HTTP server with explicit thread pool config       │
│  - Long keep-alive timeouts (24 hours)                      │
│  - Supports multiple concurrent HTTP clients                │
│  - Routes requests to resource/tool providers               │
└──────────────────────┬──────────────────────────────────────┘
                       │ Ghidra API (Direct Java calls)
┌──────────────────────┴──────────────────────────────────────┐
│              Ghidra Framework (Java)                         │
│  - Program analysis, decompilation, memory access           │
│  - Project/file management                                  │
│  - Symbol/reference resolution                              │
└──────────────────────────────────────────────────────────────┘
```

## Component Breakdown

### 1. **Python CLI Layer** (`src/agentdecompile_cli/`)

**Purpose:** Initialize Ghidra, start MCP server, and bridge stdio to HTTP

#### Files:
- **`__main__.py`** - Entry point; initializes PyGhidra, starts Java server, manages filters
- **`launcher.py`** - Wraps Java AgentDecompileHeadlessLauncher; handles project initialization
- **`stdio_bridge.py`** - MCP client that connects to Java server via HTTP; exposes stdio interface
- **`project_manager.py`** - Manages Ghidra project lifecycle (open/close/import)

#### Flow:
1. Python CLI initialized with environment variables (e.g., `AGENT_DECOMPILE_PROJECT_PATH`)
2. Installs stdout/stderr filters to ensure only JSON-RPC on stdout
3. Initializes PyGhidra (loads Ghidra into JVM)
4. Calls Java `AgentDecompileHeadlessLauncher.start()` to begin MCP server
5. Gets port from launcher
6. Starts `AgentDecompileStdioBridge` that connects to `http://localhost:{port}/mcp/message`
7. Bridge runs MCP server over stdio; all requests proxied to Java

### 2. **Java MCP Server** (`src/main/java/agentdecompile/server/`)

**Purpose:** HTTP server that handles MCP requests and coordinates Ghidra operations

#### Files:
- **`McpServerManager.java`** - Main server orchestrator; manages Jetty, thread pools, tool registration
- **`KeepAliveFilter.java`** - HTTP filter that sets `Connection: keep-alive` headers
- **`RequestLoggingFilter.java`** - Optional debug logging of HTTP requests/responses
- **`ApiKeyAuthFilter.java`** - API key authentication (if enabled)
- **`CachingRequestWrapper.java`** / **`CachingResponseWrapper.java`** - Wrap requests/responses for logging

#### Key Details:
- **Transport:** `HttpServletStreamableServerTransportProvider` (MCP SDK)
- **Endpoint:** `POST /mcp/message`
- **Thread Pool:** `QueuedThreadPool` with 24-hour idle timeout (prevents thread exhaustion)
- **Connection Timeouts:** Jetty connector + HTTP config both set to 24 hours
- **Keep-Alive:** MCP SDK sends keep-alive every 30 seconds; HTTP headers allow infinite keep-alive

### 3. **Java Headless Launcher** (`src/main/java/agentdecompile/headless/`)

**Purpose:** Initialize Ghidra in headless mode and set up server

#### Files:
- **`AgentDecompileHeadlessLauncher.java`** - Initializes Ghidra application, creates/opens project, starts MCP server

#### Key Details:
- Accepts project location and name as parameters (from Python)
- Creates `McpServerManager` with `ConfigManager` (in-memory or file-based)
- Uses random port if requested (avoids conflicts between multiple instances)
- Handles project lock files (can force-ignore if `AGENT_DECOMPILE_FORCE_IGNORE_LOCK` set)
- Starts server in a background thread; waits for startup signal

### 4. **Java Plugin (GUI Mode)** (`src/main/java/agentdecompile/plugin/`)

**Purpose:** Register MCP server as a Ghidra plugin to enable persistent, shared server across tools

#### Files:
- **`AgentDecompileApplicationPlugin.java`** - Application-level plugin; creates single `McpServerManager` at app startup
- **`ConfigManager.java`** - Manages configuration (settings, API key, server port/host)
- **`AgentDecompileProgramManager.java`** - Tracks open programs and tool associations

#### Key Details:
- Runs at Ghidra application level (not tool level) so server persists across tool sessions
- One server instance shared by all Ghidra tools
- Listens for project/tool lifecycle events and notifies server

### 5. **Tool Providers** (`src/main/java/agentdecompile/tools/*/`)

**Purpose:** Implement MCP tools for specific Ghidra capabilities

**Structure:**
- Each tool category (symbols, strings, decompiler, functions, etc.) has a `*ToolProvider` class
- Each provider registers multiple related MCP tools with the server
- Tools handle request validation, execution, and response formatting

**Examples:**
- `SymbolToolProvider` → `list_symbols`, `rename_symbol`, `demangle`
- `DecompilerToolProvider` → `decompile_function`, `get_decompiled_code`
- `StringToolProvider` → `search_strings`, `list_strings`
- `FunctionToolProvider` → `list_functions`, `get_function_info`, `analyze_function`

### 6. **Resource Providers** (`src/main/java/agentdecompile/resources/impl/`)

**Purpose:** Provide read-only data resources to clients

**Examples:**
- `ProgramListResource` → Lists all open programs
- `StaticAnalysisResultsResource` → Provides analysis metadata

### 7. **Utilities** (`src/main/java/agentdecompile/util/`)

**Purpose:** Common utilities used across tools

**Key Classes:**
- **`AddressUtil`** - Format Ghidra addresses for JSON
- **`ProgramLookupUtil`** - Resolve program path to Program object
- **`DataTypeParserUtil`** - Parse data type strings
- **`DecompilationContextUtil`** - Decompiler utilities
- **`DebugLogger`** - Structured logging

## Data Flow

### Request Flow: Client → Java

```
1. Client (Claude) sends JSON-RPC request over stdio
   │
2. stdio_bridge.py receives on stdin
   │
3. Bridge forwards to Java backend:
   POST http://localhost:{port}/mcp/message
   Content-Type: application/json
   {...JSON-RPC request...}
   │
4. Jetty receives HTTP request
   │
5. ApiKeyAuthFilter validates auth (if enabled)
   │
6. RequestLoggingFilter logs request (if enabled)
   │
7. KeepAliveFilter adds keep-alive headers
   │
8. HttpServletStreamableServerTransportProvider routes to MCP server
   │
9. MCP server dispatches to tool/resource provider
   │
10. Provider executes Ghidra operation
    │
11. Provider formats response as MCP CallToolResult
    │
12. MCP server returns via HTTP
    │
13. Bridge receives response, converts to stdio JSON-RPC
    │
14. Client reads JSON-RPC response from stdout
```

### Response Flow: Java → Client

```
1. Tool provider executes Ghidra API call
   │
2. Tool provider creates MCP response (CallToolResult)
   │
3. MCP server encodes as JSON-RPC response
   │
4. HTTP response sent back to bridge
   │
5. Bridge's ClientSession receives response
   │
6. Bridge converts to stdio JSON-RPC
   │
7. stdio_server writes to stdout
   │
8. Client receives and processes
```

## Deployment Models

### Model 1: Ghidra GUI with MCP Server (GUI Plugin)

```
┌─────────────────────────────────────┐
│  Ghidra GUI Application             │
│  ┌─────────────────────────────────┐│
│  │ AgentDecompileApplicationPlugin           ││
│  │ (starts on Ghidra init)         ││
│  │ ┌───────────────────────────────┐│
│  │ │ McpServerManager              ││
│  │ │ (HTTP on port 8080)           ││
│  │ └───────────────────────────────┘│
│  │ ┌───────────────────────────────┐│
│  │ │ Tool Providers                ││
│  │ │ (use Ghidra GUI state)        ││
│  │ └───────────────────────────────┘│
│  └─────────────────────────────────┘│
└─────────────────────────────────────┘
           ↓ HTTP ↑
    stdio_bridge (Python)
```

**Advantages:**
- Persistent server across tool/project changes
- Can use GUI features (dialogs, progress bars)
- Multiple tools can access same server
- Interactive workflows possible

**Disadvantages:**
- Requires Ghidra GUI to be running
- Server shared; one slow operation affects all clients

### Model 2: Headless Server with Stdio Bridge (CLI)

```
┌──────────────────────────────────────┐
│ Python CLI (agentdecompile_cli)                │
│ ┌────────────────────────────────────┐
│ │ launcher.py                        │
│ │ (starts Java process)              │
│ │ ┌──────────────────────────────────┐
│ │ │ AgentDecompileHeadlessLauncher (Java)      │
│ │ │ ┌──────────────────────────────┐ │
│ │ │ │ McpServerManager             │ │
│ │ │ │ (HTTP on random port)        │ │
│ │ │ └──────────────────────────────┘ │
│ │ └──────────────────────────────────┘
│ │ stdio_bridge.py                    │
│ │ (connects to HTTP, exposes stdio)  │
│ └────────────────────────────────────┘
└──────────────────────────────────────┘
            ↓ stdin/stdout ↑
         Client (Claude CLI)
```

**Advantages:**
- Headless; no GUI required
- Independent processes (each run is isolated)
- Can run multiple instances
- Suitable for scripting/automation

**Disadvantages:**
- Starts new Ghidra instance each time (slower)
- Project conflicts if multiple instances use same project
- No GUI interaction possible

## Execution Environments

### Java Thread Contexts

**Main Thread (startup):**
- Initializes Ghidra, plugins, tools
- Registers MCP server
- Spawns Jetty in background thread

**Jetty Thread Pool:**
- Handles HTTP requests concurrently
- Executes tool provider handlers
- Critical: configured with explicit thread pool to prevent thread exhaustion

**PyGhidra Thread:**
- When running headless via Python, Ghidra runs in JVM spawned by PyGhidra
- Python async event loop runs simultaneously
- JSON-RPC bridge translates between Python async and Java sync

### Python Async Contexts

**Main CLI Thread:**
- Synchronous: initializes PyGhidra, starts Java launcher
- Blocks until Java server ready

**stdio_bridge Event Loop:**
- Asynchronous: runs MCP server over stdio
- Handles multiple concurrent client requests
- Forwards requests to Java server via async HTTP client
- Runs until client disconnects

## Key Design Decisions

### 1. Separate Python and Java Processes
- **Why:** Ghidra requires JVM; Python enables CLI integration with MCP
- **Tradeoff:** IPC overhead vs. language flexibility

### 2. HTTP for Inter-Process Communication
- **Why:** Clean separation; reuses MCP SDK's HTTP transport
- **Tradeoff:** Network latency vs. simplicity and independence

### 3. Long Timeout Configuration (24 hours)
- **Why:** Ghidra operations can be slow; prevent premature connection closure
- **Tradeoff:** May hold resources longer; suitable for interactive sessions

### 4. Multiple Tool Providers Pattern
- **Why:** Modular; easy to add new tools without modifying server core
- **Tradeoff:** More classes; potentially duplicated validation logic

### 5. Session-based Projects in Headless Mode
- **Why:** Simplify cleanup; avoid project lock conflicts
- **Tradeoff:** Can't persist project state across CLI invocations (unless `AGENT_DECOMPILE_PROJECT_PATH` used)

## Future Extensibility

- **Multiple Ghidra Instances:** Currently one per process; future: pool or attach mode
- **Clustering:** Multiple servers with load balancing (would need state synchronization)
- **Plugins:** Tool providers are discoverable; could be made pluggable
- **Custom Resources:** Easy to add new resource types by extending `AbstractResourceProvider`
